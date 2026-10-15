package main

import (
	"errors"
	"flag"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// lb stands in for the cloud load balancer in front of the edges:
// round robin over backends whose /readyz answers 200, checked
// every second, a 60s idle timeout below the edges' 75s, and one retry on
// another backend when a connection can't be made, since then the request
// never reached an edge.
func lb(args []string) error {
	fs := flag.NewFlagSet("lb", flag.ContinueOnError)
	listen := fs.String("listen", ":8000", "address to serve")
	backends := fs.String("backends", "", "comma-separated edge URLs")
	health := fs.String("health", ":9090/readyz", "port and path checked on each backend host")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var pool []*backend
	for b := range strings.SplitSeq(*backends, ",") {
		u, err := url.Parse(b)
		if err != nil || u.Host == "" {
			return errors.New("backends must be URLs")
		}
		pool = append(pool, &backend{url: u, health: "http://" + u.Hostname() + *health})
	}
	p := &balancer{pool: pool, base: &http.Transport{
		DialContext:         (&net.Dialer{Timeout: time.Second}).DialContext,
		MaxIdleConnsPerHost: 512,
		IdleConnTimeout:     60 * time.Second,
	}}
	go p.check()
	proxy := &httputil.ReverseProxy{
		// Headers pass through as the CDN sent them; the edge decides trust.
		Rewrite:   func(r *httputil.ProxyRequest) { r.Out.URL.Scheme, r.Out.URL.Host = "http", "edge" },
		Transport: p,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	srv := &http.Server{Addr: *listen, Handler: proxy, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	return srv.ListenAndServe()
}

type backend struct {
	url    *url.URL
	health string
	up     atomic.Bool
}

type balancer struct {
	pool []*backend
	next atomic.Uint64
	base http.RoundTripper
}

func (b *balancer) check() {
	c := &http.Client{Timeout: 900 * time.Millisecond}
	for {
		for _, be := range b.pool {
			resp, err := c.Get(be.health)
			ok := err == nil && resp.StatusCode == http.StatusOK
			if err == nil {
				_ = resp.Body.Close()
			}
			be.up.Store(ok)
		}
		time.Sleep(time.Second)
	}
}

func (b *balancer) pick(skip *backend) *backend {
	for range b.pool {
		be := b.pool[b.next.Add(1)%uint64(len(b.pool))]
		if be.up.Load() && be != skip {
			return be
		}
	}
	return nil
}

func (b *balancer) RoundTrip(r *http.Request) (*http.Response, error) {
	var tried *backend
	var err error
	for range 2 {
		be := b.pick(tried)
		if be == nil {
			return nil, errors.New("no healthy backend")
		}
		out := r.Clone(r.Context())
		out.URL.Host = be.url.Host
		var resp *http.Response
		resp, err = b.base.RoundTrip(out)
		var op *net.OpError
		if err == nil || !errors.As(err, &op) || op.Op != "dial" || r.Body != nil && r.Body != http.NoBody {
			return resp, err
		}
		be.up.Store(false) // until the next health check says otherwise
		tried = be
	}
	return nil, err
}
