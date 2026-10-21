package main

import (
	"errors"
	"flag"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"
)

// gateway stands in for the load balancer or Istio gateway behind the edge:
// it routes each request by path prefix to a service, longest prefix first,
// so the edge forwards everything to one address as it does in production.
func gateway(args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "address to serve")
	routes := fs.String("routes", "", "comma-separated prefix=URL; include / as the default")
	if err := fs.Parse(args); err != nil {
		return err
	}
	h, err := newGateway(*routes)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	return srv.ListenAndServe()
}

type gatewayRoute struct {
	prefix string
	proxy  *httputil.ReverseProxy
}

func newGateway(spec string) (http.Handler, error) {
	t := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: time.Second}).DialContext,
		MaxIdleConnsPerHost: 512,
		IdleConnTimeout:     60 * time.Second,
	}
	var rs []gatewayRoute
	for pair := range strings.SplitSeq(spec, ",") {
		prefix, raw, _ := strings.Cut(pair, "=")
		u, err := url.Parse(raw)
		if err != nil || !strings.HasPrefix(prefix, "/") || u.Host == "" {
			return nil, errors.New("routes must be /prefix=http://host:port")
		}
		p := &httputil.ReverseProxy{
			// Headers pass through as the edge set them, Host included.
			Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(u); r.Out.Host = r.In.Host },
			Transport: t,
		}
		rs = append(rs, gatewayRoute{prefix, p})
	}
	slices.SortFunc(rs, func(a, b gatewayRoute) int { return len(b.prefix) - len(a.prefix) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, rt := range rs {
			if strings.HasPrefix(r.URL.Path, rt.prefix) {
				rt.proxy.ServeHTTP(w, r)
				return
			}
		}
		http.NotFound(w, r)
	}), nil
}
