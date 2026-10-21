package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errUpstreamTimeout = errors.New("upstream response headers timed out")

// upstreamRoots is nil (the system pool) except in tests.
var upstreamRoots *x509.CertPool

func newTransport(c *Config) *http.Transport {
	d := &net.Dialer{Timeout: c.DialTimeout, KeepAlive: 30 * time.Second}
	addr := c.Upstream.Host // config sets the port
	return &http.Transport{
		// Never use an environment proxy: the upstream is deployment-defined.
		Proxy: nil,
		// Every connection goes to UPSTREAM_URL. The request URL's host can
		// differ (see rewrite) but only names the TLS server, never the address.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12},
		// Pools are per Host for an https upstream, and a client picks the
		// Host, so the total is capped too.
		MaxIdleConns:          c.MaxIdleConns,
		MaxIdleConnsPerHost:   c.MaxIdleConns,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   c.DialTimeout,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// proxy is step 10. It never retries: a request may not be safe to repeat,
// and retries multiply load during an incident.
func (e *Edge) proxy(st *reqState, r *http.Request) {
	if r.ContentLength > st.set.bodyLimit {
		e.reject(st, kPayloadTooLarge, reasonPayloadTooLarge)
		return
	}
	if r.ContentLength != 0 {
		// A slow-body client can't hold a connection forever, and the
		// deadline is cleared at EOF so it never cuts a response stream.
		rc := http.NewResponseController(st.sw.ResponseWriter)
		_ = rc.SetReadDeadline(st.start.Add(time.Duration(st.ver.c.Config.Global.Defaults.BodyReadTimeout)))
		r.Body = &body{ReadCloser: http.MaxBytesReader(st.sw.ResponseWriter, r.Body, st.set.bodyLimit), rc: rc, st: st}
	}

	// The upstream must send response headers within the timeout; the body
	// may then stream for as long as it needs (SSE, downloads).
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	timer := time.AfterFunc(st.set.upstreamTimeout, func() { cancel(errUpstreamTimeout) })
	defer timer.Stop()

	st.upTimer = timer
	// st.ctx wraps ctx, so one WithContext copy of r carries both.
	st.ctx = stateCtx{Context: ctx, st: st}
	e.rp.ServeHTTP(&st.sw, r.WithContext(&st.ctx))
}

// newReverseProxy is the one ReverseProxy every request shares. Its hooks
// find the request's state in its context, so a request builds no proxy
// or closures of its own.
func (e *Edge) newReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			e.rewrite(pr, stateOf(pr.In))
		},
		Transport:  newTransport(e.cfg),
		BufferPool: e.pool,
		ModifyResponse: func(resp *http.Response) error {
			st := stateOf(resp.Request)
			st.upTimer.Stop()
			st.upstream, st.headersAt = true, e.now()
			// Edge-managed: replaces any the upstream sent.
			st.setRateLimitHeaders(resp.Header)
			st.setCORS(resp.Header)
			return nil
		},
		ErrorHandler: func(_ http.ResponseWriter, r *http.Request, err error) { e.proxyError(stateOf(r), r, err) },
	}
}

// stateCtx carries the request's state to the shared proxy's hooks. It
// lives inside reqState, so attaching it allocates nothing.
type stateCtx struct {
	context.Context
	st *reqState
}

type stateKey struct{}

func (c *stateCtx) Value(key any) any {
	if key == (stateKey{}) {
		return c.st
	}
	return c.Context.Value(key)
}

// stateOf is the state proxy attached to r, or to the request r was cloned from.
func stateOf(r *http.Request) *reqState { return r.Context().Value(stateKey{}).(*reqState) }

// rewrite builds the upstream request. Forwarding headers come only from
// trusted values; SetXForwarded would use the LB's address.
// ReverseProxy has already removed hop-by-hop, Forwarded and X-Forwarded-*.
func (e *Edge) rewrite(pr *httputil.ProxyRequest, st *reqState) {
	u := e.cfg.Upstream
	pr.SetURL(u)
	if raw := pr.In.URL.RawPath; raw != "" {
		// Go sends EscapedPath, which re-encodes the decoded path, turning
		// %2F into "/", when RawPath has a byte a path can't carry raw.
		pr.Out.URL.RawPath = strings.TrimSuffix(u.EscapedPath(), "/") + escapeRaw(raw)
	}
	pr.Out.Host = pr.In.Host
	if u.Scheme == "https" {
		// TLS names the request's own host, as the Host header does, so a
		// load balancer or gateway that picks its certificate and route by
		// SNI serves this host. The dial still goes to UPSTREAM_URL.
		if h := st.fields.host; u.Port() == "443" && !strings.Contains(h, ":") {
			pr.Out.URL.Host = h // the default port, without an allocation per request
		} else {
			pr.Out.URL.Host = net.JoinHostPort(h, u.Port())
		}
	}
	h := pr.Out.Header
	upstreamHeaders(st.ver.c, &st.ver.headers, st, h, e.strip)
	ip := st.client.ip.String()
	proto := "http"
	if st.client.ssl {
		proto = "https"
	}
	v := make(headerValues, 0, 10)
	v.set(h, "X-Forwarded-For", ip)
	v.set(h, "X-Forwarded-Proto", proto)
	v.set(h, "X-Forwarded-Host", pr.In.Host)
	v.set(h, "X-Request-Id", st.requestID)
	v.set(h, "X-Edge-Client-Ip", ip)
	if c := st.client.country; c != "" {
		v.set(h, "X-Edge-Geo-Country", c)
	}
	if c := st.client.continent; c != "" {
		v.set(h, "X-Edge-Geo-Continent", c)
	}
	if st.client.hasASN {
		v.set(h, "X-Edge-Geo-Asn", strconv.FormatInt(st.client.asn, 10))
	}
	if st.authIssuer != "" {
		v.set(h, "X-Edge-Auth-Issuer", st.authIssuer)
		if st.authSub != "" {
			v.set(h, "X-Edge-Auth-Sub", headerSafe(st.authSub))
		}
	}
}

// headerValues hands out one-value slices from a single allocation, for
// edge-owned headers set together. Keys must be canonical, as Header.Set
// would write them; a non-canonical key costs Set another allocation.
type headerValues []string

func (v *headerValues) set(h http.Header, key, val string) {
	*v = append(*v, val)
	n := len(*v)
	h[key] = (*v)[n-1 : n : n]
}

// proxyError maps a failed upstream exchange to a templated response.
func (e *Edge) proxyError(st *reqState, r *http.Request, err error) {
	var ne net.Error
	switch {
	case st.bodyLarge:
		e.reject(st, kPayloadTooLarge, reasonPayloadTooLarge)
	case st.bodySlow:
		e.reject(st, kBadRequest, reasonBodyTimeout)
	case errors.Is(context.Cause(r.Context()), errUpstreamTimeout):
		e.reject(st, kGatewayTimeout, reasonUpstreamTimeout)
	case r.Context().Err() != nil:
		// The client left; there is no one to answer.
		st.reason, st.rejected = reasonClientGone, true
		e.m.rejected[reasonClientGone].Add(1)
	case errors.As(err, &ne) && ne.Timeout():
		e.reject(st, kGatewayTimeout, reasonUpstreamTimeout)
	default:
		e.log.Warn("upstream request failed", "error", err.Error(), "request_id", st.requestID)
		e.reject(st, kBadGateway, reasonUpstreamError)
	}
}

// body enforces the limit and read deadline and records why reading failed,
// because the transport doesn't preserve the error type.
type body struct {
	io.ReadCloser
	rc *http.ResponseController
	st *reqState
}

func (b *body) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	var mbe *http.MaxBytesError
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
		_ = b.rc.SetReadDeadline(time.Time{})
	case errors.As(err, &mbe):
		b.st.bodyLarge = true
	case errors.Is(err, os.ErrDeadlineExceeded):
		b.st.bodySlow = true
	}
	return n, err
}

// bufferSize is the size of every pooled buffer.
const bufferSize = 32 << 10

// bufferPool shares 32 KB buffers between the proxy's copies and responses.
// It holds array pointers, so Put converts the slice back without the
// allocation that boxing a slice header would cost.
type bufferPool struct{ p sync.Pool }

func newBufferPool() *bufferPool {
	return &bufferPool{p: sync.Pool{New: func() any { return new([bufferSize]byte) }}}
}

func (b *bufferPool) Get() []byte { return b.p.Get().(*[bufferSize]byte)[:] }

// Put takes back a buffer from Get; both callers return it unchanged.
func (b *bufferPool) Put(buf []byte) { b.p.Put((*[bufferSize]byte)(buf)) }

// pathSafe are the bytes RFC 3986 §3.3 allows raw in a path, plus "%".
const pathSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/%"

// escapeRaw percent-encodes only the bytes a path can't carry raw, keeping
// every escape the client sent, so the upstream decodes the same path.
func escapeRaw(p string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if c := p[i]; strings.IndexByte(pathSafe, c) >= 0 {
			b.WriteByte(c)
		} else {
			b.Write([]byte{'%', hex[c>>4], hex[c&15]})
		}
	}
	return b.String()
}
