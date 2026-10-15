package edge

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// corsPolicy is a named CORS policy prepared once per snapshot.
// It follows the Fetch standard's CORS protocol.
type corsPolicy struct {
	anyOrigin   bool // "*"; validation forbids it with credentials
	origins     map[string]bool
	fixed       string // the one origin when there is exactly one
	credentials bool
	methods     map[string]bool
	anyHeader   bool            // "*"; validation forbids it with credentials
	headers     map[string]bool // lowercase
	expose      string
	maxAge      string // seconds; "" when unset
}

func compileCORS(ps map[string]snapshot.CORSPolicy) map[string]*corsPolicy {
	out := make(map[string]*corsPolicy, len(ps))
	for name, p := range ps {
		c := &corsPolicy{origins: map[string]bool{}, credentials: p.Credentials, methods: map[string]bool{}, headers: map[string]bool{}}
		for _, o := range p.Origins {
			c.anyOrigin = c.anyOrigin || o == "*"
			c.origins[o] = true
		}
		if len(p.Origins) == 1 && !c.anyOrigin {
			c.fixed = p.Origins[0]
		}
		for _, m := range p.Methods {
			c.methods[m] = true
		}
		for _, h := range p.RequestHeaders {
			c.anyHeader = c.anyHeader || h == "*"
			c.headers[strings.ToLower(h)] = true
		}
		c.expose = strings.Join(p.ExposedHeaders, ", ")
		if p.MaxAge != 0 {
			c.maxAge = strconv.FormatInt(int64(time.Duration(p.MaxAge)/time.Second), 10)
		}
		out[name] = c
	}
	return out
}

// allowOrigin is the Access-Control-Allow-Origin value for origin, or "".
// vary reports that the value depends on the request's Origin, so caches
// must key on it (Fetch standard, "CORS protocol and HTTP caches").
func (c *corsPolicy) allowOrigin(origin string) (value string, vary bool) {
	switch {
	case c.anyOrigin:
		return "*", false
	case c.fixed != "":
		return c.fixed, false
	case c.origins[origin]:
		return origin, true
	default:
		return "", true
	}
}

// isPreflight is a CORS-preflight request (Fetch standard).
func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != ""
}

// preflight answers a CORS-preflight request. A disallowed one gets 204
// without CORS headers, which the browser treats as a failed check.
func (e *Edge) preflight(st *reqState, r *http.Request) {
	c := st.cors
	h := st.sw.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Request-Id", st.requestID)
	origin := r.Header.Get("Origin")
	allow, vary := c.allowOrigin(origin)
	if vary {
		h.Add("Vary", "Origin")
	}
	method := r.Header.Get("Access-Control-Request-Method")
	reqHeaders := r.Header.Get("Access-Control-Request-Headers")
	if allow != "" && c.methodAllowed(method) && c.headersAllowed(reqHeaders) {
		h.Set("Access-Control-Allow-Origin", allow)
		if c.credentials {
			h.Set("Access-Control-Allow-Credentials", "true")
		}
		h.Set("Access-Control-Allow-Methods", method)
		if reqHeaders != "" {
			h.Set("Access-Control-Allow-Headers", reqHeaders)
		}
		if c.maxAge != "" {
			h.Set("Access-Control-Max-Age", c.maxAge)
		}
		e.m.corsPreflight.Add(1)
	} else {
		e.m.corsPreflightDenied.Add(1)
	}
	st.sw.WriteHeader(http.StatusNoContent)
}

// methodAllowed: CORS-safelisted methods need no listing (Fetch standard).
func (c *corsPolicy) methodAllowed(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodPost || c.methods[m]
}

func (c *corsPolicy) headersAllowed(list string) bool {
	if c.anyHeader {
		return true
	}
	for h := range strings.SplitSeq(list, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" && !c.headers[h] {
			return false
		}
	}
	return true
}

// setCORS adds the CORS response headers for a non-preflight response,
// edge-generated or upstream. Upstream Access-Control-* headers are removed
// first: the policy is the only source.
func (st *reqState) setCORS(h http.Header) {
	c := st.cors
	if c == nil {
		return
	}
	for k := range h {
		if strings.HasPrefix(k, "Access-Control-") {
			delete(h, k)
		}
	}
	allow, vary := c.allowOrigin(st.fields.r.Header.Get("Origin"))
	if vary {
		h.Add("Vary", "Origin")
	}
	if allow == "" {
		return
	}
	h.Set("Access-Control-Allow-Origin", allow)
	if c.credentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	if c.expose != "" {
		h.Set("Access-Control-Expose-Headers", c.expose)
	}
}
