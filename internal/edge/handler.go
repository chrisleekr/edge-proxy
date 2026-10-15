package edge

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// kind is an edge-generated response kind.
type kind int

const (
	kBadRequest kind = iota
	kUnauthorized
	kMisdirected
	kPayloadTooLarge
	kRateLimited
	kBadGateway
	kUnavailable
	kOverloaded
	kGatewayTimeout
	numKinds
)

// kindNames must name exactly snapshot's response kinds: an unknown name
// would map to kBadRequest. A test checks they agree.
var kindNames = [numKinds]string{
	"bad_request", "unauthorized", "misdirected", "payload_too_large", "rate_limited",
	"bad_gateway", "unavailable", "overloaded", "gateway_timeout",
}

var kindByName = func() map[string]kind {
	m := make(map[string]kind, numKinds)
	for k, n := range kindNames {
		m[n] = kind(k)
	}
	return m
}()

// settings are one request's config-phase results.
type settings struct {
	authMode         string
	accepted         []string
	cors             string
	locale           bool
	responses        [numKinds]string // template names
	bodyLimit        int64
	upstream         string
	upstreamTimeout  time.Duration
	rateLimitHeaders bool
}

// defaults are the settings before any config rule matches. They depend
// only on the config, so a version builds them once.
func defaults(c *snapshot.Compiled) settings {
	cfg := c.Config
	d := cfg.Global.Defaults
	s := settings{authMode: "none", accepted: cfg.Auth.DefaultAccepted, locale: d.Locale, bodyLimit: d.BodyLimit, upstreamTimeout: time.Duration(d.UpstreamTimeout)}
	for k, name := range d.Responses {
		s.responses[kindByName[k]] = name
	}
	return s
}

// resolve runs the config phase: s holds the defaults, then every matching
// rule applies in order, a later rule overwriting what an earlier one set.
// matched receives the indexes of matching rules.
func resolve(c *snapshot.Compiled, s settings, req expr.Request, matched []int) (settings, []int) {
	cfg := c.Config
	for i, m := range c.ConfigRules {
		if !m(req) {
			continue
		}
		matched = append(matched, i)
		r := cfg.ConfigRules[i].Settings
		if r.Auth != nil {
			s.authMode, s.accepted = r.Auth.Mode, r.Auth.Accepted
			if len(s.accepted) == 0 {
				s.accepted = cfg.Auth.DefaultAccepted
			}
		}
		if r.CORSPolicy != nil {
			s.cors = *r.CORSPolicy
		}
		if r.Locale != nil {
			s.locale = *r.Locale
		}
		for k, name := range r.Responses {
			s.responses[kindByName[k]] = name
		}
		if r.BodyLimit != nil {
			s.bodyLimit = *r.BodyLimit
		}
		if r.Upstream != nil {
			s.upstream = *r.Upstream
		}
		if r.UpstreamTimeout != nil {
			s.upstreamTimeout = time.Duration(*r.UpstreamTimeout)
		}
		if r.RateLimitHeaders != nil {
			s.rateLimitHeaders = *r.RateLimitHeaders
		}
	}
	if cfg.KillSwitch.Auth {
		s.authMode = "none"
	}
	return s, matched
}

// Edge serves the public port.
type Edge struct {
	cfg       *Config
	id        *identity
	store     *store
	m         *metrics
	alog      *accessLog
	log       *slog.Logger
	upstreams map[string]*upstream
	valkey    *ratelimit.Valkey // nil without VALKEY_URL
	penalties *ratelimit.Penalties
	tokens    *tokenCache
	pool      *bufferPool
	rp        *httputil.ReverseProxy
	now       func() time.Time
	// strip are the canonical source headers removed before forwarding.
	strip []string
}

type upstream struct {
	name      string
	url       *url.URL
	transport http.RoundTripper
	inflight  atomic.Int64
}

// reqState is everything one request accumulates. It is allocated once per
// request; fixed-size buffers avoid further allocation in the common case.
type reqState struct {
	sw        statusWriter
	start     time.Time
	headersAt time.Time // when the upstream's response headers arrived
	stream    bool      // SSE or WebSocket, by the request
	requestID string
	client    client
	fields    fields
	ver       *version
	cohort    string
	set       settings
	resolved  bool
	matchBuf  [8]int
	matched   []int
	reason    reason
	rejected  bool
	upstream  bool // response came from the upstream
	bodyLarge bool // the body hit the limit
	bodySlow  bool // the body read deadline passed
	retry     int  // Retry-After seconds

	auth                authResult
	authIssuer, authSub string // set when a token verified

	cors              *corsPolicy // nil when no CORS policy applies
	rlRule            string      // the rate-limit rule that answered 429
	rlPolicy, rlState []byte      // RateLimit-Policy and RateLimit values

	// Set by proxy for the shared ReverseProxy's hooks.
	ctx     stateCtx
	up      *upstream
	upTimer *time.Timer
}

func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st := &reqState{start: e.now()}
	st.sw.ResponseWriter = w
	defer e.finish(st, r)
	defer e.recoverPanic(st)
	e.serve(st, r)
}

func (e *Edge) serve(st *reqState, r *http.Request) {
	// Step 1: shed overload before any work. Streams have their own cap so
	// they can't starve ordinary requests.
	cnt, limit, rsn := &e.m.inflight, e.cfg.MaxInflight, reasonOverloaded
	st.stream = isStream(r)
	if st.stream {
		cnt, limit, rsn = &e.m.streams, e.cfg.MaxStreams, reasonStreamsOverloaded
	}
	if cnt.Add(1) > int64(limit) {
		cnt.Add(-1)
		e.reject(st, kOverloaded, rsn)
		return
	}
	defer cnt.Add(-1)

	// Step 2: client identity and request shape.
	cl, err := e.id.identify(r)
	st.client = cl
	st.requestID = requestID(r, cl.trusted)
	if err != nil {
		e.reject(st, kBadRequest, identifyReason(err))
		return
	}
	if checkMethod(r.Method) != nil {
		e.reject(st, kBadRequest, reasonMethod)
		return
	}
	p, err := matchPath(r)
	if err != nil {
		e.reject(st, kBadRequest, reasonPath)
		return
	}

	// Step 3: pin one snapshot for the whole request.
	ld := e.store.load()
	if ld == nil {
		e.reject(st, kUnavailable, reasonNoSnapshot)
		return
	}
	st.ver, st.cohort = pin(ld, cl.ip, st.start)

	// Step 4: config phase.
	st.fields = newFields(r, &st.client, p)
	st.set, st.matched = resolve(st.ver.c, st.ver.defaults, &st.fields, st.matchBuf[:0])
	st.resolved = true
	st.cors = st.ver.cors[st.set.cors]
	if st.set.locale {
		st.fields.loc = st.ver.locale
	}
	name := st.set.upstream
	if name == "" {
		name = e.cfg.HostUpstream[st.fields.host]
	}
	up := e.upstreams[name]
	if up == nil {
		e.reject(st, kMisdirected, reasonMisdirected)
		return
	}

	// Step 5: per-replica backstop, before any costly work.
	if !e.backstop(st) {
		return
	}

	// Step 6: the edge answers CORS preflight when a policy applies; without
	// one, preflight is forwarded like any request.
	if st.cors != nil && isPreflight(r) {
		e.preflight(st, r)
		return
	}

	// Step 7: verify the token before anything reads its claims.
	if !e.authenticate(st, r) {
		return
	}

	// Step 8: shared rate limits, one Valkey round trip at most.
	if !e.rateLimit(st) {
		return
	}

	// Step 10: proxy.
	e.proxy(st, r, up)
}

// isStream reports a WebSocket upgrade or an SSE request.
func isStream(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" || strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

func identifyReason(err error) reason {
	switch {
	case errors.Is(err, errUntrustedPeer):
		return reasonUntrustedPeer
	case errors.Is(err, errIngressSecret):
		return reasonIngressSecret
	default: // errClientIPHeader
		return reasonClientIP
	}
}

// pin picks the config version for this request. During a canary the
// candidate serves a stable slice of clients until it expires.
func pin(ld *loaded, ip netip.Addr, now time.Time) (*version, string) {
	if ld.candidate != nil && now.Before(ld.snap.CanaryExpiresAt) && cohortOf(ip) < ld.snap.CanaryBasisPoints {
		return ld.candidate, "candidate"
	}
	return ld.active, "active"
}

// cohortOf hashes the client into 0..9999 with FNV-1a, which every replica
// computes identically. IPv6 hashes by /64, so one subscriber stays in one cohort.
func cohortOf(ip netip.Addr) int {
	b := ip.As16()
	n := 16
	if ip.Is6() {
		n = 8
	}
	h := uint64(14695981039346656037)
	for _, c := range b[:n] {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return int(h % 10000)
}

// requestID accepts X-Request-Id only from trusted peers and only in a safe
// character set, because templates embed it in JSON and HTML.
func requestID(r *http.Request, trusted bool) string {
	if v := r.Header.Get("X-Request-Id"); trusted && validRequestID(v) {
		return v
	}
	return newRequestID()
}

func newRequestID() string {
	var b [16]byte
	// Request IDs correlate logs; they are not secrets, so a fast PRNG fits.
	binary.BigEndian.PutUint64(b[:8], rand.Uint64()) //nolint:gosec // not a secret
	binary.BigEndian.PutUint64(b[8:], rand.Uint64()) //nolint:gosec // not a secret
	return hex.EncodeToString(b[:])
}

func validRequestID(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-", v[i]) < 0 {
			return false
		}
	}
	return true
}

func (e *Edge) reject(st *reqState, k kind, rsn reason) {
	e.m.rejected[rsn].Add(1)
	st.reason, st.rejected = rsn, true
	e.respond(st, k)
}

// respond writes an edge-generated response from the request's template.
// Every one carries Cache-Control: no-store.
func (e *Edge) respond(st *reqState, k kind) {
	ver := st.ver
	if ver == nil {
		if ld := e.store.load(); ld != nil {
			ver = ld.active
		}
	}
	if st.requestID == "" {
		// Shed at step 1, before the peer's trust was known.
		st.requestID = newRequestID()
	}
	h := st.sw.Header()
	v := make(headerValues, 0, 8)
	v.set(h, "Cache-Control", "no-store")
	v.set(h, "X-Request-Id", st.requestID)
	if k == kUnauthorized {
		// RFC 9110 §15.5.2 requires a challenge; RFC 6750 §3.1 adds the
		// error only when a token was presented.
		c := "Bearer"
		if st.auth == authInvalid {
			c = `Bearer error="invalid_token"`
		}
		v.set(h, "Www-Authenticate", c)
	}
	if k == kRateLimited || k == kUnavailable || k == kOverloaded {
		v.set(h, "Retry-After", strconv.Itoa(max(st.retry, 1)))
	}
	st.setRateLimitHeaders(h)
	st.setCORS(h)
	if ver == nil {
		// No snapshot yet, so no templates: plain text.
		h.Set("Content-Type", "text/plain; charset=utf-8")
		st.sw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintln(&st.sw, http.StatusText(http.StatusServiceUnavailable))
		return
	}
	name := ver.c.Config.Global.Defaults.Responses[kindNames[k]]
	if st.resolved {
		name = st.set.responses[k]
	}
	tpl := ver.c.Config.Global.Responses[name]
	buf := e.pool.Get()
	defer e.pool.Put(buf)
	body := ver.c.Responses[name].Render(buf[:0], func(ph snapshot.Placeholder) string {
		switch ph.Name {
		case "retry_after":
			return strconv.Itoa(max(st.retry, 1))
		case "request_id":
			return st.requestID
		default: // status
			return strconv.Itoa(tpl.Status)
		}
	})
	v.set(h, "Content-Type", tpl.ContentType)
	v.set(h, "Content-Length", strconv.Itoa(len(body)))
	st.sw.WriteHeader(tpl.Status)
	_, _ = st.sw.Write(body)
}

// setRateLimitHeaders sets the RateLimit headers when a rule asked for them.
func (st *reqState) setRateLimitHeaders(h http.Header) {
	if len(st.rlPolicy) > 0 {
		v := make(headerValues, 0, 2)
		v.set(h, "Ratelimit-Policy", string(st.rlPolicy))
		v.set(h, "Ratelimit", string(st.rlState))
	}
}

// recoverPanic turns a handler panic into a 503 and a metric. The proxy's
// own ErrAbortHandler (a client gone mid-stream) is re-raised for net/http.
func (e *Edge) recoverPanic(st *reqState) {
	v := recover()
	if v == nil {
		return
	}
	if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
		panic(v)
	}
	e.log.Error("request panic recovered", "panic", fmt.Sprint(v), "stack", string(debug.Stack()), "request_id", st.requestID)
	if st.sw.status == 0 {
		e.reject(st, kUnavailable, reasonPanic)
	} else {
		e.m.rejected[reasonPanic].Add(1)
	}
}

func (e *Edge) finish(st *reqState, r *http.Request) {
	elapsed := e.now().Sub(st.start)
	status := st.sw.status
	e.m.requests[status/100%6].Add(1)
	if st.ver != nil {
		// A stream's latency is its time to headers: its lifetime would fill
		// the top bucket, which the guard's p99 signal reads.
		lat := elapsed
		if st.stream && st.upstream {
			lat = st.headersAt.Sub(st.start)
		}
		st.ver.stats.observe(status, st.upstream, lat)
	}
	e.alog.write(st, r, elapsed)
}

// statusWriter records the status for logs and stats. Every writer in this
// package calls WriteHeader before Write, so Write needs no hook. Unwrap lets
// http.ResponseController reach the real writer for Flush and Hijack.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 && code >= 200 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Hijack records the 101 that ReverseProxy writes on the hijacked connection
// itself, without calling WriteHeader.
func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, b, err := http.NewResponseController(s.ResponseWriter).Hijack()
	if err == nil {
		s.status = http.StatusSwitchingProtocols
	}
	return c, b, err
}
