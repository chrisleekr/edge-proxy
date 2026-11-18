package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/trace"
)

// accessRecord is copied out of the request, so the writer goroutine never
// touches request memory.
type accessRecord struct {
	method, host, path, query, requestID, cohort, decision, rateLimitRule, auth, allowlist string
	userAgent, country, ja4                                                                string
	status                                                                                 int
	client                                                                                 netip.Addr
	version, asn                                                                           int64
	hasASN, upstream                                                                       bool
	signals                                                                                uint16
	configRules                                                                            []string
	duration                                                                               time.Duration
	traceID                                                                                trace.TraceID
	spanID                                                                                 trace.SpanID
	upErr                                                                                  error
	cause                                                                                  upstreamCause

	// The fields below are what browsers and CDNs send. Strings are kept as
	// they are, since the request's strings are immutable; emit trims them.
	ja3, continent, locale, authSub, referer string
	// viewerVersion is the viewer HTTP version as the edge stores it.
	viewerVersion string
	hdr           [len(browserHeaders) + maxCDNHeaders]string
	// ssl is only meaningful with hasSSL.
	ssl, hasSSL bool
	// reqBytes is the declared body length and respBytes what the edge wrote;
	// negative means unknown.
	reqBytes, respBytes int64
	// ver names the rate-limit rules by their index.
	ver   *version
	rlIdx [maxRateLimitCalls + maxCountRules]int
	nRL   int
}

// loggedHeader is a request header an access line carries, as attr.
type loggedHeader struct{ key, attr string }

func logged(keys ...string) []loggedHeader {
	hs := make([]loggedHeader, len(keys))
	for i, k := range keys {
		hs[i] = loggedHeader{http.CanonicalHeaderKey(k), "http.request.header." + strings.ToLower(k)}
	}
	return hs
}

// browserHeaders are what bot tuning reads beyond the fingerprint, on every
// deployment, with the client's own spelling cut. Referer is logged
// separately, as an origin and path. An array, so its length sizes the record.
var browserHeaders = [...]string{"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Accept", "Accept-Language", "Accept-Encoding"}

// maxHeaderValue and maxReferer bound logged header values: the client picks
// them, and rejections are always logged.
const (
	maxHeaderValue = 256
	maxReferer     = 512
)

// accessLog writes JSON access lines from one goroutine. When
// its buffer is full a line is dropped and counted: logging never blocks a
// request or grows memory.
type accessLog struct {
	ch     chan accessRecord
	log    *slog.Logger
	m      *metrics
	sample float64
	// headers are the browser headers then the deployment's CDN headers.
	headers []loggedHeader
}

// logDraw picks which allowed requests are logged. A variable so tests can
// choose the outcome.
var logDraw = rand.Float64

// The CDN's headers are logged as received: when the CDN does not set one,
// the value is the client's.
func newAccessLog(log *slog.Logger, m *metrics, sample float64, size int, cdn []string) *accessLog {
	return &accessLog{ch: make(chan accessRecord, size), log: log, m: m, sample: sample, headers: logged(slices.Concat(browserHeaders[:], cdn)...)}
}

// decisionOf names how the edge answered: allow, or the rejection reason.
// An access rule's would_block outranks would_limit, so a decision that
// existed before log-only rate limits keeps its name.
func decisionOf(st *reqState) string {
	switch {
	case st.rejected:
		return reasonNames[st.reason]
	case st.wouldBlock:
		return "would_block"
	case st.wouldLimit:
		return "would_limit"
	}
	return "allow"
}

func (a *accessLog) write(st *reqState, r *http.Request, elapsed time.Duration, decision string) {
	// Allowed requests are sampled; rejections and 5xx are always logged.
	if decision == "allow" && st.sw.status < 500 && logDraw() >= a.sample {
		return
	}
	rec := accessRecord{
		method: r.Method, requestID: st.requestID, cohort: st.cohort, decision: decision,
		status: st.sw.status, client: st.client.ip, duration: elapsed, rateLimitRule: st.rlRule, auth: authNames[st.auth],
		allowlist: st.set.allowlist, path: st.fields.path, host: r.Host,
		// Parsed for key names by the writer, off the request path. Values
		// can carry tokens and are never logged.
		query:     r.URL.RawQuery,
		userAgent: r.UserAgent(), country: st.client.country, ja4: st.client.ja4, asn: st.client.asn, hasASN: st.client.hasASN,
		upErr: st.upErr, cause: st.cause, upstream: st.upstream,
	}
	// Signals are logged whether or not a rule read them, so rules can be
	// tuned from the logs. Before step 4 the request has no fields.
	if st.fields.r != nil {
		rec.signals = st.fields.signalBits()
	}
	if st.span != nil {
		// Logged sampled or not: the upstream logs the same trace ID.
		sc := st.span.SpanContext()
		rec.traceID, rec.spanID = sc.TraceID(), sc.SpanID()
	}
	if decision == "would_limit" {
		rec.rateLimitRule = st.wlRule
	}
	rec.ja3, rec.continent, rec.viewerVersion, rec.ssl, rec.hasSSL = st.client.ja3, st.client.continent, st.client.version, st.client.ssl, st.client.hasSSL
	if st.fields.localeSet {
		rec.locale = st.fields.locale
	}
	// Only a verified token's subject: an unverified claim is the client's.
	if st.auth == authVerified || st.auth == authCached {
		rec.authSub = st.authSub
	}
	rec.reqBytes, rec.respBytes = r.ContentLength, st.sw.bytes
	if st.sw.hijacked {
		rec.respBytes = -1
	}
	for i, h := range a.headers {
		rec.hdr[i], _ = first(r.Header[h.key])
	}
	rec.referer, _ = first(r.Header["Referer"])
	rec.ver, rec.rlIdx, rec.nRL = st.ver, st.rlIdx, st.nRL
	if st.ver != nil {
		rec.version = st.ver.c.Config.Version
		for _, i := range st.matched {
			rec.configRules = append(rec.configRules, st.ver.c.Config.ConfigRules[i].ID)
		}
	}
	select {
	case a.ch <- rec:
	default:
		a.m.logDropped.Add(1)
	}
}

// run writes lines until ctx ends and nothing is buffered. Once ctx ends,
// select picks either ready case at random, so buffered lines are written
// by the same case either way and run returns only when the buffer is empty.
func (a *accessLog) run(ctx context.Context) {
	for {
		select {
		case rec := <-a.ch:
			guard(a.m, a.log, "access log", func() { a.emit(rec) })
		case <-ctx.Done():
			if len(a.ch) == 0 {
				return
			}
		}
	}
}

// paramName is what a query key must look like to be logged.
var paramName = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)

const maxQueryKeys = 32

// queryKeys returns the unique parameter names in a raw query, sorted. A
// pair without "=" can be a bare token, and an odd or long key can be a
// secret, so those, and keys past maxQueryKeys, are only counted.
func queryKeys(raw string) (keys []string, dropped int) {
	seen := map[string]bool{}
	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}
		k, _, ok := strings.Cut(pair, "=")
		k, err := url.QueryUnescape(k)
		switch {
		case !ok || err != nil || !paramName.MatchString(k):
			dropped++
		case seen[k]:
		case len(seen) == maxQueryKeys:
			dropped++
		default:
			seen[k] = true
		}
	}
	return slices.Sorted(maps.Keys(seen)), dropped
}

// maxUpstreamError bounds the logged error message. A TLS error names the
// client-chosen Host, so its length is the client's to pick.
const maxUpstreamError = 512

// goQuoted matches a %q span. Go quotes whole header lines and Upgrade
// values in some errors, and those can carry cookies or tokens.
var goQuoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// upstreamErrorText is the message with quoted spans replaced, unless the
// chain holds a DNS, certificate or socket error, whose text is addresses,
// syscalls and certificate names an operator needs as they are.
func upstreamErrorText(err error) string {
	msg := err.Error()
	_, dns := errors.AsType[*net.DNSError](err)
	_, cert := errors.AsType[*tls.CertificateVerificationError](err)
	_, op := errors.AsType[*net.OpError](err)
	if !dns && !cert && !op {
		msg = goQuoted.ReplaceAllLiteralString(msg, `"…"`)
	}
	return cut(msg, maxUpstreamError)
}

// cut returns at most n bytes of s, ending at a rune start: a certificate's
// names and a User-Agent can be UTF-8.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// refererOrigin is a Referer without its query, fragment and user info, or
// "" when it is not an absolute URL with a host. A query can carry tokens.
func refererOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return ""
	}
	return cut(u.Scheme+"://"+u.Host+u.EscapedPath(), maxReferer)
}

// otelHTTPVersion writes the stored viewer version as OpenTelemetry does.
func otelHTTPVersion(v string) string {
	switch v {
	case "2.0":
		return "2"
	case "3.0":
		return "3"
	}
	return v
}

// maxUserAgent bounds the logged User-Agent. The client picks it, up to
// MAX_HEADER_BYTES, and rejections are always logged.
const maxUserAgent = 512

// emit uses OTel HTTP semantic-convention names where they exist.
func (a *accessLog) emit(rec accessRecord) {
	attrs := []slog.Attr{
		slog.String("http.request.method", rec.method),
		slog.String("server.address", hostOnly(rec.host)),
		slog.String("url.path", rec.path),
		slog.Int("http.response.status_code", rec.status),
		slog.String("request_id", rec.requestID),
		slog.String("edge.decision", rec.decision),
		slog.Bool("edge.upstream_answered", rec.upstream),
		slog.Float64("duration_ms", float64(rec.duration)/float64(time.Millisecond)),
	}
	keys, dropped := queryKeys(rec.query)
	if len(keys) > 0 {
		attrs = append(attrs, slog.Any("edge.query_keys", keys))
	}
	if dropped > 0 {
		attrs = append(attrs, slog.Int("edge.query_keys_dropped", dropped))
	}
	if rec.auth != "" {
		attrs = append(attrs, slog.String("edge.auth", rec.auth))
	}
	if rec.allowlist != "" {
		attrs = append(attrs, slog.String("edge.allowlist", rec.allowlist))
	}
	if rec.rateLimitRule != "" {
		attrs = append(attrs, slog.String("edge.rate_limit_rule", rec.rateLimitRule))
	}
	// A sampled line stands for 1/rate requests; readers scale by it.
	if a.sample < 1 && rec.decision == "allow" && rec.status < 500 {
		attrs = append(attrs, slog.Float64("edge.sample_rate", a.sample))
	}
	if rec.client.IsValid() {
		attrs = append(attrs, slog.String("client.address", rec.client.String()))
	}
	if rec.userAgent != "" {
		attrs = append(attrs, slog.String("user_agent.original", cut(rec.userAgent, maxUserAgent)))
	}
	if rec.hasASN {
		attrs = append(attrs, slog.Int64("client.as.number", rec.asn))
	}
	if rec.country != "" {
		attrs = append(attrs, slog.String("client.geo.country_iso_code", rec.country))
	}
	if rec.ja4 != "" {
		attrs = append(attrs, slog.String("tls.client.ja4", rec.ja4))
	}
	if rec.signals != 0 {
		attrs = append(attrs, slog.Any("client.signals", signalLists[rec.signals]))
	}
	if rec.ja3 != "" {
		attrs = append(attrs, slog.String("tls.client.ja3", rec.ja3))
	}
	if rec.continent != "" {
		attrs = append(attrs, slog.String("client.geo.continent_code", rec.continent))
	}
	if rec.viewerVersion != "" {
		attrs = append(attrs, slog.String("network.protocol.version", otelHTTPVersion(rec.viewerVersion)))
	}
	if rec.hasSSL {
		scheme := "http"
		if rec.ssl {
			scheme = "https"
		}
		attrs = append(attrs, slog.String("url.scheme", scheme))
	}
	if rec.reqBytes >= 0 {
		attrs = append(attrs, slog.Int64("http.request.body.size", rec.reqBytes))
	}
	if rec.respBytes >= 0 {
		attrs = append(attrs, slog.Int64("http.response.body.size", rec.respBytes))
	}
	if rec.locale != "" {
		attrs = append(attrs, slog.String("edge.locale", rec.locale))
	}
	if rec.authSub != "" {
		attrs = append(attrs, slog.String("edge.auth_sub", cut(rec.authSub, maxHeaderValue)))
	}
	if rec.nRL > 0 {
		names := make([]string, rec.nRL)
		for i, idx := range rec.rlIdx[:rec.nRL] {
			names[i] = rec.ver.rules[idx].ID
		}
		attrs = append(attrs, slog.Any("edge.rate_limit_rules", names))
	}
	for i, h := range a.headers {
		if rec.hdr[i] != "" {
			attrs = append(attrs, slog.String(h.attr, cut(rec.hdr[i], maxHeaderValue)))
		}
	}
	if ref := refererOrigin(rec.referer); ref != "" {
		attrs = append(attrs, slog.String("http.request.header.referer", ref))
	}
	if rec.traceID.IsValid() {
		attrs = append(attrs, slog.String("trace_id", rec.traceID.String()), slog.String("span_id", rec.spanID.String()))
	}
	if rec.upErr != nil {
		attrs = append(attrs, slog.String("edge.upstream_error", upstreamErrorText(rec.upErr)), slog.String("edge.upstream_error_kind", UpstreamCauses[rec.cause-1]))
	}
	if rec.version != 0 {
		attrs = append(attrs, slog.Int64("edge.config_version", rec.version), slog.String("edge.cohort", rec.cohort), slog.Any("edge.config_rules", rec.configRules))
	}
	a.log.LogAttrs(context.Background(), slog.LevelInfo, "access", attrs...)
}
