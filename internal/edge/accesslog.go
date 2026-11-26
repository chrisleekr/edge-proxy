package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
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

	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
)

// accessRecord is copied out of the request, so the writer goroutine never
// touches request memory.
type accessRecord struct {
	method, host, path, query, requestID, cohort, action, decidedBy, auth, allowlist string
	userAgent, country, ja4                                                          string
	status                                                                           int
	client                                                                           netip.Addr
	version, asn                                                                     int64
	hasASN, upstream                                                                 bool
	signals                                                                          uint16
	ipLists                                                                          []string
	duration                                                                         time.Duration
	traceID                                                                          trace.TraceID
	spanID                                                                           trace.SpanID
	upErr                                                                            error
	cause                                                                            upstreamCause

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
	// ban is the ban a banned request met, or the one a trap request set;
	// banDropped means the table was full and the trap's ban was not kept.
	ban        ratelimit.Ban
	banDropped bool
	// ver names the rules by their index, and the writer reads their
	// settings from it. matched and hdrRules are copies: the request's
	// buffers are reused. blockIdx is the access rule whose block won the
	// merge, including one an allow lifted, or -1.
	ver      *version
	matched  []int
	hdrRules []int
	blockIdx int
	rlIdx    [maxRateLimitCalls + maxCountRules]int
	rlOut    [maxRateLimitCalls + maxCountRules]rlResult
	nRL      int
	// logged: a log-only rule matched. lifted: an allow lifted a block.
	// blocked: an access rule's block refused the request.
	logged, lifted, blocked bool
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

// actionOf names what the edge did: allow, or why it refused the request.
// What a log-only rule would have done is in that rule's matched_rules entry.
func actionOf(st *reqState) string {
	if st.rejected {
		return reasonNames[st.reason]
	}
	return "allow"
}

// decidedBy names the rule that blocked or allowed the request, or "" when
// no rule did, such as an upstream timeout.
func decidedBy(st *reqState) string {
	if st.ver == nil {
		return ""
	}
	if !st.rejected {
		return st.set.allowRule
	}
	switch st.reason {
	case reasonBlocked:
		return st.ver.c.Config.ConfigRules[st.set.blockRule].ID
	case reasonBanned:
		return st.ban.Rule
	case reasonRateLimited, reasonRateLimitKey, reasonRateLimitUnavailable:
		return st.rlRule
	}
	return ""
}

func (a *accessLog) write(st *reqState, r *http.Request, elapsed time.Duration, action, by string) {
	// Allowed requests are sampled. Rejections, 5xx, a block an allow lifted
	// and a log-only rule's match (refusals that did not happen) are always
	// logged, so a rule can be checked before it is switched to block.
	if action == "allow" && st.set.lifted == "" && !st.logged && st.sw.status < 500 && logDraw() >= a.sample {
		return
	}
	rec := accessRecord{
		method: r.Method, requestID: st.requestID, cohort: st.cohort, action: action, decidedBy: by,
		status: st.sw.status, client: st.client.ip, duration: elapsed, auth: authNames[st.auth],
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
		rec.ipLists = st.fields.ipListNames()
	}
	if st.span != nil {
		// Logged sampled or not: the upstream logs the same trace ID.
		sc := st.span.SpanContext()
		rec.traceID, rec.spanID = sc.TraceID(), sc.SpanID()
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
	rec.logged, rec.lifted = st.logged, st.set.lifted != ""
	rec.blocked = st.rejected && st.reason == reasonBlocked
	rec.ver, rec.rlIdx, rec.rlOut, rec.nRL = st.ver, st.rlIdx, st.rlOut, st.nRL
	rec.ban, rec.banDropped = st.ban, st.banDropped
	rec.blockIdx = -1
	if st.ver != nil {
		rec.version = st.ver.c.Config.Version
		rec.matched, rec.hdrRules = slices.Clone(st.matched), slices.Clone(st.hdrMatch)
		if st.set.block != "" || rec.lifted {
			rec.blockIdx = st.set.blockRule
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
	// Lines reuse these buffers: they are local to this goroutine, and slog
	// copies the attrs into its Record and writes it before LogAttrs returns.
	var attrs []slog.Attr
	var keys []string
	for {
		select {
		case rec := <-a.ch:
			guard(a.m, a.log, "access log", func() { attrs, keys = a.emit(rec, attrs, keys) })
		case <-ctx.Done():
			if len(a.ch) == 0 {
				return
			}
		}
	}
}

// paramName reports whether a query key may be logged: 1 to 64 of
// A-Z a-z 0-9 _ . [ ] -.
func paramName(k string) bool {
	if len(k) == 0 || len(k) > 64 {
		return false
	}
	for i := range len(k) {
		c := k[i]
		ok := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("_.[]-", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

const maxQueryKeys = 32

// queryKeys appends the unique parameter names in a raw query to the empty
// dst, sorted. A pair without "=" can be a bare token, and an odd or long key
// can be a secret, so those, and keys past maxQueryKeys, are only counted.
// At most maxQueryKeys are kept, so a linear search finds duplicates.
func queryKeys(dst []string, raw string) (keys []string, dropped int) {
	keys = dst
	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}
		k, _, ok := strings.Cut(pair, "=")
		k, err := url.QueryUnescape(k)
		switch {
		case !ok || err != nil || !paramName(k):
			dropped++
		case slices.Contains(keys, k):
		case len(keys) == maxQueryKeys:
			dropped++
		default:
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys, dropped
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

// emit uses OTel HTTP semantic-convention names where they exist. It writes
// the line from attrs and keys reset to empty, and returns them for reuse.
func (a *accessLog) emit(rec accessRecord, attrs []slog.Attr, keys []string) ([]slog.Attr, []string) {
	attrs = append(attrs[:0],
		slog.String("http.request.method", rec.method),
		slog.String("server.address", hostOnly(rec.host)),
		slog.String("url.path", rec.path),
		slog.Int("http.response.status_code", rec.status),
		slog.String("request_id", rec.requestID),
		slog.String("edge.action", rec.action),
		slog.Bool("edge.upstream_answered", rec.upstream),
		slog.Float64("duration_ms", float64(rec.duration)/float64(time.Millisecond)),
	)
	keys, dropped := queryKeys(keys[:0], rec.query)
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
	if rec.decidedBy != "" {
		attrs = append(attrs, slog.String("edge.decided_by", rec.decidedBy))
	}
	if m := matchedRules(rec); len(m) > 0 {
		attrs = append(attrs, slog.Any("edge.matched_rules", m))
		if l := loggedRules(m); len(l) > 0 {
			attrs = append(attrs, slog.Any("edge.logged_rules", l))
		}
	}
	// The writer formats the times, off the request path.
	if rec.action == "banned" {
		attrs = append(attrs, slog.String("edge.ban.rule", rec.ban.Rule), slog.String("edge.ban.since", time.UnixMilli(rec.ban.Start).UTC().Format(time.RFC3339)),
			slog.String("edge.ban.host", hostOnly(rec.ban.Host)), slog.String("edge.ban.path", rec.ban.Path))
	}
	if rec.ban.End != 0 {
		attrs = append(attrs, slog.String("edge.ban.until", time.UnixMilli(rec.ban.End).UTC().Format(time.RFC3339)))
	}
	if rec.banDropped {
		attrs = append(attrs, slog.Bool("edge.ban.dropped", true))
	}
	// A sampled line stands for 1/rate requests; readers scale by it. Lines
	// that are always written stand for one.
	if a.sample < 1 && rec.action == "allow" && rec.status < 500 && !rec.lifted && !rec.logged {
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
	if len(rec.ipLists) > 0 {
		attrs = append(attrs, slog.Any("client.ip_lists", rec.ipLists))
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
		attrs = append(attrs, slog.Int64("edge.config_version", rec.version), slog.String("edge.cohort", rec.cohort))
	}
	a.log.LogAttrs(context.Background(), slog.LevelInfo, "access", attrs...)
	return attrs, keys
}

// ruleEntry is one matched rule on the access line: what it did, and for a
// rate-limit rule its count.
type ruleEntry struct {
	Rule         string `json:"rule"`
	Type         string `json:"type"`
	Result       string `json:"result"`
	Left         *int64 `json:"left,omitempty"`
	RetryAfter   int    `json:"retry_after,omitempty"`
	BlockedUntil string `json:"blocked_until,omitempty"`
}

// matchedRules lists the request's access, rate-limit and header rules in
// the order the edge ran them. It runs in the writer goroutine.
func matchedRules(rec accessRecord) []ruleEntry {
	if rec.ver == nil {
		return nil
	}
	cfg := rec.ver.c.Config
	out := make([]ruleEntry, 0, len(rec.matched)+rec.nRL+len(rec.hdrRules))
	for _, i := range rec.matched {
		s := cfg.ConfigRules[i].Settings
		e := ruleEntry{Rule: cfg.ConfigRules[i].ID, Type: "access", Result: "matched"}
		switch {
		case s.Allow:
			e.Result = "allowed"
		case s.Block == nil:
		case i != rec.blockIdx || rec.lifted:
			e.Result = "overridden"
		case rec.blocked:
			e.Result = "blocked"
		default:
			// Its block setting won and was log, or the kill switch made it log.
			e.Result = "logged"
		}
		out = append(out, e)
	}
	for k, idx := range rec.rlIdx[:rec.nRL] {
		out = append(out, rateLimitEntry(&rec.ver.rules[idx], rec.rlOut[k], cfg.KillSwitch.RateLimit))
	}
	for _, i := range rec.hdrRules {
		out = append(out, ruleEntry{Rule: cfg.RequestHeaderRules[i].ID, Type: "headers", Result: "matched"})
	}
	return out
}

// loggedRules names the rules that would have refused the request but only
// log. Log stores can't match two fields of one list entry, so this search
// gets its own flat list.
func loggedRules(m []ruleEntry) []string {
	var out []string
	for _, e := range m {
		if e.Result == "logged" {
			out = append(out, e.Rule)
		}
	}
	return out
}

// rateLimitEntry is what one rate-limit rule found for the request.
func rateLimitEntry(r *ratelimit.Rule, o rlResult, kill bool) ruleEntry {
	e := ruleEntry{Rule: r.ID, Type: "rate_limit"}
	switch o.state {
	case rlError:
		e.Result = "error"
		return e
	case rlCountPending:
		e.Result = "not_counted"
		return e
	}
	switch {
	case o.Allowed:
		e.Result = "under"
	case r.Shadow || kill:
		e.Result = "logged"
	case o.state == rlCounted:
		// The response was already sent; the penalty blocks the next requests.
		e.Result = "over"
	default:
		e.Result = "blocked"
	}
	e.Left = &o.Remaining
	if !o.Allowed && e.Result != "over" {
		e.RetryAfter = seconds(o.Retry)
	}
	if o.Blocked > 0 {
		e.BlockedUntil = time.UnixMilli(o.Blocked).UTC().Format(time.RFC3339)
	}
	return e
}
