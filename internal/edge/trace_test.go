package edge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
	"github.com/chrisleekr/edge-proxy/internal/tracing"
)

// tracedHarness is a replica exporting every trace to the shared collector.
func tracedHarness(t *testing.T, set map[string]string) (*harness, *testenv.Collector) {
	t.Helper()
	col := testenv.OTelCollector(t)
	e := map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": col.Endpoint, "TRACE_SAMPLE_RATE": "1"}
	maps.Copy(e, set)
	h := newHarness(t, e)
	h.load(envelope(testConfig(1)))
	return h, col
}

// newTraceparent is a caller's sampled trace context with fresh IDs, so
// tests sharing the collector never see each other's spans.
func newTraceparent(t *testing.T, flags string) (header, traceID, spanID string) {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	traceID, spanID = hex.EncodeToString(b[:16]), hex.EncodeToString(b[16:])
	return "00-" + traceID + "-" + spanID + "-" + flags, traceID, spanID
}

// flush exports everything the replica has buffered.
func (h *harness) flush() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.srv.m.tracing.Shutdown(ctx); err != nil {
		h.t.Fatal(err)
	}
}

// upstreamTrace splits the traceparent the upstream received.
func (h *harness) upstreamTrace() (traceID, parentID, flags string) {
	h.t.Helper()
	parts := strings.Split(h.lastApp.Header.Get("Traceparent"), "-")
	if len(parts) != 4 {
		h.t.Fatalf("upstream traceparent %q", h.lastApp.Header.Get("Traceparent"))
	}
	return parts[1], parts[2], parts[3]
}

// closedAddr is a local address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	return l.Addr().String()
}

// tracedInMemoryEdge is inMemoryEdge sampling at rate, exporting to a
// closed port so spans never leave the process.
func tracedInMemoryEdge(tb testing.TB, rate float64, target string) (*Server, *http.Request) {
	tb.Helper()
	c := testConfig(1)
	c.Global.Backstop.Limit, c.Global.Backstop.Burst = 1_000_000_000, 1_000_000_000
	s, req := inMemoryEdge(tb, c, target)
	tp, err := tracing.New(tracing.Config{Endpoint: "http://127.0.0.1:1/v1/traces", SampleRate: rate, MaxPerSecond: 1_000_000, ShutdownTimeout: time.Millisecond}, "test", newTestLogger(io.Discard))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = tp.Shutdown(context.Background()) }) //nolint:usetesting // tb.Context is cancelled before cleanups run
	s.edge.tracer = tp.Tracer("test")
	return s, req
}

func (h *harness) metric(name string) int {
	h.t.Helper()
	var b bytes.Buffer
	h.srv.m.writeTo(&b)
	for l := range strings.SplitSeq(b.String(), "\n") {
		if v, ok := strings.CutPrefix(l, name+" "); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				h.t.Fatal(err)
			}
			return n
		}
	}
	h.t.Fatalf("metric %s missing", name)
	return 0
}

// The CDN forwards a caller's trace: the edge joins it, records one server
// span under the caller's span, and hands the upstream its own span as parent.
func TestTraceJoinsTrustedCaller(t *testing.T) {
	h, col := tracedHarness(t, nil)
	tp, traceID, callerSpan := newTraceparent(t, "01")
	resp := h.do("GET", "/v1/items?id=1", nil, "Traceparent", tp, "Tracestate", "vendor=abc")
	readBody(t, resp)

	upTrace, upParent, upFlags := h.upstreamTrace()
	if upTrace != traceID || upParent == callerSpan || upFlags != "01" {
		t.Fatalf("upstream traceparent %s-%s-%s, caller %s-%s", upTrace, upParent, upFlags, traceID, callerSpan)
	}
	if got := h.lastApp.Header.Get("Tracestate"); got != "vendor=abc" {
		t.Fatalf("upstream tracestate %q", got)
	}
	h.flush()
	span := col.Spans(t, traceID, 1)[0]
	want := map[string]string{
		"http.request.method": "GET", "http.response.status_code": "200", "url.path": "/v1/items",
		"server.address": "api.example.com", "client.address": "198.51.100.7", "edge.decision": "allow",
		"edge.config_version": "1", "edge.cohort": "active", "request_id": h.lastApp.Header.Get("X-Request-Id"),
	}
	for k, v := range want {
		if span.Attrs[k] != v {
			t.Errorf("attribute %s = %q, want %q", k, span.Attrs[k], v)
		}
	}
	if span.Name != "GET" || span.Kind != 2 || span.ParentSpanID != callerSpan || span.SpanID != upParent || span.Status != 0 {
		t.Fatalf("server span %+v", span)
	}
	if _, ok := span.Attrs["url.query"]; ok {
		t.Fatal("query recorded")
	}
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
	line := h.logs.lines("access")[0]
	if line["trace_id"] != traceID || line["span_id"] != span.SpanID {
		t.Fatalf("access log trace %v span %v, want %s %s", line["trace_id"], line["span_id"], traceID, span.SpanID)
	}
}

// Without a trusted proxy in front, any trace context is the client's own
// claim: the edge starts a new trace and drops the client's tracestate.
func TestTraceRestartsForUntrustedPeer(t *testing.T) {
	h, _ := tracedHarness(t, map[string]string{"CLIENT_IP_SOURCE": "remote_addr", "TRUSTED_PROXIES": ""})
	tp, traceID, _ := newTraceparent(t, "01")
	readBody(t, h.do("GET", "/", nil, "Traceparent", tp, "Tracestate", "vendor=abc"))
	if upTrace, _, _ := h.upstreamTrace(); upTrace == traceID {
		t.Fatal("untrusted peer joined its own trace")
	}
	if got := h.lastApp.Header.Get("Tracestate"); got != "" {
		t.Fatalf("untrusted tracestate forwarded: %q", got)
	}
}

// An invalid traceparent is ignored with its tracestate, as W3C Trace
// Context requires; the request still goes through with a new trace.
func TestMalformedTraceparentStartsNewTrace(t *testing.T) {
	h, _ := tracedHarness(t, nil)
	resp := h.do("GET", "/", nil, "Traceparent", "00-zz-not-a-trace", "Tracestate", "vendor=abc")
	if readBody(t, resp); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if upTrace, _, _ := h.upstreamTrace(); len(upTrace) != 32 || h.lastApp.Header.Get("Tracestate") != "" {
		t.Fatalf("upstream trace context %v", h.lastApp.Header)
	}
}

// With tracing off the edge is not a participant: trace context reaches the
// upstream byte for byte.
func TestTracingOffPassesTraceContextThrough(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	tp, _, _ := newTraceparent(t, "01")
	readBody(t, h.do("GET", "/", nil, "Traceparent", tp, "Tracestate", "vendor=abc"))
	if h.lastApp.Header.Get("Traceparent") != tp || h.lastApp.Header.Get("Tracestate") != "vendor=abc" {
		t.Fatalf("upstream trace context %v", h.lastApp.Header)
	}
	if h.metric("edge_trace_export_errors_total") != 0 || h.metric("edge_trace_capped_total") != 0 {
		t.Fatal("tracing counters move while tracing is off")
	}
}

// An unsampled request still carries one trace ID to the upstream and into
// the access log, so logs on both sides join up.
func TestUnsampledRequestPropagatesTraceID(t *testing.T) {
	h, _ := tracedHarness(t, map[string]string{"TRACE_SAMPLE_RATE": "0"})
	readBody(t, h.do("GET", "/", nil))
	upTrace, upParent, flags := h.upstreamTrace()
	if flags != "00" {
		t.Fatalf("flags %s, want 00", flags)
	}
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
	if line := h.logs.lines("access")[0]; line["trace_id"] != upTrace || line["span_id"] != upParent {
		t.Fatalf("access log %v, upstream %s %s", line, upTrace, upParent)
	}
}

// A client forging sampled=1 on every request is held to the per-replica
// cap; the rest are counted, not exported.
func TestForgedSampledFloodIsCapped(t *testing.T) {
	h, _ := tracedHarness(t, map[string]string{"TRACE_MAX_PER_SECOND": "1"})
	var sampled atomic.Int32
	h.appHandler = func(_ http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Header.Get("Traceparent"), "-01") {
			sampled.Add(1)
		}
	}
	start := time.Now()
	for range 50 {
		tp, _, _ := newTraceparent(t, "01")
		readBody(t, h.do("GET", "/", nil, "Traceparent", tp))
	}
	// One trace per one-second window the loop touched gets through.
	windows := int32(time.Since(start)/time.Second) + 2
	capped := int32(h.metric("edge_trace_capped_total"))
	if sampled.Load() > windows || sampled.Load()+capped != 50 {
		t.Fatalf("%d forwarded as sampled and %d capped of 50 at 1/s over %d windows", sampled.Load(), capped, windows)
	}
}

// Shedding stays the cheapest path: a shed request gets no span, so its
// access line has no trace ID.
func TestShedRequestHasNoSpan(t *testing.T) {
	h, _ := tracedHarness(t, map[string]string{"MAX_INFLIGHT": "1"})
	entered, release := make(chan struct{}), make(chan struct{})
	h.appHandler = func(http.ResponseWriter, *http.Request) {
		entered <- struct{}{}
		<-release
	}
	done := make(chan struct{})
	go func() { h.do("GET", "/slow", nil).Body.Close(); close(done) }()
	<-entered
	edgeError(t, h.do("GET", "/", nil), 503, "overloaded")
	close(release)
	<-done
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 2 })
	for _, line := range h.logs.lines("access") {
		if _, traced := line["trace_id"]; traced == (line["edge.decision"] == "overloaded") {
			t.Fatalf("access line %v", line)
		}
	}
}

func TestServerSpanOutcome(t *testing.T) {
	cases := []struct {
		name, method, target string
		upstream             int
		wantName             string
		wantStatus           int
		wantAttrs            map[string]string
	}{
		{"upstream 503 is a span error", "GET", "/", 503, "GET", 2, map[string]string{"http.response.status_code": "503", "edge.decision": "allow"}},
		{"edge-rejected path is the client's error, not the span's", "GET", "/a%5Cb", 200, "GET", 0, map[string]string{"http.response.status_code": "400", "edge.decision": "path"}},
		{"unknown method doesn't name the span", "FOOBAR", "/", 200, "HTTP", 0, map[string]string{"http.request.method": "_OTHER", "http.request.method_original": "FOOBAR"}},
		{"long path is cut to the attribute limit", "GET", "/" + strings.Repeat("a", 2000), 200, "GET", 0, map[string]string{"url.path": "/" + strings.Repeat("a", 511)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, col := tracedHarness(t, nil)
			h.appHandler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.upstream) }
			tp, traceID, _ := newTraceparent(t, "01")
			readBody(t, h.do(tc.method, tc.target, nil, "Traceparent", tp))
			h.flush()
			span := col.Spans(t, traceID, 1)[0]
			if span.Name != tc.wantName || span.Status != tc.wantStatus {
				t.Fatalf("span %q status %d, want %q %d", span.Name, span.Status, tc.wantName, tc.wantStatus)
			}
			for k, v := range tc.wantAttrs {
				if span.Attrs[k] != v {
					t.Errorf("attribute %s = %q, want %q", k, span.Attrs[k], v)
				}
			}
		})
	}
}

// Rate-limit time shows as a child of the request span.
func TestValkeyCallIsChildSpan(t *testing.T) {
	col := testenv.OTelCollector(t)
	h := valkeyHarness(t, map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": col.Endpoint, "TRACE_SAMPLE_RATE": "1"})
	c := testConfig(1)
	c.Global.Backstop.Limit, c.Global.Backstop.Burst = 1000, 1000
	c.RateLimitRules = []snapshot.RateLimitRule{rlRule("traced", "true", "token_bucket", 100, "ip")}
	h.load(envelope(c))
	tp, traceID, _ := newTraceparent(t, "01")
	readBody(t, h.do("GET", "/", nil, "Traceparent", tp))
	h.flush()
	spans := col.Spans(t, traceID, 2)
	var server, vk testenv.Span
	for _, s := range spans {
		if s.Name == "valkey ratelimit" {
			vk = s
		} else {
			server = s
		}
	}
	if vk.ParentSpanID != server.SpanID || vk.Kind != 3 || vk.Attrs["db.system.name"] != "valkey" || vk.Attrs["edge.ratelimit_calls"] != "1" || vk.Attrs["edge.ratelimit_failed"] != "0" || vk.Status != 0 {
		t.Fatalf("valkey span %+v under %+v", vk, server)
	}
}

// A collector outage never touches traffic; failed exports are counted.
func TestCollectorDownStillServes(t *testing.T) {
	addr := closedAddr(t)
	h, _ := tracedHarness(t, map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://" + addr + "/v1/traces"})
	for range 3 {
		if resp := h.do("GET", "/", nil); readBody(t, resp) != "upstream ok" {
			t.Fatal("request failed while the collector is down")
		}
	}
	h.flush()
	if h.metric("edge_trace_export_errors_total") == 0 {
		t.Fatal("failed export not counted")
	}
}

// A collector that accepts but never answers can't hold shutdown beyond
// TRACE_SHUTDOWN_TIMEOUT; the edge says the flush was cut short.
func TestShutdownFlushIsBounded(t *testing.T) {
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(hung.Close)
	// Cleanups run last-in first-out: the handler returns before Close waits for it.
	t.Cleanup(func() { close(release) })
	h, _ := tracedHarness(t, map[string]string{
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": hung.URL + "/v1/traces", "TRACE_SHUTDOWN_TIMEOUT": "200ms",
		"DRAIN_DELAY": "1ms", "SHUTDOWN_TIMEOUT": "100ms",
	})
	pub, in := listen(t), listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- h.srv.Run(ctx, pub, in) }()
	waitFor(t, func() bool { return h.srv.ready() })
	req, _ := http.NewRequest("GET", "http://"+pub.Addr().String()+"/", nil)
	req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	start := time.Now()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("shutdown took %v", d)
	}
	if len(h.logs.lines("trace flush incomplete")) != 1 {
		t.Fatalf("no flush warning: %s", h.logs.String())
	}
}

// A deployment the exporter can't use fails at startup, like any other
// bad deployment config.
func TestMainRejectsUnusableTraceExporter(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", testenv.WriteCACert(t))
	e := cloudfrontEnv()
	e["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = "http://collector:4318/v1/traces"
	var out bytes.Buffer
	if code := Main(t.Context(), env(e), &out); code != 2 || !strings.Contains(out.String(), "trace exporter") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}

// Any trace context a client sends is handled without a panic, and the
// request is served.
func FuzzTraceContext(f *testing.F) {
	f.Add("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "vendor=abc,other=1")
	f.Add("ff-00000000000000000000000000000000-0000000000000000-00", "")
	f.Add("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra", strings.Repeat("k=v,", 40))
	s, req := tracedInMemoryEdge(f, 1, "/")
	f.Fuzz(func(t *testing.T, traceparent, tracestate string) {
		r := req.Clone(t.Context())
		r.Header.Set("Traceparent", traceparent)
		r.Header.Set("Tracestate", tracestate)
		w := httptest.NewRecorder()
		s.edge.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("status %d for %q %q", w.Code, traceparent, tracestate)
		}
	})
}

// Tracing adds a fixed, small number of allocations per request. Exports
// are held off during the measurement because the batch exporter's
// goroutine allocates too, and AllocsPerRun counts every goroutine.
func TestTracedRequestAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items at random under -race")
	}
	t.Setenv("OTEL_BSP_SCHEDULE_DELAY", "600000")
	t.Setenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "2048")
	cases := []struct {
		name   string
		rate   float64
		parent string
		max    float64
	}{
		{"not sampled", 0, "", 45},
		{"not sampled, caller's trace joined", 0, "00", 55},
		{"sampled", 1, "", 52},
		{"sampled, caller's trace joined", 1, "01", 62},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, req := tracedInMemoryEdge(t, tc.rate, "/v1/items?id=1")
			if tc.parent != "" {
				req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-"+tc.parent)
				req.Header.Set("Tracestate", "vendor=abc")
			}
			serve := func() {
				w := httptest.NewRecorder()
				s.edge.ServeHTTP(w, req)
				if w.Code != 200 {
					t.Fatalf("status %d", w.Code)
				}
			}
			serve()
			n := testing.AllocsPerRun(200, serve)
			t.Logf("%v allocations per request", n)
			if n > tc.max {
				t.Fatalf("%v allocations per request, ceiling %v", n, tc.max)
			}
		})
	}
}

// A 429 names the rule that answered it; it is the client's error, not
// the span's.
func TestRateLimitedSpanNamesTheRule(t *testing.T) {
	h, col := tracedHarness(t, nil)
	c := testConfig(2)
	r := rlRule("per-ip", "true", "token_bucket", 1, "ip")
	r.FailMode = "local"
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	h.load(envelope(c))
	readBody(t, h.do("GET", "/", nil))
	tp, traceID, _ := newTraceparent(t, "01")
	readBody(t, h.do("GET", "/", nil, "Traceparent", tp))
	h.flush()
	span := col.Spans(t, traceID, 1)[0]
	if span.Attrs["http.response.status_code"] != "429" || span.Attrs["edge.decision"] != "rate_limited" || span.Attrs["edge.rate_limit_rule"] != "per-ip" || span.Status != 0 {
		t.Fatalf("span %+v", span)
	}
}

// The token check's result is on the span, as in the access log.
func TestSpanRecordsAuthResult(t *testing.T) {
	h, col := tracedHarness(t, map[string]string{"JWKS_ALLOWED_HOSTS": "127.0.0.1"})
	c := authConfig(newFakeIdP(t))
	c.Version = 2
	h.load(authEnvelope(c))
	tp, traceID, _ := newTraceparent(t, "01")
	resp := h.do("GET", "/private/x", nil, append(bearerOf(corpToken()), "Traceparent", tp)...)
	if readBody(t, resp); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	h.flush()
	if span := col.Spans(t, traceID, 1)[0]; span.Attrs["edge.auth"] != "verified" {
		t.Fatalf("span %+v", span)
	}
}

// With Valkey unreachable the request still passes (fail_mode open), and
// the rate-limit span shows the failed call.
func TestValkeyDownSpanIsError(t *testing.T) {
	addr := closedAddr(t)
	h, col := tracedHarness(t, map[string]string{"VALKEY_URL": "redis://" + addr})
	c := testConfig(2)
	c.RateLimitRules = []snapshot.RateLimitRule{rlRule("per-ip", "true", "token_bucket", 100, "ip")}
	h.load(envelope(c))
	tp, traceID, _ := newTraceparent(t, "01")
	if readBody(t, h.do("GET", "/", nil, "Traceparent", tp)) != "upstream ok" {
		t.Fatal("fail_mode open did not pass the request")
	}
	h.flush()
	for _, s := range col.Spans(t, traceID, 2) {
		if s.Name == "valkey ratelimit" {
			if s.Status != 2 || s.Attrs["edge.ratelimit_failed"] != "1" {
				t.Fatalf("valkey span %+v", s)
			}
			return
		}
	}
	t.Fatal("no valkey span")
}

// A request from the CDN's network that lacks the ingress secret is
// rejected, and its span does not join the trace it claims.
func TestMissingIngressSecretDoesNotJoinTrace(t *testing.T) {
	h, col := tracedHarness(t, map[string]string{"INGRESS_SECRET_HEADER": "X-Origin-Secret", "INGRESS_SECRET_VALUES": "s3cret"})
	tp, traceID, _ := newTraceparent(t, "01")
	resp := h.do("GET", "/", nil, "Traceparent", tp)
	readBody(t, resp)
	if resp.StatusCode != 400 {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	h.flush()
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
	own := h.logs.lines("access")[0]["trace_id"].(string)
	// Once the request's own span has arrived, a joined one would have too.
	if span := col.Spans(t, own, 1)[0]; own == traceID || span.ParentSpanID != "" {
		t.Fatalf("rejected request joined the claimed trace: %+v", span)
	}
	if spans := col.Spans(t, traceID, 0); len(spans) != 0 {
		t.Fatalf("spans in the claimed trace: %+v", spans)
	}
}

// A WebSocket still open at SIGTERM ends when the edge cancels its streams;
// its span must reach the collector, not be dropped by an earlier flush.
func TestStreamSpanExportedAtShutdown(t *testing.T) {
	h, col := tracedHarness(t, map[string]string{"DRAIN_DELAY": "1ms", "SHUTDOWN_TIMEOUT": "100ms"})
	h.appHandler = echoUpgrade
	pub, in := listen(t), listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- h.srv.Run(ctx, pub, in) }()
	waitFor(t, func() bool { return h.srv.ready() })
	ws := dialUpgrade(t, pub.Addr().String())
	defer ws.Close()
	traceID, _, _ := h.upstreamTrace()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if span := col.Spans(t, traceID, 1)[0]; span.Attrs["http.response.status_code"] != "101" {
		t.Fatalf("stream span %+v", span)
	}
}
