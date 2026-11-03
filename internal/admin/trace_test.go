package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

// tracedHarness exports every traced admin request to the shared
// collector, with the test client as admin's trusted proxy.
func tracedHarness(t *testing.T, endpoint string) *harness {
	t.Helper()
	// One export at flush, so a request's spans can't be split across
	// batches by the timer.
	t.Setenv("OTEL_BSP_SCHEDULE_DELAY", "600000")
	return newHarnessWith(t, map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": endpoint, "TRACE_SAMPLE_RATE": "1", "ADMIN_TRUSTED_PROXIES": "127.0.0.1/32"})
}

// newTraceparent is a caller's sampled trace context with a fresh trace ID,
// so tests sharing the collector never see each other's spans.
func newTraceparent(t *testing.T) (header, traceID string) {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	traceID = hex.EncodeToString(b[:16])
	return "00-" + traceID + "-" + hex.EncodeToString(b[16:]) + "-01", traceID
}

func (h *harness) flush() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.s.tracing.Shutdown(ctx); err != nil {
		h.t.Fatal(err)
	}
}

// A publish is one span named by its route, with a span per query under
// it, the audit insert included. Statements are recorded with their
// placeholders: no value a query wrote appears anywhere in the trace.
func TestPublishIsTraced(t *testing.T) {
	col := testenv.OTelCollector(t)
	h := tracedHarness(t, col.Endpoint)
	h.user("pub", "publisher")
	pub := h.signedIn("pub")
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	tp, traceID := newTraceparent(t)
	const message = "publish-message-value-7f3a"
	status(t, pub.do("POST", "/api/publish", map[string]string{"message": message}, "If-Match", pub.revision(), "Traceparent", tp), 201)
	h.flush()

	spans := col.Spans(t, traceID, 3)
	var server testenv.Span
	for _, s := range spans {
		if s.Kind == 2 {
			server = s
		}
	}
	if server.Name != "POST /api/publish" || server.Attrs["http.route"] != "/api/publish" || server.Attrs["http.response.status_code"] != "201" || server.Attrs["client.address"] != "127.0.0.1" || server.Resource["service.name"] != "edge-proxy-admin" {
		t.Fatalf("server span %+v", server)
	}
	audited := false
	for _, s := range spans {
		for k, v := range s.Attrs {
			if strings.Contains(v, message) {
				t.Fatalf("span %s records a written value in %s", s.Name, k)
			}
		}
		if s.Kind != 3 {
			continue
		}
		if s.ParentSpanID != server.SpanID || s.Attrs["db.system.name"] != "postgresql" {
			t.Fatalf("query span %+v not under the request", s)
		}
		if s.Name == "INSERT" && strings.Contains(s.Attrs["db.query.text"], "audit_events") {
			audited = true
		}
	}
	if !audited {
		t.Fatal("no span for the audit insert")
	}
}

// Edge polls, reports and log shipping arrive every few seconds and the UI
// is static files: none of them is traced.
func TestMachineTrafficIsNotTraced(t *testing.T) {
	col := testenv.OTelCollector(t)
	h := tracedHarness(t, col.Endpoint)
	c := h.client()
	skipped := map[string]string{}
	for _, req := range [][2]string{{"GET", "/v1/snapshot"}, {"POST", "/v1/edge/report"}, {"POST", "/v1/logs/access"}, {"GET", "/"}} {
		tp, id := newTraceparent(t)
		c.do(req[0], req[1], nil, "Traceparent", tp).Body.Close()
		skipped[req[1]] = id
	}
	tp, anchor := newTraceparent(t)
	c.do("GET", "/api/auth/me", nil, "Traceparent", tp).Body.Close()
	h.flush()
	// Once the API request's span has arrived, the earlier ones would have.
	col.Spans(t, anchor, 1)
	for path, id := range skipped {
		if spans := col.Spans(t, id, 0); len(spans) != 0 {
			t.Fatalf("%s traced: %+v", path, spans)
		}
	}
}

// A collector outage never touches the API; the failed export is logged
// and counted in admin_trace_export_errors_total.
func TestAdminWorksWithCollectorDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	h := tracedHarness(t, "http://"+addr+"/v1/traces")
	h.user("pub", "publisher")
	pub := h.signedIn("pub")
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	h.flush()
	if !strings.Contains(h.logs.String(), `"msg":"opentelemetry error"`) {
		t.Fatal("failed export not logged")
	}
	const series = "\nadmin_trace_export_errors_total "
	_, rest, ok := strings.Cut(h.metrics(), series)
	if !ok {
		t.Fatal("metrics have no admin_trace_export_errors_total")
	}
	var n uint64
	if _, err := fmt.Sscan(rest, &n); err != nil || n < 1 {
		t.Fatalf("failed export counted %d times: %v", n, err)
	}
}

// The client address on a span is the one audit and throttling use: the
// rightmost X-Forwarded-For entry the trusted proxy didn't add, never the
// leftmost one the client wrote.
func TestSpanClientAddressIgnoresForgedForwardedFor(t *testing.T) {
	col := testenv.OTelCollector(t)
	h := tracedHarness(t, col.Endpoint)
	tp, traceID := newTraceparent(t)
	h.client().do("GET", "/api/auth/me", nil, "Traceparent", tp, "X-Forwarded-For", "198.51.100.66, 203.0.113.9").Body.Close()
	h.flush()
	if got := col.Spans(t, traceID, 1)[0].Attrs["client.address"]; got != "203.0.113.9" {
		t.Fatalf("client.address %q, want 203.0.113.9", got)
	}
}

// As on the edge, a caller that isn't a trusted proxy can't join a trace:
// admin starts a new one and keeps the caller's only as a link.
func TestUntrustedCallerGetsNewTrace(t *testing.T) {
	col := testenv.OTelCollector(t)
	h := newHarnessWith(t, map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": col.Endpoint, "TRACE_SAMPLE_RATE": "1"})
	tp, traceID := newTraceparent(t)
	h.client().do("GET", "/api/auth/me", nil, "Traceparent", tp).Body.Close()
	h.flush()
	span := col.SpansLinkedTo(t, traceID, 1)[0]
	if span.TraceID == traceID || span.ParentSpanID != "" {
		t.Fatalf("untrusted caller joined its trace: %+v", span)
	}
	if spans := col.Spans(t, traceID, 0); len(spans) != 0 {
		t.Fatalf("spans in the caller's trace: %+v", spans)
	}
}
