package tracing

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/chrisleekr/edge-proxy/internal/envparse"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

func load(env map[string]string) (Config, error) {
	p := &envparse.Parser{Get: func(k string) string { return env[k] }}
	c := Load(p, "edge-proxy")
	return c, p.Err()
}

func TestLoad(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want Config
	}{
		{"nothing set leaves tracing off with the defaults", nil,
			Config{ServiceName: "edge-proxy", SampleRate: 0.01, MaxPerSecond: 100, ShutdownTimeout: 5 * time.Second}},
		{"traces endpoint is used as given", map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://otel.example:4318/custom", "OTEL_SERVICE_NAME": "edge-syd", "TRACE_SAMPLE_RATE": "0.5", "TRACE_MAX_PER_SECOND": "20", "TRACE_SHUTDOWN_TIMEOUT": "2s"},
			Config{Endpoint: "https://otel.example:4318/custom", ServiceName: "edge-syd", SampleRate: 0.5, MaxPerSecond: 20, ShutdownTimeout: 2 * time.Second}},
		{"base endpoint gets the OTLP/HTTP traces path", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318/"},
			Config{Endpoint: "http://collector:4318/v1/traces", ServiceName: "edge-proxy", SampleRate: 0.01, MaxPerSecond: 100, ShutdownTimeout: 5 * time.Second}},
		{"traces endpoint wins over the base endpoint", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://base:4318", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://traces:4318/v1/traces"},
			Config{Endpoint: "http://traces:4318/v1/traces", ServiceName: "edge-proxy", SampleRate: 0.01, MaxPerSecond: 100, ShutdownTimeout: 5 * time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := load(tc.env)
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name, key, value, want string
	}{
		{"endpoint without a scheme", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "collector:4318", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: must be an http or https URL"},
		{"grpc base endpoint names the variable that was set", "OTEL_EXPORTER_OTLP_ENDPOINT", "grpc://collector:4317", "OTEL_EXPORTER_OTLP_ENDPOINT: must be an http or https URL"},
		{"sample rate above 1", "TRACE_SAMPLE_RATE", "2", "TRACE_SAMPLE_RATE"},
		{"cap of zero", "TRACE_MAX_PER_SECOND", "0", "TRACE_MAX_PER_SECOND"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(map[string]string{tc.key: tc.value})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

// The exporter would log a malformed header entry with its value, usually
// the collector's credential. Startup fails instead, naming only the variable.
func TestMalformedHeadersFailWithoutTheValue(t *testing.T) {
	for _, tc := range []struct{ name, key, value string }{
		{"entry without =", "OTEL_EXPORTER_OTLP_HEADERS", "Authorization Bearer tok-secret-1"},
		{"bad percent-encoding", "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "Authorization=Bearer%zztok-secret-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318", tc.key: tc.value})
			if err == nil || !strings.Contains(err.Error(), tc.key) || strings.Contains(err.Error(), "tok-secret-1") {
				t.Fatalf("err %v", err)
			}
		})
	}
	if _, err := load(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318", "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer%20tok,X-Tenant=t1,"}); err != nil {
		t.Fatalf("well-formed headers rejected: %v", err)
	}
	// With tracing off the exporter never reads them, so they can't stop the edge.
	if _, err := load(map[string]string{"OTEL_EXPORTER_OTLP_HEADERS": "malformed"}); err != nil {
		t.Fatalf("headers checked with tracing off: %v", err)
	}
}

// With no endpoint there is no provider, and every call on it is a no-op,
// so callers need no checks of their own.
func TestOffMeansNoProvider(t *testing.T) {
	p, err := New(Config{}, "edge-1", slog.Default())
	if p != nil || err != nil {
		t.Fatalf("New = %v, %v; want nil, nil", p, err)
	}
	if p.Tracer("x") != nil || p.TracerProvider() != nil || p.Shutdown(t.Context()) != nil || p.ExportErrors() != 0 || p.Capped() != 0 {
		t.Fatal("a nil provider must do nothing")
	}
}

// A CA certificate for a plain-http endpoint is a contradiction the
// exporter refuses; the deployment must fail at startup, not later.
func TestHTTPEndpointWithCertificateFailsStartup(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", testenv.WriteCACert(t))
	_, err := New(Config{Endpoint: "http://collector:4318/v1/traces", MaxPerSecond: 1, ShutdownTimeout: time.Second}, "edge-1", slog.Default())
	if err == nil || !strings.Contains(err.Error(), "trace exporter") {
		t.Fatalf("err %v, want the exporter to refuse", err)
	}
}

func TestExportsToCollector(t *testing.T) {
	col := testenv.OTelCollector(t)
	p, err := New(Config{Endpoint: col.Endpoint, ServiceName: "edge-test", SampleRate: 1, MaxPerSecond: 100, ShutdownTimeout: 5 * time.Second}, "edge-1", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	_, span := p.TracerProvider().Tracer("test").Start(t.Context(), "GET")
	id := span.SpanContext().TraceID().String()
	span.End()
	if err := p.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := col.Spans(t, id, 1)[0]
	if got.Name != "GET" || got.Resource["service.name"] != "edge-test" || got.Resource["service.instance.id"] != "edge-1" || got.Resource["service.version"] == "" {
		t.Fatalf("exported span %+v", got)
	}
	if p.ExportErrors() != 0 {
		t.Fatalf("%d export errors", p.ExportErrors())
	}
}

// A collector outage is counted, and the flush at shutdown gives up after
// its timeout instead of holding the process.
func TestCollectorDownIsCountedAndBounded(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	p, err := New(Config{Endpoint: "http://" + addr + "/v1/traces", SampleRate: 1, MaxPerSecond: 100, ShutdownTimeout: 300 * time.Millisecond}, "edge-1", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	_, span := p.Tracer("test").Start(t.Context(), "GET")
	span.End()
	start := time.Now()
	// The SDK reports export failures to the error handler, not here.
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	_ = p.Shutdown(ctx)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("shutdown took %v with a 300ms bound", d)
	}
	if p.ExportErrors() == 0 {
		t.Fatal("failed export not counted")
	}
}

// Every batch fails during an outage; one line a minute says why.
func TestExportErrorsLoggedOncePerMinute(t *testing.T) {
	var buf bytes.Buffer
	h := &errorLog{log: slog.New(slog.NewJSONHandler(&buf, nil))}
	h.Handle(errors.New("connection refused"))
	h.Handle(errors.New("connection refused"))
	if n := strings.Count(buf.String(), "opentelemetry error"); n != 1 {
		t.Fatalf("%d lines in a minute, want 1: %s", n, buf.String())
	}
}

func TestCapAdmitsMaxTracesPerSecond(t *testing.T) {
	now := time.Unix(100, 0)
	var dropped atomic.Uint64
	c := &capped{inner: sdktrace.AlwaysSample(), max: 2, now: func() time.Time { return now }, dropped: &dropped}
	root := sdktrace.SamplingParameters{TraceID: trace.TraceID{1}}
	got := []sdktrace.SamplingDecision{c.ShouldSample(root).Decision, c.ShouldSample(root).Decision, c.ShouldSample(root).Decision}
	now = now.Add(time.Second)
	got = append(got, c.ShouldSample(root).Decision)
	want := []sdktrace.SamplingDecision{sdktrace.RecordAndSample, sdktrace.RecordAndSample, sdktrace.Drop, sdktrace.RecordAndSample}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("decision %d = %v, want %v", i, got[i], want[i])
		}
	}
	if dropped.Load() != 1 {
		t.Fatalf("dropped %d, want 1", dropped.Load())
	}
	if d := c.Description(); d != "Capped{AlwaysOnSampler,2/s}" {
		t.Fatalf("description %q", d)
	}
}

// A client that forges sampled=1 on every request is still held to the cap:
// remote parents count like new traces.
func TestCapHoldsForgedSampledParents(t *testing.T) {
	var dropped atomic.Uint64
	c := &capped{inner: sdktrace.ParentBased(sdktrace.NeverSample()), max: 1, now: func() time.Time { return time.Unix(100, 0) }, dropped: &dropped}
	remote := trace.ContextWithRemoteSpanContext(t.Context(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{2}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled, Remote: true,
	}))
	p := sdktrace.SamplingParameters{ParentContext: remote, TraceID: trace.TraceID{2}}
	if c.ShouldSample(p).Decision != sdktrace.RecordAndSample || c.ShouldSample(p).Decision != sdktrace.Drop {
		t.Fatal("forged sampled parents passed the cap")
	}
	// The edge's own traces have their own budget, which the flood left alone.
	if c.ShouldSample(sdktrace.SamplingParameters{ParentContext: t.Context(), TraceID: trace.TraceID{3}}).Decision != sdktrace.Drop {
		t.Fatal("NeverSample root was sampled")
	}
}

// A flood of forged sampled flags can't use up the budget for the traces
// the edge starts itself.
func TestForgedParentsDoNotStarveOwnSampling(t *testing.T) {
	var dropped atomic.Uint64
	c := &capped{inner: sdktrace.ParentBased(sdktrace.AlwaysSample()), max: 1, now: func() time.Time { return time.Unix(100, 0) }, dropped: &dropped}
	remote := trace.ContextWithRemoteSpanContext(t.Context(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{4}, SpanID: trace.SpanID{4}, TraceFlags: trace.FlagsSampled, Remote: true,
	}))
	for range 5 {
		c.ShouldSample(sdktrace.SamplingParameters{ParentContext: remote, TraceID: trace.TraceID{4}})
	}
	if c.ShouldSample(sdktrace.SamplingParameters{ParentContext: t.Context(), TraceID: trace.TraceID{5}}).Decision != sdktrace.RecordAndSample {
		t.Fatal("forged parents used up the edge's own sampling budget")
	}
	if dropped.Load() != 4 {
		t.Fatalf("dropped %d forged traces, want 4", dropped.Load())
	}
}

// A sampled request keeps its Valkey child span after the cap is reached.
func TestCapNeverDropsChildOfSampledSpan(t *testing.T) {
	var dropped atomic.Uint64
	c := &capped{inner: sdktrace.ParentBased(sdktrace.AlwaysSample()), max: 1, now: func() time.Time { return time.Unix(100, 0) }, dropped: &dropped}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(c))
	ctx, server := tp.Tracer("t").Start(t.Context(), "GET")
	_, child := tp.Tracer("t").Start(ctx, "valkey ratelimit")
	if !server.IsRecording() || !child.IsRecording() {
		t.Fatal("child of a sampled span was dropped by the cap")
	}
}
