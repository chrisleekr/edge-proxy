// Package tracing builds the OpenTelemetry tracer provider the edge and
// admin share: OTLP/HTTP export, a ratio sampler with a per-replica cap,
// and counters for failed exports and capped traces. Tracing is off unless
// an OTLP traces endpoint is configured.
package tracing

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/chrisleekr/edge-proxy/internal/envparse"
)

// attrValueLimit caps every attribute value. The SDK default is unlimited,
// and a path can be as long as the header limit allows.
const attrValueLimit = 512

// Config is the tracing part of the deployment config.
type Config struct {
	// Endpoint is the full OTLP/HTTP traces URL; empty turns tracing off.
	Endpoint        string
	ServiceName     string
	SampleRate      float64
	MaxPerSecond    int
	ShutdownTimeout time.Duration
}

// Load reads the tracing variables. Every other standard OTEL_* variable
// (TLS, headers, compression, timeout, queue sizes, resource attributes)
// is read by the SDK itself.
func Load(p *envparse.Parser, service string) Config {
	c := Config{
		Endpoint:        p.Get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
		ServiceName:     p.Str("OTEL_SERVICE_NAME", service),
		SampleRate:      p.Fraction("TRACE_SAMPLE_RATE", 0.01),
		MaxPerSecond:    p.Integer("TRACE_MAX_PER_SECOND", 100),
		ShutdownTimeout: p.Duration("TRACE_SHUTDOWN_TIMEOUT", 5*time.Second),
	}
	src := "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
	if c.Endpoint == "" {
		// The spec's base endpoint takes the signal path for OTLP/HTTP.
		if base := p.Get("OTEL_EXPORTER_OTLP_ENDPOINT"); base != "" {
			c.Endpoint, src = strings.TrimSuffix(base, "/")+"/v1/traces", "OTEL_EXPORTER_OTLP_ENDPOINT"
		}
	}
	if c.Endpoint != "" {
		if u, err := url.Parse(c.Endpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			p.Fail(src, "must be an http or https URL such as http://collector:4318/v1/traces")
		}
	}
	// The exporter logs a malformed entry with its value, which is usually
	// the collector credential, and drops it. Fail here, naming only the
	// variable, with the exporter's own checks. Only with tracing on: the
	// exporter reads them only then.
	for _, k := range []string{"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS"} {
		for kv := range strings.SplitSeq(p.Get(k), ",") {
			_, v, ok := strings.Cut(kv, "=")
			if _, err := url.PathUnescape(v); c.Endpoint != "" && kv != "" && (!ok || err != nil) {
				p.Fail(k, "must be key=value pairs separated by commas, with values percent-encoded")
				break
			}
		}
	}
	return c
}

// Provider is a running tracer provider. A nil *Provider means tracing is
// off; its methods are safe to call and do nothing.
type Provider struct {
	tp           *sdktrace.TracerProvider
	exportErrors atomic.Uint64
	capped       atomic.Uint64
}

// New starts a provider, or returns nil when c has no endpoint. instance
// names this replica in service.instance.id.
func New(c Config, instance string, log *slog.Logger) (*Provider, error) {
	if c.Endpoint == "" {
		return nil, nil
	}
	// OTel reports failures through process-wide hooks that otherwise
	// print plain text to stderr, outside the JSON log. Set before the
	// exporter, which reports while it reads its environment.
	otel.SetLogger(logr.FromSlogHandler(log.Handler()))
	otel.SetErrorHandler(&errorLog{log: log})
	exp, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpointURL(c.Endpoint))
	if err != nil {
		return nil, fmt.Errorf("trace exporter: %w", err)
	}
	p := &Provider{}

	limits := sdktrace.NewSpanLimits()
	if limits.AttributeValueLengthLimit < 0 {
		limits.AttributeValueLengthLimit = attrValueLimit
	}
	// Module builds always carry build info.
	bi, _ := debug.ReadBuildInfo()
	// Merge fails only on two different schema URLs; ours has none.
	res, _ := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", c.ServiceName),
		attribute.String("service.instance.id", instance),
		attribute.String("service.version", bi.Main.Version),
	))
	p.tp = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(&countingExporter{SpanExporter: exp, errs: &p.exportErrors}),
		sdktrace.WithSampler(&capped{inner: sdktrace.ParentBased(sdktrace.TraceIDRatioBased(c.SampleRate)), max: int64(c.MaxPerSecond), now: time.Now, dropped: &p.capped}),
		sdktrace.WithRawSpanLimits(limits),
		sdktrace.WithResource(res),
	)
	return p, nil
}

// Tracer returns the named tracer, or nil when tracing is off.
func (p *Provider) Tracer(name string) trace.Tracer {
	if p == nil {
		return nil
	}
	return p.tp.Tracer(name)
}

// TracerProvider is the provider for instrumentation that takes one, or
// nil when tracing is off.
func (p *Provider) TracerProvider() trace.TracerProvider {
	if p == nil {
		return nil
	}
	return p.tp
}

// Shutdown flushes buffered spans until ctx ends.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	return p.tp.Shutdown(ctx)
}

// ExportErrors is the number of span batches the collector did not accept.
func (p *Provider) ExportErrors() uint64 {
	if p == nil {
		return 0
	}
	return p.exportErrors.Load()
}

// Capped is the number of traces the per-replica cap dropped.
func (p *Provider) Capped() uint64 {
	if p == nil {
		return 0
	}
	return p.capped.Load()
}

// countingExporter counts failed exports for the edge's metrics endpoint.
type countingExporter struct {
	sdktrace.SpanExporter
	errs *atomic.Uint64
}

func (e *countingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := e.SpanExporter.ExportSpans(ctx, spans)
	if err != nil {
		e.errs.Add(1)
	}
	return err
}

// errorLog logs OTel errors at most once a minute: during a collector
// outage every batch fails, and the edge's edge_trace_export_errors_total
// carries the rate.
type errorLog struct {
	log  *slog.Logger
	last atomic.Int64
}

func (h *errorLog) Handle(err error) {
	now := time.Now().Unix()
	if last := h.last.Load(); now-last >= 60 && h.last.CompareAndSwap(last, now) {
		h.log.Warn("opentelemetry error", "error", err.Error())
	}
}

// capped keeps inner's decision but samples at most max traces per second
// per replica, and as many again joined from callers. Clients choose the trace ID and the sampled flag, so neither
// a ratio nor parent-based sampling bounds what an attacker can force.
type capped struct {
	inner sdktrace.Sampler
	max   int64
	now   func() time.Time
	// Traces the edge starts and traces a caller started are capped
	// separately, so forged sampled flags can't use up the edge's own budget.
	own, callers window
	dropped      *atomic.Uint64
}

// window counts trace starts in the current second.
type window struct{ sec, n atomic.Int64 }

func (c *capped) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	r := c.inner.ShouldSample(p)
	if r.Decision != sdktrace.RecordAndSample {
		return r
	}
	w := &c.own
	if psc := trace.SpanContextFromContext(p.ParentContext); psc.IsValid() {
		// Only trace starts count: a child of a local span follows its
		// parent, so a sampled request keeps all its spans.
		if !psc.IsRemote() {
			return r
		}
		w = &c.callers
	}
	// The window reset races, so a second can admit a few over max.
	if s, old := c.now().Unix(), w.sec.Load(); s != old && w.sec.CompareAndSwap(old, s) {
		w.n.Store(0)
	}
	if w.n.Add(1) > c.max {
		c.dropped.Add(1)
		return sdktrace.SamplingResult{Decision: sdktrace.Drop, Tracestate: r.Tracestate}
	}
	return r
}

func (c *capped) Description() string {
	return fmt.Sprintf("Capped{%s,%d/s}", c.inner.Description(), c.max)
}
