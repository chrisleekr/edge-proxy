package testenv

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// CollectorImage is the OpenTelemetry Collector with the file exporter.
const CollectorImage = "otel/opentelemetry-collector-contrib:0.163.1"

// collectorConfig receives OTLP/HTTP and appends every batch to a file,
// which is read back through the Docker API, so the helper also works
// where the Docker daemon is remote (CI's dind).
const collectorConfig = `receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  file:
    path: /data/spans.jsonl
    flush_interval: 100ms
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [file]
`

// Collector is a running OpenTelemetry Collector shared by the test
// process. Tests isolate themselves by trace ID.
type Collector struct {
	// Endpoint is the OTLP/HTTP traces URL.
	Endpoint string
	c        *testcontainers.DockerContainer
}

var (
	collectorOnce sync.Once
	collector     *Collector
	collectorErr  error
)

// OTelCollector returns the process-wide collector, starting it on first use.
func OTelCollector(t testing.TB) *Collector {
	t.Helper()
	collectorOnce.Do(func() { collector, collectorErr = startCollector(context.Background()) }) //nolint:usetesting // the container is process-wide and outlives this test
	if collectorErr != nil {
		t.Fatalf("start collector: %v", collectorErr)
	}
	return collector
}

func startCollector(ctx context.Context) (*Collector, error) {
	c, err := testcontainers.Run(ctx, CollectorImage,
		testcontainers.WithExposedPorts("4318/tcp"),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{Reader: strings.NewReader(collectorConfig), ContainerFilePath: "/etc/otelcol-contrib/config.yaml", FileMode: 0o644},
			// Created here because the collector runs unprivileged in a
			// root-owned filesystem. Not a tmpfs: docker cp can't read one.
			testcontainers.ContainerFile{Reader: strings.NewReader(""), ContainerFilePath: "/data/spans.jsonl", FileMode: 0o666},
		),
		// The image has no shell, so the port can't be probed from inside.
		testcontainers.WithWaitStrategy(wait.ForLog("Everything is ready").WithStartupTimeout(time.Minute)),
	)
	if err != nil {
		return nil, err
	}
	host, err := hostOf(ctx, c)
	if err != nil {
		return nil, err
	}
	p, err := c.MappedPort(ctx, "4318/tcp")
	if err != nil {
		return nil, err
	}
	return &Collector{Endpoint: fmt.Sprintf("http://%s:%d/v1/traces", host, p.Num()), c: c}, nil
}

// Span is one exported span, flattened for assertions.
type Span struct {
	TraceID, SpanID, ParentSpanID, Name string
	// Kind is the OTLP enum: 2 server, 3 client.
	Kind int
	// Status is the OTLP enum: 0 unset, 1 ok, 2 error.
	Status int
	Attrs  map[string]string
	// Links are the trace IDs this span links to.
	Links    []string
	Resource map[string]string
}

// Spans waits until the collector holds at least want spans of traceID,
// then returns them. The exporter must have been flushed first.
func (c *Collector) Spans(t testing.TB, traceID string, want int) []Span {
	t.Helper()
	return c.wait(t, traceID, want, func(s Span) bool { return s.TraceID == traceID })
}

// SpansLinkedTo waits for at least want spans that link to traceID: the
// spans of a new trace started for a caller whose trace was not joined.
func (c *Collector) SpansLinkedTo(t testing.TB, traceID string, want int) []Span {
	t.Helper()
	return c.wait(t, traceID, want, func(s Span) bool { return slices.Contains(s.Links, traceID) })
}

func (c *Collector) wait(t testing.TB, traceID string, want int, match func(Span) bool) []Span {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		spans := c.read(t, match)
		if len(spans) >= want {
			return spans
		}
		if time.Now().After(deadline) {
			t.Fatalf("collector has %d spans of trace %s, want %d", len(spans), traceID, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// otlpJSON is the part of the OTLP JSON encoding the tests read.
type otlpJSON struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []otlpAttr `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Spans []struct {
				TraceID      string `json:"traceId"`
				SpanID       string `json:"spanId"`
				ParentSpanID string `json:"parentSpanId"`
				Links        []struct {
					TraceID string `json:"traceId"`
				} `json:"links"`
				Name       string     `json:"name"`
				Kind       int        `json:"kind"`
				Attributes []otlpAttr `json:"attributes"`
				Status     struct {
					Code int `json:"code"`
				} `json:"status"`
			} `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type otlpAttr struct {
	Key   string `json:"key"`
	Value struct {
		String string `json:"stringValue"`
		Int    string `json:"intValue"`
	} `json:"value"`
}

func attrMap(attrs []otlpAttr) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		m[a.Key] = a.Value.String + a.Value.Int
	}
	return m
}

func (c *Collector) read(t testing.TB, match func(Span) bool) []Span {
	t.Helper()
	rc, err := c.c.CopyFileFromContainer(t.Context(), "/data/spans.jsonl")
	if err != nil {
		// Read as no spans yet; Spans retries until its deadline.
		return nil
	}
	defer func() { _ = rc.Close() }()
	var out []Span
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var batch otlpJSON
		if err := json.Unmarshal(sc.Bytes(), &batch); err != nil {
			// The collector appends whole lines, so only the last can be
			// cut off mid-write; the next read picks it up.
			break
		}
		for _, rs := range batch.ResourceSpans {
			res := attrMap(rs.Resource.Attributes)
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					span := Span{TraceID: s.TraceID, SpanID: s.SpanID, ParentSpanID: s.ParentSpanID, Name: s.Name, Kind: s.Kind, Status: s.Status.Code, Attrs: attrMap(s.Attributes), Resource: res}
					for _, l := range s.Links {
						span.Links = append(span.Links, l.TraceID)
					}
					if match(span) {
						out = append(out, span)
					}
				}
			}
		}
	}
	return out
}
