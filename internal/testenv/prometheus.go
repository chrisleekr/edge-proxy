package testenv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// PrometheusImage is pinned by digest, from
// https://hub.docker.com/r/prom/prometheus/tags (v3.15.1 manifest list).
const PrometheusImage = "prom/prometheus:v3.15.1@sha256:fa3302279710be2f21a8301ec17a8b4f2301fd829bd113839b3b6b02b6f191a2"

// prometheusConfig scrapes Prometheus itself every second, so `up` and the
// prometheus_* series exist within seconds of start.
const prometheusConfig = `global:
  scrape_interval: 1s
  evaluation_interval: 1s
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["localhost:9090"]
`

var (
	promOnce sync.Once
	promURL  string
	promErr  error
)

// Prometheus returns the base URL of a Prometheus shared by the test
// process, once its self-scrape answers `up`. Tests only read from it.
func Prometheus(t testing.TB) string {
	t.Helper()
	promOnce.Do(func() { promURL, promErr = startPrometheus(context.Background()) }) //nolint:usetesting // the container is process-wide and outlives this test
	if promErr != nil {
		t.Fatalf("start prometheus: %v", promErr)
	}
	return promURL
}

func startPrometheus(ctx context.Context) (string, error) {
	c, err := testcontainers.Run(ctx, PrometheusImage,
		testcontainers.WithExposedPorts("9090/tcp"),
		testcontainers.WithFiles(testcontainers.ContainerFile{Reader: strings.NewReader(prometheusConfig), ContainerFilePath: "/etc/prometheus/prometheus.yml", FileMode: 0o644}),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/-/ready").WithPort("9090/tcp").WithStartupTimeout(time.Minute)),
	)
	if err != nil {
		return "", err
	}
	host, err := hostOf(ctx, c)
	if err != nil {
		return "", err
	}
	p, err := c.MappedPort(ctx, "9090/tcp")
	if err != nil {
		return "", err
	}
	base := fmt.Sprintf("http://%s:%d", host, p.Num())
	// Ready means the TSDB opened, not that a scrape landed.
	deadline := time.Now().Add(30 * time.Second)
	for {
		n, err := seriesCount(ctx, base, "up")
		if err == nil && n > 0 {
			return base, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("prometheus has no up series after 30s (%d series): %w", n, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func seriesCount(ctx context.Context, base, query string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/query?query="+url.QueryEscape(query), nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Data struct {
			Result []json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	return len(out.Data.Result), nil
}
