package testenv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// GrafanaImage is pinned by digest, from
// https://hub.docker.com/r/grafana/grafana/tags (13.3.0 manifest list).
const GrafanaImage = "grafana/grafana:13.3.0@sha256:488984b716c0862639f91a698adbe2862677a5a07bad42da5f03f3030883b205"

// GrafanaAdminPassword is the admin user's password, for tests that seed
// annotations and dashboards the Viewer token can't write.
const GrafanaAdminPassword = "grafana-test-admin" //nolint:gosec // a throwaway test container's password

var (
	grafanaOnce  sync.Once
	grafanaURL   string
	grafanaToken string
	grafanaErr   error
)

// Grafana returns the base URL of a Grafana shared by the test process and
// a Viewer service-account token for it, the read-only access admin's
// connector is deployed with.
func Grafana(t testing.TB) (url, token string) {
	t.Helper()
	grafanaOnce.Do(func() { grafanaURL, grafanaToken, grafanaErr = startGrafana(context.Background()) }) //nolint:usetesting // the container is process-wide and outlives this test
	if grafanaErr != nil {
		t.Fatalf("start grafana: %v", grafanaErr)
	}
	return grafanaURL, grafanaToken
}

func startGrafana(ctx context.Context) (string, string, error) {
	c, err := testcontainers.Run(ctx, GrafanaImage,
		testcontainers.WithExposedPorts("3000/tcp"),
		testcontainers.WithEnv(map[string]string{"GF_SECURITY_ADMIN_PASSWORD": GrafanaAdminPassword, "GF_ANALYTICS_REPORTING_ENABLED": "false", "GF_ANALYTICS_CHECK_FOR_UPDATES": "false"}),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/api/health").WithPort("3000/tcp").WithStartupTimeout(2*time.Minute)),
	)
	if err != nil {
		return "", "", err
	}
	host, err := hostOf(ctx, c)
	if err != nil {
		return "", "", err
	}
	p, err := c.MappedPort(ctx, "3000/tcp")
	if err != nil {
		return "", "", err
	}
	base := fmt.Sprintf("http://%s:%d", host, p.Num())
	// Service account and token API:
	// https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/serviceaccount/
	var sa struct {
		ID int64 `json:"id"`
	}
	if err := GrafanaAdmin(ctx, base, "POST", "/api/serviceaccounts", map[string]any{"name": "edge-proxy-admin", "role": "Viewer"}, &sa); err != nil {
		return "", "", err
	}
	var tok struct {
		Key string `json:"key"`
	}
	if err := GrafanaAdmin(ctx, base, "POST", fmt.Sprintf("/api/serviceaccounts/%d/tokens", sa.ID), map[string]any{"name": "tests"}, &tok); err != nil {
		return "", "", err
	}
	return base, tok.Key, nil
}

// GrafanaAdmin sends one request as Grafana's admin user and decodes the
// answer into out when out is not nil.
func GrafanaAdmin(ctx context.Context, base, method, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.SetBasicAuth("admin", GrafanaAdminPassword)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		var msg bytes.Buffer
		_, _ = msg.ReadFrom(resp.Body)
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, msg.String())
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
