package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// The real binary, built by scripts/ci/test.sh with -cover, starts from a
// bootstrap snapshot, proxies, and exits cleanly on SIGTERM. Skipped unless
// EDGE_BIN is set.
func TestE2EBinary(t *testing.T) {
	bin := os.Getenv("EDGE_BIN")
	if bin == "" {
		t.Skip("EDGE_BIN not set; scripts/ci/test.sh builds the binary")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from "+r.Header.Get("X-Edge-Client-Ip"))
	}))
	defer upstream.Close()

	boot := filepath.Join(t.TempDir(), "bootstrap.json")
	writeBootstrap(t, boot)
	pub, in := freeAddr(t), freeAddr(t)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"LISTEN_ADDR="+pub, "INTERNAL_ADDR="+in,
		"CLIENT_IP_SOURCE=cloudfront", "TRUSTED_PROXIES=127.0.0.1/32",
		"UPSTREAMS=app="+upstream.URL, "UPSTREAM_HOSTS=api.example.com=app",
		"BOOTSTRAP_PATH="+boot, "DRAIN_DELAY=10ms", "SHUTDOWN_TIMEOUT=1s",
	)
	var logs strings.Builder
	cmd.Stdout = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitReady(t, "http://"+in+"/readyz")

	req, _ := http.NewRequest("GET", "http://"+pub+"/", nil)
	req.Host = "api.example.com"
	req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from 198.51.100.7" {
		t.Fatalf("proxied body %q", body)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("exit after SIGTERM: %v\n%s", err, logs.String())
	}
	if !strings.Contains(logs.String(), `"msg":"stopped"`) {
		t.Fatalf("no clean stop in logs:\n%s", logs.String())
	}
}

// A misconfigured deployment exits 2 at startup instead of half-starting.
func TestE2EBadConfigExits(t *testing.T) {
	bin := os.Getenv("EDGE_BIN")
	if bin == "" {
		t.Skip("EDGE_BIN not set; scripts/ci/test.sh builds the binary")
	}
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "CLIENT_IP_SOURCE=nonsense")
	var ee *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("exit = %v, want 2", err)
	}
}

func writeBootstrap(t *testing.T, path string) {
	t.Helper()
	responses := map[string]snapshot.Response{}
	defaults := map[string]string{}
	for kind, status := range map[string]int{"bad_request": 400, "unauthorized": 401, "misdirected": 421, "payload_too_large": 413, "rate_limited": 429, "bad_gateway": 502, "unavailable": 503, "overloaded": 503, "gateway_timeout": 504} {
		responses[kind] = snapshot.Response{Status: status, ContentType: "text/plain; charset=utf-8", Body: kind}
		defaults[kind] = kind
	}
	sec := snapshot.Duration(time.Second)
	limit := int64(2048)
	e := snapshot.Envelope{ExportedAt: time.Now(), Active: &snapshot.Config{
		Schema: 1, Version: 1,
		Global: snapshot.Global{
			Backstop:       snapshot.Backstop{Limit: 10, Period: sec, Burst: 10, MaxEntries: 10},
			Defaults:       snapshot.Defaults{BodyLimit: 1024, BodyReadTimeout: sec, UpstreamTimeout: sec, Responses: defaults},
			Responses:      responses,
			RequestHeaders: snapshot.RequestHeaders{Forward: snapshot.Forward{Mode: "all"}},
		},
		ConfigRules: []snapshot.ConfigRule{{ID: "all", Expression: expr.True(), Settings: snapshot.Settings{BodyLimit: &limit}}},
	}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("edge never became ready")
}
