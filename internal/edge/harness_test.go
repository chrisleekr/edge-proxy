package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/tracing"
)

func dur(d time.Duration) snapshot.Duration { return snapshot.Duration(d) }

func mustParse(src string) expr.Node {
	n, err := expr.Parse(src)
	if err != nil {
		panic(err)
	}
	return n
}

// testConfig is a small valid config: JSON templates for every kind, /admin/
// routed to the admin upstream with a 1s timeout, larger bodies on /upload.
func testConfig(version int64) *snapshot.Config {
	responses := map[string]snapshot.Response{}
	defaults := map[string]string{}
	for k, status := range snapshot.ResponseStatuses() {
		responses[k] = snapshot.Response{Status: status, ContentType: "application/json", Body: `{"error":"` + k + `","status":{{status}},"retry_after":{{retry_after}},"request_id":"{{request_id}}"}`}
		defaults[k] = k
	}
	return &snapshot.Config{
		Schema: snapshot.SupportedSchema, Version: version,
		Global: snapshot.Global{
			Backstop:       snapshot.Backstop{Limit: 100, Period: dur(time.Second), Burst: 100, MaxEntries: 1000},
			Defaults:       snapshot.Defaults{BodyLimit: 1024, BodyReadTimeout: dur(time.Second), UpstreamTimeout: dur(2 * time.Second), Responses: defaults},
			Responses:      responses,
			RequestHeaders: snapshot.RequestHeaders{Forward: snapshot.Forward{Mode: "all"}},
		},
		ConfigRules: []snapshot.ConfigRule{
			{ID: "admin-route", Expression: mustParse(`starts_with(http.request.uri.path, "/admin/")`), Settings: snapshot.Settings{UpstreamTimeout: new(dur(time.Second))}},
			{ID: "uploads", Expression: mustParse(`starts_with(http.request.uri.path, "/upload")`), Settings: snapshot.Settings{BodyLimit: new(int64(1 << 20))}},
		},
	}
}

func envelope(active *snapshot.Config) *snapshot.Envelope {
	return &snapshot.Envelope{ExportedAt: time.Now(), Active: active}
}

// syncBuffer collects log output written from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// lines returns the JSON log lines whose msg is msg.
func (s *syncBuffer) lines(msg string) []map[string]any {
	var out []map[string]any
	for l := range strings.SplitSeq(s.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// harness is one edge replica behind a loopback "CDN", forwarding to app.
type harness struct {
	t     *testing.T
	srv   *Server
	front *httptest.Server
	app   *httptest.Server
	logs  *syncBuffer
	// appHandler is swapped by tests; default echo 200.
	appHandler http.HandlerFunc
	mu         sync.Mutex
	lastApp    *http.Request
}

func newHarness(t *testing.T, set map[string]string) *harness {
	t.Helper()
	h := &harness{t: t, logs: &syncBuffer{}}
	ok := func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "upstream ok") }
	h.appHandler = ok
	h.app = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.lastApp = r
		fn := h.appHandler
		h.mu.Unlock()
		fn(w, r)
	}))
	t.Cleanup(h.app.Close)

	e := map[string]string{
		"CLIENT_IP_SOURCE": "cloudfront",
		"TRUSTED_PROXIES":  "127.0.0.1/32,::1/128",
		"UPSTREAM_URL":     h.app.URL,
		"BOOTSTRAP_PATH":   t.TempDir() + "/bootstrap.json",
	}
	maps.Copy(e, set)
	cfg, err := LoadConfig(env(e))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(h.logs, nil))
	tp, err := tracing.New(cfg.Tracing, cfg.Instance, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) }) //nolint:usetesting // t.Context is cancelled before cleanups run
	h.srv = New(cfg, log, tp)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { h.srv.alog.run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	h.front = httptest.NewServer(h.srv.edge)
	t.Cleanup(h.front.Close)
	return h
}

// load activates a snapshot as the poller would.
func (h *harness) load(e *snapshot.Envelope) {
	h.t.Helper()
	if err := h.srv.poller.apply(e, "admin", 0); err != nil {
		h.t.Fatal(err)
	}
}

// do sends a request as CloudFront would: from the trusted peer, with the
// viewer's address. headers are pairs and override the defaults.
func (h *harness) do(method, target string, body io.Reader, headers ...string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(method, h.front.URL+target, body)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Host = "api.example.com"
	req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:40000")
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i] == "Host" {
			req.Host = headers[i+1]
			continue
		}
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := h.front.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// edgeError reads an edge JSON error body and checks the headers every
// edge response must carry.
func edgeError(t *testing.T, resp *http.Response, status int, kind string) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != status {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want %d: %s", resp.StatusCode, status, b)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Request-Id") == "" {
		t.Errorf("edge response headers: %v", resp.Header)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("body is not the JSON template: %v", err)
	}
	if m["error"] != kind || m["request_id"] != resp.Header.Get("X-Request-Id") {
		t.Errorf("body = %v, want kind %s", m, kind)
	}
	return m
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newTestLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewJSONHandler(w, nil)) }

func testDeployment() snapshot.Deployment {
	return snapshot.Deployment{ViewerFields: []string{"ip.src.country"}}
}

// echoUpgrade is an upstream that accepts an upgrade and echoes bytes.
func echoUpgrade(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Upgrade", "echo")
	w.WriteHeader(http.StatusSwitchingProtocols)
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = io.Copy(conn, brw)
}

func dialUpgrade(t *testing.T, addr string) net.Conn {
	t.Helper()
	return dialUpgradePath(t, addr, "/ws")
}

// ipWithCohort finds an IPv4 address inside or outside the first bp basis points.
func ipWithCohort(t *testing.T, inside bool, bp int) string {
	t.Helper()
	for i := 1; i < 65536; i++ {
		a := netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
		if (cohortOf(a) < bp) == inside {
			return a.String()
		}
	}
	t.Fatal("no address found")
	return ""
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// rlRule is a blocking rule with a 1-minute window keyed by key. Tests use
// sliding windows: a fixed window admits twice its limit across a boundary,
// which would make limit assertions depend on the wall clock.
func rlRule(id, src, algo string, limit int64, key ...string) snapshot.RateLimitRule {
	r := snapshot.RateLimitRule{ID: id, Expression: mustParse(src), Algorithm: algo, Limit: limit, Period: dur(time.Minute), Key: key, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"}
	if algo == "token_bucket" || algo == "leaky_bucket" {
		r.Burst = limit
	}
	return r
}

// statuses sends n identical requests and returns their status codes.
func (h *harness) statuses(n int, method, target string, headers ...string) []int {
	h.t.Helper()
	var out []int
	for range n {
		resp := h.do(method, target, nil, headers...)
		resp.Body.Close()
		out = append(out, resp.StatusCode)
	}
	return out
}
