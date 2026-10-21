package edge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A panic in a background loop is recovered and counted; the loop and the
// replica keep running.
func TestBackgroundPanicIsContained(t *testing.T) {
	var buf syncBuffer
	m := &metrics{}
	guard(m, newTestLogger(&buf), "test loop", func() { panic("boom") })
	if m.backgroundPanics.Load() != 1 || !strings.Contains(buf.String(), "boom") {
		t.Fatal("panic not recorded")
	}
}

// Liveness is unconditional; readiness means a snapshot is loaded and the
// replica isn't draining, never dependency health.
func TestInternalEndpoints(t *testing.T) {
	h := newHarness(t, nil)
	in := httptest.NewServer(h.srv.internalMux())
	defer in.Close()
	get := func(path string) (int, string) {
		resp, err := http.Get(in.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, readBody(t, resp)
	}
	if code, _ := get("/livez"); code != 200 {
		t.Fatal("livez failed without a snapshot")
	}
	if code, _ := get("/readyz"); code != 503 {
		t.Fatal("ready without a snapshot")
	}
	h.load(envelope(testConfig(4)))
	if code, _ := get("/readyz"); code != 200 {
		t.Fatal("not ready with a snapshot")
	}
	h.do("GET", "/a%5Cb", nil).Body.Close()
	_, body := get("/metrics")
	for _, want := range []string{`edge_rejected_total{reason="path"} 1`, `edge_requests_total{class="4xx"} 1`, "edge_snapshot_version 4", "edge_ready 1", `edge_requests_total{class="none"} 0`} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	h.srv.draining.Store(true)
	if code, _ := get("/readyz"); code != 503 {
		t.Fatal("ready while draining")
	}
}

// Shutdown: readyz fails first, in-flight requests finish, and connections
// that outlive the timeout (a WebSocket, an endless stream) are closed.
func TestGracefulShutdown(t *testing.T) {
	admin := newFakeAdmin(t, envelope(testConfig(1)))
	h := newHarness(t, map[string]string{"ADMIN_URL": admin.srv.URL, "EDGE_SERVICE_TOKEN": "t0k", "STATS_INTERVAL": "10ms", "DRAIN_DELAY": "200ms", "SHUTDOWN_TIMEOUT": "300ms"})
	pub, in := listen(t), listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- h.srv.Run(ctx, pub, in) }()
	waitFor(t, func() bool { return h.srv.ready() })

	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			echoUpgrade(w, r)
			return
		}
		if r.URL.Path == "/events" {
			w.WriteHeader(200)
			http.NewResponseController(w).Flush()
			<-r.Context().Done()
			return
		}
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, "finished")
	}
	ws := dialUpgrade(t, pub.Addr().String())
	defer ws.Close()
	stream := make(chan error)
	go func() {
		req, _ := http.NewRequest("GET", "http://"+pub.Addr().String()+"/events", nil)
		req.Host = "api.example.com"
		req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:1")
		req.Header.Set("Accept", "text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
		}
		stream <- err
	}()
	slow := make(chan string)
	go func() {
		req, _ := http.NewRequest("GET", "http://"+pub.Addr().String()+"/slow", nil)
		req.Host = "api.example.com"
		req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slow <- err.Error()
			return
		}
		slow <- readBody(t, resp)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	waitFor(t, func() bool { return !h.srv.ready() })
	if got := <-slow; got != "finished" {
		t.Fatalf("in-flight request cut: %q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-stream; err == nil {
		t.Fatal("endless stream ended cleanly instead of being cut")
	}
	if len(h.logs.lines("shutdown timed out; closing remaining connections")) != 1 {
		t.Fatal("shutdown timeout not logged")
	}
	if admin.requests.Load() < 2 {
		t.Fatal("reporter never ran")
	}
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ws.Read(make([]byte, 1)); err == nil {
		t.Fatal("WebSocket still open after shutdown")
	}
}

// A probe or scraper that keeps its connection to the internal server open
// is disconnected after IDLE_TIMEOUT, so idle sockets can't pile up.
func TestInternalServerClosesIdleConnections(t *testing.T) {
	h := newHarness(t, map[string]string{"IDLE_TIMEOUT": "200ms", "DRAIN_DELAY": "10ms", "SHUTDOWN_TIMEOUT": "100ms"})
	pub, in := listen(t), listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- h.srv.Run(ctx, pub, in) }()
	defer func() { cancel(); <-done }()

	resp, conn, br := raw(t, in.Addr().String(), "GET /livez HTTP/1.1\r\nHost: edge\r\n\r\n")
	if resp.StatusCode != 200 || resp.Close {
		t.Fatalf("livez %d, close %v", resp.StatusCode, resp.Close)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(br); err != nil {
		t.Fatalf("idle connection still open: %v", err)
	}
}

// If a listener dies, Run stops and reports it instead of serving half a replica.
func TestRunReportsListenerFailure(t *testing.T) {
	h := newHarness(t, nil)
	pub, in := listen(t), listen(t)
	in.Close()
	if err := h.srv.Run(t.Context(), pub, in); err == nil {
		t.Fatal("Run ignored a dead listener")
	}
}

// Main exits 2 on bad config and 1 when it can't listen, logging why.
func TestMainExitCodes(t *testing.T) {
	var out bytes.Buffer
	if code := Main(t.Context(), env(map[string]string{}), &out); code != 2 || !strings.Contains(out.String(), "invalid deployment config") {
		t.Fatalf("bad config: %d %s", code, out.String())
	}
	busy := listen(t)
	defer busy.Close()
	for _, which := range []string{"LISTEN_ADDR", "INTERNAL_ADDR"} {
		e := cloudfrontEnv()
		e["LISTEN_ADDR"], e["INTERNAL_ADDR"] = "127.0.0.1:0", "127.0.0.1:0"
		e[which] = busy.Addr().String()
		out.Reset()
		if code := Main(t.Context(), env(e), &out); code != 1 || !strings.Contains(out.String(), "listen failed") {
			t.Fatalf("%s busy: %d %s", which, code, out.String())
		}
	}
	if exitCode(errors.New("accept: too many open files")) != 1 || exitCode(nil) != 0 {
		t.Fatal("exit codes")
	}
	// A clean stop exits 0.
	e := cloudfrontEnv()
	e["LISTEN_ADDR"], e["INTERNAL_ADDR"], e["DRAIN_DELAY"] = "127.0.0.1:0", "127.0.0.1:0", "1ms"
	e["ADMIN_URL"], e["EDGE_SERVICE_TOKEN"] = "", ""
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out.Reset()
	if code := Main(ctx, env(e), &out); code != 0 {
		t.Fatalf("clean stop: %d %s", code, out.String())
	}
}
