package edge

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Rejections are always logged; allowed requests follow the sample rate; the
// query string never appears in a log line.
func TestAccessLog(t *testing.T) {
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "0"})
	h.load(envelope(testConfig(1)))
	h.do("GET", "/v1/ok?token=secret", nil).Body.Close()
	h.do("GET", "/a%2Fb?token=secret", nil).Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.logs.lines("access")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	lines := h.logs.lines("access")
	if len(lines) != 1 || lines[0]["edge.decision"] != "path" || lines[0]["http.response.status_code"] != 400.0 || lines[0]["client.address"] != "198.51.100.7" {
		t.Fatalf("access lines = %v", lines)
	}
	if strings.Contains(h.logs.String(), "secret") {
		t.Fatal("query string logged")
	}
}

// A full log buffer drops lines instead of blocking requests.
func TestAccessLogDropsWhenFull(t *testing.T) {
	h := newHarness(t, nil)
	// No buffer and no reader: every send would block.
	h.srv.edge.alog = &accessLog{ch: make(chan accessRecord), log: h.srv.log, m: h.srv.m, sample: 1}
	h.load(envelope(testConfig(1)))
	h.do("GET", "/", nil).Body.Close()
	if h.srv.m.logDropped.Load() != 1 {
		t.Fatal("line not dropped")
	}
}

// On shutdown the access log writes out what is buffered before exiting.
func TestAccessLogDrainsOnShutdown(t *testing.T) {
	var buf syncBuffer
	a := newAccessLog(newTestLogger(&buf), &metrics{}, 1, 8)
	for range 3 {
		a.ch <- accessRecord{method: "GET", path: "/", status: 200}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	a.run(ctx)
	if n := len(buf.lines("access")); n != 3 {
		t.Fatalf("drained %d lines, want 3", n)
	}
}
