package edge

import (
	"context"
	"fmt"
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
	h.do("GET", "/a%5Cb?token=secret", nil).Body.Close()
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

// A sampled line carries the sample rate, so a reader can count it as
// 1/rate requests; an always-logged rejection does not.
func TestAccessLogSampleRate(t *testing.T) {
	old := logDraw
	logDraw = func() float64 { return 0 }
	t.Cleanup(func() { logDraw = old })
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "0.25"})
	h.load(envelope(testConfig(1)))
	h.do("GET", "/v1/ok", nil).Body.Close()
	h.do("GET", "/a%5Cb", nil).Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.logs.lines("access")) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	lines := h.logs.lines("access")
	if len(lines) != 2 || lines[0]["edge.decision"] != "allow" || lines[0]["edge.sample_rate"] != 0.25 {
		t.Fatalf("access lines = %v", lines)
	}
	if _, ok := lines[1]["edge.sample_rate"]; ok || lines[1]["edge.decision"] != "path" {
		t.Fatalf("rejection line = %v", lines[1])
	}
}

// An access line names the host and the query's parameter names, never
// values, so routes can be grouped by host, path and query shape. A key
// that could itself be a secret is counted, not logged.
func TestAccessLogHostAndQueryKeys(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	// Dropped: a bare token, a 65-character key and a bad escape.
	h.do("GET", "/v1/ok?token=secret&b=1&a=2&a=3&&secretbare&secret"+strings.Repeat("x", 59)+"=1&%zz=1", nil, "Host", "API.example.com:443").Body.Close()
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("k%02d=1", i)
	}
	h.do("GET", "/v1/ok?"+strings.Join(many, "&"), nil).Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.logs.lines("access")) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	lines := h.logs.lines("access")
	if len(lines) != 2 {
		t.Fatalf("access lines = %v", lines)
	}
	// Unsampled lines stand for one request each and say nothing of a rate.
	if _, ok := lines[0]["edge.sample_rate"]; ok {
		t.Fatalf("unsampled line = %v", lines[0])
	}
	if fmt.Sprint(lines[0]["edge.query_keys"]) != "[a b token]" || lines[0]["edge.query_keys_dropped"] != 3.0 || lines[0]["server.address"] != "api.example.com" {
		t.Fatalf("first line = %v", lines[0])
	}
	// Keys past the cap are counted, not logged.
	if keys, _ := lines[1]["edge.query_keys"].([]any); len(keys) != 32 || keys[31] != "k31" || lines[1]["edge.query_keys_dropped"] != 1.0 {
		t.Fatalf("second line = %v", lines[1])
	}
	if strings.Contains(h.logs.String(), "secret") {
		t.Fatal("query value or secret-like key logged")
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
