package edge

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// viewer is the CDN header block for hand-written requests.
const viewer = "Host: api.example.com\r\nCloudFront-Viewer-Address: 198.51.100.7:1\r\n"

// raw sends a hand-written request, for shapes http.Client won't send
// (upgrades, HTTP/1.0, conflicting framing), and reads the response head.
func raw(t *testing.T, addr, req string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp, conn, br
}

// wsUpstream completes a real RFC 6455 handshake, echoes 4-byte messages,
// and hangs up when it reads "quit".
func wsUpstream(w http.ResponseWriter, r *http.Request) {
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Sec-WebSocket-Accept", base64.StdEncoding.EncodeToString(sum[:]))
	w.Header().Set("Sec-WebSocket-Protocol", "chat")
	w.WriteHeader(http.StatusSwitchingProtocols)
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	msg := make([]byte, 4)
	for {
		if _, err := io.ReadFull(brw, msg); err != nil || string(msg) == "quit" {
			return
		}
		_, _ = conn.Write(msg)
	}
}

// RFC 6455 §1.3's sample key and its accept value.
const wsHandshake = "GET /chat HTTP/1.1\r\n" + viewer + "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat, superchat\r\n\r\n"

func openWS(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	resp, conn, br := raw(t, addr, wsHandshake)
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" || resp.Header.Get("Sec-WebSocket-Protocol") != "chat" {
		t.Fatalf("handshake: %d %v", resp.StatusCode, resp.Header)
	}
	return conn, br
}

func echo(t *testing.T, conn net.Conn, br *bufio.Reader, msg string) {
	t.Helper()
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != msg {
		t.Fatalf("echo %q: %q %v", msg, got, err)
	}
}

// A WebSocket holds a stream slot, not an ordinary one, for exactly as long
// as it is open, whichever side hangs up, and is logged as the 101 it was.
func TestWebSocket(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	got := make(chan http.Header, 2)
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { got <- r.Header.Clone(); wsUpstream(w, r) }
	addr := h.front.Listener.Addr().String()
	closed := func() bool { return h.srv.m.streams.Load() == 0 }

	for _, tc := range []struct {
		name   string
		hangUp func(t *testing.T, conn net.Conn, br *bufio.Reader)
	}{
		{"the client hangs up", func(t *testing.T, conn net.Conn, _ *bufio.Reader) { t.Helper(); conn.Close() }},
		// The upstream's close reaches the client as a half-close; the slot
		// is freed when the client closes in turn (RFC 6455 §7.1.1).
		{"the upstream hangs up", func(t *testing.T, conn net.Conn, br *bufio.Reader) {
			t.Helper()
			_, _ = io.WriteString(conn, "quit")
			if _, err := br.ReadByte(); err != io.EOF {
				t.Fatalf("client not told the upstream left: %v", err)
			}
			conn.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, br := openWS(t, addr)
			up := <-got
			if up.Get("Sec-WebSocket-Key") == "" || up.Get("Sec-WebSocket-Version") != "13" || up.Get("Sec-WebSocket-Protocol") != "chat, superchat" || up.Get("X-Forwarded-For") != "198.51.100.7" {
				t.Fatalf("upstream handshake headers: %v", up)
			}
			echo(t, conn, br, "ping")
			if h.srv.m.streams.Load() != 1 || h.srv.m.inflight.Load() != 0 {
				t.Fatalf("open WebSocket: streams %d, inflight %d", h.srv.m.streams.Load(), h.srv.m.inflight.Load())
			}
			tc.hangUp(t, conn, br)
			waitFor(t, closed)
		})
	}
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 2 })
	for _, l := range h.logs.lines("access") {
		if l["http.response.status_code"] != 101.0 {
			t.Errorf("WebSocket logged as %v", l["http.response.status_code"])
		}
	}
	if h.srv.m.requests[1].Load() != 2 || h.srv.m.requests[0].Load() != 0 {
		t.Errorf("requests by class: 1xx %d, none %d", h.srv.m.requests[1].Load(), h.srv.m.requests[0].Load())
	}
}

// An upgrade the upstream won't complete is answered like any response:
// its own refusal passes through, a switch to the wrong protocol is a 502.
func TestUpgradeRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	addr := h.front.Listener.Addr().String()

	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
	}
	resp, _, _ := raw(t, addr, wsHandshake)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("upstream refusal: %d", resp.StatusCode)
	}

	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "something-else")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}
	resp, _, _ = raw(t, addr, wsHandshake)
	edgeError(t, resp, 502, "bad_gateway")
	waitFor(t, func() bool { return h.srv.m.streams.Load() == 0 })
}

// An upgrade is rate limited like any request, before it reaches the
// upstream: a 429 the client can read, not a half-open connection.
func TestUpgradeOverBackstop(t *testing.T) {
	h := newHarness(t, nil)
	c := testConfig(1)
	c.Global.Backstop = snapshot.Backstop{Limit: 1, Period: dur(time.Minute), Burst: 1, MaxEntries: 1000}
	h.load(envelope(c))
	var hits atomic.Int32
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { hits.Add(1); wsUpstream(w, r) }
	addr := h.front.Listener.Addr().String()

	conn, _ := openWS(t, addr)
	conn.Close()
	resp, _, _ := raw(t, addr, wsHandshake)
	edgeError(t, resp, 429, "rate_limited")
	if hits.Load() != 1 {
		t.Fatalf("upstream saw %d upgrades, want 1", hits.Load())
	}
}

// An h2c upgrade reaches the upstream without HTTP2-Settings, because
// ReverseProxy drops headers named in Connection. A compliant upstream then
// can't switch to HTTP/2 and carry requests the edge never checked.
func TestH2CUpgradeCannotSwitch(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	got := make(chan http.Header, 1)
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		_, _ = io.WriteString(w, "plain")
	}
	resp, _, _ := raw(t, h.front.Listener.Addr().String(), "GET / HTTP/1.1\r\n"+viewer+"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if up := <-got; up.Get("HTTP2-Settings") != "" || strings.Contains(strings.ToLower(up.Get("Connection")), "http2-settings") {
		t.Fatalf("upstream could switch to h2c: %v", up)
	}
}

// readLine fails the test if the next line doesn't arrive promptly, which
// is how a buffered stream shows up.
func readLine(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	ch := make(chan string, 1)
	go func() { l, _ := br.ReadString('\n'); ch <- l }()
	select {
	case l := <-ch:
		return l
	case <-time.After(2 * time.Second):
		t.Fatal("stream data held back")
		return ""
	}
}

func TestSSE(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))

	// Each write reaches the client at once: SSE by content type, any
	// response of unknown length because it may be a stream too.
	for _, ct := range []string{"text/event-stream", "application/x-ndjson"} {
		t.Run(ct+" is passed on as written", func(t *testing.T) {
			next := make(chan struct{})
			h.appHandler = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ct)
				_, _ = io.WriteString(w, "one\n")
				http.NewResponseController(w).Flush()
				<-next
				_, _ = io.WriteString(w, "two\n")
			}
			resp := h.do("GET", "/events", nil, "Accept", "text/event-stream")
			defer resp.Body.Close()
			br := bufio.NewReader(resp.Body)
			if l := readLine(t, br); l != "one\n" {
				t.Fatalf("first: %q", l)
			}
			close(next)
			if l := readLine(t, br); l != "two\n" {
				t.Fatalf("second: %q", l)
			}
		})
	}

	t.Run("a client that leaves ends the upstream stream and frees its slots", func(t *testing.T) {
		gone := make(chan struct{})
		h.appHandler = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: 1\n\n")
			http.NewResponseController(w).Flush()
			<-r.Context().Done()
			close(gone)
		}
		resp := h.do("GET", "/events", nil, "Accept", "text/event-stream")
		readLine(t, bufio.NewReader(resp.Body))
		if h.srv.m.streams.Load() != 1 || h.srv.m.inflight.Load() != 0 {
			t.Fatalf("open SSE: streams %d, inflight %d", h.srv.m.streams.Load(), h.srv.m.inflight.Load())
		}
		resp.Body.Close()
		select {
		case <-gone:
		case <-time.After(2 * time.Second):
			t.Fatal("upstream kept streaming to a client that left")
		}
		waitFor(t, func() bool { return h.srv.m.streams.Load() == 0 })
	})

	// LLM-style APIs POST a body and stream the answer. The body read
	// deadline (1s here) must not cut the answer once the body is read.
	t.Run("a POST answered with a stream outlives the body read timeout", func(t *testing.T) {
		h.appHandler = func(w http.ResponseWriter, r *http.Request) {
			if b, _ := io.ReadAll(r.Body); string(b) != `{"prompt":"hi"}` {
				http.Error(w, "body "+string(b), 400)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			for i := range 3 {
				_, _ = io.WriteString(w, "data: "+string(rune('a'+i))+"\n\n")
				http.NewResponseController(w).Flush()
				time.Sleep(600 * time.Millisecond)
			}
		}
		body := readBody(t, h.do("POST", "/v1/chat", strings.NewReader(`{"prompt":"hi"}`), "Accept", "text/event-stream", "Content-Type", "application/json"))
		if strings.Count(body, "data:") != 3 {
			t.Fatalf("stream cut short: %q", body)
		}
	})
}

// A stream's latency is its time to response headers. Its lifetime would
// fill the top histogram bucket, which the guard's p99 signal reads.
func TestStreamLatency(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	addr := h.front.Listener.Addr().String()
	slow := func(c StatsCounts) (n uint64) {
		for _, v := range c.LatencyMS[7:] { // above 100 ms
			n += v
		}
		return n
	}
	stats := func() StatsCounts { return h.srv.store.load().active.stats.counts() }

	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chat" {
			wsUpstream(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		http.NewResponseController(w).Flush()
		time.Sleep(1100 * time.Millisecond)
	}
	readBody(t, h.do("GET", "/events", nil, "Accept", "text/event-stream"))
	conn, _ := openWS(t, addr)
	time.Sleep(1100 * time.Millisecond)
	conn.Close()
	waitFor(t, func() bool { return stats().Requests == 2 })
	if c := stats(); slow(c) != 0 {
		t.Fatalf("stream lifetime recorded as latency: %v", c.LatencyMS)
	}
}

// Streams outlive the server's idle and header timeouts: those apply between
// requests, and the public server sets no write or read timeout.
func TestStreamsOutliveServerTimeouts(t *testing.T) {
	admin := newFakeAdmin(t, envelope(testConfig(1)))
	h := newHarness(t, map[string]string{"ADMIN_URL": admin.srv.URL, "EDGE_SERVICE_TOKEN": "t0k", "IDLE_TIMEOUT": "200ms", "READ_HEADER_TIMEOUT": "200ms", "DRAIN_DELAY": "10ms", "SHUTDOWN_TIMEOUT": "100ms"})
	pub, in := listen(t), listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- h.srv.Run(ctx, pub, in) }()
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { return h.srv.ready() })
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chat" {
			wsUpstream(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := range 2 {
			_, _ = io.WriteString(w, "data: "+string(rune('a'+i))+"\n\n")
			http.NewResponseController(w).Flush()
			time.Sleep(600 * time.Millisecond)
		}
	}

	conn, br := openWS(t, pub.Addr().String())
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	time.Sleep(600 * time.Millisecond)
	echo(t, conn, br, "late")

	resp, _, _ := raw(t, pub.Addr().String(), "GET /events HTTP/1.1\r\n"+viewer+"Accept: text/event-stream\r\n\r\n")
	b, err := io.ReadAll(resp.Body)
	if err != nil || strings.Count(string(b), "data:") != 2 {
		t.Fatalf("SSE cut: %q %v", b, err)
	}
}

// Plain HTTP shapes that a reverse proxy commonly gets wrong.
func TestHTTPEdgeCases(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	addr := h.front.Listener.Addr().String()
	var hits atomic.Int32
	var mu sync.Mutex
	var seen []string // method, path and body of each upstream request
	last := func() []string { mu.Lock(); defer mu.Unlock(); return seen }
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+" "+string(b))
		mu.Unlock()
		switch r.URL.Path {
		case "/cached":
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.Header().Set("ETag", `"v1"`)
				w.WriteHeader(http.StatusNotModified)
				return
			}
		case "/trailer":
			w.Header().Set("Trailer", "X-Checksum")
			_, _ = io.WriteString(w, "payload")
			w.Header().Set("X-Checksum", "abc123")
			return
		case "/empty":
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Length", "11")
		_, _ = io.WriteString(w, "upstream ok")
	}

	t.Run("HEAD gets the headers and no body", func(t *testing.T) {
		resp := h.do("HEAD", "/", nil)
		if body := readBody(t, resp); resp.StatusCode != 200 || body != "" || resp.ContentLength != 11 {
			t.Fatalf("HEAD: %d %q length %d", resp.StatusCode, body, resp.ContentLength)
		}
	})
	t.Run("304 and 204 pass through without a body", func(t *testing.T) {
		resp := h.do("GET", "/cached", nil, "If-None-Match", `"v1"`)
		if body := readBody(t, resp); resp.StatusCode != 304 || resp.Header.Get("ETag") != `"v1"` || body != "" {
			t.Fatalf("304: %d %v %q", resp.StatusCode, resp.Header, body)
		}
		if resp := h.do("GET", "/empty", nil); readBody(t, resp) != "" || resp.StatusCode != 204 {
			t.Fatalf("204: %d", resp.StatusCode)
		}
	})
	t.Run("upstream trailers reach the client", func(t *testing.T) {
		resp := h.do("GET", "/trailer", nil)
		if body := readBody(t, resp); body != "payload" || resp.Trailer.Get("X-Checksum") != "abc123" {
			t.Fatalf("trailer: %q %v", body, resp.Trailer)
		}
	})
	t.Run("Expect: 100-continue is answered before the body is sent", func(t *testing.T) {
		resp, conn, br := raw(t, addr, "POST / HTTP/1.1\r\n"+viewer+"Content-Length: 5\r\nExpect: 100-continue\r\n\r\n")
		if resp.StatusCode != http.StatusContinue {
			t.Fatalf("interim: %d", resp.StatusCode)
		}
		_, _ = io.WriteString(conn, "hello")
		resp, err := http.ReadResponse(br, nil)
		if p := last(); err != nil || resp.StatusCode != 200 || p[len(p)-1] != "POST / hello" {
			t.Fatalf("after continue: %v %v %q", resp, err, p)
		}
	})
	t.Run("an HTTP/1.0 client gets a complete response and a closed connection", func(t *testing.T) {
		resp, _, br := raw(t, addr, "GET / HTTP/1.0\r\n"+viewer+"\r\n")
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || string(body) != "upstream ok" {
			t.Fatalf("HTTP/1.0: %d %q", resp.StatusCode, body)
		}
		if _, err := br.ReadByte(); err != io.EOF {
			t.Fatalf("connection left open: %v", err)
		}
	})

	// Request smuggling shapes: the edge and the upstream must agree on where
	// the body ends, so the edge either refuses or forwards one framing.
	// Go removes the Content-Length and reads the chunked body
	// (RFC 9112 §6.3), but keeps the connection open although RFC 9112 §6.1
	// says to close it, so what follows is served as a request of its own.
	// The edge re-frames each request, so the upstream sees exactly what the
	// edge checked.
	t.Run("Content-Length with Transfer-Encoding: chunked is forwarded with one framing", func(t *testing.T) {
		before := hits.Load()
		resp, _, br := raw(t, addr, "POST / HTTP/1.1\r\n"+viewer+"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /next HTTP/1.1\r\n"+viewer+"\r\n")
		_, _ = io.ReadAll(resp.Body)
		next, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != 200 || next.StatusCode != 200 {
			t.Fatalf("statuses %d %v %v", resp.StatusCode, next, err)
		}
		if p := last(); hits.Load()-before != 2 || p[len(p)-2] != "POST / hello" || p[len(p)-1] != "GET /next " {
			t.Fatalf("upstream saw %q", p)
		}
	})
	t.Run("two different Content-Length values are refused before the upstream", func(t *testing.T) {
		before := hits.Load()
		resp, _, _ := raw(t, addr, "POST / HTTP/1.1\r\n"+viewer+"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello!")
		if resp.StatusCode != 400 || hits.Load() != before {
			t.Fatalf("status %d, upstream hits %d", resp.StatusCode, hits.Load()-before)
		}
	})
}
