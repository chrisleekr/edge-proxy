package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/edge"
)

// runServer runs s.Serve on a fresh listener until the returned stop is called.
func runServer(t *testing.T, s *Server) (addr string, stop func() error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	return l.Addr().String(), func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(20 * time.Second):
			t.Fatal("Serve did not return after shutdown")
			return nil
		}
	}
}

// A report still arriving when admin is told to stop is answered and its
// counts are written, not dropped with the replica.
func TestReportDuringShutdownIsFlushed(t *testing.T) {
	h, pub := published(t)
	addr, stop := runServer(t, h.s)
	b, _ := json.Marshal(edge.StatsReport{Instance: "edge-a", ConfigSource: "admin", Versions: []edge.StatsCounts{{Version: 1, Requests: 7, LatencyMS: []uint64{7}}}})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// 100 Continue comes once the handler reads the body: the request is in
	// flight before shutdown starts.
	_, _ = fmt.Fprintf(conn, "POST /v1/edge/report HTTP/1.1\r\nHost: admin\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: %d\r\n\r\n", h.edgeToken(pub), len(b))
	r := bufio.NewReader(conn)
	if resp, err := http.ReadResponse(r, nil); err != nil || resp.StatusCode != 100 {
		t.Fatalf("no 100 Continue: %v, %v", resp, err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	// Shutdown closes the listener first.
	waitFor(t, func() bool {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
		}
		return err != nil
	})
	_, _ = conn.Write(b)
	if resp, err := http.ReadResponse(r, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("report answer %v, %v", resp, err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	var requests int64
	if err := h.db.QueryRow(t.Context(), "SELECT coalesce(sum(requests), 0) FROM edge_stats_minute WHERE version = 1").Scan(&requests); err != nil || requests != 7 {
		t.Fatalf("flushed %d requests, %v", requests, err)
	}
}

// With Postgres accepting connections but never answering, shutdown still
// finishes: the last stats flush gives up instead of hanging the replica.
func TestShutdownWithPostgresHungFinishes(t *testing.T) {
	h := newHarness(t)
	hole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hole.Close() })
	go func() {
		var held []net.Conn // never answered, closed with the test
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			c, err := hole.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	pool, err := pgxpool.New(t.Context(), "postgres://admin@"+hole.Addr().String()+"/admin?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	s := NewServer(h.s.cfg, pool, slog.New(slog.DiscardHandler))
	s.agg.add(s.now(), []edge.StatsCounts{{Version: 1, Requests: 3, LatencyMS: []uint64{3}}})
	defer func(d time.Duration) { flushTimeout = d }(flushTimeout)
	flushTimeout = 200 * time.Millisecond

	_, stop := runServer(t, s)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// A client that stops sending its body, or keeps an idle connection open,
// doesn't hold an admin connection forever.
func TestSlowAndIdleClientsAreDisconnected(t *testing.T) {
	h := newHarness(t)
	defer func(r, i time.Duration) { readTimeout, idleTimeout = r, i }(readTimeout, idleTimeout)
	readTimeout, idleTimeout = 300*time.Millisecond, 300*time.Millisecond
	addr, stop := runServer(t, h.s)
	defer func() { _ = stop() }()
	closed := func(c net.Conn, r *bufio.Reader) bool {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := io.ReadAll(r)
		return err == nil // EOF: the server closed it; a timeout means it's still open
	}

	slow, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	_, _ = io.WriteString(slow, "POST /api/auth/login HTTP/1.1\r\nHost: admin\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"username\":")
	if !closed(slow, bufio.NewReader(slow)) {
		t.Fatal("stalled body kept the connection open")
	}

	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	_, _ = io.WriteString(idle, "GET /api/auth/me HTTP/1.1\r\nHost: admin\r\n\r\n")
	r := bufio.NewReader(idle)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil || resp.Close || strings.EqualFold(resp.Header.Get("Connection"), "close") {
		t.Fatalf("first response: close %v, %v", resp.Close, err)
	}
	if !closed(idle, r) {
		t.Fatal("idle keep-alive connection kept open")
	}
}

// One JSON value per body, bounded: oversized bodies get 413 and trailing
// data is refused rather than silently ignored.
func TestJSONBodyLimits(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	send := func(c *client, path, body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("POST", h.srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	status(t, send(e, "/v1/edge/report", `{"instance":"edge-a"} {"instance":"edge-b"}`), 400)
	status(t, send(e, "/v1/edge/report", `{"instance":"`+strings.Repeat("a", maxReport)+`"}`), 413)
	status(t, send(pub, "/api/tokens", `{"name":"x","kind":"edge"} junk`), 400)
	status(t, send(pub, "/api/tokens", `{"name":"`+strings.Repeat("a", maxBody)+`","kind":"edge"}`), 413)
}
