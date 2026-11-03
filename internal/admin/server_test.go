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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/edge"
)

// runServer runs s.Serve on fresh API and internal listeners until the
// returned stop is called.
func runServer(t *testing.T, s *Server) (addr, internal string, stop func() error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	in, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l, in) }()
	return l.Addr().String(), in.Addr().String(), func() error {
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
	addr, _, stop := runServer(t, h.s)
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

// When one of admin's listeners fails, admin stops the other server and
// still writes the stats it holds, instead of losing up to a minute of
// edge reports.
func TestListenerFailureStillFlushesStats(t *testing.T) {
	h, pub := published(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	in, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.s.Serve(t.Context(), l, in) }()
	addr := l.Addr().String()
	b, _ := json.Marshal(edge.StatsReport{Instance: "edge-a", ConfigSource: "admin", Versions: []edge.StatsCounts{{Version: 1, Requests: 7, LatencyMS: []uint64{7}}}})
	req, _ := http.NewRequest("POST", "http://"+addr+"/v1/edge/report", strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Bearer "+h.edgeToken(pub))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	status(t, resp, 200)

	_ = in.Close() // the internal server's accept loop fails
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve returned nil after a listener failed")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Serve kept running after a listener failed")
	}
	if c, err := net.Dial("tcp", addr); err == nil {
		_ = c.Close()
		t.Fatal("API address still accepts connections")
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

	_, _, stop := runServer(t, s)
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
	addr, _, stop := runServer(t, h.s)
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

// An audit row is dated by admin's clock, the one its change is stamped
// with, so it agrees with the version it describes.
func TestAuditRowTakesTheChangeTime(t *testing.T) {
	h := newHarness(t)
	h.advance(36 * time.Hour) // away from the wall clock
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	users := decode[[]struct {
		Created time.Time `json:"created_at"`
	}](t, pub.do("GET", "/api/users", nil))
	created := decode[[]struct {
		OccurredAt time.Time `json:"occurred_at"`
	}](t, pub.do("GET", "/api/audit?action=user.create", nil))
	if len(users) != 1 || len(created) != 1 || !users[0].Created.Equal(created[0].OccurredAt) || !created[0].OccurredAt.Equal(h.now().UTC().Truncate(time.Microsecond)) {
		t.Fatalf("user created at %+v, audited at %+v, clock %s", users, created, h.now())
	}
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v1"), 201)
	rows := decode[[]struct {
		Action     string    `json:"action"`
		OccurredAt time.Time `json:"occurred_at"`
	}](t, pub.do("GET", "/api/audit?action=config.publish", nil))
	versions := decode[[]struct {
		PublishedAt time.Time `json:"published_at"`
	}](t, pub.do("GET", "/api/versions", nil))
	if len(rows) != 1 || len(versions) != 1 || !rows[0].OccurredAt.Equal(versions[0].PublishedAt) || !rows[0].OccurredAt.Equal(h.now().UTC().Truncate(time.Microsecond)) {
		t.Fatalf("publish audited at %+v, version published at %+v, clock %s", rows, versions, h.now())
	}
}

// Admin serves its metrics on the internal address only, apart from the API
// and UI, so a scraper needs no session and the API never exposes them.
// Every fixed series is there from the start, at 0, so rate() sees the
// first event. A replica that isn't leading exports no fleet gauges. The
// internal address closes with the rest of admin.
func TestAdminMetricsEndpoint(t *testing.T) {
	h := newHarness(t)
	// Another replica leads.
	holder, err := pgx.Connect(t.Context(), h.s.cfg.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close(t.Context()) }()
	if _, err := holder.Exec(t.Context(), "SELECT pg_advisory_lock($1)", leaderLock); err != nil {
		t.Fatal(err)
	}
	addr, internal, stop := runServer(t, h.s)

	resp, err := http.Get("http://" + internal + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/plain; version=0.0.4" {
		t.Fatalf("internal /metrics: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	text := body(resp)
	for _, want := range []string{
		"admin_leader 0",
		`admin_publishes_total{source="manual"} 0`, `admin_publishes_total{source="revert"} 0`,
		`admin_publishes_total{source="guard_rollback"} 0`, `admin_publishes_total{source="import"} 0`,
		`admin_guard_actions_total{action="rollback"} 0`, `admin_guard_actions_total{action="canary_abort"} 0`, `admin_guard_actions_total{action="alert"} 0`,
		`admin_notifications_total{result="sent"} 0`, `admin_notifications_total{result="failed"} 0`,
		`admin_edge_reports_total{result="accepted"} 0`, `admin_edge_reports_total{result="invalid"} 0`, `admin_edge_reports_total{result="error"} 0`,
		`admin_log_lines_total{result="accepted"} 0`, `admin_log_lines_total{result="rejected"} 0`,
		"admin_log_batches_busy_total 0",
		`admin_background_job_failures_total{job="jwks"} 0`, `admin_background_job_failures_total{job="verified_bots"} 0`, `admin_background_job_failures_total{job="audit"} 0`,
		`admin_background_job_failures_total{job="audit_full"} 0`, `admin_background_job_failures_total{job="guard"} 0`, `admin_background_job_failures_total{job="notifications"} 0`,
		`admin_background_job_failures_total{job="retention"} 0`,
		"admin_audit_verify_failures_total 0",
		"admin_trace_export_errors_total 0",
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("metrics missing %q", want)
		}
	}
	for _, leaderOnly := range []string{"admin_edges_live", "admin_anomalies_firing"} {
		if strings.Contains(text, leaderOnly) {
			t.Errorf("a replica not leading exports %s", leaderOnly)
		}
	}

	resp, err = http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	if text := body(resp); strings.Contains(text, "admin_leader") {
		t.Fatal("the API address serves the metrics")
	}

	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if c, err := net.Dial("tcp", internal); err == nil {
		_ = c.Close()
		t.Fatal("internal address still accepts connections after shutdown")
	}
}
