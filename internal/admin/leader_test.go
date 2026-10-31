package admin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

// When Postgres can't say whether an issuer has keys, the save says so
// instead of passing silently as if the keys were there.
func TestKeyCheckFailureIsAWarning(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // every query fails, as with Postgres unreachable
	warns := h.s.fetchNewKeys(ctx, authConfig("https://idp.example.com/jwks"))
	if len(warns) != 1 || !strings.Contains(warns[0].Msg, "keys could not be checked") {
		t.Fatalf("warnings %+v", warns)
	}
}

func TestJWKSFetch(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	idp := newFakeJWKS(t, h)
	// Saving an issuer fetches its keys at once, so publish isn't blocked.
	resp := pub.save(`"0"`, authConfig(idp.srv.URL+"/jwks"))
	if w := decode[struct{ Warnings []any }](t, resp); len(w.Warnings) != 0 {
		t.Fatalf("warnings %v", w.Warnings)
	}
	status(t, pub.publishDraft("protect orders"), 201)
	e := h.client()
	e.token = h.edgeToken(pub)
	resp = e.do("GET", "/v1/snapshot", nil)
	tag := resp.Header.Get("ETag")
	env := decode[snapshot.Envelope](t, resp)
	if len(env.Keys) != 1 || env.Keys[0].IssuerID != "corp" || env.Keys[0].JWKSURL != idp.srv.URL+"/jwks" || string(env.Keys[0].JWKS) != string(idp.body) {
		t.Fatalf("keys %+v", env.Keys)
	}
	// Unchanged keys aren't rewritten; changed keys are, and audited.
	if err := h.s.refreshKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	idp.mu.Lock()
	idp.body = testenv.JWKS(testenv.JWK("k2", pub2, nil))
	idp.mu.Unlock()
	if err := h.s.refreshKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range h.actions() {
		if a == "jwks.keys_changed corp" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d key changes audited", n)
	}
	// New keys are a new snapshot, even fetched at the same instant.
	status(t, e.do("GET", "/v1/snapshot", nil, "If-None-Match", tag), 200)
	// The IdP going down keeps the last good keys.
	idp.mu.Lock()
	idp.body = nil
	idp.mu.Unlock()
	if err := h.s.refreshKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if env := decode[snapshot.Envelope](t, e.do("GET", "/v1/snapshot", nil)); !strings.Contains(string(env.Keys[0].JWKS), `"kid":"k2"`) {
		t.Fatal("keys lost while the IdP was down")
	}
	// An unreachable JWKS URL is a warning at save.
	resp = pub.save(pub.revision(), authConfig("https://127.0.0.1:1/jwks"))
	if w := decode[struct{ Warnings []struct{ Path string } }](t, resp); len(w.Warnings) != 1 || w.Warnings[0].Path != "config.auth.issuers[0].jwks_url" {
		t.Fatalf("warnings %+v", w.Warnings)
	}
}

// Only one admin replica runs background jobs.
func TestLeaderLock(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	idp := newFakeJWKS(t, h)
	status(t, pub.save(`"0"`, authConfig(idp.srv.URL+"/jwks")), 200)
	idp.mu.Lock()
	before := idp.hits
	idp.mu.Unlock()

	ctx := t.Context()
	holder, err := pgx.Connect(ctx, h.s.cfg.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", leaderLock); err != nil {
		t.Fatal(err)
	}
	if err := h.s.leadOnce(ctx, h.s.cfg.DatabaseURL); err != nil {
		t.Fatal(err)
	}
	idp.mu.Lock()
	if idp.hits != before {
		t.Fatal("ran jobs without the lock")
	}
	idp.mu.Unlock()
	_ = holder.Close(ctx)
	waitFor(t, func() bool { return leaderLockFree(t, h) })

	logs := leaderLogs(h)
	jobs, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- h.s.leadOnce(jobs, h.s.cfg.DatabaseURL) }()
	// The anchor is logged after the JWKS refresh, so seeing it means both
	// startup jobs ran.
	waitFor(t, func() bool { return logs.count(`"msg":"audit anchor"`) == 1 })
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if idp.hits == before {
		t.Fatal("leader did not refresh keys")
	}
}

func TestAuditEndpoints(t *testing.T) {
	h, pub := published(t)
	list := decode[[]struct {
		Seq     int64
		Action  string
		Details map[string]any
		HMAC    string
	}](t, pub.do("GET", "/api/audit?action=config.publish", nil))
	if len(list) != 1 || list[0].Details["version"] != 1.0 || list[0].HMAC != "" {
		t.Fatalf("audit %+v", list)
	}
	if v := decode[map[string]any](t, pub.do("POST", "/api/audit/verify", nil)); v["ok"] != true {
		t.Fatalf("verify %v", v)
	}
	exp := decode[[]struct{ HMAC string }](t, pub.do("POST", "/api/audit/export", nil))
	if len(exp) == 0 || len(exp[0].HMAC) != 64 {
		t.Fatalf("export %+v", exp)
	}
	// Verify and export write an audit row, so a cross-site link (a GET,
	// which cross-origin protection allows) must not trigger them.
	status(t, pub.do("GET", "/api/audit/verify", nil), 405)
	status(t, pub.do("GET", "/api/audit/export", nil), 405)
	status(t, pub.do("GET", "/api/audit?before=x", nil), 400)
	h.user("vera", "viewer")
	status(t, h.signedIn("vera").do("GET", "/api/audit", nil), 200)

	h.wantMetrics("admin_audit_verify_failures_total 0")

	// Tampering shows in the verification result, is recorded and counted.
	for _, q := range []string{"ALTER TABLE audit_events DISABLE TRIGGER USER", "UPDATE audit_events SET target = 'x' WHERE seq = 2"} {
		if _, err := h.owner.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	if v := decode[map[string]any](t, pub.do("POST", "/api/audit/verify", nil)); v["ok"] != false || v["broken_at"] != 2.0 {
		t.Fatalf("verify %v", v)
	}
	if err := h.s.fullAuditVerify(t.Context()); err == nil || !strings.Contains(h.logs.String(), "audit chain broken") {
		t.Fatalf("full verify: %v", err)
	}
	h.wantMetrics("admin_audit_verify_failures_total 2")

	// A leader verifies the chain on start, and counts the break as a failed
	// job. jwks and verified_bots fail only on Postgres errors, and retention
	// and audit_full run on a daily ticker, so they are not driven here.
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.s.leadOnce(ctx, h.s.cfg.DatabaseURL) }()
	waitFor(t, func() bool {
		return strings.Contains(h.metrics(), `admin_background_job_failures_total{job="audit"} 1`+"\n")
	})
	h.wantMetrics(`admin_background_job_failures_total{job="audit_full"} 0`)
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The activity page reads the audit log over a time range, filtered to a
// category of actions, such as every release.
func TestAuditFiltersBySinceAndActions(t *testing.T) {
	h, pub := published(t) // version 1, published now
	// Inside the session's idle timeout, so the publisher stays signed in.
	h.advance(10 * time.Minute)
	since := h.now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	c := testConfig()
	c.RateLimitRules[0].Limit = 5
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	status(t, pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "v2 too tight"}), 201)
	type event struct{ Action, Target string }
	list := func(query string) []string {
		t.Helper()
		var out []string
		for _, e := range decode[[]event](t, pub.do("GET", "/api/audit?"+query, nil)) {
			out = append(out, e.Action+" "+e.Target)
		}
		return out
	}
	for _, tc := range []struct {
		name, query string
		want        []string
	}{
		{"one action lists every event of it", "action=config.publish", []string{"config.publish version 2", "config.publish version 1"}},
		{"a list of actions lists events of any of them", "action=config.publish,config.revert", []string{"config.revert version 3", "config.publish version 2", "config.publish version 1"}},
		{"since leaves out events before it", "since=" + since + "&action=config.publish", []string{"config.publish version 2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := list(tc.query); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("since that is not a time is refused", func(t *testing.T) {
		status(t, pub.do("GET", "/api/audit?since=yesterday", nil), 400)
	})
	t.Run("a list of 51 actions is refused", func(t *testing.T) {
		actions := slices.Repeat([]string{"config.publish"}, 51)
		status(t, pub.do("GET", "/api/audit?action="+strings.Join(actions, ","), nil), 400)
	})
}

// Stepping down closes the lock connection only after the ping loop has
// stopped using it: a pgx.Conn is not safe for concurrent use.
func TestLeaderStepDownWaitsForPing(t *testing.T) {
	h := newHarness(t)
	logs := leaderLogs(h)
	defer func(d time.Duration) { leaderPing = d }(leaderPing)
	leaderPing = time.Millisecond
	for i := range 20 {
		waitFor(t, func() bool { return leaderLockFree(t, h) })
		// Cancel only once leading: a deadline would also cover connecting
		// and authenticating, which can take longer than the run itself.
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- h.s.leadOnce(ctx, h.s.cfg.DatabaseURL) }()
		// The startup jobs run while the 1ms ping loop is active.
		waitFor(t, func() bool { return logs.count(`"msg":"audit anchor"`) == i+1 })
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// leaderLockFree reports whether Postgres has released this test
// database's leader lock. A closed session's lock is released only when
// its backend exits, which is shortly after Close returns, so a replica
// trying at once can lose. Advisory locks are per database and tests share
// one container, so the check ignores leaders in other tests' databases.
func leaderLockFree(t *testing.T, h *harness) bool {
	t.Helper()
	var free bool
	if err := h.owner.QueryRow(t.Context(), `SELECT NOT EXISTS (
		SELECT 1 FROM pg_locks
		WHERE locktype = 'advisory' AND objid = $1
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database()))`, leaderLock).Scan(&free); err != nil {
		t.Fatal(err)
	}
	return free
}

// leaderLogs points the server's logger at a buffer that is safe to read
// while the leader goroutines write to it.
func leaderLogs(h *harness) *syncBuffer {
	b := &syncBuffer{}
	h.s.log = slog.New(slog.NewJSONHandler(b, nil))
	return b
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.b.String(), sub)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Every replica exports whether it leads. Only the leader exports the live
// edge count and firing anomalies by signal, from what its last
// notification check read, so a scrape never queries Postgres and replicas
// don't each report the same fleet. Stepping down takes them away.
func TestLeaderMetrics(t *testing.T) {
	h, pub, _ := notifyHarness(t)
	h.put(65, 6, minute{requests: 1000})
	h.put(5, 1, minute{requests: 1000, upstream5xx: 200})
	h.check()
	h.advance(time.Minute)
	h.put(1, 1, minute{requests: 1000, upstream5xx: 200})
	h.check()
	if a := h.anomalies(pub); len(a) != 1 || a[0].State != "firing" {
		t.Fatalf("anomalies %+v, want one firing", a)
	}
	notLeading := func(when string) {
		t.Helper()
		m := h.metrics()
		if !strings.Contains(m, "admin_leader 0\n") || strings.Contains(m, "admin_edges_live") || strings.Contains(m, "admin_anomalies_firing") {
			t.Fatalf("%s:\n%s", when, m)
		}
	}
	notLeading("not leading, after a notification check")

	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.s.leadOnce(ctx, h.s.cfg.DatabaseURL) }()
	waitFor(t, func() bool { return strings.Contains(h.metrics(), "admin_leader 1\n") })
	e := h.client()
	e.token = h.edgeToken(pub)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-a", ConfigSource: "admin"}), 200)
	h.check()
	m := h.metrics()
	if !strings.Contains(m, "admin_edges_live 1\n") {
		t.Errorf("leader metrics missing admin_edges_live 1:\n%s", m)
	}
	for _, signal := range notifyNames {
		n := 0
		if signal == "upstream_5xx_ratio" {
			n = 1
		}
		if want := fmt.Sprintf("admin_anomalies_firing{signal=%q} %d\n", signal, n); !strings.Contains(m, want) {
			t.Errorf("leader metrics missing %q", want)
		}
	}

	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	notLeading("after stepping down")
}

// When the leader's notification check fails, the fleet gauges it exports
// disappear instead of showing the last good numbers as current, and the
// failure is counted. Here the runtime role has lost its grant on settings,
// so the check can't read the notification settings.
func TestFailedNotificationCheckHidesLeaderGauges(t *testing.T) {
	h := newHarness(t)
	defer func(d time.Duration) { notifyEvery = d }(notifyEvery)
	notifyEvery = 20 * time.Millisecond
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.s.leadOnce(ctx, h.s.cfg.DatabaseURL) }()
	waitFor(t, func() bool { return strings.Contains(h.metrics(), "admin_edges_live 0\n") })

	if _, err := h.owner.Exec(t.Context(), "REVOKE SELECT ON settings FROM "+testenv.AppRole); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		return !strings.Contains(h.metrics(), `admin_background_job_failures_total{job="notifications"} 0`+"\n")
	})
	m := h.metrics()
	if strings.Contains(m, "admin_edges_live") || strings.Contains(m, "admin_anomalies_firing") || !strings.Contains(m, "admin_leader 1\n") {
		t.Fatalf("after a failed check:\n%s", m)
	}
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
