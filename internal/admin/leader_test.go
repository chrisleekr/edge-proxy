package admin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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

	// Tampering shows in the verification result and is recorded.
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
