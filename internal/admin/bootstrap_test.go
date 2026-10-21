package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

// deployToken is an edge token as a deployment would generate it.
const deployToken = "0123456789abcdefghijklmnopqrstuvwxyzABCD"

// bootstrapEnv is a fresh-install admin: a migrated database and the
// first-start settings an automated install sets, with secrets in files.
func bootstrapEnv(t *testing.T) (map[string]string, testenv.DB) {
	t.Helper()
	db := testenv.Postgres(t)
	var out bytes.Buffer
	if code := Main(t.Context(), nil, []string{"migrate"}, env(map[string]string{"MIGRATION_DATABASE_URL": db.Owner, "DB_RUNTIME_ROLE": testenv.AppRole}), nil, &out); code != 0 {
		t.Fatalf("migrate: %s", out.String())
	}
	dir := t.TempDir()
	pw, token := filepath.Join(dir, "password"), filepath.Join(dir, "token")
	if err := os.WriteFile(pw, []byte(goodPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(deployToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := baseEnv(db.App)
	e["BOOTSTRAP_ADMIN_USERNAME"] = "Admin"
	e["BOOTSTRAP_ADMIN_PASSWORD_FILE"] = pw
	e["EDGE_SERVICE_TOKEN_FILE"] = token
	e["BOOTSTRAP_PUBLISH_DEFAULT"] = "true"
	return e, db
}

// serveOnce runs admin until check returns, then stops it cleanly.
func serveOnce(t *testing.T, e map[string]string, check func(base string)) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	e["LISTEN_ADDR"] = addr
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int)
	var logs bytes.Buffer
	go func() { done <- Main(ctx, nil, nil, env(e), nil, &logs) }()
	base := "http://" + addr
	for deadline := time.Now().Add(10 * time.Second); ; {
		if resp, err := http.Get(base + "/api/auth/me"); err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("admin did not start: %s", logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	check(base)
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("serve exit %d: %s", code, logs.String())
	}
}

func login(t *testing.T, base, username string) int {
	t.Helper()
	resp, err := http.Post(base+"/api/auth/login", "application/json", strings.NewReader(`{"username":"`+username+`","password":"`+goodPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func fetchSnapshot(t *testing.T, base, token string) (int, *snapshot.Envelope) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/v1/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var env snapshot.Envelope
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, &env
}

func count(t *testing.T, dsn, sql string) int {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }() //nolint:usetesting // closed after the test context ends
	var n int
	if err := conn.QueryRow(t.Context(), sql).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A fresh install with the first-start settings needs no manual step: the
// admin can sign in, and an edge holding the deployment's token gets the
// starter policy. Restarting changes nothing.
func TestBootstrapOnAFreshInstall(t *testing.T) {
	e, db := bootstrapEnv(t)
	for range 2 {
		serveOnce(t, e, func(base string) {
			if code := login(t, base, "admin"); code != http.StatusOK {
				t.Fatalf("bootstrap admin sign-in = %d", code)
			}
			code, env := fetchSnapshot(t, base, deployToken)
			if code != http.StatusOK || env.Active == nil || env.Active.Version != 1 {
				t.Fatalf("snapshot with the deployment token = %d, active %+v", code, env.Active)
			}
			if code, _ := fetchSnapshot(t, base, deployToken+"x"); code != http.StatusUnauthorized {
				t.Fatalf("snapshot with another token = %d, want 401", code)
			}
		})
	}
	if n := count(t, db.Owner, "SELECT count(*) FROM users"); n != 1 {
		t.Fatalf("users after two starts = %d, want 1", n)
	}
	if n := count(t, db.Owner, "SELECT count(*) FROM config_versions"); n != 1 {
		t.Fatalf("versions after two starts = %d, want 1", n)
	}
	if n := count(t, db.Owner, "SELECT count(*) FROM audit_events WHERE actor = 'bootstrap' AND action IN ('user.create', 'config.publish')"); n != 2 {
		t.Fatalf("bootstrap audit rows = %d, want user.create and config.publish", n)
	}
}

// Bootstrap never touches what an operator already made: an existing user
// keeps sole access, and an existing version stays active.
func TestBootstrapLeavesAnExistingInstallAlone(t *testing.T) {
	e, db := bootstrapEnv(t)
	var out bytes.Buffer
	if code := Main(t.Context(), nil, []string{"create-user", "root", "admin"}, env(e), strings.NewReader(goodPassword+"\n"), &out); code != 0 {
		t.Fatalf("create-user: %s", out.String())
	}
	e["BOOTSTRAP_PUBLISH_DEFAULT"] = "false"
	serveOnce(t, e, func(base string) {
		if code := login(t, base, "admin"); code != http.StatusUnauthorized {
			t.Fatalf("bootstrap admin sign-in on an install with users = %d, want 401", code)
		}
		if code, _ := fetchSnapshot(t, base, deployToken); code != http.StatusServiceUnavailable {
			t.Fatalf("snapshot with publish off = %d, want 503 nothing published", code)
		}
	})
	if n := count(t, db.Owner, "SELECT count(*) FROM users"); n != 1 {
		t.Fatalf("users = %d, want only root", n)
	}
}

// Every first-start misconfiguration stops admin with the variable named,
// rather than starting without the admin or edge access it was asked for.
func TestLoadConfigRejectsBootstrap(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good, weak, short := write("good", goodPassword+"\n"), write("weak", "short\n"), write("short", "abc\n")
	long := write("long", strings.Repeat("t", 40)+"\n")
	cases := []struct {
		name   string
		change map[string]string
		msg    string
	}{
		{"username without a password file", map[string]string{"BOOTSTRAP_ADMIN_USERNAME": "admin"}, "BOOTSTRAP_ADMIN_USERNAME"},
		{"password file without a username", map[string]string{"BOOTSTRAP_ADMIN_PASSWORD_FILE": good}, "BOOTSTRAP_ADMIN_USERNAME"},
		{"unreadable password file", map[string]string{"BOOTSTRAP_ADMIN_USERNAME": "admin", "BOOTSTRAP_ADMIN_PASSWORD_FILE": "/nonexistent/password"}, "BOOTSTRAP_ADMIN_PASSWORD_FILE: cannot read"},
		{"password the policy refuses", map[string]string{"BOOTSTRAP_ADMIN_USERNAME": "admin", "BOOTSTRAP_ADMIN_PASSWORD_FILE": weak}, "at least 15 characters"},
		{"unreadable edge token file", map[string]string{"EDGE_SERVICE_TOKEN_FILE": "/nonexistent/token"}, "EDGE_SERVICE_TOKEN_FILE: cannot read"},
		{"short edge token", map[string]string{"EDGE_SERVICE_TOKEN_FILE": short}, "at least 32 characters"},
		{"unreadable log shipper token file", map[string]string{"LOG_INGEST_TOKEN_FILE": "/nonexistent/token"}, "LOG_INGEST_TOKEN_FILE: cannot read"},
		{"short log shipper token", map[string]string{"LOG_INGEST_TOKEN_FILE": short}, "LOG_INGEST_TOKEN_FILE: must hold a token of at least 32 characters"},
		{"log shipper sharing the edge token", map[string]string{"EDGE_SERVICE_TOKEN_FILE": long, "LOG_INGEST_TOKEN_FILE": long}, "LOG_INGEST_TOKEN_FILE: must hold a different token"},
		{"publish flag that isn't a bool", map[string]string{"BOOTSTRAP_PUBLISH_DEFAULT": "yes"}, "BOOTSTRAP_PUBLISH_DEFAULT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := baseEnv("postgres://app@db/admin")
			maps.Copy(e, tc.change)
			if _, err := LoadConfig(env(e)); err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v, want %q", err, tc.msg)
			}
		})
	}
}
