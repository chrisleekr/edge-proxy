package admin

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

func TestLoadConfig(t *testing.T) {
	block := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(block, []byte("Password123456789\n\n  hunter2hunter2hunter2  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := baseEnv("postgres://app@db/admin")
	// A trailing comma, as list variables allow everywhere else.
	e["AUDIT_HMAC_PREVIOUS_KEYS"] = "k0=" + testAuditKey + ","
	e["PASSWORD_BLOCKLIST_PATH"] = block
	e["SESSION_IDLE_TIMEOUT"] = "10m"
	e["JWKS_ALLOWED_HOSTS"] = "idp.internal, other.internal"
	e["ADMIN_TRUSTED_PROXIES"] = "10.0.0.5, 10.1.0.0/16"
	delete(e, "ADMIN_INTERNAL_ADDR")
	c, err := LoadConfig(env(e))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8081" || c.InternalAddr != ":9091" || c.SessionIdle != 10*time.Minute || c.SessionMaxAge != 12*time.Hour ||
		!c.Blocklist["password123456789"] || !c.Blocklist["hunter2hunter2hunter2"] || len(c.Blocklist) != 2 ||
		strings.Join(c.Audit.Order, ",") != "k0,k1" || c.Audit.Current != "k1" || len(c.JWKSAllowedHosts) != 2 || len(c.Deployment.ViewerFields) == 0 ||
		len(c.TrustedProxies) != 2 || c.TrustedProxies[0] != netip.MustParsePrefix("10.0.0.5/32") {
		t.Fatalf("config %+v", c)
	}
}

// crawlerSources is a VERIFIED_BOT_SOURCES value listing n distinct URLs.
func crawlerSources(n int) string {
	urls := make([]string, n)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://bots.example.com/%d.json", i)
	}
	return strings.Join(urls, ",")
}

func TestLoadConfigRejects(t *testing.T) {
	cases := []struct {
		name   string
		change map[string]string
		msg    string
	}{
		{"no database", map[string]string{"DATABASE_URL": ""}, "DATABASE_URL"},
		{"no audit key id", map[string]string{"AUDIT_HMAC_KEY_ID": ""}, "AUDIT_HMAC_KEY_ID"},
		{"short audit key", map[string]string{"AUDIT_HMAC_KEY": "c2hvcnQ="}, "at least 32 bytes"},
		{"previous key without id", map[string]string{"AUDIT_HMAC_PREVIOUS_KEYS": "=" + testAuditKey}, "AUDIT_HMAC_KEY"},
		{"missing blocklist", map[string]string{"PASSWORD_BLOCKLIST_PATH": "/nonexistent/blocklist"}, "PASSWORD_BLOCKLIST_PATH"},
		{"bad session timeout", map[string]string{"SESSION_MAX_AGE": "12"}, "SESSION_MAX_AGE"},
		{"admin proxy that isn't an IP", map[string]string{"ADMIN_TRUSTED_PROXIES": "proxy.internal"}, `"proxy.internal" is not an IP or CIDR`},
		{"edge deployment invalid", map[string]string{"CLIENT_IP_SOURCE": "akamai"}, "CLIENT_IP_SOURCE"},
		{"crawler source over plain http", map[string]string{"VERIFIED_BOT_SOURCES": "http://bots.example.com/googlebot.json"}, "VERIFIED_BOT_SOURCES"},
		{"crawler source with a query", map[string]string{"VERIFIED_BOT_SOURCES": "https://bots.example.com/googlebot.json?key=secret"}, "VERIFIED_BOT_SOURCES"},
		{"crawler source with credentials", map[string]string{"VERIFIED_BOT_SOURCES": "https://user:pass@bots.example.com/googlebot.json"}, "VERIFIED_BOT_SOURCES"},
		{"crawler source with a fragment", map[string]string{"VERIFIED_BOT_SOURCES": "https://bots.example.com/googlebot.json#v1"}, "VERIFIED_BOT_SOURCES"},
		{"crawler source twice", map[string]string{"VERIFIED_BOT_SOURCES": "https://bots.example.com/a.json,https://bots.example.com/a.json"}, "VERIFIED_BOT_SOURCES"},
		{"more crawler sources than allowed", map[string]string{"VERIFIED_BOT_SOURCES": crawlerSources(snapshot.MaxBotSources + 1)}, "at most 16 are allowed"},
		{"log search URL that is not http", map[string]string{"LOG_SEARCH_URL": "javascript:alert(1)//{status}"}, "LOG_SEARCH_URL"},
		{"log search URL with credentials", map[string]string{"LOG_SEARCH_URL": "https://user:pass@logs.example.com/search?q={status}"}, "LOG_SEARCH_URL"},
		{"crawler source URL over the length limit", map[string]string{"VERIFIED_BOT_SOURCES": "https://bots.example.com/" + strings.Repeat("a", snapshot.MaxBotSourceLen)}, "at most 2048 characters"},
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

// The autopilot runner's token comes from a file, like the edge and log
// shipper tokens. It must differ from both: those are checked first, so a
// shared token would leave the runner with another deployment's access.
func TestLoadConfigAutopilotToken(t *testing.T) {
	dir := t.TempDir()
	file := func(name, token string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	runner := file("runner", "autopilot-token-0123456789abcdefghijklmnop")
	edgeTok := file("edge", "edge-token-0123456789abcdefghijklmnopqrst")
	shipper := file("shipper", "shipper-token-0123456789abcdefghijklmnop")
	sameAsEdge := file("same-as-edge", "edge-token-0123456789abcdefghijklmnopqrst")
	sameAsShipper := file("same-as-shipper", "shipper-token-0123456789abcdefghijklmnop")
	short := file("short", "too-short")
	cases := []struct {
		name   string
		runner string
		msg    string // "" means the config loads
	}{
		{"a token of its own loads", runner, ""},
		{"a token equal to the edge token is refused", sameAsEdge, "AUTOPILOT_TOKEN_FILE: must hold a different token from EDGE_SERVICE_TOKEN_FILE"},
		{"a token equal to the log shipper's token is refused", sameAsShipper, "AUTOPILOT_TOKEN_FILE: must hold a different token from LOG_INGEST_TOKEN_FILE"},
		{"a short token is refused", short, "AUTOPILOT_TOKEN_FILE: must hold a token of at least 32 characters"},
		{"a missing file is refused", filepath.Join(dir, "missing"), "AUTOPILOT_TOKEN_FILE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := baseEnv("postgres://app@db/admin")
			e["EDGE_SERVICE_TOKEN_FILE"], e["LOG_INGEST_TOKEN_FILE"], e["AUTOPILOT_TOKEN_FILE"] = edgeTok, shipper, tc.runner
			_, err := LoadConfig(env(e))
			if tc.msg == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v, want %q", err, tc.msg)
			}
		})
	}
}

// The first admin comes from the CLI: migrate, create, sign in.
func TestBootstrapFromTheCLI(t *testing.T) {
	db := testenv.Postgres(t)
	ctx := t.Context()
	var out bytes.Buffer
	if code := Main(ctx, nil, []string{"migrate"}, env(map[string]string{"MIGRATION_DATABASE_URL": db.Owner, "DB_RUNTIME_ROLE": testenv.AppRole}), nil, &out); code != 0 {
		t.Fatalf("migrate: %s", out.String())
	}
	e := baseEnv(db.App)
	out.Reset()
	if code := Main(ctx, nil, []string{"create-user", "Root", "admin"}, env(e), strings.NewReader(goodPassword+"\n"), &out); code != 0 || !strings.Contains(out.String(), "created user Root") {
		t.Fatalf("create-user: %s", out.String())
	}
	// serve until canceled
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	e["LISTEN_ADDR"] = addr
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan int)
	go func() { done <- Main(sctx, nil, nil, env(e), nil, &bytes.Buffer{}) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Post("http://"+addr+"/api/auth/login", "application/json", strings.NewReader(`{"username":"root","password":"`+goodPassword+`"}`))
		if err == nil {
			if resp.StatusCode != 200 {
				t.Fatalf("login status %d", resp.StatusCode)
			}
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("serve exit %d", code)
	}
}

func TestMainRejects(t *testing.T) {
	db := testenv.Postgres(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	busyInternal := baseEnv(db.App)
	busyInternal["LISTEN_ADDR"], busyInternal["ADMIN_INTERNAL_ADDR"] = "127.0.0.1:0", busy.Addr().String()
	cases := []struct {
		name  string
		args  []string
		env   map[string]string
		stdin string
		msg   string
	}{
		{"unknown command", []string{"frobnicate"}, nil, "", "unknown command"},
		{"migrate without the owner URL", []string{"migrate"}, nil, "", "MIGRATION_DATABASE_URL"},
		{"migrate with a bad URL keeps the password out", []string{"migrate"}, map[string]string{"MIGRATION_DATABASE_URL": "postgres://u:s3cret@[bad/db", "DB_RUNTIME_ROLE": "app"}, "", "invalid connection string"},
		{"create-user without a role", []string{"create-user", "root"}, baseEnv(db.App), "", "usage"},
		{"create-user with a short password names the reason", []string{"create-user", "root", "admin"}, baseEnv(db.App), "kq7vzm2xwp\n", "Invalid user: password: password must be at least 15 characters"},
		{"create-user without config", []string{"create-user", "root", "admin"}, nil, "", "DATABASE_URL"},
		{"serve without config", nil, nil, "", "DATABASE_URL"},
		{"serve with a bad database URL", nil, baseEnv("postgres://u:s3cret@[bad/db"), "", "invalid connection string"},
		{"create-user with a bad database URL", []string{"create-user", "root", "admin"}, baseEnv("postgres://u:s3cret@[bad/db"), goodPassword + "\n", "invalid connection string"},
		{"serve with the internal address taken", nil, busyInternal, "", "address already in use"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := Main(t.Context(), nil, tc.args, env(tc.env), strings.NewReader(tc.stdin), &out); code != 1 || !strings.Contains(out.String(), tc.msg) || strings.Contains(out.String(), "s3cret") {
				t.Fatalf("exit %d: %s", code, out.String())
			}
		})
	}
}
