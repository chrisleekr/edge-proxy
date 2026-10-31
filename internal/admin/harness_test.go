package admin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/jwks"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
	"github.com/chrisleekr/edge-proxy/internal/tracing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var testAuditKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// baseEnv is a valid admin deployment.
func baseEnv(dsn string) map[string]string {
	return map[string]string{
		"DATABASE_URL": dsn, "AUDIT_HMAC_KEY_ID": "k1", "AUDIT_HMAC_KEY": testAuditKey,
		"CLIENT_IP_SOURCE": "cloudfront",
	}
}

// harness is admin over TLS against a fresh, migrated database, with a
// controllable clock.
type harness struct {
	t     *testing.T
	s     *Server
	srv   *httptest.Server
	db    *pgxpool.Pool
	owner *pgx.Conn
	logs  bytes.Buffer
	mu    sync.Mutex
	clock time.Time
	// statsSeq names the replica of each test stats row.
	statsSeq int
}

func newHarness(t *testing.T) *harness { t.Helper(); return newHarnessWith(t, nil) }

// newHarnessWith adds deployment variables to the base environment, such
// as the tracing ones, and wires tracing into the server and its pool as
// serve does. Edge routes share that pool here; serve gives them their own.
func newHarnessWith(t *testing.T, set map[string]string) *harness {
	t.Helper()
	db := testenv.Postgres(t)
	ctx := t.Context()
	owner, err := pgx.Connect(ctx, db.Owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) }) //nolint:usetesting // t.Context is already cancelled when Cleanup runs
	if err := admindb.Migrate(ctx, owner, testenv.AppRole); err != nil {
		t.Fatal(err)
	}
	e := baseEnv(db.App)
	maps.Copy(e, set)
	cfg, err := LoadConfig(env(e))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, owner: owner, clock: time.Now()}
	log := slog.New(slog.NewJSONHandler(&h.logs, nil))
	tp, err := tracing.New(cfg.Tracing, cfg.Replica, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) }) //nolint:usetesting // t.Context is already cancelled when Cleanup runs
	pool, err := openPool(ctx, db.App, tp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h.db = pool
	h.s = NewServer(cfg, pool, log)
	h.s.tracing = tp
	h.s.now = h.now
	h.srv = httptest.NewTLSServer(h.s.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) now() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.clock
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.clock = h.clock.Add(d)
	h.mu.Unlock()
}

const goodPassword = "correct horse battery staple"

// user creates a user the way the CLI bootstraps one.
func (h *harness) user(name string, roles ...string) string {
	h.t.Helper()
	id, err := CreateUser(context.Background(), h.db, h.s.cfg, h.now, "cli", name, name+"@example.com", goodPassword, roles)
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

// client is one browser with its own cookie jar.
type client struct {
	h     *harness
	c     *http.Client
	token string // sent as a bearer token when set
}

func (h *harness) client() *client {
	jar, _ := cookiejar.New(nil)
	c := *h.srv.Client() // a copy: Client() returns one shared client
	c.Jar = jar
	return &client{h: h, c: &c}
}

// signedIn is a client logged in as name.
func (h *harness) signedIn(name string) *client {
	h.t.Helper()
	c := h.client()
	if resp := c.do("POST", "/api/auth/login", map[string]string{"username": name, "password": goodPassword}); resp.StatusCode != 200 {
		h.t.Fatalf("login %s: %d %s", name, resp.StatusCode, body(resp))
	}
	return c
}

func (c *client) do(method, path string, in any, headers ...string) *http.Response {
	c.h.t.Helper()
	var r io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.h.srv.URL+path, r)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	return resp
}

func body(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func status(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("status %d, want %d: %s", resp.StatusCode, want, body(resp))
	}
	_ = resp.Body.Close()
}

// actions lists audit actions in order, and checks the chain verifies.
func (h *harness) actions() []string {
	h.t.Helper()
	ctx := context.Background()
	if _, _, err := admindb.VerifyAudit(ctx, h.db, h.s.cfg.Audit, 0, nil); err != nil {
		h.t.Fatal(err)
	}
	rows, _ := h.db.Query(ctx, "SELECT action || ' ' || target FROM audit_events ORDER BY seq")
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

// published is a harness with version 1 active and a publisher signed in.
func published(t *testing.T) (*harness, *client) {
	t.Helper()
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v1"), 201)
	return h, pub
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 10s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func newFakeJWKS(t *testing.T, h *harness) *fakeJWKS {
	t.Helper()
	f := &fakeJWKS{}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	f.body = testenv.JWKS(testenv.JWK("k1", pub, nil))
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		if f.body == nil {
			http.Error(w, "down", 500)
			return
		}
		_, _ = w.Write(f.body)
	}))
	t.Cleanup(f.srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(f.srv.Certificate())
	h.s.jwks = jwks.NewClient([]string{"127.0.0.1"}, 2*time.Second, roots)
	return f
}

func authConfig(url string) *snapshot.Config {
	c := testConfig()
	c.Auth = snapshot.Auth{Issuers: []snapshot.Issuer{{ID: "corp", Issuer: "https://auth.example.com/", Audiences: []string{"api"}, JWKSURL: url, Algorithm: "EdDSA"}}, DefaultAccepted: []string{"corp"}}
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "orders", Expression: mustParse(`starts_with(http.request.uri.path, "/orders")`), Settings: snapshot.Settings{Auth: &snapshot.AuthSetting{Mode: "required"}}})
	return c
}

func mustParse(src string) expr.Node {
	n, err := expr.Parse(src)
	if err != nil {
		panic(err)
	}
	return n
}

// testConfig is small and valid: JSON templates for every kind, a shorter
// upstream timeout under /admin/, and one login limit.
func testConfig() *snapshot.Config {
	responses := map[string]snapshot.Response{}
	defaults := map[string]string{}
	for k, st := range map[string]int{"bad_request": 400, "unauthorized": 401, "payload_too_large": 413, "rate_limited": 429, "bad_gateway": 502, "unavailable": 503, "overloaded": 503, "gateway_timeout": 504, "forbidden": 403} {
		responses[k] = snapshot.Response{Status: st, ContentType: "application/json", Body: `{"error":"` + k + `"}`}
		defaults[k] = k
	}
	return &snapshot.Config{
		Schema: snapshot.SupportedSchema,
		Global: snapshot.Global{
			Backstop:       snapshot.Backstop{Limit: 100, Period: snapshot.Duration(time.Second), Burst: 100, MaxEntries: 1000},
			Defaults:       snapshot.Defaults{BodyLimit: 1024, BodyReadTimeout: snapshot.Duration(time.Second), UpstreamTimeout: snapshot.Duration(2 * time.Second), Responses: defaults},
			Responses:      responses,
			RequestHeaders: snapshot.RequestHeaders{Forward: snapshot.Forward{Mode: "all"}},
		},
		ConfigRules: []snapshot.ConfigRule{
			{ID: "admin-route", Expression: mustParse(`starts_with(http.request.uri.path, "/admin/")`), Settings: snapshot.Settings{UpstreamTimeout: new(snapshot.Duration(time.Second))}},
		},
		RateLimitRules: []snapshot.RateLimitRule{
			{ID: "login", Expression: mustParse(`http.request.uri.path eq "/login"`), Algorithm: "sliding_window", Limit: 10, Period: snapshot.Duration(time.Minute),
				Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"},
		},
	}
}

// adminTest checks that /admin/ gets the shorter upstream timeout.
var adminTest = ConfigTest{Name: "admin is routed", Request: TestRequest{Host: "api.example.com", Path: "/%61dmin/users"},
	Expect: TestExpect{ConfigRules: &[]string{"admin-route"}, Settings: map[string]any{"upstream_timeout": "1s"}}}

func clone(c *snapshot.Config) *snapshot.Config {
	b, _ := json.Marshal(c)
	var out snapshot.Config
	_ = json.Unmarshal(b, &out)
	return &out
}

// fakeJWKS serves an Ed25519 JWKS over TLS and counts fetches.
type fakeJWKS struct {
	srv  *httptest.Server
	mu   sync.Mutex
	body []byte
	hits int
}

func (h *harness) edgeToken(pub *client) string {
	h.t.Helper()
	return decode[map[string]string](h.t, pub.do("POST", "/api/tokens", map[string]any{"name": "edges", "kind": "edge"}))["token"]
}

// putStats records one version's traffic for the minutes before now.
func (h *harness) putStats(version int64, minutes int, requests, edge5xx, upstream5xx int64, latency []int64, rules string, top string) {
	h.t.Helper()
	now := h.now().UTC().Truncate(time.Minute)
	for i := 1; i <= minutes; i++ {
		h.statsSeq++ // a replica name per write, so repeated minutes don't collide
		_, err := h.db.Exec(context.Background(), `INSERT INTO edge_stats_minute (minute, version, replica, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited)
			VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, $9)`, now.Add(time.Duration(-i)*time.Minute), version, fmt.Sprint("r", h.statsSeq), requests, edge5xx, upstream5xx, latency, rules, top)
		if err != nil {
			h.t.Fatal(err)
		}
	}
}

// save writes the draft at revision rev and returns the response.
func (c *client) save(rev string, cfg *snapshot.Config, tests ...ConfigTest) *http.Response {
	c.h.t.Helper()
	if tests == nil {
		tests = []ConfigTest{}
	}
	return c.do("PUT", "/api/draft", map[string]any{"config": cfg, "tests": tests}, "If-Match", rev)
}

// publishDraft publishes the current draft.
func (c *client) publishDraft(msg string, extra ...string) *http.Response {
	c.h.t.Helper()
	d := decode[struct{ Revision int64 }](c.h.t, c.do("GET", "/api/draft", nil))
	in := map[string]string{"message": msg}
	for i := 0; i+1 < len(extra); i += 2 {
		in[extra[i]] = extra[i+1]
	}
	return c.do("POST", "/api/publish", in, "If-Match", etag(d.Revision))
}

func (c *client) revision() string {
	c.h.t.Helper()
	return etag(decode[struct{ Revision int64 }](c.h.t, c.do("GET", "/api/draft", nil)).Revision)
}
