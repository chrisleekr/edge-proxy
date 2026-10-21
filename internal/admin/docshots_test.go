package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

// shotTime is the moment every docs screenshot shows. A fixed clock and
// fixed data make the pages render the same on every run.
var shotTime = time.Date(2026, 3, 2, 9, 30, 0, 0, time.UTC)

// TestDocScreenshots renders the pages shown in the docs and compares them
// with docs/assets/screenshots, so a UI change that alters one fails until
// the images are regenerated. The browser runs in a pinned Docker image so
// the pixels don't depend on the host. DOC_SCREENSHOTS=1 compares and
// DOC_SCREENSHOTS=update rewrites (scripts/ci/screenshots.sh).
func TestDocScreenshots(t *testing.T) {
	mode := os.Getenv("DOC_SCREENSHOTS")
	if mode == "" {
		t.Skip("set DOC_SCREENSHOTS=1 after building web/admin")
	}
	var pkg struct {
		DevDependencies map[string]string `json:"devDependencies"`
	}
	b, err := os.ReadFile("../../web/admin/package.json")
	if err == nil {
		err = json.Unmarshal(b, &pkg)
	}
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	if v := pkg.DevDependencies["@playwright/test"]; v != testenv.PlaywrightVersion {
		t.Fatalf("@playwright/test is %s but testenv.PlaywrightVersion is %s; set them equal", v, testenv.PlaywrightVersion)
	}
	ui := os.DirFS("../../web/admin/dist/app")
	if _, err := fs.Stat(ui, "index.html"); err != nil {
		t.Fatal("build the UI first: npm run build in web/admin")
	}
	ws := testenv.PlaywrightServer(t)

	h := newHarness(t)
	h.s.cfg.UI = ui
	h.s.uiRoutes()
	at := func(ago time.Duration) {
		h.mu.Lock()
		h.clock = shotTime.Add(-ago)
		h.mu.Unlock()
	}
	at(4 * 24 * time.Hour)
	h.user("admin", "admin")
	pub := h.signedIn("admin")
	// First, so its random ID is far down the audit log, below the screenshot.
	e := h.client()
	e.token = h.edgeToken(pub)

	// The demo's policy, published in steps so Versions has a history.
	var demo struct {
		Config *snapshot.Config `json:"config"`
		Tests  []ConfigTest     `json:"tests"`
	}
	b, err = os.ReadFile("../../loadtest/tools/demo-policy.json")
	if err == nil {
		err = json.Unmarshal(b, &demo)
	}
	if err != nil {
		t.Fatalf("read demo policy: %v", err)
	}
	full := demo.Config
	// The demo's issuers point at its mock IdP; a fake one here, so publish
	// finds their keys fetched.
	idp := newFakeJWKS(t, h)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idp.body = testenv.JWKS(testenv.JWK("k1", &key.PublicKey, nil))
	for i := range full.Auth.Issuers {
		full.Auth.Issuers[i].JWKSURL = idp.srv.URL + "/jwks.json"
	}
	limit := func(c *snapshot.Config, id string, n int64) {
		for i := range c.RateLimitRules {
			if c.RateLimitRules[i].ID == id {
				c.RateLimitRules[i].Limit = n
			}
		}
	}
	first := clone(full)
	limit(first, "login-per-ip", 5)
	limit(first, "api-shadow", 20)
	second := clone(first)
	limit(second, "login-per-ip", 2)
	third := clone(second)
	limit(third, "api-shadow", 8)
	steps := []struct {
		ago time.Duration
		cfg *snapshot.Config
		msg string
	}{
		{4 * 24 * time.Hour, first, "Demo policy: one example of each feature"},
		{2 * 24 * time.Hour, second, "Lower login-per-ip to 2 a minute"},
		{3 * time.Hour, third, "Lower api-shadow limit to 8"},
		{19 * time.Minute, full, "Raise api-shadow limit to 10"},
	}
	for _, s := range steps {
		at(s.ago)
		pub = h.signedIn("admin") // sessions last 12 hours; the steps are days apart
		status(t, pub.save(pub.revision(), s.cfg, demo.Tests...), http.StatusOK)
		status(t, pub.publishDraft(s.msg), http.StatusCreated)
	}

	// An hour of stats from two edges: steady traffic, a few login and API
	// limits, a log-only rule over its limit, and Valkey misses.
	for m := 60; m >= 0; m-- {
		at(time.Duration(m) * time.Minute)
		for i, name := range []string{"edge-1", "edge-2"} {
			n := uint64(5200 + 37*((m*7+i*3)%11))
			latency := make([]uint64, len(edge.LatencyBoundsMS)+1)
			latency[2], latency[3], latency[4], latency[5], latency[6] = n/10, n*3/10, n*4/10, n/10, n-n*9/10
			status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: name, ConfigSource: "admin", MaxSchema: snapshot.SupportedSchema,
				Deployment: h.s.cfg.Deployment.Fingerprint(), Upstream: "https://gateway.internal", Versions: []edge.StatsCounts{{
					Version: 4, Requests: n, Edge5xx: uint64(m % 3), Upstream5xx: n / 60, AuthFailures: n / 20, LatencyMS: latency,
					RateLimit: []edge.RuleCounts{
						{ID: "login-per-ip", Evaluated: n / 25, Limited: n / 90},
						{ID: "api-burst", Evaluated: n / 2, Limited: n / 30, Failed: uint64(30 + m%5)},
						{ID: "api-shadow", Evaluated: n / 2, WouldLimit: n / 5},
					},
					TopLimited: []edge.TopCount{
						{Rule: "api-burst", Key: "ip:203.0.113.24", Display: "203.0.113.24", Limited: n / 40},
						{Rule: "login-per-ip", Key: "ip:198.51.100.7", Display: "198.51.100.7", Limited: n / 120},
					},
				}}}), http.StatusOK)
		}
		if err := h.s.flush(t.Context(), h.now()); err != nil {
			t.Fatal(err)
		}
	}

	// Access lines for Routes, on paths the demo policy matches. Allowed
	// lines are sampled, one in 4096 (exact in floating point, so the
	// estimates don't depend on summing order), so Routes estimates about as
	// many requests as the edges reported; refusals and 5xx are always logged.
	var lines []string
	add := func(n int, method, host, path string, extra ...any) {
		for range n {
			lines = append(lines, access(method, host, path, extra...))
		}
	}
	const sampled = 1.0 / 4096
	add(46, "GET", "api.example.com", "/api/orders/1042", "edge.config_rules", []string{"api-defaults"}, "edge.sample_rate", sampled)
	add(29, "POST", "api.example.com", "/login", "edge.config_rules", []string{"login-page"}, "edge.sample_rate", sampled)
	add(5, "POST", "api.example.com", "/login", "edge.config_rules", []string{"login-page"}, "http.response.status_code", 429, "edge.decision", "rate_limited", "edge.rate_limit_rule", "login-per-ip")
	add(35, "GET", "www.example.com", "/api/catalog/2210", "edge.config_rules", []string{"api-defaults", "public-catalog"}, "edge.query_keys", []string{"ref"}, "edge.sample_rate", sampled)
	add(2, "GET", "www.example.com", "/api/catalog/2210", "edge.config_rules", []string{"api-defaults", "public-catalog"}, "http.response.status_code", 502, "edge.decision", "upstream_error")
	add(21, "PUT", "api.example.com", "/api/uploads/9f1c2b7e-4d3a-4f6e-9b1a-2c8d7e6f5a40", "edge.config_rules", []string{"api-defaults", "uploads"}, "edge.sample_rate", sampled)
	add(14, "GET", "partner.example.com", "/api/partner/catalog", "edge.config_rules", []string{"api-defaults", "partner-api"}, "edge.query_keys", []string{"page", "size"}, "edge.sample_rate", sampled)
	add(10, "GET", "www.example.com", "/pages/pricing", "edge.config_rules", []string{"pages"}, "edge.sample_rate", sampled)
	at(0)
	status(t, h.shipper().post(lines...), http.StatusAccepted)
	if err := h.s.flushRoutes(t.Context()); err != nil {
		t.Fatal(err)
	}

	args := []string{"playwright", "test", "-c", "playwright.docs.config.ts"}
	if mode == "update" {
		args = append(args, "--update-snapshots")
	}
	cmd := exec.Command("npx", args...)
	cmd.Dir = "../../web/admin"
	cmd.Env = append(os.Environ(), "BASE_URL="+h.srv.URL, "PW_WS="+ws, "SHOT_TIME="+shotTime.Format(time.RFC3339),
		"SHOT_USER=admin", "SHOT_PASSWORD="+goodPassword)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		// What the page showed when it failed, since CI keeps no artifacts.
		if pages, _ := filepath.Glob("../../web/admin/test-results/*/error-context.md"); pages != nil {
			b, _ := os.ReadFile(pages[0])
			t.Logf("%s:\n%s", pages[0], b)
		}
		t.Fatalf("playwright: %v (run scripts/ci/screenshots.sh update after a deliberate UI change)", err)
	}
}
