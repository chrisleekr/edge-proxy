package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
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

	token := filepath.Join(t.TempDir(), "autopilot-token")
	if err := os.WriteFile(token, []byte(agentToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarnessWith(t, map[string]string{"AUTOPILOT_TOKEN_FILE": token})
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
	// A config rule that blocks scripted clients, so the route-detail and
	// dashboard stats include blocks. Rules lists it below the fold, so its
	// screenshot is unchanged. Appended: the demo's own rules keep their order.
	blockRule, err := expr.Parse(`client.signals eq "ua_tool" and not starts_with(http.request.uri.path, "/api/")`)
	if err != nil {
		t.Fatal(err)
	}
	block := "block"
	full.ConfigRules = append(full.ConfigRules, snapshot.ConfigRule{ID: "block-tools", Expression: blockRule, Settings: snapshot.Settings{Block: &block}})
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

	// Twelve minutes ago a person asked the autopilot about login-per-ip
	// and about api-burst. The runner answered both as attacks with an
	// enforce rule each and recorded notes for Memory: an attack signature on
	// login-per-ip, a collateral risk on api-burst that two weeks of history
	// anchor, and a guess a person then retracted. The next run published
	// the rules log only as version 5, and the api-burst one was then marked
	// a false positive. From then on the edges serve version 5.
	agent := h.client()
	agent.token = agentToken
	var watched string
	autopilot := func() {
		pub.addPrice(price("claude-opus-5-5", 5, 25, 0.5, 6.25, shotTime.Add(-4*24*time.Hour)))
		agent.seen()
		// Each note cites the run's read of its rule's stats.
		answer := func(rule, question string, in map[string]any, refused map[string]any, u usage, cost float64, notes ...map[string]any) (string, []int64) {
			pub.investigate(rule, question)
			c := agent.claimCase()
			cs := h.mcpSession(agentToken, c.RunID)
			mustCall(t, cs, "get_case", nil)
			if refused != nil {
				if p := propose(t, cs, refused); p.Accepted {
					t.Fatalf("proposal %+v was meant to be refused", p)
				}
			}
			p := propose(t, cs, in)
			if !p.Accepted {
				t.Fatalf("proposal %+v", p)
			}
			var ids []int64
			if len(notes) > 0 {
				read := evidence(t, cs, "get_rule_stats", map[string]any{"rule": rule, "minutes": 60})
				for _, n := range notes {
					if n["basis"] == "observed" {
						n["evidence"] = []int64{read}
					}
					ids = append(ids, noteID(t, mustCall(t, cs, "record_learning", n)))
				}
			}
			body := resultBody(c.RunID, "attack", u, &cost, 0)
			body["summary"] = "Many failed logins per address from a few networks, well above the usual rate"
			status(t, agent.result(c.CaseID, body), http.StatusNoContent)
			return p.RuleID, ids
		}
		login := proposal("enforce", "login-stuffing", loginRule())
		login["evidence"] = map[string]any{"anomaly": "auth_failure_ratio firing", "failed_logins_per_minute": 412, "top_subjects": []string{"198.51.100.7", "203.0.113.24"}}
		login["rationale"] = "Failed logins rose eightfold in ten minutes, from a few addresses each over the limit"
		guess := proposal("add_sensor", "login-by-key", agentRule(`http.request.uri.path eq "/login"`, "header:x-api-key"))
		stuffing := learning("attack_signature", scopeRule("login-per-ip"), claim("rule_limited", ">=", 3000, lastMinutes(30)))
		stuffing["statement"] = "Credential stuffing on /login: login-per-ip blocks thousands of requests in half an hour from a few addresses"
		stuffing["rationale"] = "The rule's 429s rose from a handful a minute to over a hundred"
		partner := hedged("Likely a partner's monitoring retrying logins after a deploy")
		var notes []int64
		watched, notes = answer("login-per-ip", "Is someone guessing passwords on /login?", login, guess, usage{Input: 182_000, Output: 6_400, CacheRead: 410_000, CacheWrite: 38_000}, 1.84,
			stuffing, partner)
		// The same hour on each of the 14 days before: api-burst kept one
		// client over its limit, so the collateral risk below has an anchor.
		for k := 1; k <= 14; k++ {
			h.statsAt(shotTime.Add(-42*time.Minute-time.Duration(k)*24*time.Hour), 10_400, `[{"id":"api-burst","evaluated":5200,"limited":170}]`,
				`[{"rule":"api-burst","key":"ip:203.0.113.24","display":"203.0.113.24","limited":130}]`)
		}
		risk := learning("collateral_risk", scopeRule("api-burst"), claim("rule_subjects", ">=", 1, lastMinutes(60)))
		risk["effect"] = map[string]any{"max_block_share": 0.01}
		risk["statement"] = "api-burst finds one client over its limit every hour; a block on its traffic risks a partner's catalog sync"
		risk["rationale"] = "The same client is over the limit at this hour on every one of the last 14 days"
		scraper, _ := answer("api-burst", "", proposal("enforce", "catalog-scraper", agentRule(`starts_with(http.request.uri.path, "/api/catalog/")`, "ip")), nil,
			usage{Input: 96_000, Output: 3_100, CacheRead: 150_000}, 0.71, risk)
		status(t, pub.do("POST", fmt.Sprintf("/api/autopilot/notes/%d/retract", notes[1]), map[string]any{"reason": "The partner's monitoring sends no logins"}), http.StatusNoContent)
		h.tick()
		agent.seen() // answers the sweep and review the run opened
		status(t, pub.do("POST", "/api/autopilot/rules/"+scraper+"/retire", map[string]any{"reason": "The partner's catalog sync", "false_positive": true}), http.StatusNoContent)
	}

	// An hour of stats from two edges: steady traffic, a few login and API
	// limits, a log-only rule over its limit, Valkey misses, and the block
	// rule refusing scripted clients.
	for m := 60; m >= 0; m-- {
		at(time.Duration(m) * time.Minute)
		version := int64(4)
		if m == 12 {
			autopilot()
		}
		if m < 12 {
			agent.seen() // the runner keeps polling
			version = 5
		}
		for i, name := range []string{"edge-1", "edge-2"} {
			n := uint64(5200 + 37*((m*7+i*3)%11))
			// The login-stuffing rule, logging only, finds a few clients over its limit.
			var autopilotRules []edge.RuleCounts
			if m < 12 {
				autopilotRules = []edge.RuleCounts{{ID: watched, Evaluated: n / 25, WouldLimit: n / 300}}
			}
			latency := make([]uint64, len(edge.LatencyBoundsMS)+1)
			latency[2], latency[3], latency[4], latency[5], latency[6] = n/10, n*3/10, n*4/10, n/10, n-n*9/10
			// The same requests by status code: the edge's refusals and 502s,
			// and the upstream's answers. The 502s are a refused connection,
			// and one in three a name that did not resolve.
			edgeCodes := map[int]uint64{401: n / 20, 429: n/90 + n/30, 403: n / 40}
			var causes map[string]uint64
			if m%3 > 0 {
				edgeCodes[502] = uint64(m % 3)
				causes = map[string]uint64{"refused": uint64(m % 3)}
				if m%3 == 2 {
					causes = map[string]uint64{"refused": 1, "dns": 1}
				}
			}
			upCodes := map[int]uint64{503: n / 60, 404: n / 50}
			var answered uint64
			for _, c := range []map[int]uint64{edgeCodes, upCodes} {
				for _, k := range c {
					answered += k
				}
			}
			upCodes[200] = n - answered
			status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: name, ConfigSource: "admin", MaxSchema: snapshot.SupportedSchema,
				Deployment: h.s.cfg.Deployment.Fingerprint(), Upstream: "https://gateway.internal", Versions: []edge.StatsCounts{{
					Version: version, Requests: n, Edge5xx: uint64(m % 3), Upstream5xx: n / 60, AuthFailures: n / 20, LatencyMS: latency,
					RateLimit: append([]edge.RuleCounts{
						{ID: "login-per-ip", Evaluated: n / 25, Limited: n / 90},
						{ID: "api-burst", Evaluated: n / 2, Limited: n / 30, Failed: uint64(30 + m%5)},
						{ID: "api-shadow", Evaluated: n / 2, WouldLimit: n / 5},
						{ID: "pages-per-ip", Evaluated: n / 15},
						{ID: "api-per-user", Evaluated: n / 3},
						{ID: "partner-per-key", Evaluated: n / 12},
					}, autopilotRules...),
					// Steady matches for every demo rule, so Rules shows counts
					// and no rule looks like it stopped matching.
					Rules: []edge.RuleOutcome{
						{Phase: "config", ID: "private-needs-auth", Matched: n / 50},
						{Phase: "config", ID: "api-defaults", Matched: n * 7 / 10},
						{Phase: "config", ID: "public-catalog", Matched: n / 5},
						{Phase: "config", ID: "uploads", Matched: n / 8},
						{Phase: "config", ID: "partner-api", Matched: n / 12},
						{Phase: "config", ID: "pages", Matched: n / 15},
						{Phase: "config", ID: "login-page", Matched: n / 25},
						{Phase: "config", ID: "block-tools", Matched: n / 40, Blocked: n / 40},
						{Phase: "request_headers", ID: "tag-service", Matched: n},
						{Phase: "request_headers", ID: "drop-debug", Matched: n / 100},
						{Phase: "request_headers", ID: "legacy-token", Matched: n / 200},
					},
					TopLimited: []edge.TopCount{
						{Rule: "api-burst", Key: "ip:203.0.113.24", Display: "203.0.113.24", Limited: n / 40},
						{Rule: "login-per-ip", Key: "ip:198.51.100.7", Display: "198.51.100.7", Limited: n / 120},
					},
					StatusCodes:    edge.StatusCodes{Edge: edgeCodes, Upstream: upCodes},
					UpstreamErrors: causes,
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
	add(2, "GET", "www.example.com", "/api/catalog/2210", "edge.config_rules", []string{"api-defaults", "public-catalog"}, "http.response.status_code", 502, "edge.decision", "upstream_error",
		"edge.upstream_error", "dial tcp 10.20.0.15:443: connect: connection refused", "edge.upstream_error_kind", "refused")
	add(1, "GET", "www.example.com", "/api/catalog/2210", "edge.config_rules", []string{"api-defaults", "public-catalog"}, "http.response.status_code", 502, "edge.decision", "upstream_error",
		"edge.upstream_error", "dial tcp: lookup gateway.internal on 10.96.0.10:53: no such host", "edge.upstream_error_kind", "dns")
	add(21, "PUT", "api.example.com", "/api/uploads/9f1c2b7e-4d3a-4f6e-9b1a-2c8d7e6f5a40", "edge.config_rules", []string{"api-defaults", "uploads"}, "edge.sample_rate", sampled)
	add(14, "GET", "partner.example.com", "/api/partner/catalog", "edge.config_rules", []string{"api-defaults", "partner-api"}, "edge.query_keys", []string{"page", "size"}, "edge.sample_rate", sampled)
	add(10, "GET", "www.example.com", "/pages/pricing", "edge.config_rules", []string{"pages"}, "edge.sample_rate", sampled)
	// Two checks a minute apart fire what the stats above show: the
	// log-only rule over its limit and Valkey misses.
	h.s.cfg.AlertmanagerURL = newFakeAlertmanager(t).srv.URL
	for _, ago := range []time.Duration{2 * time.Minute, time.Minute} {
		at(ago)
		if err := h.s.runNotify(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
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
