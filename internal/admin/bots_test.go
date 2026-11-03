package admin

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/jwks"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

const (
	chromeJA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	knownJA3  = "e7d705a3286e19ea42f587b344ee6865"
)

// rangesJSON is a crawler range list in the format Google publishes.
func rangesJSON(prefixes ...string) string {
	var ps []string
	for _, p := range prefixes {
		key := "ipv4Prefix"
		if strings.Contains(p, ":") {
			key = "ipv6Prefix"
		}
		ps = append(ps, fmt.Sprintf(`{%q:%q}`, key, p))
	}
	return `{"creationTime":"2026-10-20T15:46:01.000000","prefixes":[` + strings.Join(ps, ",") + `]}`
}

// fakeRanges serves a crawler range list over TLS; an empty body is a 500.
type fakeRanges struct {
	srv  *httptest.Server
	mu   sync.Mutex
	body string
}

func (f *fakeRanges) set(body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = body
}

func newFakeRanges(t *testing.T, body string) *fakeRanges {
	t.Helper()
	f := &fakeRanges{body: body}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.body == "" {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(f.body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// trustRanges fetches bot sources through the SSRF-guarded client, trusting
// the fake sources' certificates.
func (h *harness) trustRanges(fs ...*fakeRanges) {
	roots := x509.NewCertPool()
	for _, f := range fs {
		roots.AddCert(f.srv.Certificate())
	}
	h.s.jwks = jwks.NewClient([]string{"127.0.0.1"}, 2*time.Second, roots)
}

// botHarness is admin with VERIFIED_BOT_SOURCES naming one fake source,
// fetched through the SSRF-guarded client that trusts it, and a publisher
// signed in. The logs are safe to read while leader jobs run.
func botHarness(t *testing.T) (*harness, *client, *fakeRanges, *syncBuffer) {
	t.Helper()
	f := newFakeRanges(t, rangesJSON("66.249.64.0/27", "2001:4860:4801:10::/64"))
	h := newHarnessWith(t, map[string]string{"VERIFIED_BOT_SOURCES": f.srv.URL + "/googlebot.json"})
	logs := leaderLogs(h)
	h.trustRanges(f)
	h.user("pub", "admin")
	return h, h.signedIn("pub"), f, logs
}

// leadBriefly runs the leader's jobs, as a replica that has just taken the
// leader lock does, until cond holds.
func leadBriefly(t *testing.T, h *harness, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); h.s.runJobs(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor(t, cond)
}

// crawlerConfig is a schema 3 policy, optionally with a rule that reads
// client.verified_bot.
func crawlerConfig(usesVerifiedBot bool) *snapshot.Config {
	c := testConfig()
	c.Schema = 3
	if usesVerifiedBot {
		c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "crawlers", Expression: mustParse(`client.verified_bot`), Settings: snapshot.Settings{CORSPolicy: new("")}})
	}
	return c
}

// edgeSnapshot is GET /v1/snapshot as an edge sees it, with its ETag.
func edgeSnapshot(t *testing.T, e *client) (map[string]any, string) {
	t.Helper()
	resp := e.do("GET", "/v1/snapshot", nil)
	tag := resp.Header.Get("ETag")
	return decode[map[string]any](t, resp), tag
}

// botPrefixes are the prefixes a snapshot carries for source, sorted.
func botPrefixes(env map[string]any, source string) []string {
	sets, _ := env["verified_bots"].([]any)
	for _, s := range sets {
		if s, _ := s.(map[string]any); s["source"] == source {
			var out []string
			for _, p := range s["prefixes"].([]any) {
				out = append(out, p.(string))
			}
			slices.Sort(out)
			return out
		}
	}
	return nil
}

// auditActors lists the actor of every audit row with action, in order.
func (h *harness) auditActors(action string) []string {
	h.t.Helper()
	h.actions() // verifies the chain
	rows, err := h.db.Query(context.Background(), "SELECT actor FROM audit_events WHERE action = $1 ORDER BY seq", action)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// Admin fetches each VERIFIED_BOT_SOURCES list through the SSRF guard and
// ships the ranges in the snapshot, outside policy versions: a change
// reaches edges as a new ETag with no publish, audited as an automated
// event.
func TestVerifiedBotSourcesRefreshIntoTheSnapshot(t *testing.T) {
	h, pub, f, _ := botHarness(t)
	src := f.srv.URL + "/googlebot.json"
	status(t, pub.save(`"0"`, crawlerConfig(true)), 200)
	status(t, pub.publishDraft("let verified crawlers through"), 201)
	e := h.client()
	e.token = h.edgeToken(pub)

	leadBriefly(t, h, func() bool { env, _ := edgeSnapshot(t, e); return botPrefixes(env, src) != nil })
	env, tag := edgeSnapshot(t, e)
	if got := botPrefixes(env, src); !slices.Equal(got, []string{"2001:4860:4801:10::/64", "66.249.64.0/27"}) {
		t.Fatalf("prefixes %v", got)
	}
	if got := h.auditActors("verified_bots.changed"); !slices.Equal(got, []string{"system:verified_bots"}) {
		t.Fatalf("audited changes by %v", got)
	}

	f.set(rangesJSON("66.249.64.0/27", "66.249.66.0/27", "2001:4860:4801:10::/64"))
	leadBriefly(t, h, func() bool { env, _ := edgeSnapshot(t, e); return len(botPrefixes(env, src)) == 3 })
	status(t, e.do("GET", "/v1/snapshot", nil, "If-None-Match", tag), 200)
	if got := h.auditActors("verified_bots.changed"); len(got) != 2 {
		t.Fatalf("audited changes by %v", got)
	}
	var versions int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM config_versions").Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("%d versions, %v: a range change must not publish", versions, err)
	}
}

// warnings counts warning lines mentioning sub.
func (s *syncBuffer) warnings(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for l := range strings.SplitSeq(s.b.String(), "\n") {
		if strings.Contains(l, `"level":"WARN"`) && strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

// A source that is down or sends something other than a range list keeps
// the last good ranges in the snapshot, with a warning and no audit row:
// losing them would turn every crawler exemption off.
func TestVerifiedBotRefreshFailureKeepsTheLastGoodSet(t *testing.T) {
	h, pub, f, logs := botHarness(t)
	src := f.srv.URL + "/googlebot.json"
	status(t, pub.save(`"0"`, crawlerConfig(true)), 200)
	status(t, pub.publishDraft("let verified crawlers through"), 201)
	e := h.client()
	e.token = h.edgeToken(pub)
	leadBriefly(t, h, func() bool { env, _ := edgeSnapshot(t, e); return botPrefixes(env, src) != nil })

	for _, tc := range []struct{ name, body string }{
		{"source down", ""},
		{"not JSON", "<html>maintenance</html>"},
		{"no prefixes", rangesJSON()},
		{"a prefix that doesn't parse", rangesJSON("66.249.64.0/33")},
		{"a range wider than /16", rangesJSON("66.249.64.0/27", "66.0.0.0/8")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.set(tc.body)
			n := logs.warnings("verified bot")
			leadBriefly(t, h, func() bool { return logs.warnings("verified bot") > n })
			env, _ := edgeSnapshot(t, e)
			if got := botPrefixes(env, src); !slices.Equal(got, []string{"2001:4860:4801:10::/64", "66.249.64.0/27"}) {
				t.Fatalf("prefixes %v", got)
			}
			if got := h.auditActors("verified_bots.changed"); len(got) != 1 {
				t.Fatalf("audited changes by %v", got)
			}
		})
	}
}

// Sources refresh independently: one that fails keeps its last good set
// while another that changed is stored and audited on its own.
func TestVerifiedBotRefreshFailureLeavesOtherSourcesRefreshing(t *testing.T) {
	h, pub, f, _ := botHarness(t)
	g := newFakeRanges(t, rangesJSON("157.55.39.0/24"))
	h.trustRanges(f, g)
	srcF, srcG := f.srv.URL+"/googlebot.json", g.srv.URL+"/bingbot.json"
	h.s.cfg.VerifiedBotSources = []string{srcF, srcG} // admin restarted with both
	status(t, pub.save(`"0"`, crawlerConfig(true)), 200)
	status(t, pub.publishDraft("let verified crawlers through"), 201)
	e := h.client()
	e.token = h.edgeToken(pub)
	leadBriefly(t, h, func() bool {
		env, _ := edgeSnapshot(t, e)
		return botPrefixes(env, srcF) != nil && botPrefixes(env, srcG) != nil
	})

	f.set("")
	g.set(rangesJSON("157.55.39.0/24", "207.46.13.0/24"))
	leadBriefly(t, h, func() bool { env, _ := edgeSnapshot(t, e); return len(botPrefixes(env, srcG)) == 2 })
	env, _ := edgeSnapshot(t, e)
	if got := botPrefixes(env, srcF); !slices.Equal(got, []string{"2001:4860:4801:10::/64", "66.249.64.0/27"}) {
		t.Fatalf("failed source's prefixes %v", got)
	}
	var targets []string
	for _, a := range h.actions() {
		if target, ok := strings.CutPrefix(a, "verified_bots.changed "); ok {
			targets = append(targets, target)
		}
	}
	if !slices.Equal(targets, []string{srcF, srcG, srcG}) {
		t.Fatalf("changes audited for %v", targets)
	}
}

// A source taken out of VERIFIED_BOT_SOURCES leaves the snapshot on the
// next refresh, and its removal is audited as an automated event.
func TestVerifiedBotSourceRemovedIsDroppedAndAudited(t *testing.T) {
	h, pub, f, _ := botHarness(t)
	src := f.srv.URL + "/googlebot.json"
	status(t, pub.save(`"0"`, crawlerConfig(true)), 200)
	status(t, pub.publishDraft("let verified crawlers through"), 201)
	e := h.client()
	e.token = h.edgeToken(pub)
	leadBriefly(t, h, func() bool { env, _ := edgeSnapshot(t, e); return botPrefixes(env, src) != nil })

	h.s.cfg.VerifiedBotSources = nil // admin restarted without the source
	leadBriefly(t, h, func() bool { env, _ := edgeSnapshot(t, e); return botPrefixes(env, src) == nil })
	if got := h.auditActors("verified_bots.removed"); !slices.Equal(got, []string{"system:verified_bots"}) {
		t.Fatalf("audited removals by %v", got)
	}
	if !slices.Contains(h.actions(), "verified_bots.removed "+src) {
		t.Fatalf("no removal audited for %s: %v", src, h.actions())
	}
}

// A changed range list is audited with the prefixes it added and removed,
// so a reviewer sees what the exemption now covers.
func TestVerifiedBotChangeAuditsAddedAndRemovedPrefixes(t *testing.T) {
	h, pub, f, _ := botHarness(t)
	src := f.srv.URL + "/googlebot.json"
	status(t, pub.save(`"0"`, crawlerConfig(true)), 200)
	status(t, pub.publishDraft("let verified crawlers through"), 201)
	e := h.client()
	e.token = h.edgeToken(pub)
	leadBriefly(t, h, func() bool { env, _ := edgeSnapshot(t, e); return botPrefixes(env, src) != nil })

	f.set(rangesJSON("66.249.66.0/27", "2001:4860:4801:10::/64"))
	leadBriefly(t, h, func() bool { return len(h.auditActors("verified_bots.changed")) == 2 })
	var details map[string]any
	if err := h.db.QueryRow(t.Context(), "SELECT details FROM audit_events WHERE action = 'verified_bots.changed' ORDER BY seq DESC LIMIT 1").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(details["added"]) != "[66.249.66.0/27]" || fmt.Sprint(details["removed"]) != "[66.249.64.0/27]" || details["prefixes"] != 2.0 {
		t.Fatalf("audit details %v", details)
	}
}

// A range list with a range wider than a crawler needs, or a range under the
// other family's key, is refused whole, so the refresh keeps the last good set.
func TestVerifiedBotSourceRefusesWideOrMislabelledRanges(t *testing.T) {
	cases := []struct{ name, body string }{
		{"IPv4 wider than /16", rangesJSON("66.249.64.0/27", "66.0.0.0/8")},
		{"IPv6 wider than /32", rangesJSON("2001::/16")},
		{"IPv4 under ipv6Prefix", `{"prefixes":[{"ipv6Prefix":"66.249.64.0/27"}]}`},
		{"IPv6 under ipv4Prefix", `{"prefixes":[{"ipv4Prefix":"2001:4860:4801:10::/64"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := parseRanges([]byte(tc.body)); err == nil {
				t.Fatalf("parseRanges accepted %v", got)
			}
		})
	}
}

// Without VERIFIED_BOT_SOURCES client.verified_bot is always false, so a
// rule that reads it would never match: admin refuses to save it.
func TestVerifiedBotFieldNeedsSources(t *testing.T) {
	h := newHarness(t)
	h.user("ed", "editor")
	ed := h.signedIn("ed")
	resp := ed.save(`"0"`, crawlerConfig(true))
	if b := body(resp); resp.StatusCode != 422 || !strings.Contains(b, "client.verified_bot needs VERIFIED_BOT_SOURCES") {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
}

// Reverts and guard rollbacks restore a version edges already served, so
// they compile with verified crawlers on, as edges do: admin restarted
// without VERIFIED_BOT_SOURCES still restores a version that reads
// client.verified_bot, though it refuses to save a new one.
func TestRestoringAVerifiedBotVersionNeedsNoSources(t *testing.T) {
	for _, tc := range []struct {
		name    string
		restore func(t *testing.T, h *harness, pub *client)
	}{
		{"revert", func(t *testing.T, h *harness, pub *client) {
			t.Helper()
			status(t, pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "back to v1"}), 201)
		}},
		{"guard rollback", func(t *testing.T, h *harness, pub *client) {
			t.Helper()
			h.advance(5 * time.Minute)
			h.live("edge-a", 2)
			h.putStats(2, 4, 2_000, 0, 400, []int64{2_000}, "[]", "[]") // 5% upstream 5xx
			if err := h.s.runGuard(t.Context()); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, _, _ := botHarness(t)
			status(t, pub.save(`"0"`, crawlerConfig(true)), 200)
			status(t, pub.publishDraft("let verified crawlers through"), 201)
			h.putStats(1, 10, 2_000, 0, 10, []int64{2_000}, "[]", "[]")
			h.advance(time.Minute)
			status(t, pub.save(pub.revision(), crawlerConfig(false)), 200)
			status(t, pub.publishDraft("v2 doesn't"), 201)

			// Admin restarted without the source.
			h.s.cfg.VerifiedBotSources = nil
			h.s.cfg.Deployment.VerifiedBots = false
			status(t, pub.save(pub.revision(), crawlerConfig(true)), 422)

			tc.restore(t, h, pub)
			list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil))
			if len(list) != 3 || list[0].Status != "active" || *list[0].BasedOn != 1 {
				t.Fatalf("versions %+v", list)
			}
		})
	}
}

// Edges that read schema 3 decode strictly and would reject the field, so
// the snapshot carries verified_bots only while the active or canary
// version uses client.verified_bot; such a version needs schema 4 edges.
func TestEnvelopeCarriesVerifiedBotsOnlyWhenAConfigUsesThem(t *testing.T) {
	h, pub, f, _ := botHarness(t)
	src := f.srv.URL + "/googlebot.json"
	status(t, pub.save(`"0"`, crawlerConfig(true)), 200)
	status(t, pub.publishDraft("v1 uses it"), 201)
	e := h.client()
	e.token = h.edgeToken(pub)
	leadBriefly(t, h, func() bool { env, _ := edgeSnapshot(t, e); return botPrefixes(env, src) != nil })

	status(t, pub.save(pub.revision(), crawlerConfig(false)), 200)
	status(t, pub.publishDraft("v2 doesn't"), 201)
	if env, _ := edgeSnapshot(t, e); env["verified_bots"] != nil {
		t.Fatalf("v2 snapshot carries verified_bots: %v", env["verified_bots"])
	}

	status(t, pub.save(pub.revision(), crawlerConfig(true)), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v3 on 10%", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	if env, _ := edgeSnapshot(t, e); botPrefixes(env, src) == nil {
		t.Fatalf("canary snapshot lacks verified_bots: %v", env["verified_bots"])
	}
}

// blockConfig is a schema 3 policy whose tools rule has the block setting
// tools, and whose crawlers rule only logs.
func blockConfig(tools string) map[string]any {
	c := testConfig()
	c.Schema = 3
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent contains "curl"`)},
		snapshot.ConfigRule{ID: "crawlers", Expression: mustParse(`http.user_agent contains "bot"`)},
	)
	b, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, r := range m["config_rules"].([]any) {
		r := r.(map[string]any)
		switch r["id"] {
		case "tools":
			r["settings"].(map[string]any)["block"] = tools
		case "crawlers":
			r["settings"].(map[string]any)["block"] = "log"
		}
	}
	return m
}

// saveJSON saves a config given in JSON form as the draft.
func (c *client) saveJSON(rev string, cfg map[string]any) *http.Response {
	c.h.t.Helper()
	return c.do("PUT", "/api/draft", map[string]any{"config": cfg, "tests": []any{}}, "If-Match", rev)
}

// putOutcomes records one version's traffic and config rule outcomes for
// each minute from from minutes ago up to and including to minutes ago.
func (h *harness) putOutcomes(version int64, from, to int, requests int64, rules string) {
	h.t.Helper()
	now := h.now().UTC().Truncate(time.Minute)
	for i := to; i <= from; i++ {
		h.statsSeq++
		_, err := h.db.Exec(context.Background(), `INSERT INTO edge_stats_minute (minute, version, replica, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited, rules)
			VALUES ($1, $2, $3, $4, 0, 0, 0, $5, '[]', '[]', $6)`, now.Add(time.Duration(-i)*time.Minute), version, fmt.Sprint("r", h.statsSeq), requests, []int64{requests}, rules)
		if err != nil {
			h.t.Fatal(err)
		}
	}
}

// A canary that switches a block rule from log to block and then blocks
// far more than it logged rolls back, like a rate-limit rule that limits
// too much: the guard reads blocks against the cohort's requests.
func TestGuardAbortsACanaryWhoseBlockRuleOverBlocks(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	status(t, pub.saveJSON(`"0"`, blockConfig("log")), 200)
	status(t, pub.publishDraft("watch tools"), 201)
	status(t, pub.saveJSON(pub.revision(), blockConfig("block")), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "block tools on 10%", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	h.advance(6 * time.Minute)
	h.live("edge-a", 1, 2)
	h.putOutcomes(1, 5, 1, 10_000, `[{"phase":"config","id":"tools","matched":100,"would_block":100}]`) // 1% would block
	h.putOutcomes(2, 5, 1, 1_000, `[{"phase":"config","id":"tools","matched":300,"blocked":300}]`)      // 30% blocked
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	v := decode[versionRow](t, pub.do("GET", "/api/versions/2", nil))
	var out guardOutcome
	_ = json.Unmarshal(v.GuardOutcome, &out)
	if sig := out.Signals["changed_rule_limited_ratio"]; v.Status != "rolled_back" || out.Decision != "rollback" || !sig.Tripped || sig.Detail != "tools" {
		t.Fatalf("version %s, outcome %+v", v.Status, out)
	}
}

// A block rule that logged first is judged by its logged share, not by the
// 5% max_ratio: blocking what it would have blocked is the point. It rolls
// back only when it blocks more than max_vs_shadow times that share.
func TestGuardJudgesABlockRuleByWhatItLogged(t *testing.T) {
	for _, tc := range []struct {
		name     string
		blocked  int
		want     string
		decision string
	}{
		{"blocks the 10% it logged", 100, "canary", "ok"},
		{"blocks 40% after logging 10%", 400, "rolled_back", "rollback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.user("pub", "admin")
			pub := h.signedIn("pub")
			status(t, pub.saveJSON(`"0"`, blockConfig("log")), 200)
			status(t, pub.publishDraft("watch tools"), 201)
			status(t, pub.saveJSON(pub.revision(), blockConfig("block")), 200)
			status(t, pub.do("POST", "/api/publish", map[string]any{"message": "block tools on 10%", "canary_percent": 10}, "If-Match", pub.revision()), 201)
			h.advance(6 * time.Minute)
			h.live("edge-a", 1, 2)
			h.putOutcomes(1, 5, 1, 10_000, `[{"phase":"config","id":"tools","matched":1000,"would_block":1000}]`) // 10% would block
			h.putOutcomes(2, 5, 1, 1_000, fmt.Sprintf(`[{"phase":"config","id":"tools","matched":%d,"blocked":%d}]`, tc.blocked, tc.blocked))
			if err := h.s.runGuard(t.Context()); err != nil {
				t.Fatal(err)
			}
			v := decode[versionRow](t, pub.do("GET", "/api/versions/2", nil))
			var out guardOutcome
			_ = json.Unmarshal(v.GuardOutcome, &out)
			if v.Status != tc.want || out.Decision != tc.decision || out.Signals["changed_rule_limited_ratio"].Tripped != (tc.decision == "rollback") {
				t.Fatalf("version %s, outcome %+v", v.Status, out)
			}
		})
	}
}

// An established block rule is judged by what it blocked in the active
// version, so an edit that leaves it blocking the same 20% does not roll
// back, though 20% is above the 5% max_ratio. It rolls back only when it
// blocks more than max_vs_shadow times that share.
func TestGuardJudgesAnEditedBlockRuleByWhatItBlocked(t *testing.T) {
	for _, tc := range []struct {
		name     string
		blocked  int
		want     string
		decision string
	}{
		{"blocks the 20% it blocked before", 200, "canary", "ok"},
		{"blocks 70% after blocking 20%", 700, "rolled_back", "rollback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.user("pub", "admin")
			pub := h.signedIn("pub")
			status(t, pub.saveJSON(`"0"`, blockConfig("block")), 200)
			status(t, pub.publishDraft("block tools"), 201)
			edited := blockConfig("block")
			b, _ := json.Marshal(mustParse(`http.user_agent contains "curl" or http.user_agent contains "curl/"`))
			for _, r := range edited["config_rules"].([]any) {
				if r := r.(map[string]any); r["id"] == "tools" {
					r["expression"] = json.RawMessage(b)
				}
			}
			status(t, pub.saveJSON(pub.revision(), edited), 200)
			status(t, pub.do("POST", "/api/publish", map[string]any{"message": "reword tools on 10%", "canary_percent": 10}, "If-Match", pub.revision()), 201)
			h.advance(6 * time.Minute)
			h.live("edge-a", 1, 2)
			h.putOutcomes(1, 5, 1, 10_000, `[{"phase":"config","id":"tools","matched":2000,"blocked":2000}]`) // 20% blocked
			h.putOutcomes(2, 5, 1, 1_000, fmt.Sprintf(`[{"phase":"config","id":"tools","matched":%d,"blocked":%d}]`, tc.blocked, tc.blocked))
			if err := h.s.runGuard(t.Context()); err != nil {
				t.Fatal(err)
			}
			v := decode[versionRow](t, pub.do("GET", "/api/versions/2", nil))
			var out guardOutcome
			_ = json.Unmarshal(v.GuardOutcome, &out)
			if sig := out.Signals["changed_rule_limited_ratio"]; v.Status != tc.want || out.Decision != tc.decision || sig.Tripped != (tc.decision == "rollback") || sig.Detail != "tools" {
				t.Fatalf("version %s, outcome %+v", v.Status, out)
			}
		})
	}
}

// rule_block_spike and rule_would_block watch config rules that block as
// they watch rate-limit rules, so a block rule that starts refusing far
// more, or a log-only one that would refuse someone, notifies.
func TestNotifyBlockSignalsCoverConfigRules(t *testing.T) {
	for _, tc := range []struct {
		name, baseline, window, signal, rule string
	}{
		{"a block rule blocks far more", `[{"phase":"config","id":"tools","matched":100,"blocked":1}]`, `[{"phase":"config","id":"tools","matched":100,"blocked":30}]`, "rule_block_spike", "tools"},
		{"a log-only block rule would block", `[{"phase":"config","id":"crawlers","matched":10}]`, `[{"phase":"config","id":"crawlers","matched":10,"would_block":3}]`, "rule_would_block", "crawlers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			am := newFakeAlertmanager(t)
			h := newHarnessWith(t, map[string]string{"ALERTMANAGER_URL": am.srv.URL + "/"})
			h.mu.Lock()
			h.clock = h.clock.Truncate(time.Minute).Add(45 * time.Second)
			h.mu.Unlock()
			h.user("pub", "admin")
			pub := h.signedIn("pub")
			status(t, pub.saveJSON(`"0"`, blockConfig("block")), 200)
			status(t, pub.publishDraft("v1"), 201)
			n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
			n.FireAfter = 1
			status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
			h.putOutcomes(1, 65, 6, 1000, tc.baseline)
			h.putOutcomes(1, 5, 1, 1000, tc.window)
			h.check()
			var got []string
			for _, a := range h.anomalies(pub) {
				got = append(got, a.Signal+" "+a.Rule+" "+a.State)
			}
			if !slices.Contains(got, tc.signal+" "+tc.rule+" firing") {
				t.Fatalf("anomalies %v", got)
			}
		})
	}
}

// A config test states the JA4, JA3, HTTP version and verified-crawler flag
// directly, as it does the country and ASN, and rules see them as live
// traffic would.
func TestConfigTestsSetJA4AndHTTPVersion(t *testing.T) {
	h := newHarnessWith(t, map[string]string{
		"VIEWER_HEADERS":       "tls.client.ja4=CloudFront-Viewer-JA4-Fingerprint,tls.client.ja3=CloudFront-Viewer-JA3-Fingerprint",
		"VERIFIED_BOT_SOURCES": "https://bots.example.com/googlebot.json",
	})
	h.user("ed", "editor")
	ed := h.signedIn("ed")
	c := testConfig()
	c.Schema = 3
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "old-tls", Expression: mustParse(`starts_with(tls.client.ja4, "t12")`), Settings: snapshot.Settings{CORSPolicy: new("")}},
		snapshot.ConfigRule{ID: "http1", Expression: mustParse(`http.request.version in {"1.0" "1.1"}`), Settings: snapshot.Settings{Locale: new(false)}},
		snapshot.ConfigRule{ID: "known-ja3", Expression: mustParse(`tls.client.ja3 eq "` + knownJA3 + `"`), Settings: snapshot.Settings{RateLimitHeaders: new(true)}},
		snapshot.ConfigRule{ID: "crawlers", Expression: mustParse(`client.verified_bot`), Settings: snapshot.Settings{BodyLimit: new(int64(2048))}},
	)
	test := func(name string, req map[string]any, rules ...string) map[string]any {
		req["host"], req["path"] = "api.example.com", "/"
		return map[string]any{"name": name, "request": req, "expect": map[string]any{"config_rules": orEmpty(rules)}}
	}
	tests := []any{
		test("TLS 1.2 client", map[string]any{"ssl": true, "ja4": "t12d1209h1_8daaf6152771_02713d6af862"}, "old-tls"),
		test("HTTP/1.1 client", map[string]any{"http_version": "1.1"}, "http1"),
		test("client with a known JA3", map[string]any{"ssl": true, "ja3": knownJA3}, "known-ja3"),
		test("fingerprint on a plain request is absent", map[string]any{"ja4": "t12d1209h1_8daaf6152771_02713d6af862", "ja3": knownJA3}),
		test("verified crawler", map[string]any{"verified_bot": true}, "crawlers"),
		test("modern client", map[string]any{"ssl": true, "ja4": chromeJA4, "http_version": "2.0"}),
	}
	status(t, ed.do("PUT", "/api/draft", map[string]any{"config": c, "tests": tests}, "If-Match", `"0"`), 200)
	res := decode[[]TestResult](t, ed.do("POST", "/api/tests/run", nil))
	if len(res) != len(tests) {
		t.Fatalf("results %+v", res)
	}
	for _, r := range res {
		if !r.Pass {
			t.Errorf("%s: %v", r.Name, r.Failures)
		}
	}
	sim := decode[SimView](t, ed.do("POST", "/api/simulate", map[string]any{"request": map[string]any{
		"host": "api.example.com", "path": "/", "ssl": true, "ja4": "t12d1209h1_8daaf6152771_02713d6af862", "http_version": "1.1",
	}}))
	if !slices.Equal(sim.ConfigRules, []string{"old-tls", "http1"}) {
		t.Fatalf("simulate %+v", sim)
	}
}
