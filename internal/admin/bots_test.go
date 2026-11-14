package admin

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/chrisleekr/edge-proxy/internal/jwks"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
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

// crawlerState is one verified_bot_status row, read with raw SQL so the tests
// stay independent of how admin names its own types.
type crawlerState struct {
	attempt  time.Time
	success  *time.Time
	failures int
	lastErr  *string
}

func (h *harness) crawlerStatus(src string) crawlerState {
	h.t.Helper()
	var st crawlerState
	err := h.db.QueryRow(h.t.Context(), "SELECT last_attempt_at, last_success_at, failures, last_error FROM verified_bot_status WHERE source_url = $1", src).
		Scan(&st.attempt, &st.success, &st.failures, &st.lastErr)
	if err != nil {
		h.t.Fatalf("status row for %s: %v", src, err)
	}
	return st
}

func (h *harness) refreshBotsOnce() {
	h.t.Helper()
	if err := h.s.refreshBots(h.t.Context()); err != nil {
		h.t.Fatal(err)
	}
}

// Each refresh records when it ran, when a list last came back good (even an
// unchanged one) and how many failed in a row, so an operator can tell a
// source that is fine from one whose ranges have been aging for days.
func TestVerifiedBotRefreshRecordsLastSuccessAndFailuresInARow(t *testing.T) {
	h, _, f, _ := botHarness(t)
	src := f.srv.URL + "/googlebot.json"
	good := rangesJSON("66.249.64.0/27", "2001:4860:4801:10::/64")
	var prev crawlerState
	for i, step := range []struct {
		name         string
		body         string
		failures     int
		successMoves bool
		wantErr      bool
	}{
		{"first success", good, 0, true, false},
		{"first failure keeps the last success", "", 1, false, true},
		{"second failure counts in a row", "", 2, false, true},
		{"success with unchanged ranges resets the count and moves the last success", good, 0, true, false},
	} {
		h.advance(time.Minute)
		f.set(step.body)
		h.refreshBotsOnce()
		st := h.crawlerStatus(src)
		if st.failures != step.failures {
			t.Fatalf("%s: failures %d, want %d", step.name, st.failures, step.failures)
		}
		if (st.lastErr != nil) != step.wantErr {
			t.Fatalf("%s: last_error %v", step.name, st.lastErr)
		}
		if st.success == nil || (i > 0 && st.success.After(*prev.success) != step.successMoves) {
			t.Fatalf("%s: last_success_at %v after %v, moves %v", step.name, st.success, prev.success, step.successMoves)
		}
		if i > 0 && !st.attempt.After(prev.attempt) {
			t.Fatalf("%s: last_attempt_at %v did not move past %v", step.name, st.attempt, prev.attempt)
		}
		prev = st
	}
}

// A parse error can quote a long entry of the remote list, so the stored
// error is cut: it must not bloat the row or stop the status being written.
func TestVerifiedBotStatusBoundsAParseError(t *testing.T) {
	h, _, f, _ := botHarness(t)
	src := f.srv.URL + "/googlebot.json"
	entry := strings.Repeat("é", 2000)
	f.set(`{"prefixes":[{"ipv4Prefix":"` + entry + `","ipv6Prefix":"` + entry + `"}]}`)
	h.refreshBotsOnce()
	st := h.crawlerStatus(src)
	if st.failures != 1 || st.lastErr == nil {
		t.Fatalf("status %+v", st)
	}
	if n := utf8.RuneCountInString(*st.lastErr); n == 0 || n > 300 {
		t.Fatalf("last_error has %d characters", n)
	}
}

// A TLS hostname error copies the names in the source's certificate, which
// can hold a NUL byte that Postgres text refuses; the failure must still be
// recorded or the source would never go stale.
func TestVerifiedBotStatusRecordsACertificateNameWithNUL(t *testing.T) {
	h, _, f, _ := botHarness(t)
	src := f.srv.URL + "/googlebot.json"
	failed := fmt.Errorf("verified bot ranges fetch: %w", &url.Error{Op: "Get", URL: src,
		Err: x509.HostnameError{Certificate: &x509.Certificate{DNSNames: []string{"evil\x00.example"}}, Host: "ranges.example"}})
	if err := h.s.recordBotRefresh(t.Context(), src, failed); err != nil {
		t.Fatal(err)
	}
	st := h.crawlerStatus(src)
	if st.failures != 1 || st.lastErr == nil || strings.ContainsRune(*st.lastErr, 0) || !strings.Contains(*st.lastErr, "evil") {
		t.Fatalf("status %+v", st)
	}
}

// Status is telemetry: recording it must not publish new ranges, or every
// edge would refetch the snapshot on each 10 minute refresh.
func TestVerifiedBotStatusLeavesTheEdgeSnapshotUnchanged(t *testing.T) {
	h, pub, f, _ := botHarness(t)
	src := f.srv.URL + "/googlebot.json"
	status(t, pub.save(`"0"`, crawlerConfig(true)), 200)
	status(t, pub.publishDraft("let verified crawlers through"), 201)
	e := h.client()
	e.token = h.edgeToken(pub)
	h.refreshBotsOnce()
	_, tag := edgeSnapshot(t, e)
	first := h.crawlerStatus(src).attempt

	h.advance(time.Minute)
	h.refreshBotsOnce() // unchanged success
	second := h.crawlerStatus(src).attempt
	status(t, e.do("GET", "/v1/snapshot", nil, "If-None-Match", tag), 304)
	if !second.After(first) {
		t.Fatalf("last_attempt_at %v did not move past %v after an unchanged success", second, first)
	}

	h.advance(time.Minute)
	f.set("")
	h.refreshBotsOnce() // failure
	status(t, e.do("GET", "/v1/snapshot", nil, "If-None-Match", tag), 304)
	if third := h.crawlerStatus(src).attempt; !third.After(second) {
		t.Fatalf("last_attempt_at %v did not move past %v after a failure", third, second)
	}
}

// crawlerRow is one source of GET /api/verified-bots.
type crawlerRow struct {
	Source          string     `json:"source"`
	Prefixes        int        `json:"prefixes"`
	RangesChangedAt *time.Time `json:"ranges_changed_at"`
	LastSuccessAt   *time.Time `json:"last_success_at"`
	LastAttemptAt   *time.Time `json:"last_attempt_at"`
	Failures        int        `json:"failures"`
	LastError       *string    `json:"last_error"`
	Stale           bool       `json:"stale"`
}

func TestVerifiedBotSourcesListEveryConfiguredSourceToStatsReaders(t *testing.T) {
	t.Run("lists sources in configuration order with their state and a stale flag from the signal threshold", func(t *testing.T) {
		h, pub, f, _ := botHarness(t)
		g := newFakeRanges(t, "") // never succeeds
		e := newFakeRanges(t, rangesJSON("157.55.39.0/24"))
		h.trustRanges(f, g, e)
		srcF, srcG, srcE := f.srv.URL+"/googlebot.json", g.srv.URL+"/bingbot.json", e.srv.URL+"/other.json"
		// Neither ascending nor descending, so the order can only come from configuration.
		srcs := []string{srcF, srcG, srcE}
		slices.Sort(srcs)
		srcs = []string{srcs[1], srcs[2], srcs[0]}
		h.s.cfg.VerifiedBotSources = srcs
		reader := h.client()
		reader.token = pub.userToken("stats.read")
		list := func() []crawlerRow {
			t.Helper()
			return decode[[]crawlerRow](t, reader.do("GET", "/api/verified-bots", nil))
		}

		before := list()
		if len(before) != 3 || before[0].Source != srcs[0] || before[1].Source != srcs[1] || before[2].Source != srcs[2] ||
			before[0].LastAttemptAt != nil || before[0].LastSuccessAt != nil || before[0].Prefixes != 0 || before[0].Stale {
			t.Fatalf("before any refresh %+v", before)
		}

		h.refreshBotsOnce()
		h.advance(time.Minute)
		h.refreshBotsOnce()
		h.advance(time.Minute)
		h.refreshBotsOnce()
		rows := map[string]crawlerRow{}
		after := list()
		for i, r := range after {
			rows[r.Source] = r
			if r.Source != srcs[i] {
				t.Fatalf("row %d is %s, want %s", i, r.Source, srcs[i])
			}
		}
		good, bad := rows[srcF], rows[srcG]
		if good.Prefixes != 2 || good.RangesChangedAt == nil || good.LastSuccessAt == nil || good.LastAttemptAt == nil || good.Failures != 0 || good.LastError != nil || good.Stale {
			t.Fatalf("good source %+v", good)
		}
		if bad.Prefixes != 0 || bad.LastSuccessAt != nil || bad.LastAttemptAt == nil || bad.Failures != 3 || bad.LastError == nil || !bad.Stale {
			t.Fatalf("failing source %+v", bad)
		}

		n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
		s := n.Signals["verified_bots_stale"]
		s.MinEvents = 4
		n.Signals["verified_bots_stale"] = s
		status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
		for _, r := range list() {
			if r.Stale {
				t.Fatalf("%s is stale at 3 failures with min_events 4", r.Source)
			}
		}
	})
	t.Run("a token without stats.read is refused", func(t *testing.T) {
		_, pub, _, _ := botHarness(t)
		c := pub.h.client()
		c.token = pub.userToken("config.read")
		status(t, c.do("GET", "/api/verified-bots", nil), 403)
	})
	t.Run("no configured sources is an empty list", func(t *testing.T) {
		h := newHarness(t)
		h.user("pub", "admin")
		resp := h.signedIn("pub").do("GET", "/api/verified-bots", nil)
		code := resp.StatusCode
		if got := strings.TrimSpace(body(resp)); code != 200 || got != "[]" {
			t.Fatalf("%d %s", code, got)
		}
	})
}

// A Postgres failure while storing ranges is the admin's own fault, not the
// source's: it counts as a failed job, the other sources still refresh, and
// the source whose store failed is not charged a failed refresh.
func TestVerifiedBotStoreFailureCountsAsAFailedJob(t *testing.T) {
	h, _, f, _ := botHarness(t)
	g := newFakeRanges(t, rangesJSON("157.55.39.0/24"))
	h.trustRanges(f, g)
	srcF, srcG := f.srv.URL+"/googlebot.json", g.srv.URL+"/bingbot.json"
	h.s.cfg.VerifiedBotSources = []string{srcF, srcG}
	h.refreshBotsOnce()

	if _, err := h.owner.Exec(t.Context(), "REVOKE INSERT, UPDATE ON verified_bot_sets FROM "+testenv.AppRole); err != nil {
		t.Fatal(err)
	}
	h.advance(time.Minute)
	f.set(rangesJSON("66.249.64.0/27", "66.249.66.0/27"))
	leadBriefly(t, h, func() bool {
		return strings.Contains(h.metrics(), `admin_background_job_failures_total{job="verified_bots"} 1`+"\n")
	})

	// The clock stood still during the job, so a row written by it carries now.
	if g := h.crawlerStatus(srcG); !g.attempt.Equal(h.now()) || g.failures != 0 {
		t.Fatalf("other source %+v, now %v", g, h.now())
	}
	if f := h.crawlerStatus(srcF); !f.attempt.Before(h.now()) || f.failures != 0 {
		t.Fatalf("source whose store failed %+v, now %v", f, h.now())
	}
}

// A Postgres failure while recording a source's status counts as a failed
// job too, and the ranges of the sources are still stored: status is
// telemetry and must not hold up what edges are served.
func TestVerifiedBotStatusStoreFailureCountsAsAFailedJob(t *testing.T) {
	h, _, f, _ := botHarness(t)
	g := newFakeRanges(t, rangesJSON("157.55.39.0/24"))
	h.trustRanges(f, g)
	srcF, srcG := f.srv.URL+"/googlebot.json", g.srv.URL+"/bingbot.json"
	h.s.cfg.VerifiedBotSources = []string{srcF, srcG}
	h.refreshBotsOnce()

	if _, err := h.owner.Exec(t.Context(), "REVOKE INSERT, UPDATE ON verified_bot_status FROM "+testenv.AppRole); err != nil {
		t.Fatal(err)
	}
	f.set(rangesJSON("66.249.64.0/27", "66.249.66.0/27"))
	g.set(rangesJSON("157.55.39.0/24", "207.46.13.0/24"))
	leadBriefly(t, h, func() bool {
		return strings.Contains(h.metrics(), `admin_background_job_failures_total{job="verified_bots"} 1`+"\n")
	})

	for _, src := range []string{srcF, srcG} {
		var n int
		if err := h.db.QueryRow(t.Context(), "SELECT jsonb_array_length(prefixes) FROM verified_bot_sets WHERE source_url = $1", src).Scan(&n); err != nil || n != 2 {
			t.Fatalf("%s stores %d prefixes, err %v", src, n, err)
		}
	}
}

// crawlerNotifyHarness is admin with notifications on and the autopilot off,
// where an anomaly fires on its first tripped check and resolves on its first
// passing one, and one crawler source that starts good.
func crawlerNotifyHarness(t *testing.T) (*harness, *client, *fakeRanges, *fakeAlertmanager, string) {
	t.Helper()
	am := newFakeAlertmanager(t)
	f := newFakeRanges(t, rangesJSON("66.249.64.0/27"))
	src := f.srv.URL + "/googlebot.json"
	h := newHarnessWith(t, map[string]string{"ALERTMANAGER_URL": am.srv.URL + "/", "VERIFIED_BOT_SOURCES": src})
	h.trustRanges(f)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v1"), 201)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter, n.ResolveAfter = 1, 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	return h, pub, f, am, src
}

func staleOf(h *harness, pub *client) *anomaly {
	h.t.Helper()
	for _, a := range h.anomalies(pub) {
		if a.Signal == "verified_bots_stale" {
			return &a
		}
	}
	return nil
}

// A crawler list that keeps failing quietly turns every crawler exemption
// into a stale one, so it raises an anomaly after three failures in a row and
// ends it on the next good refresh.
// An admin that saved notification settings before this signal existed
// notifies on a stale source at the default threshold and can save again.
func TestStaleCrawlerSignalIsOnForSettingsSavedBeforeIt(t *testing.T) {
	h, pub, f, am, src := crawlerNotifyHarness(t)
	old := decode[map[string]any](t, pub.do("GET", "/api/settings/notifications", nil))
	delete(old["signals"].(map[string]any), "verified_bots_stale")
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(t.Context(), "UPDATE settings SET value = $1 WHERE key = 'notifications'", b); err != nil {
		t.Fatal(err)
	}
	h.refreshBotsOnce()
	f.set("")
	for range 3 {
		h.advance(time.Minute)
		h.refreshBotsOnce()
	}
	h.check()
	if a := staleOf(h, pub); a == nil || a.State != "firing" || a.Rule != src {
		t.Fatalf("anomaly %+v", a)
	}
	if len(am.sent("verified_bots_stale")) == 0 {
		t.Fatal("not sent to Alertmanager")
	}
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
}

func TestStaleCrawlerSourceNotifiesAndResolvesOnTheNextGoodRefresh(t *testing.T) {
	h, pub, f, am, src := crawlerNotifyHarness(t)
	h.refreshBotsOnce()
	f.set("")
	for range 2 {
		h.advance(time.Minute)
		h.refreshBotsOnce()
		h.check()
	}
	if a := staleOf(h, pub); a != nil {
		t.Fatalf("anomaly after two failures %+v", a)
	}

	h.advance(time.Minute)
	h.refreshBotsOnce()
	h.check()
	a := staleOf(h, pub)
	if a == nil || a.State != "firing" || a.Rule != src || a.Phase != "verified_bots" {
		t.Fatalf("anomaly after three failures %+v", a)
	}
	if strings.Contains(a.Summary, "status 500") || strings.Contains(a.Summary, "fetch") {
		t.Fatalf("summary carries the remote error: %q", a.Summary)
	}
	if !slices.Contains(h.actions(), "anomaly.fire source "+src) {
		t.Fatalf("firing not audited: %v", h.actions())
	}
	sent := am.sent("verified_bots_stale")
	if len(sent) == 0 || sent[0].Labels["phase"] != "verified_bots" || sent[0].Labels["rule"] != src {
		t.Fatalf("sent %+v", sent)
	}
	if strings.Contains(sent[0].Annotations["description"], "status 500") {
		t.Fatalf("alert description carries the remote error: %q", sent[0].Annotations["description"])
	}

	// A recovered source has no finding, so it resolves at the next check
	// whatever resolve_after is.
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.ResolveAfter = defaultNotify().ResolveAfter
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	f.set(rangesJSON("66.249.64.0/27"))
	h.advance(time.Minute)
	h.refreshBotsOnce()
	h.check()
	if a := staleOf(h, pub); a == nil || a.State != "resolved" {
		t.Fatalf("anomaly after a good refresh %+v", a)
	}
	if !slices.Contains(h.actions(), "anomaly.resolve source "+src) {
		t.Fatalf("resolving not audited: %v", h.actions())
	}
}

// Taking a source out of VERIFIED_BOT_SOURCES ends its problem: nothing is
// left to refresh, so its status goes and its anomaly resolves.
func TestRemovedCrawlerSourceResolvesItsAnomalyAndDropsItsStatus(t *testing.T) {
	h, pub, f, _, src := crawlerNotifyHarness(t)
	g := newFakeRanges(t, rangesJSON("157.55.39.0/24"))
	h.trustRanges(f, g)
	srcG := g.srv.URL + "/bingbot.json"
	h.s.cfg.VerifiedBotSources = []string{src, srcG}
	f.set("")
	for range 3 {
		h.advance(time.Minute)
		h.refreshBotsOnce()
	}
	h.check()
	if a := staleOf(h, pub); a == nil || a.State != "firing" {
		t.Fatalf("anomaly before removal %+v", a)
	}

	h.s.cfg.VerifiedBotSources = []string{srcG}
	h.advance(time.Minute)
	h.refreshBotsOnce()
	h.check()
	var removed, kept int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM verified_bot_status WHERE source_url = $1", src).Scan(&removed); err != nil || removed != 0 {
		t.Fatalf("%d status rows for the removed source, err %v", removed, err)
	}
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM verified_bot_status WHERE source_url = $1", srcG).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("%d status rows for the kept source, err %v", kept, err)
	}
	if a := staleOf(h, pub); a == nil || a.State != "resolved" {
		t.Fatalf("anomaly after removal %+v", a)
	}
	if !slices.Contains(h.actions(), "anomaly.resolve source "+src) {
		t.Fatalf("resolving not audited: %v", h.actions())
	}
}

// Ranges stored by an admin from before status was recorded are still what
// edges match, so a source that then fails reports when they were fetched,
// not that it never succeeded.
func TestStaleCrawlerSourceWithStoredRangesReportsWhenTheyWereFetched(t *testing.T) {
	h, pub, f, _, src := crawlerNotifyHarness(t)
	fetched := h.now().Add(-72 * time.Hour)
	if _, err := h.owner.Exec(t.Context(), "INSERT INTO verified_bot_sets (source_url, fetched_at, prefixes) VALUES ($1, $2, '[\"66.249.64.0/27\"]')", src, fetched); err != nil {
		t.Fatal(err)
	}
	f.set("")
	for range 3 {
		h.advance(time.Minute)
		h.refreshBotsOnce()
	}
	h.check()
	want := "Fetching it failed 3 times in a row; edges still treat addresses in its ranges from " + fetched.UTC().Format(time.RFC3339) + " as verified crawlers"
	if a := staleOf(h, pub); a == nil || a.Summary != want {
		t.Fatalf("anomaly %+v, want summary %q", a, want)
	}
	rows := decode[[]crawlerRow](t, pub.do("GET", "/api/verified-bots", nil))
	if len(rows) != 1 || rows[0].LastSuccessAt == nil || !rows[0].LastSuccessAt.Equal(fetched) || !rows[0].Stale {
		t.Fatalf("rows %+v, want last_success_at %v", rows, fetched)
	}
}

// With the signal off and no threshold saved, no anomaly fires, but Fleet
// still judges a source stale at the default of three failures.
func TestVerifiedBotSignalOffStillMarksASourceStale(t *testing.T) {
	h, pub, f, _, src := crawlerNotifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.Signals["verified_bots_stale"] = NotifySignal{Mode: "off"}
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	f.set("")
	for range 3 {
		h.advance(time.Minute)
		h.refreshBotsOnce()
		h.check()
	}
	if a := staleOf(h, pub); a != nil {
		t.Fatalf("anomaly with the signal off %+v", a)
	}
	rows := decode[[]crawlerRow](t, pub.do("GET", "/api/verified-bots", nil))
	if len(rows) != 1 || rows[0].Source != src || rows[0].Failures != 3 || !rows[0].Stale {
		t.Fatalf("rows %+v", rows)
	}
}

// With the threshold at one, the summary must still read as a sentence: an
// operator sees it in Needs attention and in the alert.
func TestStaleCrawlerSummaryReadsRightForOneFailure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		succeedFirst bool
		want         func(success time.Time) string
	}{
		{"a source that never succeeded", false, func(time.Time) string {
			return "Fetching it failed 1 time in a row and has never succeeded, so no address counts as this source's verified crawler"
		}},
		{"a source that had a success", true, func(success time.Time) string {
			return "Fetching it failed 1 time in a row; edges still treat addresses in its ranges from " + success.UTC().Format(time.RFC3339) + " as verified crawlers"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, f, _, _ := crawlerNotifyHarness(t)
			n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
			sig := n.Signals["verified_bots_stale"]
			sig.MinEvents = 1
			n.Signals["verified_bots_stale"] = sig
			status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
			success := h.now()
			if tc.succeedFirst {
				h.refreshBotsOnce()
				h.advance(time.Minute)
			}
			f.set("")
			h.refreshBotsOnce()
			h.check()
			if want := tc.want(success); staleOf(h, pub) == nil || staleOf(h, pub).Summary != want {
				t.Fatalf("anomaly %+v, want summary %q", staleOf(h, pub), want)
			}
		})
	}
}
