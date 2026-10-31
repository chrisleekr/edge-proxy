package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

func (h *harness) live(instance string, versions ...int64) {
	h.t.Helper()
	if _, err := h.db.Exec(context.Background(), "INSERT INTO fleet (instance, last_seen, config_source, bootstrap_age_seconds, versions, max_schema) VALUES ($1, $2, 'admin', 0, $3, $4) ON CONFLICT (instance) DO UPDATE SET versions = $3, last_seen = $2", instance, h.now(), versions, snapshot.SupportedSchema); err != nil {
		h.t.Fatal(err)
	}
}

func TestGuardAbortsABadCanary(t *testing.T) {
	h, pub := published(t)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	h.advance(6 * time.Minute)
	h.live("edge-a", 1, 2)
	h.putStats(1, 5, 10_000, 10, 0, []int64{10_000}, "[]", "[]") // active: 0.1% edge 5xx
	h.putStats(2, 5, 1_000, 100, 0, []int64{1_000}, "[]", "[]")  // candidate: 10%
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	v := decode[versionRow](t, pub.do("GET", "/api/versions/2", nil))
	var out guardOutcome
	_ = json.Unmarshal(v.GuardOutcome, &out)
	if v.Status != "rolled_back" || out.Decision != "rollback" || !out.Signals["edge_5xx_ratio"].Tripped {
		t.Fatalf("version %s, outcome %+v", v.Status, out)
	}
	if !slices.Contains(h.actions(), "guard.canary_abort version 2") {
		t.Fatal("abort not audited")
	}
	// An abort makes no new version.
	h.wantMetrics(`admin_guard_actions_total{action="canary_abort"} 1`, `admin_guard_actions_total{action="rollback"} 0`, `admin_publishes_total{source="guard_rollback"} 0`)
}

// The guard judges state it read before taking the publish lock. If an
// operator promoted the canary meanwhile, the guard must not roll back what
// is now the active version.
func TestGuardSkipsStateThatChanged(t *testing.T) {
	h, pub := published(t)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	ctx := t.Context()
	c, _ := loadCanary(ctx, h.db)
	subject, _ := h.s.loadVersion(ctx, h.db, 2)
	baseline, _ := h.s.loadVersion(ctx, h.db, 1)
	h.advance(6 * time.Minute)
	h.putStats(2, 5, 1_000, 0, 0, []int64{1_000}, "[]", "[]")
	status(t, pub.do("POST", "/api/canary/promote", nil), 204)

	if err := h.s.act(ctx, defaultGuard(), subject, baseline, c, guardOutcome{At: h.now(), Decision: "rollback"}); err != nil {
		t.Fatal(err)
	}
	if v := decode[versionRow](t, pub.do("GET", "/api/versions/2", nil)); v.Status != "active" || string(v.GuardOutcome) != "null" {
		t.Fatalf("version 2 %s, outcome %s", v.Status, v.GuardOutcome)
	}

	// Same after a full rollout replaced the version being judged.
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v3"), 201)
	if err := h.s.act(ctx, defaultGuard(), subject, baseline, nil, guardOutcome{At: h.now(), Decision: "rollback"}); err != nil {
		t.Fatal(err)
	}
	if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 3 || list[0].Status != "active" {
		t.Fatalf("versions %+v", list)
	}
	h.wantMetrics(`admin_guard_actions_total{action="rollback"} 0`, `admin_guard_actions_total{action="canary_abort"} 0`,
		`admin_guard_actions_total{action="alert"} 0`, `admin_publishes_total{source="guard_rollback"} 0`)
}

func TestGuardAfterFullRollout(t *testing.T) {
	h, pub := published(t)
	h.putStats(1, 10, 2_000, 0, 10, []int64{2_000}, "[]", "[]") // before publish
	h.advance(time.Minute)
	c := testConfig()
	c.RateLimitRules[0].Limit = 9
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	h.advance(5 * time.Minute)
	h.live("edge-a", 2)
	h.putStats(2, 4, 2_000, 0, 400, []int64{2_000}, "[]", "[]") // 5% upstream 5xx
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil))
	if len(list) != 3 || list[0].Source != "guard_rollback" || *list[0].BasedOn != 1 || list[0].Status != "active" || list[1].Status != "rolled_back" || list[0].Author != "system:guard" {
		t.Fatalf("versions %+v", list)
	}
	// A full rollout is compared with the version it replaced.
	var out guardOutcome
	if err := json.Unmarshal(decode[versionRow](t, pub.do("GET", "/api/versions/2", nil)).GuardOutcome, &out); err != nil {
		t.Fatal(err)
	}
	if out.Decision != "rollback" || out.Baseline != 1 {
		t.Fatalf("outcome %+v", out)
	}
	// The rollback is watched but never rolled back.
	h.putStats(3, 4, 2_000, 0, 400, []int64{2_000}, "[]", "[]")
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 3 {
		t.Fatalf("rolled back a rollback: %d versions", len(list))
	}
	// The rollback counts as an action and as a version of its own.
	h.wantMetrics(`admin_guard_actions_total{action="rollback"} 1`, `admin_publishes_total{source="guard_rollback"} 1`, `admin_guard_actions_total{action="alert"} 0`)
}

func TestGuardSignals(t *testing.T) {
	g := defaultGuard()
	base := &cohort{Requests: 10_000, Edge5xx: 10, LatencyMS: []uint64{9_000, 1_000}, rules: map[string]*edge.RuleCounts{
		"login": {ID: "login", Evaluated: 1_000, Limited: 10, WouldLimit: 0}, "search": {ID: "search", Evaluated: 1_000, WouldLimit: 20},
	}}
	cases := []struct {
		name    string
		sub     *cohort
		changed []string
		adopt   float64
		signal  string
		tripped bool
	}{
		{"edge 5xx double and over the floor", &cohort{Requests: 1_000, Edge5xx: 30}, nil, 1, "edge_5xx_ratio", true},
		{"edge 5xx double but under the floor", &cohort{Requests: 10_000, Edge5xx: 25}, nil, 1, "edge_5xx_ratio", false},
		{"p99 in a slower bucket", &cohort{Requests: 1_000, LatencyMS: []uint64{0, 0, 0, 0, 0, 0, 1_000}}, nil, 1, "p99_latency", true},
		{"changed rule limiting 10%", &cohort{Requests: 1_000, rules: map[string]*edge.RuleCounts{"login": {ID: "login", Evaluated: 100, Limited: 10}}}, []string{"login"}, 1, "changed_rule_limited_ratio", true},
		{"changed rule far tighter than its shadow estimate", &cohort{Requests: 1_000, rules: map[string]*edge.RuleCounts{"search": {ID: "search", Evaluated: 1_000, Limited: 49}}}, []string{"search"}, 1, "changed_rule_limited_ratio", false},
		{"changed rule tighter than 3x shadow", &cohort{Requests: 1_000, rules: map[string]*edge.RuleCounts{"search": {ID: "search", Evaluated: 1_000, Limited: 61}}}, []string{"search"}, 1, "changed_rule_limited_ratio", true},
		{"unchanged rule limiting 4x more", &cohort{Requests: 1_000, rules: map[string]*edge.RuleCounts{"login": {ID: "login", Evaluated: 1_000, Limited: 41}}}, nil, 1, "unchanged_rule_limited_ratio", true},
		{"fleet hasn't loaded the version", &cohort{Requests: 1_000}, nil, 0.5, "fleet_adoption", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := map[string]bool{}
			for _, id := range tc.changed {
				changed[id] = true
			}
			if tc.sub.rules == nil {
				tc.sub.rules = map[string]*edge.RuleCounts{}
			}
			res := evaluate(g, tc.sub, base, changed, tc.adopt, 3*time.Minute)
			if res[tc.signal].Tripped != tc.tripped {
				t.Fatalf("%s = %+v", tc.signal, res[tc.signal])
			}
		})
	}
	// Validation requires exactly the signals evaluate computes: one it
	// requires but never computes could never trip.
	all := evaluate(g, &cohort{Requests: 1_000, rules: map[string]*edge.RuleCounts{}}, base, nil, 1, 0)
	if got := slices.Sorted(maps.Keys(all)); !slices.Equal(got, signalNames) {
		t.Fatalf("evaluate computes %v, validation requires %v", got, signalNames)
	}
	// A signal turned off never trips.
	g.Signals["edge_5xx_ratio"] = Signal{Mode: "off", Factor: 2, Floor: 0.01}
	if evaluate(g, &cohort{Requests: 1_000, Edge5xx: 500, rules: map[string]*edge.RuleCounts{}}, base, nil, 1, 0)["edge_5xx_ratio"].Tripped {
		t.Fatal("off signal tripped")
	}
}

// A trip names the rule that tripped, with its own numbers, even when
// another rule limits a larger share without tripping. Otherwise the alert
// points the operator at a rule that is fine.
func TestGuardNamesTheRuleThatTripped(t *testing.T) {
	g := defaultGuard()
	base := &cohort{Requests: 10_000, rules: map[string]*edge.RuleCounts{
		"api":    {ID: "api", Evaluated: 1_000, Limited: 10, WouldLimit: 10},
		"login":  {ID: "login", Evaluated: 1_000, Limited: 300},
		"search": {ID: "search", Evaluated: 1_000, Limited: 10},
	}}
	cases := []struct {
		name     string
		changed  []string
		search   uint64
		signal   string
		baseline float64
	}{
		// api goes from 1% to 4%, over 3x. login, sorted after it, limits
		// 35% against 30% and search 2% against 1%: neither trips.
		{"unchanged rule", nil, 20, "unchanged_rule_limited_ratio", 0.01},
		// api, changed, limits 4%, over 3x its 1% shadow estimate. search,
		// also changed and sorted after it, limits 4.5% with no shadow
		// estimate, under the 5% cap.
		{"changed rule", []string{"api", "search"}, 45, "changed_rule_limited_ratio", 0.05},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := map[string]bool{}
			for _, id := range tc.changed {
				changed[id] = true
			}
			sub := &cohort{Requests: 1_000, rules: map[string]*edge.RuleCounts{
				"api":    {ID: "api", Evaluated: 1_000, Limited: 40},
				"login":  {ID: "login", Evaluated: 1_000, Limited: 350},
				"search": {ID: "search", Evaluated: 1_000, Limited: tc.search},
			}}
			res := evaluate(g, sub, base, changed, 1, 3*time.Minute)[tc.signal]
			if !res.Tripped || res.Detail != "api" || res.Value != 0.04 || res.Baseline != tc.baseline {
				t.Fatalf("%s = %+v, want tripped by api at 0.04 against %v", tc.signal, res, tc.baseline)
			}
		})
	}
}

// One attacker's few IPs don't make a changed rule look too tight: the
// most-limited subjects are left out.
func TestGuardLeavesOutTheMostLimited(t *testing.T) {
	h, pub := published(t)
	c := testConfig()
	c.RateLimitRules[0].Limit = 3
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	h.advance(6 * time.Minute)
	h.live("edge-a", 1, 2)
	h.putStats(1, 5, 10_000, 0, 0, []int64{10_000}, `[{"id":"login","evaluated":1000,"limited":0}]`, "[]")
	h.putStats(2, 5, 1_000, 0, 0, []int64{1_000}, `[{"id":"login","evaluated":1000,"limited":400}]`,
		`[{"rule":"login","key":"k","display":"198.51.100.7","limited":395}]`)
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	var out guardOutcome
	_ = json.Unmarshal(decode[versionRow](t, pub.do("GET", "/api/versions/2", nil)).GuardOutcome, &out)
	if out.Decision != "ok" || out.Signals["changed_rule_limited_ratio"].Tripped {
		t.Fatalf("outcome %+v", out)
	}
}

func TestGuardAlertsOnceAndNeedsData(t *testing.T) {
	h, pub := published(t)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	h.advance(6 * time.Minute)
	h.live("edge-a", 1, 2)
	h.putStats(2, 5, 100, 0, 0, []int64{100}, "[]", "[]")
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	var out guardOutcome
	_ = json.Unmarshal(decode[versionRow](t, pub.do("GET", "/api/versions/2", nil)).GuardOutcome, &out)
	if out.Decision != "insufficient_data" {
		t.Fatalf("outcome %+v", out)
	}
	h.putStats(1, 5, 10_000, 0, 0, []int64{10_000}, "[]", "[]")
	h.putStats(2, 5, 1_000, 0, 0, []int64{0, 0, 0, 0, 0, 0, 0, 1_000}, "[]", "[]") // p99 alert only
	for range 2 {
		if err := h.s.runGuard(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for _, a := range h.actions() {
		if a == "guard.alert version 2" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d alerts", n)
	}
	h.wantMetrics(`admin_guard_actions_total{action="alert"} 1`)
	// The outcome names the live version the canary was compared with.
	var alert guardOutcome
	if err := json.Unmarshal(decode[versionRow](t, pub.do("GET", "/api/versions/2", nil)).GuardOutcome, &alert); err != nil {
		t.Fatal(err)
	}
	if alert.Decision != "alert" || alert.Baseline != 1 {
		t.Fatalf("outcome %+v", alert)
	}
}

func TestGuardSettings(t *testing.T) {
	h, pub := published(t)
	g := decode[GuardSettings](t, pub.do("GET", "/api/settings/guard", nil))
	if !g.Enabled || g.MinRequests != 1000 {
		t.Fatalf("defaults %+v", g)
	}
	g.MinRequests = 50
	status(t, pub.do("PUT", "/api/settings/guard", g), 204)
	if decode[GuardSettings](t, pub.do("GET", "/api/settings/guard", nil)).MinRequests != 50 {
		t.Fatal("not saved")
	}
	g.Signals["made_up"] = Signal{Mode: "rollback"}
	status(t, pub.do("PUT", "/api/settings/guard", g), 422)
	delete(g.Signals, "made_up")
	g.Enabled = false
	status(t, pub.do("PUT", "/api/settings/guard", g), 204)
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.actions(), "settings.guard ") {
		t.Fatal("settings change not audited")
	}
}

// A signal left out, or one without the threshold its mode needs, would
// silently never trip or trip on any traffic. Both are refused.
func TestGuardSettingsNeedEverySignalAndItsThresholds(t *testing.T) {
	_, pub := published(t)
	cases := []struct {
		name   string
		change func(g *GuardSettings)
		path   string
	}{
		{"signal left out", func(g *GuardSettings) { delete(g.Signals, "edge_5xx_ratio") }, "signals.edge_5xx_ratio"},
		{"rollback without a factor", func(g *GuardSettings) { g.Signals["edge_5xx_ratio"] = Signal{Mode: "rollback", Floor: 0.01} }, "signals.edge_5xx_ratio"},
		{"factor below 1", func(g *GuardSettings) { g.Signals["p99_latency"] = Signal{Mode: "alert", Factor: 0.5, FloorMS: 50} }, "signals.p99_latency"},
		{"ratio floor above 1", func(g *GuardSettings) { g.Signals["auth_failure_ratio"] = Signal{Mode: "alert", Factor: 2, Floor: 2} }, "signals.auth_failure_ratio"},
		{"adoption without a minimum", func(g *GuardSettings) {
			g.Signals["fleet_adoption"] = Signal{Mode: "rollback", After: snapshot.Duration(time.Minute)}
		}, "signals.fleet_adoption"},
		{"changed rules without a shadow factor", func(g *GuardSettings) {
			g.Signals["changed_rule_limited_ratio"] = Signal{Mode: "rollback", MaxRatio: 0.05}
		}, "signals.changed_rule_limited_ratio"},
		{"unchanged rules without a factor", func(g *GuardSettings) { g.Signals["unchanged_rule_limited_ratio"] = Signal{Mode: "alert"} }, "signals.unchanged_rule_limited_ratio"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := defaultGuard()
			tc.change(&g)
			p := decode[problem](t, pub.do("PUT", "/api/settings/guard", g))
			if len(p.Errors) != 1 || p.Errors[0].Path != tc.path {
				t.Fatalf("errors %+v", p.Errors)
			}
		})
	}
	// A signal that is off needs no thresholds.
	g := defaultGuard()
	g.Signals["edge_5xx_ratio"] = Signal{Mode: "off"}
	status(t, pub.do("PUT", "/api/settings/guard", g), 204)
}

// A publisher can loosen the guard for one publish with a reason: a change
// expected to limit more traffic is then alerted on, not rolled back.
func TestPerPublishGuardOverride(t *testing.T) {
	h, pub := published(t)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	loose := defaultGuard()
	loose.Signals["edge_5xx_ratio"] = Signal{Mode: "alert", Factor: 2, Floor: 0.01}
	req := map[string]any{"message": "v2", "canary_percent": 10, "guard_override": loose}
	status(t, pub.do("POST", "/api/publish", req, "If-Match", pub.revision()), 422) // no reason
	req["guard_override_reason"] = "maintenance page returns 503 on purpose"
	status(t, pub.do("POST", "/api/publish", req, "If-Match", pub.revision()), 201)
	// The audit row keeps the saved settings beside the override, so it can
	// say what this publish changed.
	var saved, override string
	if err := h.db.QueryRow(t.Context(), `SELECT details->'guard_settings'->'signals'->'edge_5xx_ratio'->>'mode', details->'guard_override'->'signals'->'edge_5xx_ratio'->>'mode'
		FROM audit_events WHERE action = 'config.publish' ORDER BY seq DESC LIMIT 1`).Scan(&saved, &override); err != nil || saved != "rollback" || override != "alert" {
		t.Fatalf("audit guard settings %q, override %q, err %v", saved, override, err)
	}

	h.advance(6 * time.Minute)
	h.live("edge-a", 1, 2)
	h.putStats(1, 5, 10_000, 10, 0, []int64{10_000}, "[]", "[]")
	h.putStats(2, 5, 1_000, 100, 0, []int64{1_000}, "[]", "[]")
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	v := decode[versionRow](t, pub.do("GET", "/api/versions/2", nil))
	var out guardOutcome
	_ = json.Unmarshal(v.GuardOutcome, &out)
	if v.Status != "canary" || out.Decision != "alert" || *v.GuardOverrideReason != "maintenance page returns 503 on purpose" {
		t.Fatalf("status %s, outcome %+v", v.Status, out)
	}
}

// A change that limits many clients a little each must still roll back.
// Their sampled top-K estimates (16 per sample) add up to the whole limited
// count, so leaving all of them out hid exactly this over-block.
func TestGuardCatchesBroadOverBlocking(t *testing.T) {
	h, pub := published(t)
	c := testConfig()
	c.RateLimitRules[0].Limit = 1
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 50}, "If-Match", pub.revision()), 201)
	h.advance(6 * time.Minute)
	h.live("edge-a", 1, 2)
	var top []string
	for i := range 60 {
		top = append(top, fmt.Sprintf(`{"rule":"login","key":"k%d","display":"20.0.0.%d","limited":16}`, i, i))
	}
	h.putStats(1, 5, 3_000, 0, 0, []int64{3_000}, `[{"id":"login","evaluated":3000,"limited":0}]`, "[]")
	h.putStats(2, 5, 3_000, 0, 0, []int64{3_000}, `[{"id":"login","evaluated":3000,"limited":900}]`, "["+strings.Join(top, ",")+"]")
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	var out guardOutcome
	_ = json.Unmarshal(decode[versionRow](t, pub.do("GET", "/api/versions/2", nil)).GuardOutcome, &out)
	if out.Decision != "rollback" || !out.Signals["changed_rule_limited_ratio"].Tripped {
		t.Fatalf("outcome %+v", out)
	}
}

// acrossAnAutopilotPublish publishes a person's version 2, which tightens
// login to 9, and two minutes later autopilot's version 3, which adds
// ap-scraper; the clock ends 3 minutes after that. Version 1 served 2,000
// requests a minute for the 10 minutes before version 2. Versions 2 and 3
// then served 1,000 a minute each, upstream5xx of them failing, with
// subjectRules as their rate-limit counts. edge-a runs version 3.
func acrossAnAutopilotPublish(t *testing.T, upstream5xx int64, subjectRules string) (*harness, *client) {
	t.Helper()
	h, pub := published(t) // version 1: login at 10
	h.putStats(1, 10, 2_000, 0, 0, []int64{2_000}, "[]", "[]")
	c := testConfig()
	c.RateLimitRules[0].Limit = 9
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("Tighten login"), 201) // version 2
	h.advance(2 * time.Minute)
	h.putStats(2, 2, 1_000, 0, upstream5xx, []int64{1_000}, subjectRules, "[]")
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 3
	h.advance(3 * time.Minute)
	h.putStats(3, 3, 1_000, 0, upstream5xx, []int64{1_000}, subjectRules, "[]")
	h.live("edge-a", 3)
	return h, pub
}

// outcomeOf is the guard outcome stored on version v, or "" before one.
func outcomeOf(t *testing.T, pub *client, v int64) guardOutcome {
	t.Helper()
	var out guardOutcome
	if raw := pub.version(v).GuardOutcome; string(raw) != "null" {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// Autopilot publishes often during an attack. Each one must not hide the
// person's publish before it from the guard: the guard judges the person's
// version over its own minutes and every autopilot version after it, and a
// rollback restores the rules before it under today's overlay.
func TestGuardJudgesPeoplesPublishAcrossAutopilotPublishes(t *testing.T) {
	t.Run("a person's publish that breaks the upstream rolls back after an autopilot publish", func(t *testing.T) {
		h, pub := acrossAnAutopilotPublish(t, 50, "[]") // 5% upstream 5xx against none
		if err := h.s.runGuard(t.Context()); err != nil {
			t.Fatal(err)
		}
		if out := outcomeOf(t, pub, 2); out.Decision != "rollback" || out.Baseline != 1 || !out.Signals["upstream_5xx_ratio"].Tripped {
			t.Fatalf("version 2 outcome %+v", out)
		}
		got := pub.version(4)
		if got.Source != "guard_rollback" || got.BasedOn == nil || *got.BasedOn != 1 || got.Status != "active" ||
			!slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || limitOf(got.Config, "login") != 10 {
			t.Fatalf("version 4 %s based on %v %s, rules %v, login limit %d", got.Source, got.BasedOn, got.Status, rateLimitIDs(got.Config), limitOf(got.Config, "login"))
		}
		if v2, v3 := pub.version(2), pub.version(3); v2.Status != "rolled_back" || v3.Status != "superseded" || string(v3.GuardOutcome) != "null" {
			t.Fatalf("version 2 %s, version 3 %s with outcome %s", v2.Status, v3.Status, v3.GuardOutcome)
		}
		if !slices.Contains(h.actions(), "guard.rollback version 2") {
			t.Fatalf("audit %v", h.actions())
		}
	})
	t.Run("edges on a later autopilot version have adopted the person's publish", func(t *testing.T) {
		h, pub := acrossAnAutopilotPublish(t, 0, "[]")
		if err := h.s.runGuard(t.Context()); err != nil {
			t.Fatal(err)
		}
		if out := outcomeOf(t, pub, 2); out.Decision != "ok" || out.Signals["fleet_adoption"].Tripped || out.Signals["fleet_adoption"].Value != 1 {
			t.Fatalf("version 2 outcome %+v", out)
		}
		if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 3 {
			t.Fatalf("%d versions, want 3", len(list))
		}
	})
	t.Run("the person's publish is not judged once its window has passed", func(t *testing.T) {
		h, pub := published(t)
		h.putStats(1, 10, 2_000, 0, 0, []int64{2_000}, "[]", "[]")
		c := testConfig()
		c.RateLimitRules[0].Limit = 9
		status(t, pub.save(pub.revision(), c, adminTest), 200)
		status(t, pub.publishDraft("Tighten login"), 201) // version 2
		h.advance(9 * time.Minute)
		h.putStats(2, 9, 1_000, 0, 50, []int64{1_000}, "[]", "[]")
		h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 3
		h.advance(2 * time.Minute)
		h.putStats(3, 2, 1_000, 0, 50, []int64{1_000}, "[]", "[]")
		h.live("edge-a", 3)
		if err := h.s.runGuard(t.Context()); err != nil {
			t.Fatal(err)
		}
		if v2, v3 := pub.version(2), pub.version(3); string(v2.GuardOutcome) != "null" || string(v3.GuardOutcome) != "null" {
			t.Fatalf("version 2 outcome %s, version 3 outcome %s", v2.GuardOutcome, v3.GuardOutcome)
		}
		if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 3 {
			t.Fatalf("%d versions, want 3", len(list))
		}
	})
}

// Autopilot rules are judged by their own guard, from their own shadow
// counts. The version guard leaves them out, so an autopilot rule blocking
// an attack never rolls back a person's publish.
func TestGuardIgnoresAutopilotRules(t *testing.T) {
	g := defaultGuard()
	base := &cohort{Requests: 10_000, rules: map[string]*edge.RuleCounts{
		"ap-scraper": {ID: "ap-scraper", Evaluated: 1_000, Limited: 10},
	}}
	cases := []struct {
		name    string
		rules   map[string]*edge.RuleCounts
		changed []string
		signal  string
	}{
		{"a new autopilot rule limiting half its requests", map[string]*edge.RuleCounts{"ap-feed": {ID: "ap-feed", Evaluated: 1_000, Limited: 500}},
			[]string{"ap-feed"}, "changed_rule_limited_ratio"},
		{"an autopilot rule limiting ten times more than before", map[string]*edge.RuleCounts{"ap-scraper": {ID: "ap-scraper", Evaluated: 1_000, Limited: 100}},
			nil, "unchanged_rule_limited_ratio"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := map[string]bool{}
			for _, id := range tc.changed {
				changed[id] = true
			}
			res := evaluate(g, &cohort{Requests: 1_000, rules: tc.rules}, base, changed, 1, 3*time.Minute)[tc.signal]
			if res.Tripped || strings.HasPrefix(res.Detail, "ap-") {
				t.Fatalf("%s = %+v", tc.signal, res)
			}
		})
	}
	t.Run("a person's publish is not rolled back for an autopilot rule's blocks", func(t *testing.T) {
		h, pub := acrossAnAutopilotPublish(t, 0, `[{"id":"login","evaluated":100,"limited":0},{"id":"ap-scraper","evaluated":1000,"limited":500}]`)
		if err := h.s.runGuard(t.Context()); err != nil {
			t.Fatal(err)
		}
		if out := outcomeOf(t, pub, 2); out.Decision != "ok" || out.Signals["changed_rule_limited_ratio"].Detail == "ap-scraper" {
			t.Fatalf("version 2 outcome %+v", out)
		}
	})
}

// A rollback restores rules that already ran, so it is never blocked. An
// edge that reads only schema 4 can't load today's overlay, whose rules
// expire, so the rollback publishes without the overlay and says so.
func TestGuardRollbackDropsAnOverlayOldEdgesCannotRead(t *testing.T) {
	h, pub := acrossAnAutopilotPublish(t, 50, "[]")
	e := h.client()
	e.token = h.edgeToken(pub)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "schema-4-edge", MaxSchema: 4, Deployment: h.s.cfg.Deployment.Fingerprint()}), 200)
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := pub.version(4)
	if got.Source != "guard_rollback" || got.BasedOn == nil || *got.BasedOn != 1 || !slices.Equal(rateLimitIDs(got.Config), []string{"login"}) || limitOf(got.Config, "login") != 10 {
		t.Fatalf("version 4 %s based on %v, rules %v, login limit %d", got.Source, got.BasedOn, rateLimitIDs(got.Config), limitOf(got.Config, "login"))
	}
	if v2 := pub.version(2); v2.Status != "rolled_back" {
		t.Fatalf("version 2 %s", v2.Status)
	}
	var dropped bool
	if err := h.db.QueryRow(t.Context(), "SELECT (details->>'overlay_dropped')::boolean FROM audit_events WHERE action = 'config.rollback' AND target = 'version 4'").Scan(&dropped); err != nil || !dropped {
		t.Fatalf("overlay_dropped %v, err %v", dropped, err)
	}
}

// sampledTop is a rule's top subjects as the edges report them: n subjects,
// each with its count, field "limited" or "would_limit", estimated as est.
// The edges sample one request in 16, so est is a multiple of 16 that
// scatters around the exact count from minute to minute.
func sampledTop(rule, field string, n int, est int64) string {
	var parts []string
	for i := range n {
		parts = append(parts, fmt.Sprintf(`{"rule":%q,"key":"k%d","display":"198.51.100.%d",%q:%d}`, rule, i, i+1, field, est))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// statsMinute writes one replica's minute of stats on version, ago
// minutes before now.
func (h *harness) statsMinute(version int64, ago int, requests int64, rules, top string) {
	h.t.Helper()
	h.statsSeq++
	minute := h.now().UTC().Truncate(time.Minute).Add(-time.Duration(ago) * time.Minute)
	if _, err := h.db.Exec(context.Background(), `INSERT INTO edge_stats_minute (minute, version, replica, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited)
		VALUES ($1, $2, $3, $4, 0, 0, 0, $5, $6, $7)`, minute, version, fmt.Sprint("r", h.statsSeq), requests, []int64{requests}, rules, top); err != nil {
		h.t.Fatal(err)
	}
}

// A changed rule whose blocks all go to attackers is not judged too tight
// because the sampled estimates of their counts fall short in some minutes:
// the shortfalls and the overshoots cancel over the window.
func TestGuardSampledAttackersCancelOverTheWindow(t *testing.T) {
	h, pub := published(t)
	c := testConfig()
	c.RateLimitRules[0].Limit = 3
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	h.advance(6 * time.Minute)
	h.live("edge-a", 1, 2)
	h.putStats(1, 5, 10_000, 0, 0, []int64{10_000}, `[{"id":"login","evaluated":500,"limited":0}]`, "[]")
	// 10 attackers, 40 blocks each a minute; estimated at 32 in some minutes, 48 in others.
	for ago, est := range map[int]int64{1: 32, 2: 48, 3: 32, 4: 48} {
		h.statsMinute(2, ago, 1_000, `[{"id":"login","evaluated":500,"limited":400}]`, sampledTop("login", "limited", 10, est))
	}
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	var out guardOutcome
	_ = json.Unmarshal(decode[versionRow](t, pub.do("GET", "/api/versions/2", nil)).GuardOutcome, &out)
	if out.Decision != "ok" || out.Signals["changed_rule_limited_ratio"].Tripped {
		t.Fatalf("outcome %+v", out)
	}
}
