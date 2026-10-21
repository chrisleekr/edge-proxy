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
