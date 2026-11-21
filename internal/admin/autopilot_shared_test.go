package admin

import (
	"slices"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

const outdated = `client.signals eq "browser_outdated"`

// ja4Harness is an autopilot harness whose deployment has a JA4 source and
// whose config has a site-wide ip rule and a browser floor, so a ja4-only
// key compiles.
func ja4Harness(t *testing.T) (*harness, *client, *client) {
	t.Helper()
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"VIEWER_HEADERS": "tls.client.ja4=CloudFront-Viewer-JA4-Fingerprint"})
	c := testConfig()
	c.Global.BrowserFloor = map[string]int{"chromium": 100}
	c.RateLimitRules = append(c.RateLimitRules, snapshot.RateLimitRule{ID: "site", Expression: expr.True(), Algorithm: "sliding_window", Limit: 1000,
		Period: snapshot.Duration(time.Minute), Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"})
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	return h, pub, agent
}

// signalDays stores the previous 3 days, under ja4Harness's version 2 whose
// floor is the active one, with the signal at perMinute around the clock
// time a rule that just went live runs in, and an hour of 10,000 requests
// a minute before now.
func (h *harness) signalDays(perMinute uint64) { h.signalDaysOn(2, perMinute) }

// signalDaysOn is signalDays with the days stored under version.
func (h *harness) signalDaysOn(version int64, perMinute uint64) {
	h.t.Helper()
	for k := 1; k <= 3; k++ {
		h.put(1440*k+8, 1440*k-8, minute{version: version, requests: 10_000, signals: signalCounts("browser_outdated", perMinute)})
	}
	h.put(60, 1, minute{requests: 10_000})
}

func sharedRule() map[string]any { return agentRule(outdated, "ja4") }

// shadowMinutes stores minutes of traffic in which the rule logged
// per minute, all on the signal.
func shadowMinutes(h *harness, pub *client, id string, minutes int, would int64) {
	h.t.Helper()
	h.put(minutes, 1, minute{version: pub.active().Version, requests: 10_000, signals: signalCounts("browser_outdated", uint64(would)),
		rateLimit: []edge.RuleCounts{{ID: id, Evaluated: 1_000, Logged: uint64(would)}}})
}

// sharedObserved has a ja4-only enforce rule observed for 6 minutes with
// the signal at baseline a minute on the previous days, the rule logging
// 900 a minute of 10,000.
func sharedObserved(t *testing.T, baseline uint64) (*harness, *client, string) {
	t.Helper()
	return sharedObservedFrom(t, func(h *harness) { h.signalDays(baseline) })
}

// sharedObservedFrom is sharedObserved with the history stored by seed.
func sharedObservedFrom(t *testing.T, seed func(*harness)) (*harness, *client, string) {
	t.Helper()
	return sharedObservedOn(t, outdated, seed)
}

// sharedObservedOn is sharedObservedFrom for a rule on expression.
func sharedObservedOn(t *testing.T, expression string, seed func(*harness)) (*harness, *client, string) {
	t.Helper()
	h, pub, agent := ja4Harness(t)
	seed(h)
	id := liveRule(t, h, pub, agent, proposal("enforce", "fp-outdated", agentRule(expression, "ja4")))
	h.advance(6 * time.Minute)
	shadowMinutes(h, pub, id, 6, 900)
	return h, pub, id
}

func TestAutopilotSharedKeyPropose(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rule   func() map[string]any
		reason string // "" when accepted
	}{
		{"ja4 key without a signal condition is refused key_needs_ip_or_jwt", func() map[string]any {
			return agentRule(`http.request.uri.path eq "/login"`, "ja4")
		}, "key_needs_ip_or_jwt"},
		{"ja4 key with a negated signal condition is refused", func() map[string]any {
			return agentRule(`client.signals ne "browser_outdated" and http.request.uri.path eq "/login"`, "ja4")
		}, "key_needs_ip_or_jwt"},
		{"ja4 key with a signal under or is refused", func() map[string]any {
			return agentRule(outdated+` or http.request.uri.path eq "/login"`, "ja4")
		}, "key_needs_ip_or_jwt"},
		{"ja4 key with a penalty is refused shared_key_penalty", func() map[string]any {
			r := sharedRule()
			r["penalty"] = "10m"
			return r
		}, "shared_key_penalty"},
		{"ja4 key scoped on browser_outdated is accepted", sharedRule, ""},
		{"ja4 key scoped on a signal list is accepted", func() map[string]any {
			return agentRule(`client.signals in {"browser_outdated" "client_hints_mismatch"}`, "ja4")
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := ja4Harness(t)
			_, cs := agentCase(t, h, pub, agent)
			p := propose(t, cs, proposal("add_sensor", "fp-outdated", tc.rule()))
			if tc.reason == "" {
				if !p.Accepted {
					t.Fatalf("proposal %+v", p)
				}
				return
			}
			if p.Accepted || !slices.Contains(p.Reasons, tc.reason) {
				t.Fatalf("proposal %+v, want refused for %s", p, tc.reason)
			}
		})
	}
	t.Run("a ja4-only rule without the operator's site-wide ip rule is refused compile", func(t *testing.T) {
		h, pub, agent := autopilotHarnessWith(t, map[string]string{"VIEWER_HEADERS": "tls.client.ja4=CloudFront-Viewer-JA4-Fingerprint"})
		c := testConfig()
		c.Global.BrowserFloor = map[string]int{"chromium": 100}
		status(t, pub.save(pub.revision(), c, adminTest), 200)
		status(t, pub.publishDraft("v2"), 201)
		_, cs := agentCase(t, h, pub, agent)
		p := propose(t, cs, proposal("add_sensor", "fp-outdated", sharedRule()))
		i := slices.IndexFunc(p.Checks, func(c policyCheck) bool { return c.Name == "compile" })
		if p.Accepted || i < 0 || p.Checks[i].OK || p.Checks[i].Detail == "" {
			t.Fatalf("proposal %+v", p)
		}
	})
}

func TestAutopilotSharedKeyEnforce(t *testing.T) {
	t.Run("shared rule enforces when the signal baseline is low", func(t *testing.T) {
		h, _, id := sharedObserved(t, 5)
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s, reason %q", st, lastReason(t, h, id, "rejected"))
		}
		var base float64
		var days, tripped int
		if err := h.db.QueryRow(t.Context(), `SELECT (numbers->>'signal_baseline_per_minute')::float8, (numbers->>'baseline_days')::int, (numbers->>'tripped_minutes')::int
			FROM autopilot_transitions WHERE rule_id = $1 AND to_state = 'enforcing'`, id).Scan(&base, &days, &tripped); err != nil || base != 5 || days != 3 || tripped != 6 {
			t.Fatalf("baseline %v over %d days, %d tripped minutes, err %v", base, days, tripped, err)
		}
	})
	// The attack is one fingerprint's worth of subjects, and the sampled
	// top subject would be left out of a per-client rule's count.
	t.Run("shared rule is rejected block_share when normal traffic carries the signal", func(t *testing.T) {
		h, pub, id := sharedObserved(t, 2_000)
		h.put(6, 1, minute{version: pub.active().Version, top: []edge.TopCount{{Rule: id, Key: "k0", Display: "ja4", Logged: 900}}})
		h.tick()
		if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != "block_share" {
			t.Fatalf("rule %s, reason %q", st, lastReason(t, h, id, "rejected"))
		}
	})
}

// A baseline of nothing measured is unknown, not zero: the rule is judged on
// its raw logged count, which a spread attack exceeds.
func TestAutopilotSharedKeyUnmeasuredBaseline(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(*harness)
	}{
		{"shared rule is not bounded by days stored before signal counts existed", func(h *harness) {
			for k := 1; k <= 3; k++ {
				h.put(1440*k+8, 1440*k-8, minute{requests: 10_000})
			}
			h.put(60, 1, minute{requests: 10_000})
		}},
		{"shared rule with no signal history is judged on its raw logged count", func(h *harness) { h.put(60, 1, minute{requests: 10_000}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, id := sharedObservedFrom(t, tc.seed)
			h.tick()
			if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != "block_share" {
				t.Fatalf("rule %s, reason %q", st, lastReason(t, h, id, "rejected"))
			}
			var known bool
			if err := h.db.QueryRow(t.Context(), `SELECT (numbers->>'baseline_known')::bool FROM autopilot_transitions WHERE rule_id = $1 AND to_state = 'rejected'`, id).Scan(&known); err != nil || known {
				t.Fatalf("baseline_known %v, err %v", known, err)
			}
		})
	}
}

// The days were stored under a version with no browser floor, where
// browser_outdated could not fire, so their zeros are not normal traffic.
// The rule is judged on its raw logged count and observes the full time.
func TestAutopilotSharedKeyBaselineBeforeTheFloorIsUnknown(t *testing.T) {
	t.Run("shared rule is not bounded by days stored before the floor was set", func(t *testing.T) {
		h, _, id := sharedObservedFrom(t, func(h *harness) { h.signalDaysOn(1, 0) })
		h.tick()
		if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != "block_share" {
			t.Fatalf("rule %s, reason %q", st, lastReason(t, h, id, "rejected"))
		}
		var known bool
		if err := h.db.QueryRow(t.Context(), `SELECT (numbers->>'baseline_known')::bool FROM autopilot_transitions WHERE rule_id = $1 AND to_state = 'rejected'`, id).Scan(&known); err != nil || known {
			t.Fatalf("baseline_known %v, err %v", known, err)
		}
	})
	t.Run("shared rule observes the full time when its baseline days were stored before the floor", func(t *testing.T) {
		h, pub, agent := ja4Harness(t)
		h.signalDaysOn(1, 0)
		id := liveRule(t, h, pub, agent, proposal("enforce", "fp-outdated", sharedRule()))
		h.advance(2 * time.Minute)
		shadowMinutes(h, pub, id, 2, 900)
		h.tick()
		if st := ruleState(t, h, id); st != "observing" {
			t.Fatalf("rule %s, want observing", st)
		}
	})
}

// Normal traffic carries browser_outdated 5 a minute and client_hints_mismatch
// 2,000. The rule logs 900 a minute, of 10,000.
func TestAutopilotSharedKeyScopeShape(t *testing.T) {
	seed := func(h *harness) {
		c := signalCounts("browser_outdated", 5)
		c[slices.IndexFunc(expr.Signals, func(d expr.SignalDef) bool { return d.Name == "client_hints_mismatch" })] = 2_000
		for k := 1; k <= 3; k++ {
			h.put(1440*k+8, 1440*k-8, minute{version: 2, requests: 10_000, signals: c})
		}
		h.put(60, 1, minute{requests: 10_000})
	}
	for _, tc := range []struct {
		name, expression, state string
	}{
		{"in-list scope is bounded by the sum of its signals, not the smaller", `client.signals in {"browser_outdated" "client_hints_mismatch"}`, "rejected"},
		{"ANDed signals are bounded by the smaller", `client.signals eq "browser_outdated" and client.signals eq "client_hints_mismatch"`, "enforcing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, id := sharedObservedOn(t, tc.expression, seed)
			h.tick()
			if st := ruleState(t, h, id); st != tc.state {
				t.Fatalf("rule %s, want %s", st, tc.state)
			}
			if tc.state == "rejected" && lastReason(t, h, id, "rejected") != "block_share" {
				t.Fatalf("reason %q", lastReason(t, h, id, "rejected"))
			}
		})
	}
}

func TestAutopilotSharedKeyObserve(t *testing.T) {
	for _, tc := range []struct {
		name     string
		baseline uint64
		state    string
	}{
		{"shared rule observes one minute when its worst case fits the budget", 5, "enforcing"},
		{"shared rule observes the full time when its worst case does not fit", 2_000, "observing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := ja4Harness(t)
			h.signalDays(tc.baseline)
			id := liveRule(t, h, pub, agent, proposal("enforce", "fp-outdated", sharedRule()))
			h.advance(2 * time.Minute)
			shadowMinutes(h, pub, id, 2, 900)
			h.tick()
			if st := ruleState(t, h, id); st != tc.state {
				t.Fatalf("rule %s, want %s", st, tc.state)
			}
		})
	}
}

func TestAutopilotSharedKeyGuard(t *testing.T) {
	// The fleet on the fingerprint is most of what the rule limits: 900 of
	// every 10,000 requests, against a 2% budget.
	guard := func(t *testing.T, baselineAfter uint64) string {
		t.Helper()
		h, pub, id := sharedObserved(t, 5)
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
		if _, err := h.db.Exec(t.Context(), "UPDATE edge_stats_minute SET client_signals = $1 WHERE minute < $2", signalCounts("browser_outdated", baselineAfter), h.now().Add(-20*time.Hour)); err != nil {
			t.Fatal(err)
		}
		h.advance(3 * time.Minute)
		h.put(3, 1, minute{version: pub.active().Version, requests: 10_000, rateLimit: []edge.RuleCounts{{ID: id, Evaluated: 1_000, Limited: 900}}})
		h.tick()
		return ruleState(t, h, id)
	}
	t.Run("rule guard keeps a working shared rule during the attack", func(t *testing.T) {
		if st := guard(t, 5); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("rule guard rolls back a shared rule when the bound exceeds the budget", func(t *testing.T) {
		if st := guard(t, 2_000); st != "rolled_back" {
			t.Fatalf("rule %s", st)
		}
	})
}

func TestAutopilotSignalSurgeOpensCase(t *testing.T) {
	h, pub, agent, _ := alertHarness(t, 1)
	agent.seen()
	c := testConfig()
	c.Global.BrowserFloor = map[string]int{"chromium": 100}
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	h.put(65, 6, minute{version: 2, requests: 1000, signals: signalCounts("browser_outdated", 10)})
	h.put(5, 1, minute{version: 2, requests: 1000, signals: signalCounts("browser_outdated", 600)})
	h.check()
	h.tick()
	var n int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_cases WHERE kind = 'anomaly'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d anomaly cases, err %v", n, err)
	}
}

func TestAutopilotGetStatsNamesClientSignals(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	h.put(3, 1, minute{requests: 1000, signals: signalCounts("browser_outdated", 600)})
	_, cs := agentCase(t, h, pub, agent)
	res := mustCall(t, cs, "get_stats", map[string]any{"minutes": 60})
	rows, _ := res["stats"].(map[string]any)["untrusted"].([]any)
	if len(rows) == 0 {
		t.Fatalf("stats %+v", res)
	}
	if got, _ := rows[0].(map[string]any)["client_signals"].(map[string]any)["browser_outdated"].(float64); got != 600 {
		t.Fatalf("browser_outdated %v in %+v", got, rows[0])
	}
}
