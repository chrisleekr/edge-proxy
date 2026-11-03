package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// oldEdge reports an edge that reads only schema 4 and runs other
// deployment settings, so a publish that changes what edges run waits.
func oldEdge(h *harness, pub *client) {
	h.t.Helper()
	e := h.client()
	e.token = h.edgeToken(pub)
	status(h.t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "old-edge", MaxSchema: 4, Deployment: "0123456789abcdef"}), 200)
}

func apIDs(c snapshot.Config) []string {
	var out []string
	for _, r := range c.RateLimitRules {
		if isOverlay(r.ID) {
			out = append(out, r.ID)
		}
	}
	return out
}

// Taking autopilot rules out runs only rules edges already served, so an
// old or misconfigured edge never holds it back.
func TestAutopilotRemovalsAreNeverHeldBack(t *testing.T) {
	t.Run("turning autopilot off with an old edge live removes its rules", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		oldEdge(h, pub)
		pub.setAutopilot(map[string]any{"mode": "off"})
		if v := pub.active(); v.Source != "autopilot" || len(apIDs(v.Config)) != 0 {
			t.Fatalf("version %d %s, autopilot rules %v", v.Version, v.Source, apIDs(v.Config))
		}
	})
	t.Run("a per-rule guard rollback with an old edge live removes the rule", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		oldEdge(h, pub)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
		h.tick()
		if _, live := liveRuleIn(pub.active().Config, id); live || ruleState(t, h, id) != "rolled_back" {
			t.Fatalf("rule %s, still live %v", ruleState(t, h, id), live)
		}
	})
	t.Run("an old edge rejects a new rule and still lets an expiry out in the same tick", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"max_ttl": "1h", "default_ttl": "1h"})
		old := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		h.advance(time.Minute)
		c, cs := agentCase(t, h, pub, agent)
		p := propose(t, cs, proposal("add_sensor", "account-watch", agentRule(`http.request.uri.path eq "/account"`, "ip")))
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
		// Past the old sensor's expiry.
		if _, err := h.db.Exec(t.Context(), "UPDATE autopilot_rules SET expires_at = $2 WHERE id = $1", old, h.now().Add(30*time.Second)); err != nil {
			t.Fatal(err)
		}
		h.advance(time.Minute)
		oldEdge(h, pub)
		h.tick()
		if st := ruleState(t, h, old); st != "expired" {
			t.Fatalf("old sensor %s", st)
		}
		if _, live := liveRuleIn(pub.active().Config, old); live {
			t.Fatal("the expired sensor is still published")
		}
		// The new rule is what the edge refused, so it leaves the queue with
		// that reason instead of holding back every later tick.
		if st := ruleState(t, h, p.RuleID); st != "rejected" || lastReason(t, h, p.RuleID, "rejected") != "a live edge runs other deployment settings" {
			t.Fatalf("new sensor %s", st)
		}
		h.wantMetrics(`admin_autopilot_policy_rejections_total{reason="deployment"} 1`)
	})
}

// Admin checks the addresses an enforce rule would block, as the edge
// displays them, against verified crawlers and protected subjects.
func TestAutopilotEnforceChecksSubjectAddresses(t *testing.T) {
	t.Run("an IPv6 crawler /64 rejects the rule", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		if _, err := h.db.Exec(t.Context(), `INSERT INTO verified_bot_sets (source_url, fetched_at, prefixes) VALUES ('https://bots.example.com/googlebot.json', now(), '["2001:4860:4801::/48"]')`); err != nil {
			t.Fatal(err)
		}
		id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 20, id, fmt.Sprintf(`[{"rule":%q,"key":"k1","display":"2001:4860:4801:10::/64","limited":0,"would_limit":20}]`, id))
		h.tick()
		if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != "crawler_subject" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("a key with ip after another part is stored ip first and checked", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
		id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", agentRule(`http.request.uri.path eq "/login"`, "method", "ip")))
		r, _ := liveRuleIn(pub.active().Config, id)
		if !slices.Equal(r.Key, []string{"ip", "method"}) {
			t.Fatalf("key %v", r.Key)
		}
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 20, id, fmt.Sprintf(`[{"rule":%q,"key":"k1","display":"203.0.113.9 POST","limited":0,"would_limit":20}]`, id))
		h.tick()
		if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != "protected_subject" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("blocks mostly on heavy attackers stay within max_block_share", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		// 500 of 10,000 a minute is 5%, but 480 of them are one attacker's.
		id := observed(t, h, pub, agent, 500, "[]")
		if _, err := h.db.Exec(t.Context(), "UPDATE edge_stats_minute SET top_limited = $1", fmt.Sprintf(`[{"rule":%q,"key":"k1","display":"198.51.100.7","limited":0,"would_limit":480}]`, id)); err != nil {
			t.Fatal(err)
		}
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s, want enforcing", st)
		}
	})
}

// A comparison on the client's IP, AS number or a JWT claim picks clients
// out, whatever its operator.
func TestAutopilotRefusesAnyNamedSubject(t *testing.T) {
	for _, expression := range []string{
		`http.request.uri.path eq "/login" and not (ip.src ne 198.51.100.7)`,
		`http.request.uri.path eq "/login" and ip.src.asnum ge 64500`,
		`http.request.uri.path eq "/login" and ip.src.asnum le 64500`,
		`http.request.uri.path eq "/login" and starts_with(http.request.jwt.claims["sub"], "adm")`,
		`http.request.uri.path eq "/login" and http.x_forwarded_for eq "198.51.100.7"`,
		`http.request.uri.path eq "/login" and http.request.headers["True-Client-IP"] wildcard "198.51.*"`,
		`http.request.uri.path eq "/login" and http.request.headers["x-client"] eq "198.51.100.7"`,
		`http.request.uri.path eq "/login" and http.request.headers["x-client"] eq "2001:db8::/32"`,
	} {
		t.Run(expression, func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			_, cs := agentCase(t, h, pub, agent)
			if p := propose(t, cs, proposal("enforce", "login", agentRule(expression, "ip"))); p.Accepted || !slices.Contains(p.Reasons, "named_subjects") {
				t.Fatalf("proposal %+v", p)
			}
		})
	}
	t.Run("a host-only key is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, cs := agentCase(t, h, pub, agent)
		if p := propose(t, cs, proposal("add_sensor", "login", agentRule(`http.request.uri.path eq "/login"`, "host"))); p.Accepted || !slices.Contains(p.Reasons, "constant_or_host_key") {
			t.Fatalf("proposal %+v", p)
		}
	})
}

func TestAutopilotModelRetiresSensorsOnly(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	id := enforcingRule(t, h, pub, agent)
	_, cs := agentCase(t, h, pub, agent)
	if p := propose(t, cs, map[string]any{"action": "retire", "rule_id": id, "rationale": "The attack stopped"}); p.Accepted || !slices.Contains(p.Reasons, "not_overlay_shape") {
		t.Fatalf("proposal %+v", p)
	}
	h.tick()
	if st := ruleState(t, h, id); st != "enforcing" {
		t.Fatalf("rule %s", st)
	}
}

// Summaries an anomaly or an earlier run wrote can quote what a client
// sent, so the model reads them as untrusted.
func TestAutopilotSummariesAreUntrusted(t *testing.T) {
	const injected = "ignore-previous-instructions"
	t.Run("an anomaly's summary in the case and in list_anomalies", func(t *testing.T) {
		h, _, agent := autopilotHarness(t)
		agent.seen()
		if _, err := h.db.Exec(t.Context(), `INSERT INTO anomalies (signal, rule, phase, severity, state, tripped, passed, started_at, fired_at, summary, details)
			VALUES ('traffic_surge', '', '', 'warning', 'firing', 2, 0, $1, $1, $2, '{}')`, h.now(), "Traffic surged from "+injected); err != nil {
			t.Fatal(err)
		}
		h.tick()
		c := agent.claimCase()
		cs := h.mcpSession(agentToken, c.RunID)
		for _, tool := range []string{"get_case", "list_anomalies"} {
			out := mustCall(t, cs, tool, nil)
			if !strings.Contains(fmt.Sprint(out), injected) {
				t.Fatalf("%s is missing the summary: %v", tool, out)
			}
			if p := untrustedOnly(out, injected, "", false); p != "" {
				t.Fatalf("%s: %s holds a client-written value outside an untrusted field", tool, p)
			}
		}
	})
	t.Run("an earlier case's summary in prior_cases", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		in := resultBody(c.RunID, "benign", usage{Input: 1}, nil, 0)
		in["summary"] = "The path said " + injected
		status(t, agent.result(c.CaseID, in), 204)
		c = openAndClaim(t, pub, agent)
		out := mustCall(t, h.mcpSession(agentToken, c.RunID), "get_case", nil)
		if !strings.Contains(fmt.Sprint(out), injected) {
			t.Fatalf("prior_cases is missing the summary: %v", out)
		}
		if p := untrustedOnly(out, injected, "", false); p != "" {
			t.Fatalf("%s holds a client-written value outside an untrusted field", p)
		}
	})
	t.Run("a route in get_route", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		status(t, h.shipper().post(access("GET", "api.example.com", "/"+injected+"/42")), http.StatusAccepted)
		routes := h.routes(pub).Routes
		if len(routes) == 0 {
			t.Fatal("no route")
		}
		c := openAndClaim(t, pub, agent)
		out := mustCall(t, h.mcpSession(agentToken, c.RunID), "get_route", map[string]any{"id": routes[0].ID})
		if !strings.Contains(fmt.Sprint(out), injected) {
			t.Fatalf("the route is missing: %v", out)
		}
		if p := untrustedOnly(out, injected, "", false); p != "" {
			t.Fatalf("%s holds a client-written value outside an untrusted field", p)
		}
	})
}

// A proposal and the record of the call that made it commit together.
func TestAutopilotProposalNeedsRoomInTheRunRecord(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c, cs := agentCase(t, h, pub, agent)
	for batch := range 10 {
		var evs []map[string]any
		for i := range 100 {
			evs = append(evs, event(batch*100+i+1, "message", `{"text":"a"}`))
		}
		status(t, agent.events(c.RunID, evs...), 204)
	}
	if _, refused := callTool(t, cs, "propose", proposal("add_sensor", "login-watch", loginRule())); refused == "" {
		t.Fatal("a proposal with no room for its record was accepted")
	}
	var n int
	if err := h.db.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM autopilot_proposals) + (SELECT count(*) FROM autopilot_rules)").Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d proposals and rules, err %v", n, err)
	}
}

// A call that was in flight when its run reported its result is not
// recorded after it: the record ends with the result.
func TestAutopilotNoCallRecordAfterTheResult(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c := openAndClaim(t, pub, agent)
	status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
	_, _, err := h.s.recordCall(t.Context(), c.RunID, "list_rules", json.RawMessage("{}"), []byte("{}"), "", time.Millisecond)
	if p, ok := errors.AsType[*problem](err); !ok || p.Status != 409 {
		t.Fatalf("err %v", err)
	}
	if got := adminEvents(t, h, c.RunID); len(got) != 0 {
		t.Fatalf("recorded %v", got)
	}
}

// A canary aborted after a person's publish is not that publish's
// traffic, so its errors never roll the publish back.
func TestGuardLeavesAnAbortedCanaryOut(t *testing.T) {
	h, pub := published(t)
	h.putStats(1, 10, 2_000, 0, 0, []int64{2_000}, "[]", "[]")
	c := testConfig()
	c.RateLimitRules[0].Limit = 9
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("Tighten login"), 201) // version 2
	h.advance(2 * time.Minute)
	h.putStats(2, 2, 1_000, 0, 0, []int64{1_000}, "[]", "[]")
	c.RateLimitRules[0].Limit = 8
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v3 on 10%", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	h.advance(time.Minute)
	h.putStats(3, 1, 1_000, 0, 500, []int64{1_000}, "[]", "[]") // the canary failed half its requests
	status(t, pub.do("POST", "/api/canary/abort", map[string]string{"reason": "errors on login"}), 204)
	h.advance(2 * time.Minute)
	h.putStats(2, 2, 1_000, 0, 0, []int64{1_000}, "[]", "[]")
	h.live("edge-a", 2)
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v := pub.version(2); v.Status != "active" {
		t.Fatalf("version 2 %s", v.Status)
	}
	if out := outcomeOf(t, pub, 2); out.Decision != "ok" || out.Signals["upstream_5xx_ratio"].Tripped {
		t.Fatalf("version 2 outcome %+v", out)
	}
}

// When a new rule no longer compiles with the rules a person published
// since, the tick publishes without it and rejects it.
func TestAutopilotRejectsAProposalThatNoLongerCompiles(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c, cs := agentCase(t, h, pub, agent)
	p := propose(t, cs, proposal("add_sensor", "login-watch", loginRule()))
	other := propose(t, cs, proposal("add_sensor", "account-watch", agentRule(`http.request.uri.path eq "/account"`, "ip")))
	status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
	full := testConfig()
	for i := len(full.RateLimitRules); i < snapshot.MaxRulesPerPhase; i++ {
		r := full.RateLimitRules[0]
		r.ID = fmt.Sprint("bulk-", i)
		full.RateLimitRules = append(full.RateLimitRules, r)
	}
	status(t, pub.save(pub.revision(), full), 200)
	status(t, pub.publishDraft("200 rate-limit rules"), 201)
	h.tick()
	// Admin can't tell which new rule broke the publish, so every proposed
	// rule leaves the queue.
	for _, id := range []string{p.RuleID, other.RuleID} {
		if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != "it no longer compiles with the live rules" {
			t.Fatalf("rule %s %s", id, st)
		}
	}
	h.wantMetrics(`admin_autopilot_policy_rejections_total{reason="compile"} 2`)
}

func TestAutopilotReadTools(t *testing.T) {
	const injected = "ignore-previous-instructions"
	t.Run("rule stats past six hours come in hourly steps, filtered to the rule", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		h.putStats(1, 400, 100, 0, 0, []int64{100}, `[{"id":"login","evaluated":10,"limited":1,"would_limit":0},{"id":"other","evaluated":5}]`,
			`[{"rule":"login","key":"k1","display":"q=`+injected+`","limited":1}]`)
		out := mustCall(t, h.mcpSession(pub.userToken("stats.read"), 0), "get_rule_stats", map[string]any{"rule": "login", "minutes": 600})
		series, _ := out["series"].([]any)
		var evaluated float64
		for _, b := range series {
			evaluated += b.(map[string]any)["counts"].(map[string]any)["evaluated"].(float64)
		}
		if out["step_minutes"] != float64(60) || len(series) > 8 || evaluated != 4_000 {
			t.Fatalf("step %v, %d buckets, %v evaluated", out["step_minutes"], len(series), evaluated)
		}
		if !strings.Contains(fmt.Sprint(out), injected) {
			t.Fatalf("top_subjects is missing the subject: %v", out)
		}
		if p := untrustedOnly(out, injected, "", false); p != "" {
			t.Fatalf("%s holds a client-written value outside an untrusted field", p)
		}
	})
	t.Run("list_versions returns at most limit versions", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
		status(t, pub.publishDraft("v2"), 201)
		if v := mustCall(t, h.mcpSession(pub.userToken("config.read"), 0), "list_versions", map[string]any{"limit": 1})["versions"].([]any); len(v) != 1 {
			t.Fatalf("%d versions", len(v))
		}
	})
	t.Run("get_autopilot_state marks rule expressions untrusted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		out := mustCall(t, h.mcpSession(pub.userToken("autopilot.read"), 0), "get_autopilot_state", nil)
		if !strings.Contains(fmt.Sprint(out), "/login") {
			t.Fatalf("the rule is missing: %v", out)
		}
		if p := untrustedOnly(out, "/login", "", false); p != "" {
			t.Fatalf("%s holds an expression outside an untrusted field", p)
		}
	})
	t.Run("get_autopilot_state marks a rule's host and path prefix untrusted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		liveRule(t, h, pub, agent, proposal("add_sensor", "orders-watch", ordersRule()))
		out := mustCall(t, h.mcpSession(pub.userToken("autopilot.read"), 0), "get_autopilot_state", nil)
		if !strings.Contains(fmt.Sprint(out), "path_prefix:map[untrusted:/api/orders/]") {
			t.Fatalf("the path prefix is missing: %v", out)
		}
		if p := untrustedOnly(out, "/api/orders/", "", false); p != "" {
			t.Fatalf("%s holds a rule literal outside an untrusted field", p)
		}
	})
	t.Run("get_autopilot_state marks an exclusion's path untrusted and leaves out who made it and why", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		exclude(t, pub, map[string]any{"subject": "198.51.100.7", "host": "api.example.com", "path_prefix": "/api/orders/", "reason": "Our CI polls orders"})
		out := mustCall(t, h.mcpSession(pub.userToken("autopilot.read"), 0), "get_autopilot_state", nil)
		if s := fmt.Sprint(out); !strings.Contains(s, "path_prefix:map[untrusted:/api/orders/]") || strings.Contains(s, "Our CI") || strings.Contains(s, "created_by") {
			t.Fatalf("exclusions as the model reads them: %v", out)
		}
		if p := untrustedOnly(out, "/api/orders/", "", false); p != "" {
			t.Fatalf("%s holds an exclusion's path outside an untrusted field", p)
		}
	})
	t.Run("list_rules marks expressions untrusted", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		out := mustCall(t, h.mcpSession(pub.userToken("config.read"), 0), "list_rules", nil)
		if !strings.Contains(fmt.Sprint(out), "/login") {
			t.Fatalf("the login rule is missing: %v", out)
		}
		if p := untrustedOnly(out, "/login", "", false); p != "" {
			t.Fatalf("%s holds an expression outside an untrusted field", p)
		}
	})
	t.Run("check_subject finds crawlers and protected subjects, and refuses a prefix", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		if _, err := h.db.Exec(t.Context(), `INSERT INTO verified_bot_sets (source_url, fetched_at, prefixes) VALUES ('https://bots.example.com/googlebot.json', now(), '["66.249.64.0/19"]')`); err != nil {
			t.Fatal(err)
		}
		pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
		cs := h.mcpSession(pub.userToken("stats.read"), 0)
		if out := mustCall(t, cs, "check_subject", map[string]any{"ip": "66.249.66.1"}); out["verified_crawler"] != true || out["protected"] != false {
			t.Fatalf("crawler %v", out)
		}
		if out := mustCall(t, cs, "check_subject", map[string]any{"ip": "203.0.113.9"}); out["verified_crawler"] != false || out["protected"] != true {
			t.Fatalf("protected %v", out)
		}
		if _, refused := callTool(t, cs, "check_subject", map[string]any{"ip": "203.0.113.0/24"}); !strings.Contains(refused, "ip must be an IP address") {
			t.Fatalf("a prefix: %q", refused)
		}
	})
}

// A runner takes the oldest case it holds a credential for.
func TestAutopilotClaimByProvider(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	pub.setAutopilot(map[string]any{"sweep_model": "gpt-5"})
	status(t, agent.claim("claude"), 204)
	h.tick() // queues a sweep and a review, which run on openai
	status(t, agent.claim("claude"), 409)
	id := pub.investigate("login", "Guessing passwords?")
	if c := agent.claimCase(); c.CaseID != id || c.Provider != "claude" {
		t.Fatalf("claimed %+v, want case %d", c, id)
	}
}

func TestAutopilotRunFailures(t *testing.T) {
	t.Run("an error then a timeout requeue once, then the case needs a person", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		in := resultBody(c.RunID, "", usage{Input: 1}, nil, 0)
		in["status"] = "error"
		status(t, agent.result(c.CaseID, in), 204)
		again := agent.claimCase()
		if again.CaseID != c.CaseID || again.Attempt != 2 {
			t.Fatalf("second claim %+v", again)
		}
		in = resultBody(again.RunID, "", usage{Input: 1}, nil, 0)
		in["status"] = "timeout"
		status(t, agent.result(c.CaseID, in), 204)
		var state string
		if err := h.db.QueryRow(t.Context(), "SELECT state FROM autopilot_cases WHERE id = $1", c.CaseID).Scan(&state); err != nil || state != "failed" {
			t.Fatalf("case %s, err %v", state, err)
		}
	})
	t.Run("a rule rolled back is not proposed again", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
		h.tick()
		_, cs := agentCase(t, h, pub, agent)
		if p := propose(t, cs, proposal("enforce", "login-again", loginRule())); p.Accepted || !slices.Contains(p.Reasons, "suppressed") {
			t.Fatalf("proposal %+v", p)
		}
	})
	t.Run("with the guard disabled an enforcing rule is not judged", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		g := decode[GuardSettings](t, pub.do("GET", "/api/settings/guard", nil))
		g.Enabled = false
		status(t, pub.do("PUT", "/api/settings/guard", g), 204)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
	})
}

func TestAutopilotNotificationsResolve(t *testing.T) {
	setup := func(t *testing.T) (*harness, *client, *client) {
		t.Helper()
		am := newFakeAlertmanager(t)
		h, pub, agent := autopilotHarnessWith(t, map[string]string{"ALERTMANAGER_URL": am.srv.URL + "/"})
		n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
		n.FireAfter, n.ResolveAfter = 1, 1
		status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
		return h, pub, agent
	}
	state := func(h *harness, pub *client, signal string) string {
		h.t.Helper()
		for _, a := range h.anomalies(pub) {
			if a.Signal == signal && a.State != "resolved" {
				return a.State
			}
		}
		return "none"
	}
	want := func(h *harness, pub *client, signal, st string) {
		h.t.Helper()
		if got := state(h, pub, signal); got != st {
			h.t.Fatalf("%s %s, want %s", signal, got, st)
		}
	}
	t.Run("autopilot_enforced resolves when the rule ends", func(t *testing.T) {
		h, pub, agent := setup(t)
		id := enforcingRule(t, h, pub, agent)
		h.check()
		want(h, pub, "autopilot_enforced", "firing")
		status(t, pub.do("POST", "/api/autopilot/rules/"+id+"/retire", map[string]any{"reason": "Attack over"}), 204)
		h.check()
		want(h, pub, "autopilot_enforced", "none")
	})
	t.Run("autopilot_rolled_back resolves an hour later", func(t *testing.T) {
		h, pub, agent := setup(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
		h.tick()
		h.check()
		want(h, pub, "autopilot_rolled_back", "firing")
		h.advance(61 * time.Minute)
		h.check()
		want(h, pub, "autopilot_rolled_back", "none")
	})
	t.Run("autopilot_needs_person fires for a failed case and resolves an hour later", func(t *testing.T) {
		h, pub, agent := setup(t)
		c := openAndClaim(t, pub, agent)
		h.advance(11 * time.Minute)
		h.tick()
		again := agent.claimCase()
		h.advance(11 * time.Minute)
		h.tick()
		if again.CaseID != c.CaseID {
			t.Fatalf("claimed %d", again.CaseID)
		}
		agent.seen()
		h.check()
		want(h, pub, "autopilot_needs_person", "firing")
		h.advance(61 * time.Minute)
		agent.seen()
		h.check()
		want(h, pub, "autopilot_needs_person", "none")
	})
	t.Run("autopilot_budget_exhausted resolves an hour after the refusal", func(t *testing.T) {
		h, pub, agent := setup(t)
		pub.setAutopilot(map[string]any{"max_sensors": 1})
		liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		_, cs := agentCase(t, h, pub, agent)
		if p := propose(t, cs, proposal("add_sensor", "search-watch", agentRule(`http.request.uri.path eq "/search"`, "ip"))); p.Accepted {
			t.Fatalf("proposal %+v", p)
		}
		h.check()
		want(h, pub, "autopilot_budget_exhausted", "firing")
		h.advance(61 * time.Minute)
		agent.seen()
		h.check()
		want(h, pub, "autopilot_budget_exhausted", "none")
	})
	t.Run("autopilot_agent_down still fires a day after the runner went away", func(t *testing.T) {
		h, pub, agent := setup(t)
		status(t, agent.claim("claude"), 204)
		h.advance(25 * time.Hour)
		h.tick() // prunes runners not seen for a day
		h.check()
		want(h, pub, "autopilot_agent_down", "firing")
	})
}

// The model label holds 16 priced models per provider; more are "other".
func TestAutopilotModelLabelIsBounded(t *testing.T) {
	var m autopilotMetrics
	for i := range maxModelLabels + 1 {
		m.runFinished("claude", fmt.Sprint("claude-model-", i), "ok", [4]int64{1, 1, 0, 0}, [2]*int64{}, time.Second)
	}
	var b bytes.Buffer
	m.write(&b)
	out := b.String()
	if !strings.Contains(out, `admin_autopilot_llm_runs_total{provider="claude",model="other",status="ok"} 1`) ||
		strings.Contains(out, fmt.Sprintf(`model="claude-model-%d"`, maxModelLabels)) ||
		!strings.Contains(out, `model="claude-model-0"`) {
		t.Fatalf("metrics:\n%s", out)
	}
}

// The MCP tools table names each tool's own permission.
func TestDocsMCPToolPermissions(t *testing.T) {
	name := regexp.MustCompile(`^[a-z_]+$`)
	perm := regexp.MustCompile(`^[a-z]+\.[a-z]+$`)
	for _, row := range docRows(t, "reference/api.md", "MCP tools") {
		for _, tool := range spans(row[0], name) {
			i := slices.IndexFunc(mcpTools, func(m mcpTool) bool { return m.Name == tool })
			ps := spans(strings.Join(row[1:], "|"), perm)
			if i < 0 || len(ps) == 0 || ps[0] != mcpTools[i].Perm {
				t.Errorf("%s is documented with %v", tool, ps)
			}
		}
	}
}

// An edge's capped count reaches admin's stats.
func TestStatsCarryCapped(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-a", MaxSchema: snapshot.SupportedSchema, Deployment: h.s.cfg.Deployment.Fingerprint(),
		Versions: []edge.StatsCounts{{Version: 1, Requests: 10, LatencyMS: []uint64{10}, RateLimit: []edge.RuleCounts{{ID: "ap-scraper", Evaluated: 4, Capped: 6}}}}}), 200)
	h.advance(time.Minute)
	if err := h.s.flush(t.Context(), h.now()); err != nil {
		t.Fatal(err)
	}
	rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=5", nil))
	if len(rows) != 1 || len(rows[0].RateLimit) != 1 || rows[0].RateLimit[0].Capped != 6 {
		t.Fatalf("stats %+v", rows)
	}
}

// A revert or rollback that publishes without the autopilot rules ends
// them, so the next tick does not publish them back.
func TestRollbackWithoutTheOverlayRetiresAutopilotRules(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	id := enforcingRule(t, h, pub, agent)
	h.putStats(pub.active().Version, 5, 1_000, 0, 0, []int64{1_000}, "[]", "[]")
	c := testConfig()
	c.RateLimitRules[0].Limit = 9
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("Tighten login"), 201)
	person := pub.active().Version
	h.advance(2 * time.Minute)
	h.putStats(person, 2, 1_000, 0, 500, []int64{1_000}, "[]", "[]")
	h.live("edge-a", person)
	oldEdge(h, pub) // can't read the overlay's expiring rules
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	v := pub.active()
	if v.Source != "guard_rollback" || len(apIDs(v.Config)) != 0 {
		t.Fatalf("version %d %s, autopilot rules %v", v.Version, v.Source, apIDs(v.Config))
	}
	if ruleState(t, h, id) != "retired" || lastReason(t, h, id, "retired") != "a revert or rollback published without the autopilot rules" {
		t.Fatalf("rule %s", ruleState(t, h, id))
	}
	h.tick()
	if got := pub.active(); got.Version != v.Version {
		t.Fatalf("the tick published version %d", got.Version)
	}
}

// During a canary no publish goes out, so a rollback is recorded as
// waiting for it.
func TestAutopilotRollbackDuringACanary(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	id := enforcingRule(t, h, pub, agent)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	canary := decode[map[string]int64](t, pub.do("POST", "/api/publish", map[string]any{"message": "on 10%", "canary_percent": 10}, "If-Match", pub.revision()))["version"]
	h.advance(3 * time.Minute)
	ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
	h.tick()
	var published bool
	var waits int64
	if err := h.db.QueryRow(t.Context(), `SELECT (numbers->>'published')::boolean, (numbers->>'waits_for_canary')::bigint FROM autopilot_transitions
		WHERE rule_id = $1 AND to_state = 'rolled_back'`, id).Scan(&published, &waits); err != nil || published || waits != canary {
		t.Fatalf("published %v, waits for %d, err %v", published, waits, err)
	}
	if _, live := liveRuleIn(pub.active().Config, id); !live {
		t.Fatal("the rule left the edges during the canary")
	}
}

// Every autopilot rule leaves out verified crawlers and protected networks
// on the edge itself, whatever the top subjects showed.
func TestAutopilotRulesExcludeCrawlersAndProtectedNetworks(t *testing.T) {
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"VERIFIED_BOT_SOURCES": "https://bots.example.com/googlebot.json"})
	pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
	id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
	cfg := pub.active().Config
	r, _ := liveRuleIn(cfg, id)
	if text := expr.Render(r.Expression); !strings.Contains(text, "client.verified_bot") || !strings.Contains(text, "203.0.113.0/24") {
		t.Fatalf("expression %s", text)
	}
	compiled, _, errs := snapshot.Compile(&cfg, h.s.cfg.Deployment)
	if errs != nil {
		t.Fatal(errs)
	}
	for _, tc := range []struct {
		req  TestRequest
		want bool
	}{
		{TestRequest{Method: "POST", Host: "api.example.com", Path: "/login", IP: "198.51.100.7"}, true},
		{TestRequest{Method: "POST", Host: "api.example.com", Path: "/login", IP: "203.0.113.9"}, false},
		{TestRequest{Method: "POST", Host: "api.example.com", Path: "/login", IP: "66.249.66.1", VerifiedBot: true}, false},
	} {
		res, err := simulate(compiled, tc.req)
		if err != nil || slices.Contains(res.RateLimitRules, id) != tc.want {
			t.Fatalf("%s: rules %v, err %v", tc.req.IP, res.RateLimitRules, err)
		}
	}
}

func TestAutopilotShadowAndDuplicates(t *testing.T) {
	t.Run("the stored shadow ratio leaves heavy subjects out", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := observed(t, h, pub, agent, 600, "[]")
		if _, err := h.db.Exec(t.Context(), "UPDATE edge_stats_minute SET top_limited = $1", fmt.Sprintf(`[{"rule":%q,"key":"k1","display":"198.51.100.7","limited":0,"would_limit":384}]`, id)); err != nil {
			t.Fatal(err)
		}
		h.tick()
		// Over 6 minutes: 3,600 would-limits, 2,304 of them the attacker's,
		// less 3 standard deviations of its sampled estimate, sqrt(16 x 2,304) = 192:
		// 720 of 6,000 evaluated.
		var shadow float64
		if err := h.db.QueryRow(t.Context(), "SELECT shadow_ratio FROM autopilot_rules WHERE id = $1", id).Scan(&shadow); err != nil || shadow != 0.12 {
			t.Fatalf("shadow %v, err %v", shadow, err)
		}
	})
	t.Run("a subject whose estimate is mostly inherited is not heavy", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := observed(t, h, pub, agent, 500, "[]")
		if _, err := h.db.Exec(t.Context(), "UPDATE edge_stats_minute SET top_limited = $1", fmt.Sprintf(`[{"rule":%q,"key":"k1","display":"198.51.100.7","limited":0,"would_limit":480,"err":470}]`, id)); err != nil {
			t.Fatal(err)
		}
		h.tick()
		if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != "block_share" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("a key in another order is a duplicate", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := testConfig()
		r := c.RateLimitRules[0]
		r.ID, r.Expression, r.Key = "account", mustParse(`http.request.uri.path eq "/account"`), []string{"method", "ip"}
		c.RateLimitRules = append(c.RateLimitRules, r)
		status(t, pub.save(pub.revision(), c, adminTest), 200)
		status(t, pub.publishDraft("Limit account"), 201)
		_, cs := agentCase(t, h, pub, agent)
		if p := propose(t, cs, proposal("add_sensor", "account", agentRule(`http.request.uri.path eq "/account"`, "ip", "method"))); p.Accepted || !slices.Contains(p.Reasons, "duplicate") {
			t.Fatalf("proposal %+v", p)
		}
	})
}

func TestAutopilotInvestigate(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"two targets are refused", map[string]any{"rule": "login", "route_id": 1}, 422},
		{"no target and no question is refused", map[string]any{}, 422},
		{"a question over 2000 characters is refused", map[string]any{"question": strings.Repeat("a", 2001)}, 422},
		{"a rule over 200 characters is refused", map[string]any{"rule": strings.Repeat("a", 201)}, 422},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pub, agent := autopilotHarness(t)
			status(t, agent.claim("claude"), 204)
			status(t, pub.do("POST", "/api/autopilot/cases", tc.body), tc.want)
		})
	}
	t.Run("autopilot off is refused", func(t *testing.T) {
		_, pub, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		pub.setAutopilot(map[string]any{"mode": "off"})
		status(t, pub.do("POST", "/api/autopilot/cases", map[string]any{"rule": "login"}), 409)
	})
	t.Run("a question alone opens a case, and the same question again is refused", func(t *testing.T) {
		_, pub, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		q := map[string]any{"question": "Why did traffic drop at noon?"}
		status(t, pub.do("POST", "/api/autopilot/cases", q), 201)
		status(t, pub.do("POST", "/api/autopilot/cases", q), 409)
	})
}

// A rule whose shadow limits all went to heavy subjects has no shadow
// estimate, so the guard holds it to the absolute ratio.
func TestAutopilotPerRuleGuardWithoutAShadow(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	id := observed(t, h, pub, agent, 500, "[]")
	if _, err := h.db.Exec(t.Context(), "UPDATE edge_stats_minute SET top_limited = $1", fmt.Sprintf(`[{"rule":%q,"key":"k1","display":"198.51.100.7","limited":0,"would_limit":500}]`, id)); err != nil {
		t.Fatal(err)
	}
	h.tick()
	var shadow float64
	if err := h.db.QueryRow(t.Context(), "SELECT shadow_ratio FROM autopilot_rules WHERE id = $1", id).Scan(&shadow); err != nil || ruleState(t, h, id) != "enforcing" || shadow != 0 {
		t.Fatalf("rule %s, shadow %v, err %v", ruleState(t, h, id), shadow, err)
	}
	h.advance(3 * time.Minute)
	ruleMinutes(h, pub, 3, 100_000, 1_000, 400, 0, id, "[]") // 40% of its own traffic, 0.4% of the fleet
	h.tick()
	if _, live := liveRuleIn(pub.active().Config, id); live || ruleState(t, h, id) != "rolled_back" {
		t.Fatalf("rule %s, still live %v", ruleState(t, h, id), live)
	}
}

// A person's adopted copy carries the published expression, exclusions
// included, and is still the same rule.
func TestAutopilotAdoptedRuleIsADuplicate(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
	id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
	status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": id}, "If-Match", pub.revision()), 200)
	status(t, pub.publishDraft("Adopt the login watch"), 201)
	h.tick()
	if st := ruleState(t, h, id); st != "adopted" {
		t.Fatalf("rule %s", st)
	}
	_, cs := agentCase(t, h, pub, agent)
	if p := propose(t, cs, proposal("add_sensor", "login-watch-again", loginRule())); p.Accepted || !slices.Contains(p.Reasons, "duplicate") {
		t.Fatalf("proposal %+v", p)
	}
}

// Every autopilot rule carries the protected networks, so they must leave
// room for the model's own condition.
func TestAutopilotProtectedSubjectsFitAnExpression(t *testing.T) {
	_, pub, _ := autopilotHarness(t)
	var subjects []any
	for i := range 150 {
		subjects = append(subjects, fmt.Sprintf("2001:db8:0:%x::1", i))
	}
	s := pub.autopilotSettings()
	s["protected_subjects"] = subjects
	resp := pub.do("PUT", "/api/settings/autopilot", s)
	if b := body(resp); resp.StatusCode != 422 || !strings.Contains(b, "use fewer or wider CIDRs") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

// A proposal that commits as the call's deadline ends is recorded once,
// as the call that made it, and counted.
func TestAutopilotProposalCommittedAtTheDeadline(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c, cs := agentCase(t, h, pub, agent)
	proposeDone = func(err error) error {
		if err == nil {
			return context.DeadlineExceeded
		}
		return err
	}
	t.Cleanup(func() { proposeDone = func(err error) error { return err } })
	if _, refused := callTool(t, cs, "propose", proposal("add_sensor", "login-watch", loginRule())); refused == "" {
		t.Fatal("the call was answered as if it had finished in time")
	}
	var n int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_proposals").Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d proposals, err %v", n, err)
	}
	var refusals int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_run_events WHERE run_id = $1 AND source = 'admin' AND payload->>'allowed' = 'false'", c.RunID).
		Scan(&refusals); err != nil || refusals != 0 {
		t.Fatalf("%d refusal events, err %v", refusals, err)
	}
	if got := adminEvents(t, h, c.RunID); !slices.Equal(got, []string{"propose"}) {
		t.Fatalf("recorded %v", got)
	}
	h.wantMetrics(`admin_autopilot_proposals_total{action="add_sensor",result="accepted"} 1`)
}

// A canary revert that goes out without the autopilot rules retires them,
// noting that the active version runs them until the canary ends.
func TestCanaryRevertWithoutTheOverlay(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
	oldEdge(h, pub)
	resp := pub.do("POST", "/api/versions/1/revert", map[string]any{"reason": "Back to the first policy", "canary_percent": 10})
	v := decode[map[string]int64](t, resp)["version"]
	if resp.StatusCode != 201 || v == 0 {
		t.Fatalf("revert %d", resp.StatusCode)
	}
	var waits int64
	if err := h.db.QueryRow(t.Context(), "SELECT (numbers->>'waits_for_canary')::bigint FROM autopilot_transitions WHERE rule_id = $1 AND to_state = 'retired'", id).
		Scan(&waits); err != nil || waits != v || ruleState(t, h, id) != "retired" {
		t.Fatalf("rule %s, waits for %d, err %v", ruleState(t, h, id), waits, err)
	}
}
