package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// tick runs one round of the autopilot leader job.
func (h *harness) tick() {
	h.t.Helper()
	if err := h.s.runAutopilot(h.t.Context()); err != nil {
		h.t.Fatal(err)
	}
}

// headerTransport adds the runner's headers to every MCP request.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return t.base.RoundTrip(r)
}

// mcpSession connects to admin's MCP server with a bearer token, naming the
// run the calls belong to when run is set.
func (h *harness) mcpSession(token string, run int64) *mcp.ClientSession {
	h.t.Helper()
	headers := map[string]string{"Authorization": "Bearer " + token}
	if run != 0 {
		headers["X-Autopilot-Run"] = fmt.Sprint(run)
	}
	hc := *h.srv.Client()
	hc.Transport = headerTransport{base: h.srv.Client().Transport, headers: headers}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "autopilot-test", Version: "v0"}, nil).
		Connect(h.t.Context(), &mcp.StreamableClientTransport{Endpoint: h.srv.URL + "/v1/mcp", HTTPClient: &hc, DisableStandaloneSSE: true}, nil)
	if err != nil {
		h.t.Fatalf("mcp connect: %v", err)
	}
	h.t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// callTool calls a tool. It returns the structured result, or the refusal
// text when the call failed or the tool reported an error.
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, string) {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, err.Error()
	}
	if res.IsError {
		var text []string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text = append(text, tc.Text)
			}
		}
		return nil, strings.Join(text, " ")
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s result %s: %v", name, b, err)
	}
	return out, ""
}

// mustCall is callTool for a call that must succeed.
func mustCall(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	out, refused := callTool(t, cs, name, args)
	if refused != "" {
		t.Fatalf("%s refused: %s", name, refused)
	}
	return out
}

// agentRule is a rate-limit rule as the agent proposes it: admin names it,
// sets its expiry and decides whether it logs or blocks.
func agentRule(expression string, key ...string) map[string]any {
	return map[string]any{"expression": expression, "algorithm": "sliding_window", "limit": 20, "period": "1m", "key": key,
		"on_missing_key": "fallback_ip", "fail_mode": "open"}
}

// loginRule watches POSTs to /login per client IP. It is narrower than the
// base login rule, so it is not a duplicate.
func loginRule() map[string]any {
	return agentRule(`http.request.uri.path eq "/login" and http.request.method eq "POST"`, "ip")
}

func proposal(action, name string, rule map[string]any) map[string]any {
	return map[string]any{"action": action, "name": name, "rule": rule, "ttl": "1h", "rationale": "Many failed logins per address",
		"evidence": map[string]any{"anomaly": "rule_would_block on login"}}
}

// proposed is a propose answer.
type proposed struct {
	ProposalID int64         `json:"proposal_id"`
	Accepted   bool          `json:"accepted"`
	RuleID     string        `json:"rule_id"`
	Reasons    []string      `json:"reasons"`
	Checks     []policyCheck `json:"checks"`
}

func propose(t *testing.T, cs *mcp.ClientSession, in map[string]any) proposed {
	t.Helper()
	b, _ := json.Marshal(mustCall(t, cs, "propose", in))
	var p proposed
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// agentCase claims a new case on login and connects as its run.
func agentCase(t *testing.T, h *harness, pub, agent *client) (claimed, *mcp.ClientSession) {
	t.Helper()
	c := openAndClaim(t, pub, agent)
	return c, h.mcpSession(agentToken, c.RunID)
}

// liveRule has the agent propose in, closes its case as an attack and runs
// one tick, which publishes the rule log-only. It returns the rule id.
func liveRule(t *testing.T, h *harness, pub, agent *client, in map[string]any) string {
	t.Helper()
	c, cs := agentCase(t, h, pub, agent)
	p := propose(t, cs, in)
	if !p.Accepted || !strings.HasPrefix(p.RuleID, "ap-") {
		t.Fatalf("proposal %+v", p)
	}
	status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
	h.tick()
	if st := ruleState(t, h, p.RuleID); st != "observing" {
		t.Fatalf("rule %s %s, want observing", p.RuleID, st)
	}
	return p.RuleID
}

func ruleState(t *testing.T, h *harness, id string) string {
	t.Helper()
	var st string
	if err := h.db.QueryRow(t.Context(), "SELECT state FROM autopilot_rules WHERE id = $1", id).Scan(&st); err != nil {
		t.Fatalf("rule %s: %v", id, err)
	}
	return st
}

// lastReason is the reason of the rule's last transition into state.
func lastReason(t *testing.T, h *harness, id, state string) string {
	t.Helper()
	var reason string
	if err := h.db.QueryRow(t.Context(), "SELECT reason FROM autopilot_transitions WHERE rule_id = $1 AND to_state = $2 ORDER BY at DESC LIMIT 1", id, state).Scan(&reason); err != nil {
		t.Fatalf("rule %s to %s: %v", id, state, err)
	}
	return reason
}

// active is the active version.
func (c *client) active() versionRow {
	c.h.t.Helper()
	for _, v := range decode[[]versionRow](c.h.t, c.do("GET", "/api/versions", nil)) {
		if v.Status == "active" {
			return c.version(v.Version)
		}
	}
	c.h.t.Fatal("no active version")
	return versionRow{}
}

// liveRuleIn is the rate-limit rule id in c, or false.
func liveRuleIn(c snapshot.Config, id string) (snapshot.RateLimitRule, bool) {
	i := slices.IndexFunc(c.RateLimitRules, func(r snapshot.RateLimitRule) bool { return r.ID == id })
	if i < 0 {
		return snapshot.RateLimitRule{}, false
	}
	return c.RateLimitRules[i], true
}

// ruleMinutes writes minutes of fleet traffic on the active version, with
// rule id counted as given and top as its most-limited subjects.
func ruleMinutes(h *harness, pub *client, minutes int, fleet, evaluated, limited, wouldLimit int64, id, top string) {
	h.t.Helper()
	rules := fmt.Sprintf(`[{"id":%q,"evaluated":%d,"limited":%d,"would_limit":%d}]`, id, evaluated, limited, wouldLimit)
	h.putStats(pub.active().Version, minutes, fleet, 0, 0, []int64{fleet}, rules, top)
}

// observed has an enforce proposal live log-only, then 6 minutes of
// traffic at 10,000 requests a minute, of which the rule would limit
// wouldLimit, with top as its subjects.
func observed(t *testing.T, h *harness, pub, agent *client, wouldLimit int64, top string) string {
	t.Helper()
	id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
	h.advance(6 * time.Minute)
	ruleMinutes(h, pub, 6, 10_000, 1_000, 0, wouldLimit, id, top)
	return id
}

func TestAutopilotPolicy(t *testing.T) {
	refusedAtProposal := []struct {
		reason   string
		settings map[string]any
		in       func() map[string]any
	}{
		{"not_overlay_shape", nil, func() map[string]any { return proposal("add_sensor", "Login Stuffing!", loginRule()) }},
		{"site_wide", nil, func() map[string]any { return proposal("add_sensor", "everything", agentRule("true", "ip")) }},
		{"fail_mode", nil, func() map[string]any {
			r := loginRule()
			r["fail_mode"] = "closed"
			return proposal("add_sensor", "login", r)
		}},
		{"key_needs_ip_or_jwt", nil, func() map[string]any {
			return proposal("add_sensor", "login", agentRule(`http.request.uri.path eq "/login"`, "header:x-api-key"))
		}},
		{"constant_or_host_key", nil, func() map[string]any {
			return proposal("add_sensor", "login", agentRule(`http.request.uri.path eq "/login"`, "constant"))
		}},
		{"missing_key_rejects", nil, func() map[string]any {
			r := agentRule(`http.request.uri.path eq "/account"`, "jwt_claim:sub")
			r["on_missing_key"] = "reject"
			return proposal("add_sensor", "account", r)
		}},
		{"ttl_over_max", nil, func() map[string]any {
			p := proposal("add_sensor", "login", loginRule())
			p["ttl"] = "25h"
			return p
		}},
		{"penalty_past_expiry", nil, func() map[string]any {
			r := loginRule()
			r["penalty"] = "2h"
			return proposal("enforce", "login", r)
		}},
		{"named_subjects", nil, func() map[string]any {
			return proposal("enforce", "login", agentRule(`http.request.uri.path eq "/login" and ip.src in {198.51.100.7 198.51.100.8}`, "ip"))
		}},
		{"duplicate", nil, func() map[string]any {
			return proposal("add_sensor", "login", agentRule(`http.request.uri.path eq "/login"`, "ip")) // the base login rule's shape
		}},
		{"compile", nil, func() map[string]any {
			return proposal("add_sensor", "login", agentRule(`http.request.nope eq "x"`, "ip"))
		}},
		{"budget_sensors", map[string]any{"max_sensors": 0}, func() map[string]any { return proposal("add_sensor", "login", loginRule()) }},
		{"budget_enforcing", map[string]any{"max_enforcing": 0}, func() map[string]any { return proposal("enforce", "login", loginRule()) }},
	}
	for _, tc := range refusedAtProposal {
		t.Run(tc.reason+" is refused when proposed", func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			if tc.settings != nil {
				pub.setAutopilot(tc.settings)
			}
			_, cs := agentCase(t, h, pub, agent)
			p := propose(t, cs, tc.in())
			if p.Accepted || !slices.Contains(p.Reasons, tc.reason) || p.ProposalID == 0 {
				t.Fatalf("proposal %+v, want refused for %s", p, tc.reason)
			}
			var accepted bool
			if err := h.db.QueryRow(t.Context(), "SELECT accepted FROM autopilot_proposals WHERE id = $1", p.ProposalID).Scan(&accepted); err != nil || accepted {
				t.Fatalf("stored accepted %v, err %v", accepted, err)
			}
			h.wantMetrics(fmt.Sprintf(`admin_autopilot_policy_rejections_total{reason=%q} 1`, tc.reason))
			h.tick()
			if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 1 {
				t.Fatalf("%d versions, want 1", len(list))
			}
		})
	}
	// Its first renewal comes in its last quarter, on a 30s tick that may
	// publish only min_publish_interval (1m) after the last: 6m at least.
	t.Run("a ttl too short to renew within one tick and the publish interval is refused when proposed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, cs := agentCase(t, h, pub, agent)
		in := proposal("enforce", "login-stuffing", loginRule())
		in["ttl"] = "5m"
		p := propose(t, cs, in)
		i := slices.IndexFunc(p.Checks, func(c policyCheck) bool { return c.Name == "not_overlay_shape" })
		if p.Accepted || !slices.Contains(p.Reasons, "not_overlay_shape") || i < 0 || !strings.Contains(p.Checks[i].Detail, "a ttl of at least 6m0s") {
			t.Fatalf("proposal %+v", p)
		}
	})
	// An enforcing rule's lifetime counts from the sensor it cites.
	t.Run("lifetime_over_max is refused when proposed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"max_ttl": "1h", "default_ttl": "1h", "max_lifetime": "1h"})
		sensor := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", agentRule(`http.request.uri.path eq "/login"`, "ip", "jwt_claim:sub")))
		h.advance(40 * time.Minute)
		_, cs := agentCase(t, h, pub, agent)
		in := proposal("enforce", "login-stuffing", loginRule())
		in["ttl"], in["cites"] = "30m", sensor
		if p := propose(t, cs, in); p.Accepted || !slices.Contains(p.Reasons, "lifetime_over_max") {
			t.Fatalf("proposal %+v", p)
		}
		h.wantMetrics(`admin_autopilot_policy_rejections_total{reason="lifetime_over_max"} 1`)
	})
	// A rule an operator retired as a false positive is not proposed again
	// for max_lifetime.
	t.Run("suppressed is refused when proposed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		status(t, pub.do("POST", "/api/autopilot/rules/"+id+"/retire", map[string]any{"reason": "This is our load test", "false_positive": true}), 204)
		h.tick()
		_, cs := agentCase(t, h, pub, agent)
		if p := propose(t, cs, proposal("add_sensor", "login-again", loginRule())); p.Accepted || !slices.Contains(p.Reasons, "suppressed") {
			t.Fatalf("proposal %+v", p)
		}
		h.wantMetrics(`admin_autopilot_policy_rejections_total{reason="suppressed"} 1`)
	})
	t.Run("observed_too_short refuses a person's early approval", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"mode": "observe"})
		id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(time.Minute)
		resp := pub.do("POST", "/api/autopilot/rules/"+id+"/enforce", nil)
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, "observed_too_short") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		if st := ruleState(t, h, id); st != "observing" {
			t.Fatalf("rule %s", st)
		}
		h.wantMetrics(`admin_autopilot_policy_rejections_total{reason="observed_too_short"} 1`)
	})
	refusedAtEnforce := []struct {
		reason     string
		settings   map[string]any
		wouldLimit int64
		top        string
	}{
		// 500 of 10,000 fleet requests a minute is 5%, over the 2% default.
		{"block_share", nil, 500, "[]"},
		{"crawler_subject", nil, 20, `[{"rule":"%s","key":"k1","display":"66.249.66.1","limited":20}]`},
		{"protected_subject", map[string]any{"protected_subjects": []any{"203.0.113.0/24"}}, 20, `[{"rule":"%s","key":"k1","display":"203.0.113.9","limited":20}]`},
		{"attack_stopped", nil, 0, "[]"},
	}
	// The share budget is for collateral. Estimates of the attackers' counts
	// that fall short in some minutes and overshoot in others cancel.
	t.Run("would-limits that all go to 10 attackers, estimated over and under, enforce with no block_share refusal", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(6 * time.Minute)
		for ago := 1; ago <= 6; ago++ {
			est := int64(32 + 16*(ago%2)) // 40 each a minute, estimated at 48 or 32
			h.statsMinute(1, ago, 1_500, fmt.Sprintf(`[{"id":%q,"evaluated":500,"limited":0,"would_limit":400}]`, id), sampledTop(id, "would_limit", 10, est))
		}
		h.tick()
		var shadow float64
		if err := h.db.QueryRow(t.Context(), "SELECT shadow_ratio FROM autopilot_rules WHERE id = $1", id).Scan(&shadow); err != nil || ruleState(t, h, id) != "enforcing" || shadow != 0 {
			t.Fatalf("rule %s shadow %v, err %v; reason %q", ruleState(t, h, id), shadow, err, lastReason(t, h, id, ruleState(t, h, id)))
		}
	})
	for _, tc := range refusedAtEnforce {
		t.Run(tc.reason+" rejects an observed rule instead of enforcing it", func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			if tc.settings != nil {
				pub.setAutopilot(tc.settings)
			}
			if _, err := h.db.Exec(t.Context(), `INSERT INTO verified_bot_sets (source_url, fetched_at, prefixes) VALUES ('https://bots.example.com/googlebot.json', now(), '["66.249.64.0/19"]')`); err != nil {
				t.Fatal(err)
			}
			id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
			h.advance(6 * time.Minute)
			top := tc.top
			if strings.Contains(top, "%s") {
				top = fmt.Sprintf(top, id)
			}
			ruleMinutes(h, pub, 6, 10_000, 1_000, 0, tc.wouldLimit, id, top)
			h.tick()
			if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != tc.reason {
				t.Fatalf("rule %s, want rejected for %s", st, tc.reason)
			}
			if _, live := liveRuleIn(pub.active().Config, id); live {
				t.Fatal("a rejected rule is still published")
			}
			h.wantMetrics(fmt.Sprintf(`admin_autopilot_policy_rejections_total{reason=%q} 1`, tc.reason))
		})
	}
}

// The runner may retry a call after a timeout, so the same proposal from
// the same case is recorded once and answered the same way.
func TestAutopilotProposeIsIdempotent(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c, cs := agentCase(t, h, pub, agent)
	first := propose(t, cs, proposal("add_sensor", "login-watch", loginRule()))
	again := propose(t, cs, proposal("add_sensor", "login-watch", loginRule()))
	if !first.Accepted || again.ProposalID != first.ProposalID || again.RuleID != first.RuleID || !again.Accepted {
		t.Fatalf("first %+v, again %+v", first, again)
	}
	var proposals, audits int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_proposals WHERE case_id = $1", c.CaseID).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action = 'autopilot.propose'").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if proposals != 1 || audits != 1 {
		t.Fatalf("%d proposals, %d audit rows", proposals, audits)
	}
	h.tick()
	n := 0
	for _, r := range pub.active().Config.RateLimitRules {
		if strings.HasPrefix(r.ID, "ap-") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d autopilot rules published", n)
	}
}

func TestAutopilotRuleLifecycle(t *testing.T) {
	t.Run("an accepted proposal goes live log-only in an autopilot version", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
		v := pub.active()
		r, ok := liveRuleIn(v.Config, id)
		if v.Source != "autopilot" || !ok || r.Action != "log" || r.FailMode != "open" || r.ExpiresAt.Sub(h.now().Add(time.Hour)).Abs() > time.Second {
			t.Fatalf("version %d %s, rule %+v", v.Version, v.Source, r)
		}
		var actor string
		if err := h.db.QueryRow(t.Context(), "SELECT actor FROM audit_events WHERE action = 'autopilot.observe' AND target = $1", "rule "+id).Scan(&actor); err != nil || actor != "system:autopilot" {
			t.Fatalf("observe audit actor %q, err %v", actor, err)
		}
		if lastReason(t, h, id, "observing") == "" {
			t.Fatal("no transition reason")
		}
	})
	t.Run("in auto mode a rule enforces once it observed long enough", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(2 * time.Minute)
		ruleMinutes(h, pub, 2, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "observing" {
			t.Fatalf("after 2m the rule is %s", st)
		}
		h.advance(4 * time.Minute)
		ruleMinutes(h, pub, 4, 10_000, 1_000, 0, 100, id, "[]") // 1% of the fleet, under 2%
		h.tick()
		r, _ := liveRuleIn(pub.active().Config, id)
		if st := ruleState(t, h, id); st != "enforcing" || r.Action != "block" {
			t.Fatalf("rule %s, published action %q", st, r.Action)
		}
		var shadow float64
		if err := h.db.QueryRow(t.Context(), "SELECT shadow_ratio FROM autopilot_rules WHERE id = $1", id).Scan(&shadow); err != nil || shadow != 0.1 {
			t.Fatalf("shadow ratio %v, err %v", shadow, err)
		}
		if !slices.Contains(h.actions(), "autopilot.enforce rule "+id) {
			t.Fatalf("audit %v", h.actions())
		}
	})
	t.Run("in observe mode a rule enforces only once a person approves", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.user("vera", "viewer")
		pub.setAutopilot(map[string]any{"mode": "observe"})
		id := observed(t, h, pub, agent, 100, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "observing" {
			t.Fatalf("rule %s before approval", st)
		}
		status(t, h.signedIn("vera").do("POST", "/api/autopilot/rules/"+id+"/enforce", nil), 403)
		status(t, pub.do("POST", "/api/autopilot/rules/"+id+"/enforce", nil), 204)
		h.tick()
		if r, _ := liveRuleIn(pub.active().Config, id); ruleState(t, h, id) != "enforcing" || r.Action != "block" {
			t.Fatalf("rule %s, action %q", ruleState(t, h, id), r.Action)
		}
	})
	t.Run("a sensor never enforces on its own", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		if r, _ := liveRuleIn(pub.active().Config, id); ruleState(t, h, id) != "observing" || r.Action != "log" {
			t.Fatalf("sensor %s, action %q", ruleState(t, h, id), r.Action)
		}
	})
	t.Run("an enforcing rule still limiting near its expiry is renewed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := observed(t, h, pub, agent, 100, "[]")
		h.tick() // enforcing, expiring an hour after it started blocking
		h.advance(48 * time.Minute)
		ruleMinutes(h, pub, 5, 10_000, 1_000, 50, 0, id, "[]")
		h.tick()
		r, _ := liveRuleIn(pub.active().Config, id)
		if ruleState(t, h, id) != "enforcing" || r.ExpiresAt.Sub(h.now().Add(time.Hour)).Abs() > time.Second {
			t.Fatalf("rule %s expiring %v, want an hour from now", ruleState(t, h, id), r.ExpiresAt)
		}
		if !slices.Contains(h.actions(), "autopilot.renew rule "+id) {
			t.Fatalf("audit %v", h.actions())
		}
	})
	// Its ttl counts from when it starts blocking: counted from when it went
	// live, observe_for and the wait for a publish would leave it too little
	// to renew while the attack goes on.
	t.Run("an enforce rule gets its whole ttl from when it starts blocking, and renews while it limits", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		in := proposal("enforce", "login-stuffing", loginRule())
		in["ttl"] = "8m"
		id := liveRule(t, h, pub, agent, in)
		h.advance(6 * time.Minute) // past observe_for, 5m
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		r, _ := liveRuleIn(pub.active().Config, id)
		if ruleState(t, h, id) != "enforcing" || r.ExpiresAt.Sub(h.now().Add(8*time.Minute)).Abs() > time.Second {
			t.Fatalf("rule %s expiring %v, want 8m from now", ruleState(t, h, id), r.ExpiresAt)
		}
		h.advance(6*time.Minute + 30*time.Second) // under a quarter of its ttl left
		ruleMinutes(h, pub, 5, 10_000, 1_000, 50, 0, id, "[]")
		h.tick()
		r, _ = liveRuleIn(pub.active().Config, id)
		if ruleState(t, h, id) != "enforcing" || r.ExpiresAt.Sub(h.now().Add(time.Hour)).Abs() > time.Second {
			t.Fatalf("rule %s expiring %v, want default_ttl from now", ruleState(t, h, id), r.ExpiresAt)
		}
	})
	t.Run("an observing rule whose max_lifetime was lowered past its age ends expired instead of enforcing", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
		pub.setAutopilot(map[string]any{"max_ttl": "6m", "default_ttl": "6m", "max_lifetime": "6m"})
		h.advance(7 * time.Minute) // past observe_for and the new max_lifetime
		ruleMinutes(h, pub, 7, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "expired" {
			t.Fatalf("rule %s, want expired", st)
		}
		if _, live := liveRuleIn(pub.active().Config, id); live {
			t.Fatal("an expired rule is still in the active version")
		}
		if a := h.actions(); !slices.Contains(a, "autopilot.expire rule "+id) || slices.Contains(a, "autopilot.enforce rule "+id) {
			t.Fatalf("audit %v", a)
		}
	})
	t.Run("an enforcing rule no longer limiting expires and is pruned", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := observed(t, h, pub, agent, 100, "[]")
		h.tick()
		h.advance(48 * time.Minute)
		ruleMinutes(h, pub, 15, 10_000, 1_000, 0, 0, id, "[]") // limited nothing for 15m
		h.tick()
		if ruleState(t, h, id) != "enforcing" || slices.Contains(h.actions(), "autopilot.renew rule "+id) {
			t.Fatalf("rule %s renewed without limiting", ruleState(t, h, id))
		}
		h.advance(13 * time.Minute) // past its expiry
		h.tick()
		var outcome string
		if err := h.db.QueryRow(t.Context(), "SELECT outcome FROM autopilot_rules WHERE id = $1", id).Scan(&outcome); err != nil || ruleState(t, h, id) != "expired" || outcome != "expired" {
			t.Fatalf("rule %s outcome %q, err %v", ruleState(t, h, id), outcome, err)
		}
		if _, live := liveRuleIn(pub.active().Config, id); live {
			t.Fatal("an expired rule is still in the active version")
		}
		if !slices.Contains(h.actions(), "autopilot.expire rule "+id) {
			t.Fatalf("audit %v", h.actions())
		}
	})
	t.Run("a sensor is renewed without traffic, up to max_lifetime", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"max_lifetime": "25h"})
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		live := h.now()
		h.advance(50 * time.Minute)
		h.tick()
		if r, _ := liveRuleIn(pub.active().Config, id); r.ExpiresAt.Sub(h.now().Add(24*time.Hour)).Abs() > time.Second {
			t.Fatalf("sensor expires %v, want max_ttl from now", r.ExpiresAt)
		}
		h.advance(19 * time.Hour) // under a quarter of max_ttl left
		h.tick()
		if r, _ := liveRuleIn(pub.active().Config, id); r.ExpiresAt.Sub(live.Add(25*time.Hour)).Abs() > time.Second {
			t.Fatalf("sensor expires %v, want max_lifetime after it went live", r.ExpiresAt)
		}
	})
	t.Run("a person retires a rule and the overlay drops it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		status(t, pub.do("POST", "/api/autopilot/rules/"+id+"/retire", map[string]any{"reason": "Our load test"}), 204)
		h.tick()
		if _, live := liveRuleIn(pub.active().Config, id); live || ruleState(t, h, id) != "retired" {
			t.Fatalf("rule %s, live %v", ruleState(t, h, id), live)
		}
		var actor string
		if err := h.db.QueryRow(t.Context(), "SELECT actor FROM audit_events WHERE action = 'autopilot.retire' AND target = $1", "rule "+id).Scan(&actor); err != nil || actor != "user:pub" {
			t.Fatalf("retire actor %q, err %v", actor, err)
		}
	})
	t.Run("the agent retires a rule on review", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		_, cs := agentCase(t, h, pub, agent)
		if p := propose(t, cs, map[string]any{"action": "retire", "rule_id": id, "rationale": "Never fired in a day"}); !p.Accepted {
			t.Fatalf("proposal %+v", p)
		}
		h.tick()
		var outcome string
		if err := h.db.QueryRow(t.Context(), "SELECT outcome FROM autopilot_rules WHERE id = $1", id).Scan(&outcome); err != nil || ruleState(t, h, id) != "retired" || outcome != "retired_by_review" {
			t.Fatalf("rule %s outcome %q, err %v", ruleState(t, h, id), outcome, err)
		}
	})
	t.Run("a rule a person adopts ends as adopted, and a revert past the adopt brings it back", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := observed(t, h, pub, agent, 100, "[]")
		h.tick() // enforcing
		before := pub.active().Version
		status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": id}, "If-Match", pub.revision()), 200)
		status(t, pub.publishDraft("Keep blocking the stuffing"), 201)
		h.tick()
		if st := ruleState(t, h, id); st != "adopted" {
			t.Fatalf("rule %s after the adopt", st)
		}
		status(t, pub.do("POST", fmt.Sprintf("/api/versions/%d/revert", before), map[string]string{"reason": "The adopted copy blocks too much"}), 201)
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s after the revert", st)
		}
	})
}

// enforcingRule has an enforce proposal observed at a 10% shadow ratio
// (100 of 1,000 evaluated) and enforcing; the clock is at enforcing_since.
func enforcingRule(t *testing.T, h *harness, pub, agent *client) string {
	t.Helper()
	id := observed(t, h, pub, agent, 100, "[]")
	h.tick()
	if st := ruleState(t, h, id); st != "enforcing" {
		t.Fatalf("rule %s", st)
	}
	return id
}

// enforcingOnAttackers is an enforcing rule whose shadow blocks all went
// to one heavy subject: its shadow ratio is 0, so the guard holds it to
// max_ratio, 5% of the requests it checks.
func enforcingOnAttackers(t *testing.T, h *harness, pub, agent *client) string {
	t.Helper()
	id := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
	h.advance(6 * time.Minute)
	ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, id, sampledTop(id, "would_limit", 1, 100))
	h.tick()
	var shadow float64
	if err := h.db.QueryRow(t.Context(), "SELECT shadow_ratio FROM autopilot_rules WHERE id = $1", id).Scan(&shadow); err != nil || ruleState(t, h, id) != "enforcing" || shadow != 0 {
		t.Fatalf("rule %s shadow %v, err %v", ruleState(t, h, id), shadow, err)
	}
	return id
}

func TestAutopilotPerRuleGuard(t *testing.T) {
	rolledBack := func(t *testing.T, h *harness, pub *client, id string) {
		t.Helper()
		if _, live := liveRuleIn(pub.active().Config, id); live || ruleState(t, h, id) != "rolled_back" {
			t.Fatalf("rule %s, still live %v", ruleState(t, h, id), live)
		}
		var actor string
		if err := h.db.QueryRow(t.Context(), "SELECT actor FROM audit_events WHERE action = 'autopilot.rollback' AND target = $1", "rule "+id).Scan(&actor); err != nil || actor != "system:guard" {
			t.Fatalf("rollback actor %q, err %v", actor, err)
		}
		h.wantMetrics(`admin_guard_actions_total{action="rollback"} 1`)
	}
	t.Run("limiting far more than its shadow estimate rolls back at once", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		// A removal is never held. default_ttl rises so a rule can still renew between publishes.
		pub.setAutopilot(map[string]any{"min_publish_interval": "15m", "default_ttl": "2h"})
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]") // 40% against a 10% shadow, over 3x
		h.tick()
		rolledBack(t, h, pub, id)
	})
	t.Run("blocking more than max_block_share of the fleet rolls back", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 10_000, 1_000, 250, 0, id, "[]") // 25%: under 3x shadow, but 2.5% of the fleet
		h.tick()
		rolledBack(t, h, pub, id)
	})
	t.Run("a rule limiting what its shadow estimate said keeps enforcing", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 10_000, 1_000, 120, 0, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("most of the blocks going to one attacker does not roll back", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, fmt.Sprintf(`[{"rule":%q,"key":"k1","display":"198.51.100.7","limited":380}]`, id))
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("blocks that all go to 10 attackers, estimated over in some minutes and under in others, keep enforcing", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingOnAttackers(t, h, pub, agent)
		h.advance(4 * time.Minute)
		// 40 blocks each a minute, estimated at 32 or 48: 1,600 blocks, 1,600 estimated.
		for ago, est := range map[int]int64{1: 32, 2: 48, 3: 32, 4: 48} {
			h.statsMinute(1, ago, 10_000, fmt.Sprintf(`[{"id":%q,"evaluated":500,"limited":400}]`, id), sampledTop(id, "limited", 10, est))
		}
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("blocks spread over 40 subjects, each under 5%, still roll back", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingOnAttackers(t, h, pub, agent)
		h.advance(3 * time.Minute)
		// 10 blocks each a minute, one sample of 16: 4% of 400, never heavy.
		ruleMinutes(h, pub, 3, 10_000, 500, 400, 0, id, sampledTop(id, "limited", 40, 16))
		h.tick()
		rolledBack(t, h, pub, id)
	})
	t.Run("real collateral well past the sampling allowance, beside heavy attackers, still rolls back", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingOnAttackers(t, h, pub, agent)
		h.advance(3 * time.Minute)
		// 2 attackers at 150 blocks a minute each, and 700 more blocks a minute of clients the top never names.
		ruleMinutes(h, pub, 3, 10_000, 2_000, 1_000, 0, id, sampledTop(id, "limited", 2, 150))
		h.tick()
		rolledBack(t, h, pub, id)
	})
	t.Run("too few requests are not judged", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 100, 100, 40, 0, id, "[]") // 300 fleet requests, under min_requests
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("after its first guard window a rule is no longer judged", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(11 * time.Minute)
		ruleMinutes(h, pub, 1, 10_000, 1_000, 400, 0, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("with the signal on alert it alerts once and keeps enforcing", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		g := decode[GuardSettings](t, pub.do("GET", "/api/settings/guard", nil))
		g.Signals["changed_rule_limited_ratio"] = Signal{Mode: "alert", MaxRatio: 0.05, MaxVsShadow: 3}
		status(t, pub.do("PUT", "/api/settings/guard", g), 204)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
		h.tick()
		h.tick()
		n := 0
		for _, a := range h.actions() {
			if a == "guard.alert rule "+id {
				n++
			}
		}
		if n != 1 || ruleState(t, h, id) != "enforcing" {
			t.Fatalf("%d alerts, rule %s", n, ruleState(t, h, id))
		}
	})
	t.Run("with the signal off it does nothing", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		g := decode[GuardSettings](t, pub.do("GET", "/api/settings/guard", nil))
		g.Signals["changed_rule_limited_ratio"] = Signal{Mode: "off"}
		status(t, pub.do("PUT", "/api/settings/guard", g), 204)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
		h.tick()
		if ruleState(t, h, id) != "enforcing" || slices.ContainsFunc(h.actions(), func(a string) bool { return strings.HasPrefix(a, "guard.") }) {
			t.Fatalf("rule %s, audit %v", ruleState(t, h, id), h.actions())
		}
	})
}

// Autopilot publishes wait for a person's canary and for
// min_publish_interval since the last one. Removals wait only for the
// canary, which no publish can pass.
func TestAutopilotWaitsForCanary(t *testing.T) {
	t.Run("a new rule waits for a canary to end", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c, cs := agentCase(t, h, pub, agent)
		p := propose(t, cs, proposal("add_sensor", "login-watch", loginRule()))
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
		edit := testConfig()
		edit.RateLimitRules[0].Limit = 5
		status(t, pub.save(pub.revision(), edit, adminTest), 200)
		status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2 on 10%", "canary_percent": 10}, "If-Match", pub.revision()), 201)
		h.tick()
		if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 2 {
			t.Fatalf("%d versions during the canary, want 2", len(list))
		}
		h.advance(5 * time.Minute)
		h.putStats(2, 3, 400, 0, 0, []int64{400}, "[]", "[]")
		status(t, pub.do("POST", "/api/canary/promote", nil), 204)
		h.tick()
		if _, live := liveRuleIn(pub.active().Config, p.RuleID); !live || ruleState(t, h, p.RuleID) != "observing" {
			t.Fatalf("after the canary rule %s, live %v", ruleState(t, h, p.RuleID), live)
		}
	})
	t.Run("a new rule waits for min_publish_interval and a removal does not", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		first := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		h.advance(10 * time.Second)
		c, cs := agentCase(t, h, pub, agent)
		p := propose(t, cs, proposal("add_sensor", "account-watch", agentRule(`http.request.uri.path eq "/account"`, "ip")))
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
		h.tick()
		if _, live := liveRuleIn(pub.active().Config, p.RuleID); live {
			t.Fatal("published within min_publish_interval")
		}
		status(t, pub.do("POST", "/api/autopilot/rules/"+first+"/retire", map[string]any{"reason": "Our load test"}), 204)
		h.tick()
		if _, live := liveRuleIn(pub.active().Config, first); live {
			t.Fatal("a removal waited for min_publish_interval")
		}
		h.advance(time.Minute)
		h.tick()
		if _, live := liveRuleIn(pub.active().Config, p.RuleID); !live {
			t.Fatal("not published after min_publish_interval")
		}
	})
}

func (h *harness) caseRows() []string {
	h.t.Helper()
	rows, err := h.db.Query(h.t.Context(), "SELECT kind || ' ' || state FROM autopilot_cases ORDER BY id")
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// firingAnomaly records a firing fleet anomaly.
func (h *harness) firingAnomaly(signal string) int64 {
	h.t.Helper()
	var id int64
	if err := h.db.QueryRow(h.t.Context(), `INSERT INTO anomalies (signal, rule, phase, severity, state, tripped, passed, started_at, fired_at, summary, details)
		VALUES ($1, '', '', 'warning', 'firing', 2, 0, $2, $2, 'Traffic surged', '{}') RETURNING id`, signal, h.now()).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func TestAutopilotCases(t *testing.T) {
	t.Run("a firing anomaly opens one case while the runner is connected", func(t *testing.T) {
		h, _, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		a := h.firingAnomaly("traffic_surge")
		h.tick()
		h.tick()
		var n int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_cases WHERE kind = 'anomaly' AND anomaly_id = $1", a).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%d anomaly cases, err %v", n, err)
		}
		var actor string
		if err := h.db.QueryRow(t.Context(), "SELECT actor FROM audit_events WHERE action = 'autopilot.case_open' ORDER BY seq LIMIT 1").Scan(&actor); err != nil || actor != "system:autopilot" {
			t.Fatalf("case_open actor %q, err %v", actor, err)
		}
	})
	t.Run("no case opens without a runner", func(t *testing.T) {
		h, _, agent := autopilotHarness(t)
		h.firingAnomaly("traffic_surge")
		h.tick()
		status(t, agent.claim("claude"), 204)
		h.advance(3 * time.Minute) // last seen over 2m ago
		h.tick()
		if got := h.caseRows(); len(got) != 0 {
			t.Fatalf("cases %v", got)
		}
	})
	t.Run("the first tick with a runner opens a sweep and a review, and the next sweep an hour later", func(t *testing.T) {
		h, _, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		h.tick()
		h.tick()
		if got := h.caseRows(); !slices.Equal(got, []string{"sweep queued", "review queued"}) && !slices.Equal(got, []string{"review queued", "sweep queued"}) {
			t.Fatalf("cases %v", got)
		}
		h.advance(61 * time.Minute)
		status(t, agent.claim("claude"), 200) // takes one; the runner stays seen
		h.tick()
		var sweeps int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_cases WHERE kind = 'sweep'").Scan(&sweeps); err != nil || sweeps != 2 {
			t.Fatalf("%d sweeps, err %v", sweeps, err)
		}
	})
	t.Run("a case queued over an hour is cancelled", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		status(t, agent.claim("openai"), 204) // seen, but can't run the claude model
		id := pub.investigate("login", "Guessing passwords?")
		h.advance(61 * time.Minute)
		h.tick()
		var state string
		if err := h.db.QueryRow(t.Context(), "SELECT state FROM autopilot_cases WHERE id = $1", id).Scan(&state); err != nil || state != "cancelled" {
			t.Fatalf("case %s, err %v", state, err)
		}
	})
	t.Run("Investigate without a runner is refused", func(t *testing.T) {
		_, pub, _ := autopilotHarness(t)
		resp := pub.do("POST", "/api/autopilot/cases", map[string]any{"rule": "login", "question": "Guessing passwords?"})
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, "runner") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("Investigate on a rule with an open case is refused", func(t *testing.T) {
		_, pub, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		pub.investigate("login", "Guessing passwords?")
		status(t, pub.do("POST", "/api/autopilot/cases", map[string]any{"rule": "login", "question": "Still guessing?"}), 409)
	})
	t.Run("a 1,000-character question in Korean is accepted", func(t *testing.T) {
		_, pub, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		pub.investigate("login", strings.Repeat("가", 1000))
	})
	t.Run("at most 100 cases are open", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		for i := range 100 {
			if _, err := h.owner.Exec(t.Context(), "INSERT INTO autopilot_cases (kind, dedupe_key, state, opened_by, brief) VALUES ('investigate', $1, 'queued', 'user:pub', '{}')", fmt.Sprint("test:", i)); err != nil {
				t.Fatal(err)
			}
		}
		status(t, pub.do("POST", "/api/autopilot/cases", map[string]any{"rule": "login", "question": "Guessing passwords?"}), 409)
		h.firingAnomaly("traffic_surge")
		h.tick()
		var n int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_cases WHERE state IN ('queued', 'running')").Scan(&n); err != nil || n != 100 {
			t.Fatalf("%d open cases, err %v", n, err)
		}
	})
	t.Run("a case reads with its tool calls, cited evidence and the rule it made", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c, cs := agentCase(t, h, pub, agent)
		mustCall(t, cs, "get_case", nil)
		p := propose(t, cs, proposal("enforce", "login-stuffing", loginRule()))
		// The runner's own report of a tool call is its transcript, not a tool call admin answered.
		status(t, agent.events(c.RunID, event(1, "tool_use", `{"tool":"get_case","arguments":{}}`)), 204)
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10, Output: 5, CacheRead: 30, CacheWrite: 40}, nil, 1)), 204)
		h.tick() // publishes the rule log-only
		got := decode[struct {
			Runs      []map[string]any `json:"runs"`
			Proposals []map[string]any `json:"proposals"`
			ToolCalls *[]struct {
				RunID   int64          `json:"run_id"`
				Seq     int            `json:"seq"`
				At      time.Time      `json:"at"`
				Payload map[string]any `json:"payload"`
			} `json:"tool_calls"`
			Rules *[]ruleView `json:"rules"`
		}](t, pub.do("GET", fmt.Sprintf("/api/autopilot/cases/%d", c.CaseID), nil))
		if got.ToolCalls == nil || len(*got.ToolCalls) != 2 {
			t.Fatalf("tool_calls %+v, want get_case then propose", got.ToolCalls)
		}
		for i, tool := range []string{"get_case", "propose"} {
			if tc := (*got.ToolCalls)[i]; tc.RunID != c.RunID || tc.Seq != i+1 || tc.At.IsZero() || tc.Payload["tool"] != tool {
				t.Fatalf("tool call %d %+v, want %s", i, tc, tool)
			}
		}
		if len(got.Proposals) != 1 {
			t.Fatalf("proposals %v", got.Proposals)
		}
		rule, _ := got.Proposals[0]["rule"].(map[string]any)
		evidence, _ := got.Proposals[0]["evidence"].(map[string]any)
		if rule["expression"] != loginRule()["expression"] || got.Proposals[0]["ttl_seconds"] != float64(3600) || evidence["anomaly"] != "rule_would_block on login" {
			t.Fatalf("proposal %v", got.Proposals[0])
		}
		st := decode[autopilotState](t, pub.do("GET", "/api/autopilot", nil))
		i := slices.IndexFunc(st.Rules, func(r ruleView) bool { return r.ID == p.RuleID })
		if i < 0 {
			t.Fatalf("rule %s is not live", p.RuleID)
		}
		if got.Rules == nil || len(*got.Rules) != 1 {
			t.Fatalf("rules %+v", got.Rules)
		}
		if r := (*got.Rules)[0]; r.ID != p.RuleID || r.Kind != "enforce" || r.State != "observing" || r.Outcome != nil || r.Expression == "" || r.Expression != st.Rules[i].Expression {
			t.Fatalf("rule %+v", r)
		}
		if len(got.Runs) != 1 {
			t.Fatalf("runs %v", got.Runs)
		}
		run := got.Runs[0]
		if ec, ok := run["error_category"]; !ok || ec != "" || run["cache_read_tokens"] != float64(30) || run["cache_write_tokens"] != float64(40) {
			t.Fatalf("run %v", run)
		}
	})
	t.Run("a tool call's answer is hidden from a token with only autopilot.read", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c, cs := agentCase(t, h, pub, agent)
		mustCall(t, cs, "get_case", nil)
		reader := h.client()
		reader.token = decode[map[string]string](t, pub.do("POST", "/api/tokens", map[string]any{"name": "reader", "kind": "user",
			"scopes": []string{"autopilot.read"}, "expires_in": "720h"}))["token"]
		read := func(cl *client) map[string]any {
			got := decode[struct {
				ToolCalls []struct {
					Payload map[string]any `json:"payload"`
				} `json:"tool_calls"`
			}](t, cl.do("GET", fmt.Sprintf("/api/autopilot/cases/%d", c.CaseID), nil))
			if len(got.ToolCalls) != 1 {
				t.Fatalf("tool_calls %+v, want get_case", got.ToolCalls)
			}
			return got.ToolCalls[0].Payload
		}
		if p := read(reader); p["tool"] != "get_case" || p["hidden"] != true || p["result"] != nil {
			t.Fatalf("autopilot.read only got %v, want the answer hidden", p)
		}
		if p := read(pub); p["result"] == nil || p["hidden"] != nil {
			t.Fatalf("admin got %v, want the answer", p)
		}
	})
	for _, scopes := range [][]string{{"autopilot.read", "stats.read"}, {"autopilot.read", "config.read"}} {
		t.Run(fmt.Sprintf("a tool call's answer is hidden from a token with only %s", strings.Join(scopes, " and ")), func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			c, cs := agentCase(t, h, pub, agent)
			mustCall(t, cs, "get_case", nil)
			reader := h.client()
			reader.token = decode[map[string]string](t, pub.do("POST", "/api/tokens", map[string]any{"name": "reader", "kind": "user",
				"scopes": scopes, "expires_in": "720h"}))["token"]
			got := decode[struct {
				ToolCalls []struct {
					Payload map[string]any `json:"payload"`
				} `json:"tool_calls"`
			}](t, reader.do("GET", fmt.Sprintf("/api/autopilot/cases/%d", c.CaseID), nil))
			if len(got.ToolCalls) != 1 {
				t.Fatalf("tool_calls %+v, want get_case", got.ToolCalls)
			}
			if p := got.ToolCalls[0].Payload; p["tool"] != "get_case" || p["hidden"] != true || p["result"] != nil {
				t.Fatalf("%v got %v, want the answer hidden", scopes, p)
			}
		})
	}
}

func (c *client) heartbeat(caseID, runID int64) *http.Response {
	c.h.t.Helper()
	return c.do("POST", fmt.Sprintf("/v1/autopilot/cases/%d/heartbeat", caseID), map[string]any{"run_id": runID, "providers": []string{"claude"}})
}

func TestAutopilotLease(t *testing.T) {
	caseState := func(t *testing.T, h *harness, id int64) (string, int) {
		t.Helper()
		var state string
		var attempts int
		if err := h.db.QueryRow(t.Context(), "SELECT state, attempts FROM autopilot_cases WHERE id = $1", id).Scan(&state, &attempts); err != nil {
			t.Fatal(err)
		}
		return state, attempts
	}
	t.Run("a heartbeat extends the lease", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		h.advance(8 * time.Minute)
		resp := agent.heartbeat(c.CaseID, c.RunID)
		got := decode[struct {
			LeaseUntil time.Time `json:"lease_until"`
		}](t, resp)
		if resp.StatusCode != 200 || got.LeaseUntil.Sub(h.now().Add(10*time.Minute)).Abs() > time.Second {
			t.Fatalf("%d lease until %v", resp.StatusCode, got.LeaseUntil)
		}
		h.advance(5 * time.Minute)
		h.tick()
		if st, _ := caseState(t, h, c.CaseID); st != "running" {
			t.Fatalf("case %s", st)
		}
	})
	t.Run("a lapsed lease requeues once, then the case needs a person", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		h.advance(11 * time.Minute)
		h.tick()
		if st, n := caseState(t, h, c.CaseID); st != "queued" || n != 1 {
			t.Fatalf("case %s after %d attempts", st, n)
		}
		if !slices.Contains(h.actions(), fmt.Sprintf("autopilot.case_release case %d", c.CaseID)) {
			t.Fatalf("audit %v", h.actions())
		}
		again := agent.claimCase()
		if again.CaseID != c.CaseID || again.Attempt != 2 || again.RunID == c.RunID {
			t.Fatalf("second claim %+v", again)
		}
		h.advance(11 * time.Minute)
		h.tick()
		if st, n := caseState(t, h, c.CaseID); st != "failed" || n != 2 {
			t.Fatalf("case %s after %d attempts", st, n)
		}
	})
	t.Run("a case requeued an hour after it opened gets its second attempt", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		agent.seen()
		id := pub.investigate("login", "Is someone guessing passwords?")
		h.advance(55 * time.Minute) // waiting under cases_per_hour
		if c := agent.claimCase(); c.CaseID != id {
			t.Fatalf("claimed %+v", c)
		}
		h.advance(11 * time.Minute)
		h.tick()
		if st, n := caseState(t, h, id); st != "queued" || n != 1 {
			t.Fatalf("case %s after %d attempts, want it queued again", st, n)
		}
		h.advance(61 * time.Minute)
		h.tick()
		if st, _ := caseState(t, h, id); st != "cancelled" {
			t.Fatalf("case %s an hour after it was requeued, want cancelled", st)
		}
	})
	t.Run("a result after the lease lapsed is refused and still recorded", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		h.advance(11 * time.Minute)
		h.tick()
		status(t, agent.heartbeat(c.CaseID, c.RunID), 409)
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 409)
		var runStatus string
		if err := h.db.QueryRow(t.Context(), "SELECT status FROM autopilot_run_results WHERE run_id = $1", c.RunID).Scan(&runStatus); err != nil || runStatus != "lease_lost" {
			t.Fatalf("run %q, err %v", runStatus, err)
		}
		if st, _ := caseState(t, h, c.CaseID); st != "queued" {
			t.Fatalf("case %s", st)
		}
	})
}

// The kill switch removes every autopilot rule in one publish, cancels
// open cases and is audited with the version it published, all at once.
func TestAutopilotKillSwitch(t *testing.T) {
	t.Run("turning autopilot off removes its rules and cancels its cases", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		sensor := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		h.advance(time.Minute)
		enforcing := liveRule(t, h, pub, agent, proposal("enforce", "account-stuffing", agentRule(`http.request.uri.path eq "/account"`, "ip")))
		running := openAndClaim(t, pub, agent).CaseID
		queued := pub.investigate("admin-route", "Scanning the admin pages?")
		before := pub.active().Version
		pub.setAutopilot(map[string]any{"mode": "off"})
		v := pub.active()
		if v.Version != before+1 || v.Source != "autopilot" || slices.ContainsFunc(v.Config.RateLimitRules, func(r snapshot.RateLimitRule) bool { return strings.HasPrefix(r.ID, "ap-") }) {
			t.Fatalf("version %d %s, rules %v", v.Version, v.Source, rateLimitIDs(v.Config))
		}
		for _, id := range []string{sensor, enforcing} {
			if ruleState(t, h, id) != "retired" || lastReason(t, h, id, "retired") != "kill_switch" {
				t.Fatalf("rule %s %s", id, ruleState(t, h, id))
			}
		}
		for _, id := range []int64{running, queued} {
			var state string
			if err := h.db.QueryRow(t.Context(), "SELECT state FROM autopilot_cases WHERE id = $1", id).Scan(&state); err != nil || state != "cancelled" {
				t.Fatalf("case %d %s, err %v", id, state, err)
			}
		}
		var after string
		var version int64
		if err := h.db.QueryRow(t.Context(), "SELECT details->'after'->>'mode', (details->>'version')::bigint FROM audit_events WHERE action = 'settings.autopilot' ORDER BY seq DESC LIMIT 1").
			Scan(&after, &version); err != nil || after != "off" || version != v.Version {
			t.Fatalf("audit mode %q version %d, err %v", after, version, err)
		}
		h.tick()
		if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != int(v.Version) {
			t.Fatalf("a tick published while off: %d versions", len(list))
		}
	})
	t.Run("turning autopilot off with no rules publishes nothing", func(t *testing.T) {
		_, pub, _ := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"mode": "off"})
		if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 1 {
			t.Fatalf("%d versions, want 1", len(list))
		}
	})
	t.Run("turning autopilot off during a canary is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
		resp := pub.do("POST", "/api/publish", map[string]any{"message": "on 10%", "canary_percent": 10}, "If-Match", pub.revision())
		v := decode[map[string]int64](t, resp)["version"]
		s := pub.autopilotSettings()
		s["mode"] = "off"
		resp = pub.do("PUT", "/api/settings/autopilot", s)
		want := fmt.Sprintf("version %d is in canary; promote or abort it, then turn autopilot off", v)
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, want) {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		if pub.autopilotSettings()["mode"] != "auto" {
			t.Fatal("the mode changed")
		}
	})
	t.Run("the reason for turning autopilot off is audited, not saved", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		s := pub.autopilotSettings()
		s["mode"], s["reason"] = "off", "It blocked our partner's checkout"
		status(t, pub.do("PUT", "/api/settings/autopilot", s), 204)
		var reason string
		if err := h.db.QueryRow(t.Context(), "SELECT details->>'reason' FROM audit_events WHERE action = 'settings.autopilot' ORDER BY seq DESC LIMIT 1").
			Scan(&reason); err != nil || reason != "It blocked our partner's checkout" {
			t.Fatalf("audit reason %q, err %v", reason, err)
		}
		got := pub.autopilotSettings()
		if _, saved := got["reason"]; saved || got["mode"] != "off" {
			t.Fatalf("settings %v", got)
		}
		var stored bool
		if err := h.db.QueryRow(t.Context(), "SELECT value ? 'reason' FROM settings WHERE key = 'autopilot'").Scan(&stored); err != nil || stored {
			t.Fatalf("reason stored %v, err %v", stored, err)
		}
	})
	t.Run("a 500-character reason in Korean is audited", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		s := pub.autopilotSettings()
		s["mode"], s["reason"] = "off", strings.Repeat("가", 500)
		status(t, pub.do("PUT", "/api/settings/autopilot", s), 204)
		var reason string
		if err := h.db.QueryRow(t.Context(), "SELECT details->>'reason' FROM audit_events WHERE action = 'settings.autopilot' ORDER BY seq DESC LIMIT 1").
			Scan(&reason); err != nil || reason != strings.Repeat("가", 500) {
			t.Fatalf("audit reason of %d characters, err %v", len([]rune(reason)), err)
		}
	})
	t.Run("a reason of only spaces is not audited", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		s := pub.autopilotSettings()
		s["mode"], s["reason"] = "off", "   "
		status(t, pub.do("PUT", "/api/settings/autopilot", s), 204)
		var has bool
		if err := h.db.QueryRow(t.Context(), "SELECT details::jsonb ? 'reason' FROM audit_events WHERE action = 'settings.autopilot' ORDER BY seq DESC LIMIT 1").
			Scan(&has); err != nil || has {
			t.Fatalf("audit has reason %v, err %v", has, err)
		}
	})
	t.Run("a reason over 500 characters is refused at its field", func(t *testing.T) {
		_, pub, _ := autopilotHarness(t)
		s := pub.autopilotSettings()
		s["mode"], s["reason"] = "off", strings.Repeat("a", 501)
		resp := pub.do("PUT", "/api/settings/autopilot", s)
		p := decode[problem](t, resp)
		if resp.StatusCode != 422 || len(p.Errors) != 1 || p.Errors[0].Path != "reason" {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
		if pub.autopilotSettings()["mode"] != "auto" {
			t.Fatal("the mode changed")
		}
	})
}

func TestAutopilotNotifications(t *testing.T) {
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
	t.Run("autopilot_agent_down fires when the runner goes quiet and resolves when it is back", func(t *testing.T) {
		h, pub, agent := setup(t)
		status(t, agent.claim("claude"), 204)
		h.advance(3 * time.Minute)
		h.check()
		if st := state(h, pub, "autopilot_agent_down"); st != "firing" {
			t.Fatalf("autopilot_agent_down %s", st)
		}
		status(t, agent.claim("claude"), 204)
		h.check()
		if st := state(h, pub, "autopilot_agent_down"); st != "none" {
			t.Fatalf("autopilot_agent_down %s after the runner came back", st)
		}
	})
	t.Run("autopilot_needs_person fires for an unsure verdict", func(t *testing.T) {
		h, pub, agent := setup(t)
		c := openAndClaim(t, pub, agent)
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "unsure", usage{Input: 10}, nil, 0)), 204)
		h.check()
		if st := state(h, pub, "autopilot_needs_person"); st != "firing" {
			t.Fatalf("autopilot_needs_person %s", st)
		}
	})
	t.Run("autopilot_needs_person stays firing for every such case in the hour, past 20", func(t *testing.T) {
		h, pub, agent := setup(t)
		pub.setAutopilot(map[string]any{"cases_per_hour": 30})
		for range 21 {
			c := openAndClaim(t, pub, agent)
			status(t, agent.result(c.CaseID, resultBody(c.RunID, "unsure", usage{Input: 10}, nil, 0)), 204)
		}
		h.check()
		firing := 0
		for _, a := range h.anomalies(pub) {
			if a.Signal == "autopilot_needs_person" && a.State == "firing" {
				firing++
			}
		}
		if firing != 21 {
			t.Fatalf("%d cases needing a person are firing, want 21", firing)
		}
	})
	t.Run("autopilot_enforced fires while a rule enforces", func(t *testing.T) {
		h, pub, agent := setup(t)
		id := enforcingRule(t, h, pub, agent)
		h.check()
		if st := state(h, pub, "autopilot_enforced"); st != "firing" || !slices.ContainsFunc(h.anomalies(pub), func(a anomaly) bool { return a.Rule == id }) {
			t.Fatalf("autopilot_enforced %s", st)
		}
	})
	t.Run("autopilot_rolled_back fires after the guard rolls a rule back", func(t *testing.T) {
		h, pub, agent := setup(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
		h.tick()
		h.check()
		if st := state(h, pub, "autopilot_rolled_back"); st != "firing" {
			t.Fatalf("autopilot_rolled_back %s", st)
		}
	})
	t.Run("a full sensor budget alone raises nothing, since sensors renew", func(t *testing.T) {
		h, pub, agent := setup(t)
		pub.setAutopilot(map[string]any{"max_sensors": 1})
		liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		h.check()
		if st := state(h, pub, "autopilot_budget_exhausted"); st != "none" {
			t.Fatalf("autopilot_budget_exhausted %s", st)
		}
	})
	t.Run("autopilot_budget_exhausted fires when the sensors budget refuses a proposal", func(t *testing.T) {
		h, pub, agent := setup(t)
		pub.setAutopilot(map[string]any{"max_sensors": 1})
		liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		_, cs := agentCase(t, h, pub, agent)
		if p := propose(t, cs, proposal("add_sensor", "search-watch", agentRule(`http.request.uri.path eq "/search"`, "ip"))); p.Accepted || !slices.Contains(p.Reasons, "budget_sensors") {
			t.Fatalf("proposal %+v", p)
		}
		h.check()
		if st := state(h, pub, "autopilot_budget_exhausted"); st != "firing" {
			t.Fatalf("autopilot_budget_exhausted %s", st)
		}
	})
	t.Run("autopilot_budget_exhausted fires when the enforcing budget refuses a proposal", func(t *testing.T) {
		h, pub, agent := setup(t)
		pub.setAutopilot(map[string]any{"max_enforcing": 0})
		_, cs := agentCase(t, h, pub, agent)
		if p := propose(t, cs, proposal("enforce", "login-stuffing", loginRule())); p.Accepted || !slices.Contains(p.Reasons, "budget_enforcing") {
			t.Fatalf("proposal %+v", p)
		}
		h.check()
		if st := state(h, pub, "autopilot_budget_exhausted"); st != "firing" {
			t.Fatalf("autopilot_budget_exhausted %s", st)
		}
	})
	t.Run("autopilot_budget_exhausted fires when cases_per_hour is used up and a case waits", func(t *testing.T) {
		h, pub, agent := setup(t)
		pub.setAutopilot(map[string]any{"cases_per_hour": 1})
		openAndClaim(t, pub, agent)
		pub.investigate("admin-route", "Scanning the admin pages?")
		h.check()
		if st := state(h, pub, "autopilot_budget_exhausted"); st != "firing" {
			t.Fatalf("autopilot_budget_exhausted %s", st)
		}
	})
	t.Run("autopilot_needs_person fires for an attack no accepted rule blocks", func(t *testing.T) {
		h, pub, agent := setup(t)
		c := openAndClaim(t, pub, agent)
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
		h.check()
		if st := state(h, pub, "autopilot_needs_person"); st != "firing" {
			t.Fatalf("autopilot_needs_person %s", st)
		}
	})
	t.Run("an attack with an accepted enforce rule needs no person", func(t *testing.T) {
		h, pub, agent := setup(t)
		liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
		h.check()
		if st := state(h, pub, "autopilot_needs_person"); st != "none" {
			t.Fatalf("autopilot_needs_person %s", st)
		}
	})
	t.Run("in observe mode an attack with an accepted enforce rule waits for a person's approval", func(t *testing.T) {
		h, pub, agent := setup(t)
		pub.setAutopilot(map[string]any{"mode": "observe"})
		liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
		h.check()
		list := h.anomalies(pub)
		i := slices.IndexFunc(list, func(a anomaly) bool { return a.Signal == "autopilot_needs_person" })
		if i < 0 || list[i].State != "firing" || !strings.Contains(list[i].Summary, "waits for a person's approval") {
			t.Fatalf("anomalies %+v", list)
		}
	})
	t.Run("in observe mode a person approving the enforce rule ends the need", func(t *testing.T) {
		h, pub, agent := setup(t)
		pub.setAutopilot(map[string]any{"mode": "observe"})
		id := observed(t, h, pub, agent, 100, "[]")
		h.check()
		if st := state(h, pub, "autopilot_needs_person"); st != "firing" {
			t.Fatalf("autopilot_needs_person %s before approval", st)
		}
		status(t, pub.do("POST", "/api/autopilot/rules/"+id+"/enforce", nil), 204)
		h.advance(time.Minute)
		agent.seen()
		h.check()
		if st := state(h, pub, "autopilot_needs_person"); st != "none" {
			t.Fatalf("autopilot_needs_person %s after approval", st)
		}
	})
	t.Run("an attack on an autopilot rule that already enforces needs no person", func(t *testing.T) {
		h, pub, agent := setup(t)
		id := enforcingRule(t, h, pub, agent)
		agent.seen()
		cid := pub.investigate(id, "Is the attack still on?")
		c := agent.claimCase()
		if c.CaseID != cid {
			t.Fatalf("claimed case %d, opened %d", c.CaseID, cid)
		}
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
		h.check()
		if st := state(h, pub, "autopilot_needs_person"); st != "none" {
			t.Fatalf("autopilot_needs_person %s", st)
		}
	})
}

// A sensor can count upstream statuses, as a person's rule can: failed
// logins and not-found probes are what stuffing and scanning look like.
func TestAutopilotCountStatusesSensor(t *testing.T) {
	failedLogins := func(statuses ...string) map[string]any {
		r := agentRule(`http.request.uri.path eq "/login" and http.request.method eq "POST"`, "ip")
		r["count_statuses"] = statuses
		return r
	}

	t.Run("a sensor counting 401s is proposed and goes live counting them", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-401", failedLogins("401")))
		r, ok := liveRuleIn(pub.active().Config, id)
		if !ok || !slices.Equal(r.CountStatuses, []string{"401"}) || r.Action != "log" {
			t.Fatalf("rule %s live %v, count_statuses %v, action %q", id, ok, r.CountStatuses, r.Action)
		}
	})

	t.Run("a sensor counting 5xx is refused by the validator", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, cs := agentCase(t, h, pub, agent)
		p := propose(t, cs, proposal("add_sensor", "login-5xx", failedLogins("5xx")))
		if p.Accepted || !slices.Contains(p.Reasons, "compile") {
			t.Fatalf("proposal %+v, want refused for compile", p)
		}
		i := slices.IndexFunc(p.Checks, func(c policyCheck) bool { return c.Name == "compile" })
		if i < 0 || !strings.Contains(p.Checks[i].Detail, "5xx can't be counted") {
			t.Fatalf("checks %+v", p.Checks)
		}
	})
}
