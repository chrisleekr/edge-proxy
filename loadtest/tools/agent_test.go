package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

func planRule(expression string, key ...string) map[string]any {
	return map[string]any{"expression": expression, "algorithm": "sliding_window", "limit": 10, "period": "1m", "key": key, "on_missing_key": "fallback_ip"}
}

// testPlan has two sensors, one with a first try admin must refuse. Both
// names hold a hyphen and one a number, as a rule id ap-<name>-<n> does.
var testPlan = plan{Sensors: []planSensor{
	{
		Name:  "login-401",
		Rule:  planRule(`http.request.uri.path eq "/login"`, "ip"),
		Block: planRule(`http.request.uri.path eq "/login" and http.request.method eq "POST"`, "ip"),
		TTL:   "5m",
	},
	{
		Name:     "search-per-ip",
		Rule:     planRule(`http.request.uri.path eq "/api/search"`, "ip"),
		Block:    planRule(`http.request.uri.path eq "/api/search" and http.request.method eq "POST"`, "ip"),
		TTL:      "5m",
		FirstTry: planRule(`http.request.uri.path eq "/api/search" and http.request.method eq "POST"`, "asnum"),
	},
}}

// withoutRationale checks every propose step has a rationale, which admin
// requires, and drops it so the rest compares exactly.
func withoutRationale(t *testing.T, got []step) []step {
	t.Helper()
	out := []step{}
	for _, s := range got {
		if s.Tool == "propose" {
			if r, _ := s.Arguments["rationale"].(string); r == "" {
				t.Fatalf("propose %v has no rationale", s.Arguments)
			}
			args := map[string]any{}
			for k, v := range s.Arguments {
				if k != "rationale" {
					args[k] = v
				}
			}
			s.Arguments = args
		}
		out = append(out, s)
	}
	return out
}

func TestAgentPlansSensorsOnSweep(t *testing.T) {
	sweep := map[string]any{"kind": "sweep", "question": "Find observed routes no rule watches"}
	sensor := func(s planSensor) step {
		return step{"propose", map[string]any{"action": "add_sensor", "name": s.Name, "rule": s.Rule}}
	}
	for _, tc := range []struct {
		name string
		live live
		want []step
	}{
		{"with none live it proposes every plan sensor", live{}, []step{
			{"get_case", map[string]any{}}, {"get_autopilot_state", map[string]any{}}, sensor(testPlan.Sensors[0]), sensor(testPlan.Sensors[1]),
		}},
		{"a sensor already live is not proposed again", live{Sensors: map[string]string{"login-401": "ap-login-401-3"}}, []step{
			{"get_case", map[string]any{}}, {"get_autopilot_state", map[string]any{}}, sensor(testPlan.Sensors[1]),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, verdict := testPlan.steps("sweep", sweep, tc.live)
			if verdict != "benign" {
				t.Errorf("verdict %q, want benign", verdict)
			}
			if got := withoutRationale(t, got); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("steps\n%v\nwant\n%v", got, tc.want)
			}
		})
	}
}

func TestAgentPlansEnforceForItsSensor(t *testing.T) {
	reads := func(rule string) []step {
		return []step{
			{"get_case", map[string]any{}}, {"get_autopilot_state", map[string]any{}}, {"get_rule_stats", map[string]any{"rule": rule}}, {"list_rules", map[string]any{}},
			{"check_subject", map[string]any{"ip": "203.0.113.7"}}, {"check_subject", map[string]any{"ip": "198.51.100.9"}},
		}
	}
	enforce := func(s planSensor, rule map[string]any, cites string) step {
		return step{"propose", map[string]any{"action": "enforce", "name": s.Name + "-block", "rule": rule, "ttl": s.TTL, "cites": cites,
			"evidence": map[string]any{"evidence_ids": []int{3, 4}}}}
	}
	// What the reads answered: two IP subjects and a user id, which
	// check_subject can't take, and the evidence ids of the stats reads.
	l := live{Subjects: []string{"203.0.113.7", "198.51.100.9", "user-42"}, Evidence: []int{3, 4}}
	login, search := testPlan.Sensors[0], testPlan.Sensors[1]
	for _, tc := range []struct {
		name string
		rule string
		want []step
	}{
		{"a sensor without a first try reads, checks its subjects and enforces its block rule", "ap-login-401-12",
			append(reads("ap-login-401-12"), enforce(login, login.Block, "ap-login-401-12"))},
		{"a sensor with a first try proposes it before its block rule", "ap-search-per-ip-15",
			append(reads("ap-search-per-ip-15"), enforce(search, search.FirstTry, "ap-search-per-ip-15"), enforce(search, search.Block, "ap-search-per-ip-15"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			brief := map[string]any{"kind": "anomaly", "signal": "rule_would_block", "rule": tc.rule, "summary": map[string]any{"untrusted": "would block 3 addresses"}}
			got, verdict := testPlan.steps("anomaly", brief, l)
			if verdict != "attack" {
				t.Errorf("verdict %q, want attack", verdict)
			}
			if got := withoutRationale(t, got); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("steps\n%v\nwant\n%v", got, tc.want)
			}
		})
	}
}

func TestAgentAnswersOtherCasesBenign(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  string
		brief map[string]any
	}{
		{"a review", "review", map[string]any{"kind": "review", "question": "Review the autopilot rules"}},
		{"a person's question", "investigate", map[string]any{"kind": "investigate", "question": "Is someone guessing passwords?"}},
		{"an anomaly on a person's rule", "anomaly", map[string]any{"kind": "anomaly", "signal": "rule_would_block", "rule": "login"}},
		{"an anomaly on an autopilot rule the plan does not name", "anomaly", map[string]any{"kind": "anomaly", "signal": "rule_would_block", "rule": "ap-checkout-9"}},
		{"an anomaly on no rule", "anomaly", map[string]any{"kind": "anomaly", "signal": "status_5xx", "rule": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, verdict := testPlan.steps(tc.kind, tc.brief, live{})
			if want := []step{{"get_case", map[string]any{}}}; verdict != "benign" || !reflect.DeepEqual(got, want) {
				t.Fatalf("steps %v verdict %q, want %v benign", got, verdict, want)
			}
		})
	}
}

// overlayRule decodes a plan rule as admin's propose does, refusing a field
// it does not take, and builds the rule admin publishes. The fields are
// admin's ruleIn; keep them in step with it.
func overlayRule(t *testing.T, id, action string, in map[string]any) snapshot.RateLimitRule {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Expression    string            `json:"expression"`
		Algorithm     string            `json:"algorithm"`
		Limit         int64             `json:"limit"`
		Period        snapshot.Duration `json:"period"`
		Burst         int64             `json:"burst,omitempty"`
		Key           []string          `json:"key"`
		OnMissingKey  string            `json:"on_missing_key"`
		FailMode      string            `json:"fail_mode,omitempty"`
		Penalty       snapshot.Duration `json:"penalty,omitempty"`
		DistinctOf    string            `json:"distinct_of,omitempty"`
		CountStatuses []string          `json:"count_statuses,omitempty"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	n, err := expr.Parse(r.Expression)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return snapshot.RateLimitRule{ID: id, Expression: n, Algorithm: r.Algorithm, Limit: r.Limit, Period: r.Period, Burst: r.Burst, Key: r.Key,
		OnMissingKey: r.OnMissingKey, Action: action, Penalty: r.Penalty, FailMode: "open", DistinctOf: r.DistinctOf, CountStatuses: r.CountStatuses}
}

// The load-full attacks need the embedded plan's five sensors, and every
// rule the agent proposes must pass the one validator with the load policy,
// or admin refuses it on compile and the attack is never enforced.
func TestAutopilotPlanCompiles(t *testing.T) {
	p, err := readPlan(autopilotPlan)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range p.Sensors {
		names = append(names, s.Name)
	}
	if want := []string{"idor-paths", "catalog-per-user", "login-401", "notfound-per-ip", "search-per-ip"}; !slices.Equal(names, want) {
		t.Fatalf("sensors %v, want %v", names, want)
	}
	var base struct {
		Config snapshot.Config `json:"config"`
	}
	if err := json.Unmarshal(policy, &base); err != nil {
		t.Fatal(err)
	}
	base.Config.Version = 1
	// The load environment's admin and edges, as compose.yaml sets them:
	// CloudFront is the trusted viewer source, so asnum is a key it accepts.
	deployment, err := edge.LoadDeployment(func(k string) string {
		return map[string]string{"CLIENT_IP_SOURCE": "cloudfront", "TRUSTED_PROXIES": "10.77.0.0/24"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	compile := func(t *testing.T, rules ...snapshot.RateLimitRule) {
		t.Helper()
		cfg := base.Config
		cfg.RateLimitRules = append(slices.Clone(cfg.RateLimitRules), rules...)
		if _, _, errs := snapshot.Compile(&cfg, deployment); errs != nil {
			t.Fatalf("errors %v", errs)
		}
	}

	t.Run("every sensor and its block rule compile together", func(t *testing.T) {
		var rules []snapshot.RateLimitRule
		for i, s := range p.Sensors {
			rules = append(rules, overlayRule(t, fmt.Sprintf("ap-%s-%d", s.Name, 2*i+1), "log", s.Rule),
				overlayRule(t, fmt.Sprintf("ap-%s-block-%d", s.Name, 2*i+2), "block", s.Block))
		}
		compile(t, rules...)
	})

	t.Run("every sensor's ttl is at least admin's 4m renewal minimum", func(t *testing.T) {
		for _, s := range p.Sensors {
			// Admin refuses a ttl under 4 x (30s tick + min_publish_interval),
			// 4m with the 30s interval load-full sets: a rule renews in the
			// last quarter of its ttl.
			if d, err := time.ParseDuration(s.TTL); err != nil || d < 4*time.Minute {
				t.Fatalf("%s ttl %q, want at least 4m, the shortest ttl admin renews within", s.Name, s.TTL)
			}
		}
	})

	// The ASN attack's first try compiles, so admin refuses it for its key
	// alone: key_needs_ip_or_jwt.
	t.Run("only the asn sensor has a first try, keyed on asnum alone, and it compiles", func(t *testing.T) {
		for _, s := range p.Sensors {
			if (s.FirstTry != nil) != (s.Name == "search-per-ip") {
				t.Fatalf("%s first_try %v", s.Name, s.FirstTry)
			}
		}
		try := p.Sensors[4].FirstTry
		if key := overlayRule(t, "ap-search-per-ip-block-1", "block", try).Key; !slices.Equal(key, []string{"asnum"}) {
			t.Fatalf("first try key %v, want [asnum]", key)
		}
		compile(t, overlayRule(t, "ap-search-per-ip-block-1", "block", try))
	})
}
