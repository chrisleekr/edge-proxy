package admin

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// ordersRule watches order reads on one host per client IP: the shape of
// a sensor the sweep proposes for a busy API route.
func ordersRule() map[string]any {
	return agentRule(`http.host eq "api.example.com" and starts_with(http.request.uri.path, "/api/orders/")`, "ip")
}

// matches is the autopilot rules the active version matches for a GET
// from ip to path on api.example.com.
func matches(t *testing.T, pub *client, ip, path string) []string {
	t.Helper()
	v := pub.active().Version
	sim := decode[SimView](t, pub.do("POST", "/api/simulate", map[string]any{"version": v, "request": TestRequest{Host: "api.example.com", Path: path, IP: ip}}))
	return slices.DeleteFunc(sim.RateLimitRules, func(id string) bool { return !strings.HasPrefix(id, overlayPrefix) })
}

func exclude(t *testing.T, pub *client, in map[string]any) exclusion {
	t.Helper()
	resp := pub.do("POST", "/api/autopilot/exclusions", in)
	if resp.StatusCode != 201 {
		t.Fatalf("exclude %d: %s", resp.StatusCode, body(resp))
	}
	return decode[exclusion](t, resp)
}

// A person who finds a sensor's client legitimate excludes it: the sensor
// ends, and the autopilot's rules from then on leave the client out on
// that host and path, while everyone else is still counted.
func TestAutopilotExclusions(t *testing.T) {
	const ci, other = "198.51.100.7", "203.0.113.9"
	t.Run("excluding a sensor's client retires the sensor and takes its host and path", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "orders-watch", ordersRule()))
		e := exclude(t, pub, map[string]any{"subject": ci, "rule_id": id, "reason": "Our CI polls merge requests", "ttl": "720h"})
		if e.Subject.String() != ci+"/32" || e.Host != "api.example.com" || e.PathPrefix != "/api/orders/" || e.RuleID == nil || *e.RuleID != id ||
			e.ExpiresAt == nil || e.ExpiresAt.Sub(h.now()) <= 720*time.Hour-time.Second || e.ExpiresAt.Sub(h.now()) > 720*time.Hour {
			t.Fatalf("exclusion %+v", e)
		}
		if st := ruleState(t, h, id); st != "retired" {
			t.Fatalf("sensor %s", st)
		}
		if r := lastReason(t, h, id, "retired"); !strings.Contains(r, "excluded") {
			t.Fatalf("reason %q", r)
		}
	})
	t.Run("a sensor proposed after it leaves the client out on the edges and counts everyone else", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exclude(t, pub, map[string]any{"subject": ci, "host": "api.example.com", "path_prefix": "/api/orders/", "reason": "Our CI"})
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "orders-watch", ordersRule()))
		if got := matches(t, pub, ci, "/api/orders/1"); slices.Contains(got, id) {
			t.Fatalf("the excluded client matched %v", got)
		}
		if got := matches(t, pub, other, "/api/orders/1"); !slices.Contains(got, id) {
			t.Fatalf("another client matched %v", got)
		}
	})
	t.Run("an exclusion on another path leaves the client counted here", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exclude(t, pub, map[string]any{"subject": ci, "host": "api.example.com", "path_prefix": "/api/uploads/", "reason": "Our CI"})
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "orders-watch", ordersRule()))
		if got := matches(t, pub, ci, "/api/orders/1"); !slices.Contains(got, id) {
			t.Fatalf("the client matched %v", got)
		}
	})
	t.Run("revoking it retires the sensors that carry it, and an enforcing rule keeps blocking", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		e := exclude(t, pub, map[string]any{"subject": ci, "host": "api.example.com", "reason": "Our CI"})
		sensor := liveRule(t, h, pub, agent, proposal("add_sensor", "orders-watch", ordersRule()))
		h.advance(time.Minute) // min_publish_interval
		enforce := liveRule(t, h, pub, agent, proposal("enforce", "orders-flood",
			agentRule(`http.host eq "api.example.com" and http.request.method eq "POST"`, "ip")))
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, enforce, "[]")
		h.tick()
		if st := ruleState(t, h, enforce); st != "enforcing" {
			t.Fatalf("enforce rule %s", st)
		}
		status(t, pub.do("POST", "/api/autopilot/exclusions/"+fmt.Sprint(e.ID)+"/revoke", map[string]any{"reason": "The CI moved"}), 204)
		h.tick()
		if st := ruleState(t, h, sensor); st != "retired" {
			t.Fatalf("sensor %s", st)
		}
		if st := ruleState(t, h, enforce); st != "enforcing" {
			t.Fatalf("enforce rule %s", st)
		}
		status(t, pub.do("POST", "/api/autopilot/exclusions/"+fmt.Sprint(e.ID)+"/revoke", map[string]any{"reason": "Again"}), 409)
	})
	t.Run("an expired exclusion is not added to new rules", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exclude(t, pub, map[string]any{"subject": ci, "host": "api.example.com", "reason": "Our CI", "ttl": "1h"})
		h.advance(61 * time.Minute)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "orders-watch", ordersRule()))
		if got := matches(t, pub, ci, "/api/orders/1"); !slices.Contains(got, id) {
			t.Fatalf("the client matched %v", got)
		}
	})
	t.Run("refused exclusions", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		enforce := liveRule(t, h, pub, agent, proposal("enforce", "login-stuffing", loginRule()))
		ok := map[string]any{"subject": ci, "host": "api.example.com", "reason": "Our CI"}
		with := func(k string, v any) map[string]any {
			m := maps.Clone(ok)
			m[k] = v
			return m
		}
		for _, tc := range []struct {
			name string
			in   map[string]any
			path string
		}{
			{"a network wider than /24", with("subject", "198.51.0.0/16"), "subject"},
			{"an AS number", with("subject", "AS64500"), "subject"},
			{"an IPv4-mapped network wider than /24", with("subject", "::ffff:0.0.0.0/96"), "subject"},
			{"no host", with("host", ""), "host"},
			{"a path prefix not starting with /", with("path_prefix", "api"), "path_prefix"},
			{"no reason", with("reason", " "), "reason"},
			{"a reason over 500 characters", with("reason", strings.Repeat("a", 501)), "reason"},
			{"a ttl under an hour", with("ttl", "30m"), "ttl"},
			{"an enforce rule to promote from", with("rule_id", enforce), "rule_id"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				resp := pub.do("POST", "/api/autopilot/exclusions", tc.in)
				p := decode[problem](t, resp)
				if resp.StatusCode != 422 || !slices.ContainsFunc(p.Errors, func(e expr.Issue) bool { return e.Path == tc.path }) {
					t.Fatalf("%d %+v", resp.StatusCode, p)
				}
			})
		}
		t.Run("more than the shared half of an expression", func(t *testing.T) {
			var last *problem
			for i := range 60 {
				resp := pub.do("POST", "/api/autopilot/exclusions", with("subject", "198.51.100."+fmt.Sprint(i+1)))
				if resp.StatusCode == 422 {
					p := decode[problem](t, resp)
					last = &p
					break
				}
				status(t, resp, 201)
			}
			if last == nil || !strings.Contains(last.Errors[0].Msg, "characters") {
				t.Fatalf("refusal %+v", last)
			}
		})
	})
	t.Run("protected networks that don't fit beside the active exclusions are refused", func(t *testing.T) {
		_, pub, _ := autopilotHarness(t)
		for i := range 60 { // until the exclusions fill the shared half
			resp := pub.do("POST", "/api/autopilot/exclusions", map[string]any{"subject": "198.51.100." + fmt.Sprint(i+1), "host": "api.example.com", "reason": "Our CI"})
			if resp.StatusCode == 422 {
				_ = resp.Body.Close()
				break
			}
			status(t, resp, 201)
		}
		s := pub.autopilotSettings()
		s["protected_subjects"] = []string{"203.0.113.0/24", "192.0.2.0/24"}
		resp := pub.do("PUT", "/api/settings/autopilot", s)
		if p := decode[problem](t, resp); resp.StatusCode != 422 || len(p.Errors) != 1 || p.Errors[0].Path != "protected_subjects" {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
	})
	t.Run("the list keeps revoked and expired exclusions for 30 days, newest first", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		expiring := exclude(t, pub, map[string]any{"subject": "198.51.100.7", "host": "api.example.com", "reason": "Our CI", "ttl": "1h"})
		revoked := exclude(t, pub, map[string]any{"subject": "198.51.100.8", "host": "api.example.com", "reason": "Our CI"})
		active := exclude(t, pub, map[string]any{"subject": "198.51.100.9", "host": "api.example.com", "reason": "Our CI"})
		status(t, pub.do("POST", "/api/autopilot/exclusions/"+fmt.Sprint(revoked.ID)+"/revoke", map[string]any{"reason": "The CI moved"}), 204)
		ids := func() []int64 {
			t.Helper()
			var out []int64
			for _, e := range decode[[]exclusion](t, h.signedIn("pub").do("GET", "/api/autopilot/exclusions", nil)) {
				out = append(out, e.ID)
			}
			return out
		}
		h.advance(61 * time.Minute)
		if got := ids(); !slices.Equal(got, []int64{active.ID, revoked.ID, expiring.ID}) {
			t.Fatalf("listed %v", got)
		}
		h.advance(30 * 24 * time.Hour)
		if got := ids(); !slices.Equal(got, []int64{active.ID}) {
			t.Fatalf("listed %v after 30 days", got)
		}
	})
	t.Run("viewers read exclusions; adding and revoking needs autopilot.manage", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		e := exclude(t, pub, map[string]any{"subject": ci, "host": "api.example.com", "reason": "Our CI"})
		h.user("vic", "viewer")
		vic := h.signedIn("vic")
		if got := decode[[]exclusion](t, vic.do("GET", "/api/autopilot/exclusions", nil)); len(got) != 1 {
			t.Fatalf("exclusions %+v", got)
		}
		status(t, vic.do("POST", "/api/autopilot/exclusions", map[string]any{"subject": other, "host": "api.example.com", "reason": "Mine"}), 403)
		status(t, vic.do("POST", "/api/autopilot/exclusions/"+fmt.Sprint(e.ID)+"/revoke", map[string]any{"reason": "No"}), 403)
	})
	t.Run("adding and revoking are audited, and the autopilot's state lists the active ones", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		e := exclude(t, pub, map[string]any{"subject": ci, "host": "api.example.com", "reason": "Our CI"})
		st := decode[struct{ Exclusions []exclusion }](t, pub.do("GET", "/api/autopilot", nil))
		if len(st.Exclusions) != 1 || st.Exclusions[0].ID != e.ID {
			t.Fatalf("state %+v", st.Exclusions)
		}
		status(t, pub.do("POST", "/api/autopilot/exclusions/"+fmt.Sprint(e.ID)+"/revoke", map[string]any{"reason": "The CI moved"}), 204)
		acts := h.actions()
		for _, want := range []string{"autopilot.exclusion_add exclusion " + fmt.Sprint(e.ID), "autopilot.exclusion_revoke exclusion " + fmt.Sprint(e.ID)} {
			if !slices.Contains(acts, want) {
				t.Fatalf("audit %v, want %q", acts, want)
			}
		}
		if st := decode[struct{ Exclusions []exclusion }](t, pub.do("GET", "/api/autopilot", nil)); len(st.Exclusions) != 0 {
			t.Fatalf("state after revoke %+v", st.Exclusions)
		}
	})
}
