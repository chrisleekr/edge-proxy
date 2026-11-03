package admin

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
)

// alertHarness is an autopilot harness sending to a fake Alertmanager,
// where an anomaly fires on its first tripped check and resolves after
// resolveAfter passed ones.
func alertHarness(t *testing.T, resolveAfter int) (*harness, *client, *client, *fakeAlertmanager) {
	t.Helper()
	am := newFakeAlertmanager(t)
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"ALERTMANAGER_URL": am.srv.URL + "/"})
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter, n.ResolveAfter = 1, resolveAfter
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	return h, pub, agent, am
}

// sent is every alert Alertmanager got for signal, across all posts.
func (am *fakeAlertmanager) sent(signal string) []amAlert {
	am.mu.Lock()
	defer am.mu.Unlock()
	var out []amAlert
	for _, p := range am.posts {
		for _, a := range p {
			if a.Labels["signal"] == signal {
				out = append(out, a)
			}
		}
	}
	return out
}

func withheldOf(t *testing.T, pub *client, signal string) string {
	t.Helper()
	for _, a := range decode[struct{ Anomalies []triagedAnomaly }](t, pub.do("GET", "/api/anomalies", nil)).Anomalies {
		if a.Signal == signal {
			return a.Withheld
		}
	}
	t.Fatalf("no %s anomaly", signal)
	return ""
}

// loginSurge is an hour of login matching 10 requests a minute, then 5
// minutes of 600: a person's rule matching far more than its share.
func loginSurge(h *harness) {
	login := func(n uint64) []edge.RuleCounts { return []edge.RuleCounts{{ID: "login", Evaluated: n}} }
	h.put(65, 6, minute{requests: 1000, rateLimit: login(10)})
	h.put(5, 1, minute{requests: 1000, rateLimit: login(600)})
}

// The autopilot is the first responder for what it works: its sensors'
// anomalies are its input, and an anomaly it opens a case for waits a
// little for the verdict. A person still hears critical anomalies at once,
// everything while no runner is connected, and every verdict but benign
// info.
func TestNotifyWithholdsWhatTheAutopilotWorks(t *testing.T) {
	t.Run("a sensor's would-block is not sent while a runner is connected, nor its resolve", func(t *testing.T) {
		h, pub, agent, am := alertHarness(t, 1)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		ruleMinutes(h, pub, 5, 1_000, 100, 0, 5, id, "[]")
		h.check()
		if w := withheldOf(t, pub, "rule_would_block"); w != "own_rule" {
			t.Fatalf("withheld %q", w)
		}
		h.advance(6 * time.Minute)
		agent.seen()
		h.check()
		if got := am.sent("rule_would_block"); got != nil {
			t.Fatalf("sent %+v", got)
		}
	})
	t.Run("a sensor's would-block is sent when no runner is connected", func(t *testing.T) {
		h, pub, agent, am := alertHarness(t, 1)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 5, 1_000, 100, 0, 5, id, "[]")
		h.check()
		if got := am.sent("rule_would_block"); len(got) == 0 || got[0].Labels["rule"] != id {
			t.Fatalf("sent %+v", got)
		}
	})
	t.Run("an info anomaly the autopilot found benign is never sent", func(t *testing.T) {
		h, pub, agent, am := alertHarness(t, 1)
		agent.seen()
		loginSurge(h)
		h.check()
		if w := withheldOf(t, pub, "rule_match_surge"); w != "investigating" {
			t.Fatalf("withheld %q before its case opens", w)
		}
		h.tick()
		agent.seen() // closes the case as benign
		h.check()
		if w := withheldOf(t, pub, "rule_match_surge"); w != "benign" {
			t.Fatalf("withheld %q", w)
		}
		if got := am.sent("rule_match_surge"); got != nil {
			t.Fatalf("sent %+v", got)
		}
	})
	t.Run("an info anomaly the autopilot found benign is sent once no runner is connected", func(t *testing.T) {
		h, pub, agent, am := alertHarness(t, 1)
		agent.seen()
		loginSurge(h)
		h.check()
		h.tick()
		agent.seen() // closes the case as benign
		h.check()
		if w := withheldOf(t, pub, "rule_match_surge"); w != "benign" {
			t.Fatalf("withheld %q", w)
		}
		h.advance(3 * time.Minute)
		loginSurge(h) // still surging
		h.check()
		if got := am.sent("rule_match_surge"); len(got) == 0 {
			t.Fatal("not sent")
		}
	})
	t.Run("a critical rule_fail_mode on a sensor is sent at once while a runner is connected", func(t *testing.T) {
		h, pub, agent, am := alertHarness(t, 1)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		h.putStats(pub.active().Version, 5, 1_000, 0, 0, []int64{1_000}, fmt.Sprintf(`[{"id":%q,"evaluated":100,"failed":100}]`, id), "[]")
		h.check()
		if got := am.sent("rule_fail_mode"); len(got) == 0 || got[0].Labels["rule"] != id || got[0].Labels["severity"] != "critical" {
			t.Fatalf("sent %+v", got)
		}
	})
	t.Run("a warning waits for its case, then is sent with the verdict", func(t *testing.T) {
		h, _, agent, am := alertHarness(t, 1)
		agent.seen()
		h.put(65, 6, minute{requests: 100})
		h.put(5, 1, minute{requests: 1000})
		h.check()
		if got := am.sent("traffic_surge"); got != nil {
			t.Fatalf("sent before the verdict %+v", got)
		}
		h.tick()
		agent.seen() // closes the case as benign
		h.check()
		got := am.sent("traffic_surge")
		if len(got) == 0 || !strings.Contains(got[len(got)-1].Annotations["description"], "Autopilot case") ||
			!strings.Contains(got[len(got)-1].Annotations["description"], ": benign.") {
			t.Fatalf("sent %+v", got)
		}
	})
	t.Run("a warning still waiting after 10 minutes is sent", func(t *testing.T) {
		h, _, agent, am := alertHarness(t, 60)
		agent.seen()
		h.put(65, 6, minute{requests: 100})
		h.put(5, 1, minute{requests: 1000})
		h.check()
		h.advance(11 * time.Minute)
		agent.seen()
		h.check()
		if got := am.sent("traffic_surge"); len(got) == 0 {
			t.Fatal("not sent after the hold")
		}
	})
	t.Run("a critical anomaly is sent at once", func(t *testing.T) {
		h, pub, agent, am := alertHarness(t, 1)
		n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
		s := n.Signals["traffic_surge"]
		s.Severity = "critical"
		n.Signals["traffic_surge"] = s
		status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
		agent.seen()
		h.put(65, 6, minute{requests: 100})
		h.put(5, 1, minute{requests: 1000})
		h.check()
		if got := am.sent("traffic_surge"); len(got) == 0 {
			t.Fatal("not sent")
		}
	})
	t.Run("an anomaly already sent keeps being sent after a benign verdict", func(t *testing.T) {
		h, _, agent, am := alertHarness(t, 1)
		loginSurge(h)
		h.check() // no runner yet: sent
		if got := am.sent("rule_match_surge"); len(got) != 1 {
			t.Fatalf("sent %+v", got)
		}
		agent.seen()
		h.tick()
		agent.seen()
		h.check()
		if got := am.sent("rule_match_surge"); len(got) != 2 {
			t.Fatalf("sent %d times, want 2", len(got))
		}
	})
}

// A sensor whose case closed benign is quiet for one renewal; the sweep,
// which only proposes sensors, waits while the sensor budget is full.
func TestAutopilotSensorCases(t *testing.T) {
	cases := func(h *harness, kind string, rule *string) int {
		h.t.Helper()
		var n int
		if err := h.db.QueryRow(h.t.Context(), "SELECT count(*) FROM autopilot_cases WHERE kind = $1 AND ($2::text IS NULL OR rule = $2)", kind, rule).Scan(&n); err != nil {
			h.t.Fatal(err)
		}
		return n
	}
	t.Run("a sensor's would-block within max_ttl of a benign case on it opens no case", func(t *testing.T) {
		h, pub, agent, _ := alertHarness(t, 1)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		ruleMinutes(h, pub, 5, 1_000, 100, 0, 5, id, "[]")
		h.check()
		h.tick()
		agent.seen() // the case closes benign
		if n := cases(h, "anomaly", &id); n != 1 {
			t.Fatalf("%d anomaly cases", n)
		}
		h.advance(6 * time.Minute)
		agent.seen()
		h.check() // quiet: it resolves
		ruleMinutes(h, pub, 5, 1_000, 100, 0, 5, id, "[]")
		h.check() // and fires again
		h.tick()
		if n := cases(h, "anomaly", &id); n != 1 {
			t.Fatalf("%d anomaly cases after it fired again", n)
		}
	})
	t.Run("no sweep opens while the sensor budget is full; the review still does", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"max_sensors": 1})
		liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		if n, r := cases(h, "sweep", nil), cases(h, "review", nil); n != 0 || r != 1 {
			t.Fatalf("%d sweeps, %d reviews", n, r)
		}
	})
	t.Run("a sensor named with the ap- prefix is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, cs := agentCase(t, h, pub, agent)
		if p := propose(t, cs, proposal("add_sensor", "ap-login", loginRule())); p.Accepted || !slices.Contains(p.Reasons, "not_overlay_shape") {
			t.Fatalf("proposal %+v", p)
		}
	})
}
