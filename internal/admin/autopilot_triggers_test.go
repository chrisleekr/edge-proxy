package admin

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// autoTriggers are the settings that switch on the cases the autopilot
// opens by itself: the hourly sweep, the daily review and a case for each
// firing anomaly.
var autoTriggers = []string{"sweep_enabled", "review_enabled", "anomaly_investigation_enabled"}

func allTriggers(on bool) map[string]any {
	m := map[string]any{}
	for _, k := range autoTriggers {
		m[k] = on
	}
	return m
}

func TestAutopilotTriggerSettings(t *testing.T) {
	t.Run("a settings row saved before the toggles existed reads them as on", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		old := pub.autopilotSettings()
		for _, k := range autoTriggers {
			delete(old, k)
		}
		b, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.db.Exec(t.Context(), `INSERT INTO settings (key, value) VALUES ('autopilot', $1)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, b); err != nil {
			t.Fatal(err)
		}
		s := pub.autopilotSettings()
		for _, k := range autoTriggers {
			if s[k] != true {
				t.Errorf("%s %v, want true", k, s[k])
			}
		}
	})
	t.Run("a save that omits the toggles turns them on", func(t *testing.T) {
		_, pub, _ := autopilotHarness(t)
		pub.setAutopilot(allTriggers(false))
		s := pub.autopilotSettings()
		for _, k := range autoTriggers {
			delete(s, k)
		}
		status(t, pub.do("PUT", "/api/settings/autopilot", s), 204)
		got := pub.autopilotSettings()
		for _, k := range autoTriggers {
			if got[k] != true {
				t.Errorf("%s %v, want true", k, got[k])
			}
		}
	})
	for _, off := range autoTriggers {
		t.Run(off+" saves off on its own and is audited", func(t *testing.T) {
			h, pub, _ := autopilotHarness(t)
			pub.setAutopilot(map[string]any{off: false})
			s := pub.autopilotSettings()
			for _, k := range autoTriggers {
				if want := k != off; s[k] != want {
					t.Errorf("%s %v, want %v", k, s[k], want)
				}
			}
			var before, after string
			var rows int
			if err := h.db.QueryRow(t.Context(), `SELECT details->'before'->>$1, details->'after'->>$1, (SELECT count(*) FROM audit_events WHERE action = 'settings.autopilot')
				FROM audit_events WHERE action = 'settings.autopilot' AND actor = 'user:pub' ORDER BY seq DESC LIMIT 1`, off).Scan(&before, &after, &rows); err != nil ||
				before != "true" || after != "false" || rows != 1 {
				t.Fatalf("audit before %q after %q in %d rows, err %v", before, after, rows, err)
			}
		})
	}
	t.Run("a viewer can't turn a toggle off", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		h.user("vera", "viewer")
		vera := h.signedIn("vera")
		s := pub.autopilotSettings()
		s["sweep_enabled"] = false
		status(t, vera.do("PUT", "/api/settings/autopilot", s), 403)
		if pub.autopilotSettings()["sweep_enabled"] != true {
			t.Fatal("the toggle changed")
		}
	})
}

// The toggles only decide which cases the autopilot opens on its own.
func TestAutopilotCaseTriggers(t *testing.T) {
	for _, mode := range []string{"auto", "observe"} {
		for _, tc := range []struct {
			name string
			off  map[string]any
			want []string // sorted
		}{
			{"in %s mode with the sweep off a tick opens the anomaly case and the review", map[string]any{"sweep_enabled": false}, []string{"anomaly queued", "review queued"}},
			{"in %s mode with the review off a tick opens the anomaly case and the sweep", map[string]any{"review_enabled": false}, []string{"anomaly queued", "sweep queued"}},
			{"in %s mode with anomaly investigation off a tick opens the sweep and the review", map[string]any{"anomaly_investigation_enabled": false}, []string{"review queued", "sweep queued"}},
			{"in %s mode with all three off a tick opens no case", allTriggers(false), nil},
		} {
			t.Run(fmt.Sprintf(tc.name, mode), func(t *testing.T) {
				h, pub, agent := autopilotHarness(t)
				pub.setAutopilot(map[string]any{"mode": mode})
				pub.setAutopilot(tc.off)
				status(t, agent.claim("claude"), 204)
				h.firingAnomaly("traffic_surge")
				h.tick()
				got := h.caseRows()
				slices.Sort(got)
				if !slices.Equal(got, tc.want) {
					t.Fatalf("cases %v, want %v", got, tc.want)
				}
				if m := pub.autopilotSettings()["mode"]; m != mode {
					t.Fatalf("mode %v, want %s", m, mode)
				}
			})
		}
	}
	t.Run("with every toggle on and the autopilot off a tick opens no case", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		pub.setAutopilot(map[string]any{"mode": "off"})
		h.firingAnomaly("traffic_surge")
		h.tick()
		if got := h.caseRows(); len(got) != 0 {
			t.Fatalf("cases %v", got)
		}
	})
	t.Run("a person can still investigate with every toggle off", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(allTriggers(false))
		status(t, agent.claim("claude"), 204)
		pub.investigate("login", "Is someone guessing passwords?")
		if got := h.caseRows(); !slices.Equal(got, []string{"investigate queued"}) {
			t.Fatalf("cases %v", got)
		}
	})
	t.Run("an ablation still opens with every toggle off", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		// A confirmed note served to three benign cases is the condition for
		// an ablation.
		n := batchNote(t, h, pub, agent)
		for range 3 {
			benignWith(t, h, pub, agent, n, scopeGlobal())
		}
		pub.setAutopilot(allTriggers(false))
		h.tick()
		if got := h.ablations(); got != 1 {
			t.Fatalf("%d ablation cases", got)
		}
	})
	t.Run("turning the toggles off leaves queued cases queued and autopilot rules live", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule())) // the tick also queued a sweep and a review
		pub.investigate("admin-route", "Scanning the admin pages?")
		before, version := h.caseRows(), pub.active().Version
		if !slices.Contains(before, "sweep queued") || !slices.Contains(before, "review queued") || !slices.Contains(before, "investigate queued") {
			t.Fatalf("cases %v", before)
		}
		pub.setAutopilot(allTriggers(false))
		h.tick()
		if got := h.caseRows(); !slices.Equal(got, before) {
			t.Fatalf("cases %v, want %v", got, before)
		}
		v := pub.active()
		if _, live := liveRuleIn(v.Config, id); !live || v.Version != version || ruleState(t, h, id) != "observing" {
			t.Fatalf("rule %s %s in version %d, want it live in %d", id, ruleState(t, h, id), v.Version, version)
		}
	})
	t.Run("a sweep turned off and on within the hour opens no second sweep until the hour is up", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		sweeps := func() int {
			n := 0
			for _, r := range h.caseRows() {
				if strings.HasPrefix(r, "sweep ") {
					n++
				}
			}
			return n
		}
		agent.seen()
		h.tick()
		pub.setAutopilot(map[string]any{"sweep_enabled": false})
		h.advance(20 * time.Minute)
		agent.seen()
		pub.setAutopilot(map[string]any{"sweep_enabled": true})
		h.tick()
		if n := sweeps(); n != 1 {
			t.Fatalf("%d sweeps 20 minutes after the first, want 1", n)
		}
		h.advance(41 * time.Minute)
		agent.seen()
		h.tick()
		if n := sweeps(); n != 2 {
			t.Fatalf("%d sweeps over an hour after the first, want 2", n)
		}
	})
	t.Run("an anomaly that fired while investigation was off gets its case once it is turned on", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"anomaly_investigation_enabled": false})
		status(t, agent.claim("claude"), 204)
		h.firingAnomaly("traffic_surge")
		h.tick()
		if got := h.caseRows(); slices.Contains(got, "anomaly queued") {
			t.Fatalf("cases %v while investigation is off", got)
		}
		pub.setAutopilot(map[string]any{"anomaly_investigation_enabled": true})
		h.tick()
		if got := h.caseRows(); !slices.Contains(got, "anomaly queued") {
			t.Fatalf("cases %v after turning investigation on", got)
		}
	})
	t.Run("a sweep opens on the first tick after it is turned back on", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"sweep_enabled": false})
		status(t, agent.claim("claude"), 204)
		h.tick()
		c := agent.claimCase() // the review
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
		h.advance(61 * time.Minute)
		status(t, agent.claim("claude"), 204) // the runner stays seen
		h.tick()
		if got := h.caseRows(); !slices.Equal(got, []string{"review done"}) {
			t.Fatalf("cases %v while the sweep is off", got)
		}
		pub.setAutopilot(map[string]any{"sweep_enabled": true})
		h.tick()
		if got := h.caseRows(); !slices.Equal(got, []string{"review done", "sweep queued"}) {
			t.Fatalf("cases %v after turning the sweep on", got)
		}
	})
}

// A sweep's model is only used by sweeps and reviews, so with both off and
// none queued a credential no runner has for it is nothing to warn about.
func TestAutopilotStateWarnsOfASweepModelOnlyWhileASweepOrReviewIsOn(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  map[string]any
		warn bool
	}{
		{"the sweep and the review off", map[string]any{"sweep_enabled": false, "review_enabled": false}, false},
		{"only the sweep off", map[string]any{"sweep_enabled": false}, true},
		{"only the review off", map[string]any{"review_enabled": false}, true},
		{"both on", map[string]any{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pub, agent := autopilotHarness(t)
			change := map[string]any{"sweep_model": "gpt-5"}
			maps.Copy(change, tc.set)
			pub.setAutopilot(change)
			status(t, agent.claim("claude"), 204)
			page := decode[struct {
				Warnings []string `json:"warnings"`
			}](t, pub.do("GET", "/api/autopilot", nil))
			warned := slices.ContainsFunc(page.Warnings, func(w string) bool { return strings.Contains(w, "gpt-5") && strings.Contains(w, "openai") })
			if warned != tc.warn {
				t.Fatalf("warnings %v, want a gpt-5 warning: %v", page.Warnings, tc.warn)
			}
		})
	}
	t.Run("both off but a sweep queued from before still warns", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		h.tick() // queues a sweep and a review
		pub.setAutopilot(map[string]any{"sweep_model": "gpt-5", "sweep_enabled": false, "review_enabled": false})
		page := decode[struct {
			Warnings []string `json:"warnings"`
		}](t, pub.do("GET", "/api/autopilot", nil))
		if !slices.ContainsFunc(page.Warnings, func(w string) bool { return strings.Contains(w, "gpt-5") && strings.Contains(w, "openai") }) {
			t.Fatalf("warnings %v, want a gpt-5 warning", page.Warnings)
		}
	})
}
