package admin

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// guardOnLogin publishes login at limit 3 as version 2 on a canary, with
// version 2 limiting 400 of 1,000 and 395 of those going to one subject, and
// returns the guard's decision. key is login's key in version 2.
func guardOnLogin(t *testing.T, key []string) string {
	t.Helper()
	h, pub := published(t)
	c := testConfig()
	c.RateLimitRules[0].Limit = 3
	c.RateLimitRules[0].Key = key
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
	return out.Decision
}

func TestSharedKeyGuard(t *testing.T) {
	t.Run("rollback guard rolls back a shared-key block that limits far more than its shadow", func(t *testing.T) {
		if got := guardOnLogin(t, []string{"constant"}); got != decisionRollback {
			t.Fatalf("decision %s", got)
		}
	})
	t.Run("per-IP rule still leaves its heavy attacker out", func(t *testing.T) {
		if got := guardOnLogin(t, []string{"ip"}); got != decisionOK {
			t.Fatalf("decision %s", got)
		}
	})
}

// One bucket holding most blocks is the shared key's population, not one
// client misbehaving. The same counts on a per-IP rule fire in TestNotifySignals.
func TestSharedKeyNotify(t *testing.T) {
	h, pub, _ := notifyHarnessWith(t, func(*harness) *snapshot.Config {
		c := testConfig()
		c.RateLimitRules[0].Key = []string{"constant"}
		return c
	})
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter = 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	h.put(65, 6, minute{requests: 1000, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 100}}})
	h.put(5, 1, minute{requests: 1000, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 100, Limited: 30}},
		top: []edge.TopCount{{Rule: "login", Key: "k1", Display: "198.51.100.7", Limited: 32}}})
	h.check()
	for _, a := range h.anomalies(pub) {
		if a.Signal == "rule_subject_dominates" && a.Rule == "login" {
			t.Fatalf("rule_subject_dominates %s for a shared-key rule", a.State)
		}
	}
}

// A rule's key can change between versions inside the baseline window. Each
// row is classified by the rules of the version that served it, so rows from
// when the rule was shared keep their one bucket's blocks.
func TestSharedKeyGuardBaselineSpansAKeyChange(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	c := testConfig()
	c.RateLimitRules[0].Key = []string{"constant"}
	status(t, pub.save(`"0"`, c, adminTest), 200)
	status(t, pub.publishDraft("v1"), 201)
	h.advance(4 * time.Minute)
	// Version 1 limited 40% in one bucket; version 2, per-IP, limited none.
	h.putStats(1, 3, 1_000, 0, 0, []int64{1_000}, `[{"id":"login","evaluated":1000,"limited":400}]`,
		`[{"rule":"login","key":"k","display":"198.51.100.7","limited":200}]`)
	c.RateLimitRules[0].Key = []string{"ip"}
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	h.advance(4 * time.Minute)
	h.putStats(2, 3, 1_000, 0, 0, []int64{1_000}, `[{"id":"login","evaluated":1000,"limited":0}]`, "[]")
	c.Global.Defaults.BodyLimit = 2048 // a publish that leaves login unchanged
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("v3"), 201)
	h.advance(4 * time.Minute)
	h.putStats(3, 3, 1_000, 0, 0, []int64{1_000}, `[{"id":"login","evaluated":1000,"limited":200}]`, "[]")
	h.live("edge-a", 3)
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	if out := outcomeOf(t, pub, 3); out.Decision != decisionOK || out.Signals["unchanged_rule_limited_ratio"].Tripped {
		t.Fatalf("outcome %+v", out)
	}
}
