package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// fakeAlertmanager records what admin posts to /api/v2/alerts.
type fakeAlertmanager struct {
	srv    *httptest.Server
	mu     sync.Mutex
	posts  [][]amAlert
	status int
	// hold, when set, is closed on the first valid post, which then gets
	// no answer until the sender gives up.
	hold chan struct{}
}

func newFakeAlertmanager(t *testing.T) *fakeAlertmanager {
	t.Helper()
	am := &fakeAlertmanager{status: http.StatusOK}
	am.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got []amAlert
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/alerts" || r.Header.Get("Content-Type") != "application/json" || json.Unmarshal(b, &got) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if am.hold != nil {
			close(am.hold)
			<-r.Context().Done()
			return
		}
		am.mu.Lock()
		defer am.mu.Unlock()
		am.posts = append(am.posts, got)
		w.WriteHeader(am.status)
	}))
	t.Cleanup(am.srv.Close)
	return am
}

func (am *fakeAlertmanager) last() []amAlert {
	am.mu.Lock()
	defer am.mu.Unlock()
	if len(am.posts) == 0 {
		return nil
	}
	return am.posts[len(am.posts)-1]
}

// notifyHarness has version 1 (testConfig) live, a fake Alertmanager, and
// a clock 45s into a minute, so the minute before is complete.
func notifyHarness(t *testing.T) (*harness, *client, *fakeAlertmanager) {
	t.Helper()
	return notifyHarnessWith(t, func(*harness) *snapshot.Config { return testConfig() })
}

// notifyHarnessWith is notifyHarness with version 1 from config.
func notifyHarnessWith(t *testing.T, config func(*harness) *snapshot.Config) (*harness, *client, *fakeAlertmanager) {
	t.Helper()
	am := newFakeAlertmanager(t)
	h := newHarnessWith(t, map[string]string{"ALERTMANAGER_URL": am.srv.URL + "/"})
	h.mu.Lock()
	h.clock = h.clock.Truncate(time.Minute).Add(45 * time.Second)
	h.mu.Unlock()
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	status(t, pub.save(`"0"`, config(h), adminTest), 200)
	status(t, pub.publishDraft("v1"), 201)
	return h, pub, am
}

// minute is one minute of a version's stats, version 1 unless set.
type minute struct {
	version                                      int64
	requests, edge5xx, upstream5xx, authFailures uint64
	rateLimit                                    []edge.RuleCounts
	rules                                        []edge.RuleOutcome
	top                                          []edge.TopCount
	// latency is the latency histogram's counts; all in the first bucket
	// when nil.
	latency []uint64
}

// put writes m for each of the minutes from minutes ago up to and
// including to minutes ago.
func (h *harness) put(from, to int, m minute) {
	h.t.Helper()
	now := h.now().UTC().Truncate(time.Minute)
	latency := m.latency
	if latency == nil {
		latency = []uint64{m.requests}
	}
	for i := to; i <= from; i++ {
		h.statsSeq++
		_, err := h.db.Exec(context.Background(), `INSERT INTO edge_stats_minute (minute, version, replica, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited, rules)
			VALUES ($1, $11, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, now.Add(time.Duration(-i)*time.Minute), fmt.Sprint("r", h.statsSeq),
			m.requests, m.edge5xx, m.upstream5xx, m.authFailures, latency, orEmpty(m.rateLimit), orEmpty(m.top), orEmpty(m.rules), max(m.version, 1))
		if err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *harness) check() {
	h.t.Helper()
	if err := h.s.runNotify(h.t.Context()); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) anomalies(pub *client) []anomaly {
	h.t.Helper()
	return decode[struct{ Anomalies []anomaly }](h.t, pub.do("GET", "/api/anomalies", nil)).Anomalies
}

// An upstream starting to fail notifies once two checks in a row see it,
// and resolves, with its resolved notification sent, once five checks pass.
func TestNotifyFiresAfterTwoChecksAndResolvesAfterFive(t *testing.T) {
	h, pub, am := notifyHarness(t)
	h.put(65, 6, minute{requests: 1000})
	h.put(5, 1, minute{requests: 1000, upstream5xx: 200})

	h.check()
	if a := h.anomalies(pub); len(a) != 1 || a[0].State != "pending" || a[0].Signal != "upstream_5xx_ratio" || am.last() != nil {
		t.Fatalf("after one check: %+v, sent %+v", a, am.last())
	}
	h.advance(time.Minute)
	h.put(1, 1, minute{requests: 1000, upstream5xx: 200})
	h.check()
	a := h.anomalies(pub)
	if len(a) != 1 || a[0].State != "firing" || a[0].NotifiedAt == nil || !strings.Contains(a[0].Summary, "20.0% of requests") {
		t.Fatalf("after two checks: %+v", a)
	}
	sent := am.last()
	if len(sent) != 1 || sent[0].Labels["alertname"] != "EdgeProxyUpstream5xxRatio" || sent[0].Labels["severity"] != "critical" ||
		sent[0].Labels["service"] != "edge-proxy" || sent[0].Annotations["summary"] != "Edge proxy: More 5xx from the upstream" || !sent[0].EndsAt.After(h.now()) {
		t.Fatalf("sent %+v", sent)
	}
	if !slices.Contains(h.actions(), "anomaly.fire fleet") {
		t.Fatalf("firing not audited: %v", h.actions())
	}

	// The upstream recovers. Once the bad minutes leave the window, each
	// check passes.
	h.advance(4 * time.Minute)
	h.put(4, 1, minute{requests: 1000})
	for i := range 5 {
		h.advance(time.Minute)
		h.put(1, 1, minute{requests: 1000})
		h.check()
		if s := h.anomalies(pub)[0].State; s != map[bool]string{true: "resolved", false: "firing"}[i == 4] {
			t.Fatalf("after %d passing checks: %s", i+1, s)
		}
	}
	sent = am.last()
	if len(sent) != 1 || !sent[0].EndsAt.Equal(*h.anomalies(pub)[0].ResolvedAt) {
		t.Fatalf("resolved alert %+v", sent)
	}
	if !slices.Contains(h.actions(), "anomaly.resolve fleet") {
		t.Fatal("resolving not audited")
	}
	// Past resolvedResend it is no longer sent.
	am.posts = nil
	h.advance(6 * time.Minute)
	h.check()
	if am.last() != nil {
		t.Fatalf("resolved anomaly still sent: %+v", am.last())
	}
}

// Changing a signal's severity while its anomaly fires keeps the alert's
// labels, so Alertmanager sees one alert, not a second one beside it.
func TestNotifyKeepsSeverityWhileFiring(t *testing.T) {
	h, pub, am := notifyHarness(t)
	h.put(65, 6, minute{requests: 1000})
	h.put(5, 1, minute{requests: 1000, upstream5xx: 200})
	h.check()
	h.advance(time.Minute)
	h.put(1, 1, minute{requests: 1000, upstream5xx: 200})
	h.check()
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	s := n.Signals["upstream_5xx_ratio"]
	s.Severity = "warning"
	n.Signals["upstream_5xx_ratio"] = s
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	h.advance(time.Minute)
	h.put(1, 1, minute{requests: 1000, upstream5xx: 200})
	h.check()
	if sent := am.last(); len(sent) != 1 || sent[0].Labels["severity"] != "critical" {
		t.Fatalf("sent %+v, want the firing alert still critical", sent)
	}
}

// A blip that trips one check and passes the next never notifies and
// leaves nothing behind.
func TestNotifyIgnoresAOneCheckBlip(t *testing.T) {
	h, pub, am := notifyHarness(t)
	h.put(65, 2, minute{requests: 1000})
	h.put(1, 1, minute{requests: 5000, upstream5xx: 1500})
	h.check()
	h.advance(5 * time.Minute)
	h.put(5, 1, minute{requests: 1000})
	h.check()
	if a := h.anomalies(pub); len(a) != 0 || am.last() != nil {
		t.Fatalf("anomalies %+v, sent %+v", a, am.last())
	}
}

// A block rule published just before the window is judged on the minutes it
// was live, so its steady block share is not a spike.
func TestNotifyBlockSpikeCountsOnlyLiveMinutes(t *testing.T) {
	h, pub, _ := notifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter = 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	block := []edge.RuleOutcome{{Phase: "config", ID: "admin-route", Matched: 100, Blocked: 100}}
	h.put(65, 11, minute{requests: 1000})
	h.put(10, 1, minute{requests: 1000, rules: block}) // 10% blocked since it was published
	h.check()
	for _, a := range h.anomalies(pub) {
		if a.Signal == "rule_block_spike" {
			t.Fatalf("a steady block share fired %+v", a)
		}
	}
}

// Each signal reads the stats it is about: a fleet's traffic and errors, a
// config rule's outcomes, and a rate-limit rule's counts and subjects.
func TestNotifySignals(t *testing.T) {
	login := func(evaluated, limited, would, failed uint64) []edge.RuleCounts {
		return []edge.RuleCounts{{ID: "login", Evaluated: evaluated, Limited: limited, WouldLimit: would, Failed: failed}}
	}
	admin := func(matched, upstream5xx uint64) []edge.RuleOutcome {
		return []edge.RuleOutcome{{Phase: "config", ID: "admin-route", Matched: matched, Upstream5xx: upstream5xx}}
	}
	for _, tc := range []struct {
		name             string
		baseline, window minute
		signal, rule     string
	}{
		{"traffic falls to a tenth", minute{requests: 1000}, minute{requests: 100}, "traffic_drop", ""},
		{"traffic grows tenfold", minute{requests: 1000}, minute{requests: 10_000}, "traffic_surge", ""},
		{"a config rule's upstream starts failing", minute{requests: 1000, rules: admin(100, 0)}, minute{requests: 1000, upstream5xx: 50, rules: admin(100, 50)}, "rule_upstream_5xx_ratio", "admin-route"},
		{"a rule stops matching", minute{requests: 1000, rateLimit: login(100, 0, 0, 0)}, minute{requests: 1000, rateLimit: login(0, 0, 0, 0)}, "rule_stopped_matching", "login"},
		{"a rule the edges stop reporting fires rule_stopped_matching", minute{requests: 1000, rateLimit: login(100, 0, 0, 0)}, minute{requests: 1000}, "rule_stopped_matching", "login"},
		{"a rule blocks far more", minute{requests: 1000, rateLimit: login(100, 1, 0, 0)}, minute{requests: 1000, rateLimit: login(100, 30, 0, 0)}, "rule_block_spike", "login"},
		{"a log-only rule goes over its limit", minute{requests: 1000, rateLimit: login(100, 0, 0, 0)}, minute{requests: 1000, rateLimit: login(100, 0, 3, 0)}, "rule_would_block", "login"},
		{"Valkey stops answering a rule", minute{requests: 1000, rateLimit: login(100, 0, 0, 0)}, minute{requests: 1000, rateLimit: login(100, 0, 0, 100)}, "rule_fail_mode", "login"},
		{"one client gets most blocks", minute{requests: 1000, rateLimit: login(100, 0, 0, 0)},
			minute{requests: 1000, rateLimit: login(100, 30, 0, 0), top: []edge.TopCount{{Rule: "login", Key: "k1", Display: "198.51.100.7", Limited: 32}}}, "rule_subject_dominates", "login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, _ := notifyHarness(t)
			n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
			n.FireAfter = 1
			status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
			h.put(65, 6, tc.baseline)
			h.put(5, 1, tc.window)
			h.check()
			var got []string
			for _, a := range h.anomalies(pub) {
				got = append(got, a.Signal+" "+a.Rule+" "+a.State)
			}
			if !slices.Contains(got, tc.signal+" "+tc.rule+" firing") {
				t.Fatalf("anomalies %v", got)
			}
		})
	}
}

// One cause notifies once. A rise every rule shares is the fleet's, so
// only the fleet signal fires; a rise concentrated on one rule, or a rule
// that holds while the fleet moves, still names the rule. Version 1 checks
// tokens on the orders rule, so only its requests can fail a token check.
func TestNotifyOneCauseNotifiesOnce(t *testing.T) {
	admin := func(matched, upstream5xx uint64) []edge.RuleOutcome {
		return []edge.RuleOutcome{{Phase: "config", ID: "admin-route", Matched: matched, Upstream5xx: upstream5xx}}
	}
	orders := func(matched, authFailures uint64) []edge.RuleOutcome {
		return []edge.RuleOutcome{{Phase: "config", ID: "orders", Matched: matched, AuthFailures: authFailures}}
	}
	login := func(evaluated uint64) []edge.RuleCounts {
		return []edge.RuleCounts{{ID: "login", Evaluated: evaluated}}
	}
	for _, tc := range []struct {
		name             string
		baseline, window minute
		want, notWant    []string
	}{
		{"an upstream outage spread over every request notifies as the fleet only",
			minute{requests: 1000, rules: admin(1000, 0)}, minute{requests: 1000, upstream5xx: 300, rules: admin(1000, 300)},
			[]string{"upstream_5xx_ratio "}, []string{"rule_upstream_5xx_ratio admin-route"}},
		{"one route failing outright notifies for the fleet and for its rule",
			minute{requests: 1000, rules: admin(100, 0)}, minute{requests: 1000, upstream5xx: 100, rules: admin(100, 100)},
			[]string{"upstream_5xx_ratio ", "rule_upstream_5xx_ratio admin-route"}, nil},
		{"traffic growing on every rule alike notifies as a traffic surge only",
			minute{requests: 1000, rateLimit: login(100)}, minute{requests: 10_000, rateLimit: login(1000)},
			[]string{"traffic_surge "}, []string{"rule_match_surge login"}},
		{"one rule's matches growing while traffic holds notifies for the rule only",
			minute{requests: 1000, rateLimit: login(100)}, minute{requests: 1000, rateLimit: login(600)},
			[]string{"rule_match_surge login"}, []string{"traffic_surge "}},
		{"a rule matching for the first time on busy traffic notifies for the rule",
			minute{requests: 1000, rateLimit: login(0)}, minute{requests: 1000, rateLimit: login(120)},
			[]string{"rule_match_surge login"}, []string{"traffic_surge "}},
		{"traffic starting after a quiet hour notifies as a traffic surge only",
			minute{requests: 1}, minute{requests: 1000, rateLimit: login(200)},
			[]string{"traffic_surge "}, []string{"rule_match_surge login"}},
		{"traffic stopping notifies as a traffic drop only",
			minute{requests: 1000, rateLimit: login(100)}, minute{requests: 0, rateLimit: login(0)},
			[]string{"traffic_drop "}, []string{"rule_stopped_matching login"}},
		{"edge 5xx spread over every request notify as the fleet only",
			minute{requests: 1000, rules: []edge.RuleOutcome{{Phase: "config", ID: "admin-route", Matched: 1000}}},
			minute{requests: 1000, edge5xx: 300, rules: []edge.RuleOutcome{{Phase: "config", ID: "admin-route", Matched: 1000, Edge5xx: 300}}},
			[]string{"edge_5xx_ratio "}, []string{"rule_edge_5xx_ratio admin-route"}},
		// The rule's share is 100% and the fleet's is the token-checked
		// share, so the rule stays under factor 2 times the fleet's only
		// while token-checked requests are over half of all requests.
		{"an IdP outage on mostly token-checked traffic notifies as the fleet only",
			minute{requests: 1000, rules: orders(800, 0)}, minute{requests: 1000, authFailures: 800, rules: orders(800, 800)},
			[]string{"auth_failure_ratio "}, []string{"rule_auth_failure_ratio orders"}},
		{"an IdP outage on a minority of token-checked traffic notifies for the fleet and for the rule",
			minute{requests: 1000, rules: orders(300, 0)}, minute{requests: 1000, authFailures: 300, rules: orders(300, 300)},
			[]string{"auth_failure_ratio ", "rule_auth_failure_ratio orders"}, nil},
		{"token failures on one route notify for the fleet and for its rule",
			minute{requests: 1000, rules: orders(100, 0)}, minute{requests: 1000, authFailures: 60, rules: orders(100, 60)},
			[]string{"auth_failure_ratio ", "rule_auth_failure_ratio orders"}, nil},
		{"traffic dropping while one rule holds notifies the drop and the rule's larger share",
			minute{requests: 1000, rateLimit: login(120)}, minute{requests: 120, rateLimit: login(120)},
			[]string{"traffic_drop ", "rule_match_surge login"}, nil},
		{"traffic growing tenfold while one rule holds notifies as a traffic surge only",
			minute{requests: 1000, rateLimit: login(100)}, minute{requests: 10_000, rateLimit: login(100)},
			[]string{"traffic_surge "}, []string{"rule_match_surge login", "rule_stopped_matching login"}},
		{"traffic growing tenfold while a quiet rule stops matching notifies the surge and the rule",
			minute{requests: 1000, rateLimit: login(10)}, minute{requests: 10_000, rateLimit: login(0)},
			[]string{"traffic_surge ", "rule_stopped_matching login"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, _ := notifyHarnessWith(t, func(h *harness) *snapshot.Config { return authConfig(newFakeJWKS(t, h).srv.URL + "/jwks") })
			n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
			n.FireAfter = 1
			status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
			h.put(65, 6, tc.baseline)
			h.put(5, 1, tc.window)
			h.check()
			var got []string
			for _, a := range h.anomalies(pub) {
				got = append(got, a.Signal+" "+a.Rule)
			}
			for _, w := range tc.want {
				if !slices.Contains(got, w) {
					t.Errorf("missing %q in %v", w, got)
				}
			}
			for _, w := range tc.notWant {
				if slices.Contains(got, w) {
					t.Errorf("unexpected %q in %v", w, got)
				}
			}
		})
	}
}

// A rule is judged by its share of the requests the edges served while it
// was live, so a rule just published is no surge. One that was live all
// hour and matched nothing, then matches many, is.
func TestRuleMatchSurgeJudgesARuleOnlyWhileItWasLive(t *testing.T) {
	login := func(evaluated uint64) []edge.RuleCounts {
		return []edge.RuleCounts{{ID: "login", Evaluated: evaluated}}
	}
	for _, tc := range []struct {
		name string
		// The hour before, until since minutes ago and then up to the window.
		since                   int
		earlier, recent, window minute
		fires                   bool
	}{
		{"a rule published in the last 5 minutes does not fire rule_match_surge",
			10, minute{requests: 1000}, minute{requests: 1000}, minute{requests: 1000, rateLimit: login(600)}, false},
		{"a rule published 10 minutes ago is too briefly live to judge and does not fire rule_match_surge",
			10, minute{requests: 1000}, minute{requests: 1000, rateLimit: login(600)}, minute{requests: 1000, rateLimit: login(600)}, false},
		{"a rule published 15 minutes ago, matching as it has since, does not fire rule_match_surge",
			15, minute{requests: 1000}, minute{requests: 1000, rateLimit: login(600)}, minute{requests: 1000, rateLimit: login(600)}, false},
		{"a rule that matched nothing all hour and now matches many still fires rule_match_surge",
			10, minute{requests: 1000, rateLimit: login(0)}, minute{requests: 1000, rateLimit: login(0)}, minute{requests: 1000, rateLimit: login(600)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, _ := notifyHarness(t)
			n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
			n.FireAfter = 1
			status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
			h.put(65, tc.since+1, tc.earlier)
			h.put(tc.since, 6, tc.recent)
			h.put(5, 1, tc.window)
			h.check()
			fired := slices.ContainsFunc(h.anomalies(pub), func(a anomaly) bool { return a.Signal == "rule_match_surge" && a.Rule == "login" })
			if fired != tc.fires {
				t.Fatalf("rule_match_surge on login fired %v, want %v", fired, tc.fires)
			}
		})
	}
}

// A rule on a canary version is still judged, and its surge still fires.
func TestRuleMatchSurgeOnACanaryJudgesItAgainstTheCanarysRequests(t *testing.T) {
	h, pub, _ := notifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter = 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	// Version 2 serves 10% of requests and is the only one with login, which
	// matches 10% of them for the hour and 60% in the window.
	h.put(65, 6, minute{requests: 1800})
	h.put(65, 6, minute{version: 2, requests: 200, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 20}}})
	h.put(5, 1, minute{requests: 1800})
	h.put(5, 1, minute{version: 2, requests: 200, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 120}}})
	h.check()
	if !slices.ContainsFunc(h.anomalies(pub), func(a anomaly) bool { return a.Signal == "rule_match_surge" && a.Rule == "login" }) {
		t.Fatalf("rule_match_surge on login did not fire: %+v", h.anomalies(pub))
	}
}

// A canary that grows to more of the fleet takes more matches with it: login
// keeps matching 10% of version 2's requests while version 2 grows from 10%
// to 60% of all requests, so its share has not changed.
func TestRuleMatchSurgeOnAGrowingCanaryDoesNotFire(t *testing.T) {
	h, pub, _ := notifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter = 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	h.put(65, 6, minute{requests: 1800})
	h.put(65, 6, minute{version: 2, requests: 200, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 20}}})
	h.put(5, 1, minute{requests: 800})
	h.put(5, 1, minute{version: 2, requests: 1200, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 120}}})
	h.check()
	if slices.ContainsFunc(h.anomalies(pub), func(a anomaly) bool { return a.Signal == "rule_match_surge" && a.Rule == "login" }) {
		t.Fatalf("rule_match_surge on login fired: %+v", h.anomalies(pub))
	}
}

// A canary that served no requests in the window gives its rule nothing to
// match, so no matches there is no anomaly. Its edges still list the rule.
func TestRuleStoppedMatchingOnACanaryWithNoRequestsDoesNotFire(t *testing.T) {
	h, pub, _ := notifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter = 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	h.put(65, 6, minute{requests: 1800})
	h.put(65, 6, minute{version: 2, requests: 200, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 20}}})
	h.put(5, 1, minute{requests: 2000})
	h.put(5, 1, minute{version: 2, rateLimit: []edge.RuleCounts{{ID: "login"}}})
	h.check()
	if slices.ContainsFunc(h.anomalies(pub), func(a anomaly) bool { return a.Signal == "rule_stopped_matching" && a.Rule == "login" }) {
		t.Fatalf("rule_stopped_matching on login fired: %+v", h.anomalies(pub))
	}
}

// A canary that grows to more of the fleet is expected to match more: login
// matched 3% of version 2's requests, so version 2's 6000 in the window
// should give about 180, and none is an anomaly.
func TestRuleStoppedMatchingOnAGrowingCanaryFires(t *testing.T) {
	h, pub, _ := notifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter = 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	h.put(65, 6, minute{requests: 1800})
	h.put(65, 6, minute{version: 2, requests: 200, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 6}}})
	h.put(5, 1, minute{requests: 800})
	h.put(5, 1, minute{version: 2, requests: 1200, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 0}}})
	h.check()
	if !slices.ContainsFunc(h.anomalies(pub), func(a anomaly) bool { return a.Signal == "rule_stopped_matching" && a.Rule == "login" }) {
		t.Fatalf("rule_stopped_matching on login did not fire: %+v", h.anomalies(pub))
	}
}

// A rule only on a canary is still judged: a rarely matching canary rule
// with no matches in the window is no anomaly.
func TestRuleStoppedMatchingOnACanaryJudgesItAgainstTheCanarysRequests(t *testing.T) {
	h, pub, _ := notifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter = 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	// Version 2 serves 10% of requests and is the only one with login, which
	// matches 1.5% of them: about 15 in the window's 1000.
	h.put(65, 6, minute{requests: 1800})
	h.put(65, 6, minute{version: 2, requests: 200, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 3}}})
	h.put(5, 1, minute{requests: 1800})
	h.put(5, 1, minute{version: 2, requests: 200, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 0}}})
	h.check()
	if slices.ContainsFunc(h.anomalies(pub), func(a anomaly) bool { return a.Signal == "rule_stopped_matching" && a.Rule == "login" }) {
		t.Fatalf("rule_stopped_matching on login fired: %+v", h.anomalies(pub))
	}
}

// A rule published partway through the baseline is expected to keep the
// share it had since, not that share spread over the whole hour.
func TestRuleStoppedMatchingJudgesARuleOnlyWhileItWasLive(t *testing.T) {
	login := func(evaluated uint64) []edge.RuleCounts {
		return []edge.RuleCounts{{ID: "login", Evaluated: evaluated}}
	}
	for _, tc := range []struct {
		name string
		// The hour before, until 10 minutes ago and then up to the window.
		earlier, recent, window minute
		fires                   bool
	}{
		{"a rule published 10 minutes ago that now matches nothing fires rule_stopped_matching",
			minute{requests: 1000}, minute{requests: 1000, rateLimit: login(100)}, minute{requests: 1000, rateLimit: login(0)}, true},
		{"a rule published 10 minutes ago, matching as it has since, does not fire rule_stopped_matching",
			minute{requests: 1000}, minute{requests: 1000, rateLimit: login(100)}, minute{requests: 1000, rateLimit: login(100)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, _ := notifyHarness(t)
			n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
			n.FireAfter = 1
			status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
			h.put(65, 11, tc.earlier)
			h.put(10, 6, tc.recent)
			h.put(5, 1, tc.window)
			h.check()
			fired := slices.ContainsFunc(h.anomalies(pub), func(a anomaly) bool { return a.Signal == "rule_stopped_matching" && a.Rule == "login" })
			if fired != tc.fires {
				t.Fatalf("rule_stopped_matching on login fired %v, want %v", fired, tc.fires)
			}
		})
	}
}

// A rule's own setting replaces the default: turning a signal off for one
// rule resolves its open anomaly at the next check, and no other rule's.
func TestNotifyRuleOverride(t *testing.T) {
	h, pub, am := notifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter = 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	would := minute{requests: 1000, rateLimit: []edge.RuleCounts{{ID: "login", Evaluated: 100, WouldLimit: 5}}}
	h.put(65, 1, would)
	h.check()
	if a := h.anomalies(pub); len(a) != 1 || a[0].Signal != "rule_would_block" || a[0].State != "firing" || am.last()[0].Labels["rule"] != "login" || am.last()[0].Labels["phase"] != "rate_limit" {
		t.Fatalf("anomalies %+v sent %+v", a, am.last())
	}

	n.Rules = map[string]map[string]NotifySignal{"login": {"rule_would_block": {Mode: "off"}}}
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	h.advance(time.Minute)
	h.put(1, 1, would)
	h.check()
	if a := h.anomalies(pub); a[0].State != "resolved" {
		t.Fatalf("override off left %+v", a)
	}
	// Severity can be raised for one rule too.
	n.Rules["login"]["rule_would_block"] = NotifySignal{Mode: "notify", Severity: "critical", MinRequests: 1}
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	h.advance(time.Minute)
	h.put(1, 1, would)
	h.check()
	if a := h.anomalies(pub); a[0].State != "firing" || a[0].Severity != "critical" {
		t.Fatalf("override severity %+v", a[0])
	}
}

// Turning notifications off resolves what is firing, so Alertmanager is
// told rather than left to time it out.
func TestNotifyOffResolvesOpenAnomalies(t *testing.T) {
	h, pub, am := notifyHarness(t)
	h.put(65, 6, minute{requests: 1000})
	h.put(5, 1, minute{requests: 1000, upstream5xx: 500})
	h.check()
	h.advance(time.Minute)
	h.check()
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.Enabled = false
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	h.check()
	if a := h.anomalies(pub); len(a) != 1 || a[0].State != "resolved" || !am.last()[0].EndsAt.Equal(*a[0].ResolvedAt) {
		t.Fatalf("anomalies %+v sent %+v", a, am.last())
	}
}

// With Alertmanager failing, anomalies are still recorded and shown; the
// next check sends them again.
func TestNotifyKeepsRecordingWhenAlertmanagerFails(t *testing.T) {
	h, pub, am := notifyHarness(t)
	am.status = http.StatusServiceUnavailable
	h.put(65, 6, minute{requests: 1000})
	h.put(5, 1, minute{requests: 1000, upstream5xx: 500})
	h.check()
	h.advance(time.Minute)
	if err := h.s.runNotify(t.Context()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("error %v", err)
	}
	if a := h.anomalies(pub); len(a) != 1 || a[0].State != "firing" || a[0].NotifiedAt != nil {
		t.Fatalf("anomalies %+v", a)
	}
	// The first check had nothing firing to send, so only the 503 counts.
	h.wantMetrics(`admin_notifications_total{result="sent"} 0`, `admin_notifications_total{result="failed"} 1`)
	am.status = http.StatusOK
	h.check()
	if a := h.anomalies(pub); a[0].NotifiedAt == nil {
		t.Fatal("not sent once Alertmanager recovered")
	}
	h.wantMetrics(`admin_notifications_total{result="sent"} 1`, `admin_notifications_total{result="failed"} 1`)
}

// An anomaly that fired while Alertmanager refused every post and then
// resolved is never posted as resolved: Alertmanager never had it firing.
func TestNotifySendsNoResolveForAFiringAlertmanagerNeverAccepted(t *testing.T) {
	h, pub, am := notifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.ResolveAfter = 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	am.status = http.StatusServiceUnavailable
	h.put(65, 6, minute{requests: 1000})
	h.put(5, 1, minute{requests: 1000, upstream5xx: 500})
	h.check()
	h.advance(time.Minute)
	if err := h.s.runNotify(t.Context()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("error %v", err)
	}
	refused := len(am.sent("upstream_5xx_ratio"))
	am.status = http.StatusOK
	h.advance(6 * time.Minute)
	h.put(5, 1, minute{requests: 1000})
	h.check()
	if a := h.anomalies(pub); len(a) != 1 || a[0].State != "resolved" || a[0].NotifiedAt != nil {
		t.Fatalf("anomalies %+v", a)
	}
	if got := am.sent("upstream_5xx_ratio"); len(got) != refused {
		t.Fatalf("posted %+v after Alertmanager recovered", got[refused:])
	}
}

// A leader that steps down mid-send cuts the post off. That is not a failed
// send: the next leader sends the same anomalies.
func TestNotifySendCutOffByStepDownIsNotAFailure(t *testing.T) {
	h, _, am := notifyHarness(t)
	am.hold = make(chan struct{})
	h.put(65, 6, minute{requests: 1000})
	h.put(5, 1, minute{requests: 1000, upstream5xx: 500})
	h.check()
	h.advance(time.Minute)
	leading, stepDown := context.WithCancel(t.Context())
	go func() { <-am.hold; stepDown() }()
	if err := h.s.runNotify(leading); !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v", err)
	}
	h.wantMetrics(`admin_notifications_total{result="sent"} 0`, `admin_notifications_total{result="failed"} 0`)
}

// Settings are validated before they are saved, and every change is
// audited. A fleet signal can't be set per rule.
func TestNotifySettings(t *testing.T) {
	h, pub, _ := notifyHarness(t)
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	if !n.Enabled || n.FireAfter != 2 || len(n.Signals) != len(notifyChecks) || n.Rules == nil {
		t.Fatalf("defaults %+v", n)
	}
	bad := func(edit func(*NotifySettings), path string) {
		t.Helper()
		c := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
		edit(&c)
		p := decode[problem](t, pub.do("PUT", "/api/settings/notifications", c))
		if p.Status != 422 || !slices.ContainsFunc(p.Errors, func(e expr.Issue) bool { return e.Path == path }) {
			t.Fatalf("want an error at %s: %+v", path, p)
		}
	}
	bad(func(c *NotifySettings) { delete(c.Signals, "traffic_drop") }, "signals.traffic_drop")
	bad(func(c *NotifySettings) { c.Signals["made_up"] = NotifySignal{Mode: "off"} }, "signals.made_up")
	bad(func(c *NotifySettings) {
		s := c.Signals["rule_block_spike"]
		s.Severity = "page"
		c.Signals["rule_block_spike"] = s
	}, "signals.rule_block_spike.severity")
	bad(func(c *NotifySettings) {
		s := c.Signals["rule_block_spike"]
		s.Factor = 0.5
		c.Signals["rule_block_spike"] = s
	}, "signals.rule_block_spike")
	bad(func(c *NotifySettings) { c.Window = 0 }, "window")
	bad(func(c *NotifySettings) { c.FireAfter = 0 }, "fire_after")
	bad(func(c *NotifySettings) {
		c.Rules = map[string]map[string]NotifySignal{"login": {"traffic_drop": {Mode: "off"}}}
	}, "rules.login.traffic_drop")
	// A signal turned off needs no thresholds.
	n.Signals["traffic_surge"] = NotifySignal{Mode: "off"}
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	if !slices.Contains(h.actions(), "settings.notifications ") {
		t.Fatal("settings change not audited")
	}
	h.user("viewer", "viewer")
	status(t, h.signedIn("viewer").do("PUT", "/api/settings/notifications", n), 403)
	status(t, h.signedIn("viewer").do("GET", "/api/anomalies", nil), 200)
}

// A signal judges only with enough to judge by. p99 of a few hundred
// requests is its few slowest, and a share of errors over its floor is
// noise when it is a handful of errors in a quiet window.
func TestNotifyNeedsEnoughToJudge(t *testing.T) {
	// at is n requests in the latency bucket of bound ms.
	at := func(n uint64, ms float64) []uint64 {
		i := slices.Index(edge.LatencyBoundsMS[:], ms)
		out := make([]uint64, i+1)
		out[i] = n
		return out
	}
	admin := func(matched, upstream5xx uint64) []edge.RuleOutcome {
		return []edge.RuleOutcome{{Phase: "config", ID: "admin-route", Matched: matched, Upstream5xx: upstream5xx}}
	}
	for _, tc := range []struct {
		name         string
		baseline     minute
		window       []minute // the last 5 minutes, oldest first
		signal, rule string
		fires        bool
	}{
		{"p99 over its bound with 995 requests does not fire", minute{requests: 200, latency: at(200, 1000)},
			slices.Repeat([]minute{{requests: 199, latency: at(199, 2500)}}, 5), "p99_latency", "", false},
		{"p99 over its bound with 1000 requests fires", minute{requests: 200, latency: at(200, 1000)},
			slices.Repeat([]minute{{requests: 200, latency: at(200, 2500)}}, 5), "p99_latency", "", true},
		{"the edge's 5xx at 2% with 5 errors does not fire", minute{requests: 50},
			slices.Repeat([]minute{{requests: 50, edge5xx: 1}}, 5), "edge_5xx_ratio", "", false},
		{"the edge's 5xx at 50% with 125 errors fires", minute{requests: 50},
			slices.Repeat([]minute{{requests: 50, edge5xx: 25}}, 5), "edge_5xx_ratio", "", true},
		{"a rule's upstream 5xx at 6% with 9 errors does not fire", minute{requests: 1000, rules: admin(30, 0)},
			append(slices.Repeat([]minute{{requests: 1000, upstream5xx: 2, rules: admin(30, 2)}}, 4), minute{requests: 1000, upstream5xx: 1, rules: admin(30, 1)}),
			"rule_upstream_5xx_ratio", "admin-route", false},
		{"a rule's upstream 5xx at 7% with 10 errors fires", minute{requests: 1000, rules: admin(30, 0)},
			slices.Repeat([]minute{{requests: 1000, upstream5xx: 2, rules: admin(30, 2)}}, 5), "rule_upstream_5xx_ratio", "admin-route", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, _ := notifyHarness(t)
			n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
			n.FireAfter = 1
			status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
			h.put(65, 6, tc.baseline)
			for i, m := range tc.window {
				h.put(5-i, 5-i, m)
			}
			h.check()
			fired := slices.ContainsFunc(h.anomalies(pub), func(a anomaly) bool { return a.Signal == tc.signal && a.Rule == tc.rule && a.State == "firing" })
			if fired != tc.fires {
				t.Fatalf("%s fired %v, want %v: %+v", tc.signal, fired, tc.fires, h.anomalies(pub))
			}
		})
	}
}
