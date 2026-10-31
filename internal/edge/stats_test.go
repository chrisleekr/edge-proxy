package edge

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// Edge-generated 5xx and upstream 5xx are counted apart, per version.
func TestStatsSplitEdgeAndUpstreamErrors(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }
	h.do("GET", "/", nil).Body.Close()
	h.app.Close()
	h.do("GET", "/", nil).Body.Close()
	c := h.srv.store.load().active.stats.counts()
	if c.Requests != 2 || c.Upstream5xx != 1 || c.Edge5xx != 1 {
		t.Fatalf("requests %d upstream5xx %d edge5xx %d", c.Requests, c.Upstream5xx, c.Edge5xx)
	}
	if got := statusCodes(t, c); fmt.Sprint(got) != fmt.Sprint(map[string]map[string]uint64{"edge": {"502": 1}, "upstream": {"500": 1}}) {
		t.Fatalf("status codes %v, want edge 502 and upstream 500", got)
	}
}

// Reports carry each status code by origin since the previous report, so
// admin shows which code the edge or the upstream answered. Go accepts any
// three-digit code from an upstream; one above 599 shares the last slot
// and still counts as an upstream 5xx.
func TestStatusCodesReportedAsDeltas(t *testing.T) {
	g := newStatsRegistry()
	v := g.use(&snapshot.Compiled{Config: &snapshot.Config{Version: 1}})[0]
	v.observe(502, false, time.Millisecond, nil, nil)
	v.observe(502, false, time.Millisecond, nil, nil)
	v.observe(200, true, time.Millisecond, nil, nil)
	v.observe(799, true, time.Millisecond, nil, nil)
	d := g.deltas()[0]
	want := map[string]map[string]uint64{"edge": {"502": 2}, "upstream": {"200": 1, "600": 1}}
	if got := statusCodes(t, d); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("status codes %v, want %v", got, want)
	}
	if d.Requests != 4 || d.Edge5xx != 2 || d.Upstream5xx != 1 {
		t.Fatalf("totals %+v", d.Totals)
	}
	if got := statusCodes(t, g.deltas()[0]); len(got) != 0 {
		t.Fatalf("second report repeats codes: %v", got)
	}
}

// statusCodes is the status_codes object of c as reports send it.
func statusCodes(t *testing.T, c StatsCounts) map[string]map[string]uint64 {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		StatusCodes map[string]map[string]uint64 `json:"status_codes"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m.StatusCodes
}

// Reports name the most-limited subjects, so the canary guard can leave an
// attacker's few IPs out of its cohort comparison.
func TestTopLimitedReported(t *testing.T) {
	old := sampleTop
	sampleTop = func() bool { return true }
	t.Cleanup(func() { sampleTop = old })
	h := newHarness(t, nil) // no Valkey: fail_mode local counts in process
	c := testConfig(1)
	r := rlRule("per-ip", "true", "sliding_window", 1, "ip")
	r.FailMode = "local"
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	h.load(envelope(c))
	h.statuses(5, "GET", "/")
	h.statuses(2, "GET", "/", "CloudFront-Viewer-Address", "198.51.100.8:1")

	top := h.srv.poller.reg.deltas()[0].TopLimited
	if len(top) != 2 || top[0].Rule != "per-ip" || top[0].Display != "198.51.100.7" || top[0].Limited != 4*TopSample ||
		top[1].Display != "198.51.100.8" || top[1].Limited != TopSample || !strings.HasPrefix(top[0].Key, "rl:sliding_window:60000:per-ip:{") {
		t.Fatalf("top limited %+v", top)
	}
	if top := h.srv.poller.reg.deltas()[0].TopLimited; len(top) != 0 {
		t.Fatalf("next report repeats subjects: %+v", top)
	}
}

// A log-only rule over its limit lists the client as would-limit, so an
// operator sees who a new rule would hit before switching it to block.
func TestTopWouldLimitReported(t *testing.T) {
	old := sampleTop
	sampleTop = func() bool { return true }
	t.Cleanup(func() { sampleTop = old })
	h := newHarness(t, nil)
	c := testConfig(1)
	r := rlRule("search-per-ip", "true", "sliding_window", 1, "ip")
	r.FailMode = "local"
	r.Action = "log"
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	h.load(envelope(c))
	if got := h.statuses(3, "GET", "/"); !slices.Equal(got, []int{200, 200, 200}) {
		t.Fatalf("log-only rule blocked: %v", got)
	}

	top := h.srv.poller.reg.deltas()[0].TopLimited
	if len(top) != 1 || top[0].Rule != "search-per-ip" || top[0].Display != "198.51.100.7" || top[0].Limited != 0 || top[0].WouldLimit != 2*TopSample {
		t.Fatalf("top limited %+v", top)
	}
}

// Space-Saving against exact counts: memory stays bounded, counts never
// underestimate, and any subject above 1/topCapacity of the stream is
// tracked with an error of at most stream/topCapacity.
func FuzzTopKeys(f *testing.F) {
	heavy := make([]byte, 0, 4096)
	for i := range 2048 {
		heavy = append(heavy, 0, 7, byte(i), byte(i>>3))
	}
	f.Add(heavy)
	f.Add([]byte{1, 2, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		var tk topKeys
		exact := map[string]uint64{}
		n := uint64(0)
		for i := 0; i+1 < len(b); i += 2 {
			k := fmt.Sprintf("k%d", int(b[i])<<8|int(b[i+1]))
			tk.add(k, "r", k)
			exact[k] += TopSample
			n += TopSample
		}
		if len(tk.m) > topCapacity {
			t.Fatalf("%d entries", len(tk.m))
		}
		for k, e := range tk.m {
			if e.Limited < exact[k] || e.Limited-exact[k] > n/topCapacity || e.Limited-e.Err > exact[k] {
				t.Fatalf("%s estimated %d with error %d, true %d, stream %d", k, e.Limited, e.Err, exact[k], n)
			}
		}
		for k, c := range exact {
			if c > n/topCapacity && tk.m[k] == nil {
				t.Fatalf("%s (%d of %d) not tracked", k, c, n)
			}
		}
		top := tk.drain()
		if len(top) > topReported || !slices.IsSortedFunc(top, func(a, b TopCount) int { return cmp.Compare(b.Limited, a.Limited) }) {
			t.Fatalf("drain %+v", top)
		}
	})
}

// A subject that takes an evicted subject's slot reports the count it
// inherited, so admin can tell how much of its estimate is its own.
func TestTopKeysReportInheritedCount(t *testing.T) {
	var tk topKeys
	for i := range topCapacity {
		k := fmt.Sprint("k", i)
		tk.add(k, "r", k)
	}
	tk.add("attacker", "r", "198.51.100.7")
	tk.add("attacker", "r", "198.51.100.7")
	top := tk.drain()
	if top[0].Key != "attacker" || top[0].Limited != 3*TopSample || top[0].Err != TopSample {
		t.Fatalf("top %+v", top[0])
	}
	if top[1].Err != 0 {
		t.Fatalf("a subject that never took a slot reports error %d", top[1].Err)
	}
}

// Each replica posts per-version deltas to admin with its service token; a
// failed report is dropped and counted, never queued.
func TestStatsReporter(t *testing.T) {
	var mu sync.Mutex
	var got []StatsReport
	status := 200
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/v1/edge/report" || r.Header.Get("Authorization") != "Bearer t0k" {
			w.WriteHeader(401)
			return
		}
		var rep StatsReport
		_ = json.NewDecoder(r.Body).Decode(&rep)
		got = append(got, rep)
		w.WriteHeader(status)
	}))
	defer admin.Close()
	h := newHarness(t, map[string]string{"ADMIN_URL": admin.URL, "EDGE_SERVICE_TOKEN": "t0k", "STATS_INTERVAL": "10ms", "INSTANCE": "edge-1"})
	h.load(envelope(testConfig(1)))
	h.do("GET", "/", nil).Body.Close()
	h.do("GET", "/", nil).Body.Close()

	rp := h.srv.reporter
	ctx := t.Context()
	rp.report(ctx)
	rp.report(ctx)
	mu.Lock()
	if len(got) != 2 || got[0].Instance != "edge-1" || got[0].MaxSchema != snapshot.SupportedSchema || got[0].Deployment != h.srv.cfg.Deployment().Fingerprint() || got[0].Upstream != h.app.URL || got[0].ConfigSource != "admin" || len(got[0].Versions) != 1 || got[0].Versions[0].Requests != 2 {
		t.Fatalf("first report = %+v", got)
	}
	if got[1].Versions[0].Requests != 0 || sum(got[1].Versions[0].LatencyMS) != 0 {
		t.Fatalf("second report repeats counts: %+v", got[1])
	}
	status = 500
	mu.Unlock()
	rp.report(ctx)
	admin.Close()
	rp.report(ctx)
	if h.srv.m.statsDropped.Load() != 2 {
		t.Fatalf("dropped = %d", h.srv.m.statsDropped.Load())
	}
}

func sum(xs []uint64) uint64 {
	var n uint64
	for _, x := range xs {
		n += x
	}
	return n
}

// Each config and request-header rule reports how the requests it matched
// ended, so admin can tell which rule's traffic turned into 401s or 5xx.
func TestRuleOutcomesReported(t *testing.T) {
	h, _ := newAuthHarness(t)
	h.do("GET", "/private/a", nil).Body.Close() // no token: the edge answers 401
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }
	h.do("GET", "/admin/x", nil).Body.Close()
	h.do("GET", "/private/b", nil, "Authorization", "Bearer "+corpToken()).Body.Close()

	got := map[string]RuleOutcome{}
	for _, r := range h.srv.poller.reg.deltas()[0].Rules {
		got[r.ID] = r
	}
	want := map[string]RuleOutcome{
		"admin-route": {Phase: "config", ID: "admin-route", Matched: 1, Upstream5xx: 1},
		"uploads":     {Phase: "config", ID: "uploads"},
		"private":     {Phase: "config", ID: "private", Matched: 2, AuthFailures: 1, Upstream5xx: 1},
		"partner":     {Phase: "config", ID: "partner"},
		"ed":          {Phase: "config", ID: "ed"},
		"optional":    {Phase: "config", ID: "optional"},
		// Header rules run only on requests sent upstream: not the 401.
		"tenant": {Phase: "request_headers", ID: "tenant", Matched: 2, Upstream5xx: 2},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("rule outcomes\n got %+v\nwant %+v", got, want)
	}

	h.do("GET", "/admin/y", nil).Body.Close()
	for _, r := range h.srv.poller.reg.deltas()[0].Rules {
		if n := map[string]uint64{"admin-route": 1, "tenant": 1}[r.ID]; r.Matched != n {
			t.Fatalf("second report repeats counts: %+v", r)
		}
	}
}

// A version that stops serving reports its last delta, then is forgotten,
// so the registry can't grow without bound across publishes.
func TestStatsRegistryForgetsRetiredVersions(t *testing.T) {
	g := newStatsRegistry()
	v1 := g.use(&snapshot.Compiled{Config: &snapshot.Config{Version: 1}})[0]
	v1.observe(200, true, 3*time.Millisecond, nil, nil)
	v1.observe(503, false, 20*time.Second, nil, nil)
	v1.observe(401, false, time.Millisecond, nil, nil) // the edge refused a token
	v1.observe(401, true, time.Millisecond, nil, nil)  // the upstream did: not an auth failure here
	g.use(&snapshot.Compiled{Config: &snapshot.Config{Version: 2}})
	d := g.deltas()
	if len(d) != 2 {
		t.Fatalf("deltas = %+v", d)
	}
	for _, c := range d {
		if c.Version == 1 && (c.Requests != 4 || c.Edge5xx != 1 || c.AuthFailures != 1 || c.LatencyMS[2] != 1 || c.LatencyMS[len(LatencyBoundsMS)] != 1) {
			t.Fatalf("v1 delta = %+v", c)
		}
	}
	if d := g.deltas(); len(d) != 1 || d[0].Version != 2 {
		t.Fatalf("retired version still reported: %+v", d)
	}
}

// Config rules that block report how many requests they blocked and, in
// log mode, would have blocked, so admin's guard and notifications see a
// bad block rule. Only the rule that decided counts: the last matching rule
// with a block setting, as with every other setting.
func TestBlockOutcomesReported(t *testing.T) {
	h := newHarness(t, nil)
	c := testConfig(1)
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent contains "curl"`)},
		snapshot.ConfigRule{ID: "crawlers", Expression: mustParse(`http.user_agent contains "bot"`)},
	)
	h.loadJSON(envelope(c), func(env map[string]any) {
		cfg := activeJSON(env)
		setBlock(cfg, "tools", "block")
		setBlock(cfg, "crawlers", "log")
	})
	h.statuses(2, "GET", "/", "User-Agent", "curl/8.5.0")
	h.statuses(1, "GET", "/", "User-Agent", "examplebot/1.0")
	h.statuses(1, "GET", "/", "User-Agent", "curlbot/1.0") // both match; crawlers is later and decides
	h.statuses(1, "GET", "/", "User-Agent", firefoxUA)

	b, err := json.Marshal(h.srv.poller.reg.deltas()[0])
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	num := func(r map[string]any, k string) float64 { n, _ := r[k].(float64); return n }
	got := map[string]string{}
	for _, r := range rep.Rules {
		got[r["id"].(string)] = fmt.Sprintf("matched=%v blocked=%v would_block=%v", num(r, "matched"), num(r, "blocked"), num(r, "would_block"))
	}
	want := map[string]string{
		"admin-route": "matched=0 blocked=0 would_block=0",
		"uploads":     "matched=0 blocked=0 would_block=0",
		"tools":       "matched=3 blocked=2 would_block=0",
		"crawlers":    "matched=2 blocked=0 would_block=2",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("rule outcomes\n got %v\nwant %v", got, want)
	}
}

// A publish retires the version that served earlier requests, yet what
// /metrics exports never goes down, so rate() sees no counter reset. A
// rate-limit rule's series stays while a held version carries the rule and
// goes once none does, so renamed rules can't pile up series.
func TestMetricsKeepRetiredVersionCounts(t *testing.T) {
	h := newHarness(t, nil) // no Valkey: fail_mode local counts in process
	withRule := func(version int64, id string) *snapshot.Envelope {
		c := testConfig(version)
		r := rlRule(id, "true", "sliding_window", 100, "ip")
		r.FailMode = "local"
		c.RateLimitRules = []snapshot.RateLimitRule{r}
		return envelope(c)
	}
	const count = "edge_request_duration_seconds_count"
	evaluated := `edge_ratelimit_rule_total{rule="per-ip",outcome="evaluated"}`
	want := func(when string, requests float64) {
		t.Helper()
		if m := h.metrics(); m[count] != requests || m[evaluated] != requests {
			t.Fatalf("%s: %s %v, %s %v, want %v", when, count, m[count], evaluated, m[evaluated], requests)
		}
	}

	h.load(withRule(1, "per-ip"))
	h.statuses(3, "GET", "/")
	want("serving v1", 3)
	h.load(withRule(2, "per-ip"))
	want("v2 published, v1 not yet reported", 3)
	h.srv.poller.reg.deltas()
	want("v1 reported and retired", 3)
	h.statuses(1, "GET", "/")
	want("v2 serving", 4)

	h.load(withRule(3, "per-ip-renamed"))
	h.srv.poller.reg.deltas()
	m := h.metrics()
	if m[count] != 4 {
		t.Fatalf("%s %v after v2 retired, want 4", count, m[count])
	}
	if _, ok := m[evaluated]; ok {
		t.Fatalf("%s still exported with no held version carrying the rule", evaluated)
	}
	if n, ok := m[`edge_ratelimit_rule_total{rule="per-ip-renamed",outcome="evaluated"}`]; !ok || n != 0 {
		t.Fatalf("renamed rule's series %v (present %v), want 0", n, ok)
	}
}
