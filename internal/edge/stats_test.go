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
	s := h.srv.store.load().active.stats
	if s.requests.Load() != 2 || s.upstream5xx.Load() != 1 || s.edge5xx.Load() != 1 {
		t.Fatalf("requests %d upstream5xx %d edge5xx %d", s.requests.Load(), s.upstream5xx.Load(), s.edge5xx.Load())
	}
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
	if len(top) != 2 || top[0].Rule != "per-ip" || top[0].Display != "198.51.100.7" || top[0].Limited != 4*topSample ||
		top[1].Display != "198.51.100.8" || top[1].Limited != topSample || !strings.HasPrefix(top[0].Key, "rl:sliding_window:60000:per-ip:{") {
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
	if len(top) != 1 || top[0].Rule != "search-per-ip" || top[0].Display != "198.51.100.7" || top[0].Limited != 0 || top[0].WouldLimit != 2*topSample {
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
			exact[k] += topSample
			n += topSample
		}
		if len(tk.m) > topCapacity {
			t.Fatalf("%d entries", len(tk.m))
		}
		for k, e := range tk.m {
			if e.Limited < exact[k] || e.Limited-exact[k] > n/topCapacity {
				t.Fatalf("%s estimated %d, true %d, stream %d", k, e.Limited, exact[k], n)
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

// A version that stops serving reports its last delta, then is forgotten,
// so the registry can't grow without bound across publishes.
func TestStatsRegistryForgetsRetiredVersions(t *testing.T) {
	g := newStatsRegistry()
	v1 := g.use(&snapshot.Compiled{Config: &snapshot.Config{Version: 1}})[0]
	v1.observe(200, true, 3*time.Millisecond)
	v1.observe(503, false, 20*time.Second)
	v1.observe(401, false, time.Millisecond) // the edge refused a token
	v1.observe(401, true, time.Millisecond)  // the upstream did: not an auth failure here
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
