package edge

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// LatencyBoundsMS are the histogram's upper bounds in milliseconds; a final
// bucket counts everything slower. Admin's guard reads buckets by them.
var LatencyBoundsMS = [...]float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

// versionStats counts requests served under one config version. The guard
// compares a canary's candidate against the active version.
type versionStats struct {
	version     int64
	requests    atomic.Uint64
	edge5xx     atomic.Uint64 // 5xx the edge generated
	upstream5xx atomic.Uint64 // 5xx the upstream returned
	// authFailures are edge 401s: the guard's auth_failure_ratio.
	authFailures atomic.Uint64
	latency      [len(LatencyBoundsMS) + 1]atomic.Uint64
	// rules counts each rate-limit rule, by index.
	rules   []ruleStats
	ruleIDs []string
	top     topKeys

	// last holds the counts at the previous report, so reports carry deltas.
	// Only the reporter goroutine touches it.
	last StatsCounts
}

// Totals are the request counts the guard compares. Admin sums reports,
// stored minutes and cohorts with this one type, so a new signal is one
// field here, one entry in Counters, and a column in admin's stats table.
type Totals struct {
	Requests     uint64   `json:"requests"`
	Edge5xx      uint64   `json:"edge_5xx"`
	Upstream5xx  uint64   `json:"upstream_5xx"`
	AuthFailures uint64   `json:"auth_failures"`
	LatencyMS    []uint64 `json:"latency_ms_buckets"`
}

// Counters lists every count in t, latency buckets last. Differences,
// sums and range checks all walk it, so none can miss a field.
func (t *Totals) Counters() []*uint64 {
	c := []*uint64{&t.Requests, &t.Edge5xx, &t.Upstream5xx, &t.AuthFailures}
	for i := range t.LatencyMS {
		c = append(c, &t.LatencyMS[i])
	}
	return c
}

// since is t minus an earlier reading of the same counters, which only grow.
func (t *Totals) since(prev Totals) Totals {
	d := *t
	d.LatencyMS = slices.Clone(t.LatencyMS)
	dc := d.Counters()
	for i, p := range prev.Counters() {
		*dc[i] -= *p
	}
	return d
}

// StatsCounts are one config version's counts since the previous report.
type StatsCounts struct {
	Version   int64        `json:"version"`
	Totals                 // flattened in JSON
	RateLimit []RuleCounts `json:"rate_limit_rules,omitempty"`
	// TopLimited are the most-limited subjects this interval, which the
	// guard leaves out when comparing cohorts.
	TopLimited []TopCount `json:"top_limited,omitempty"`
}

type ruleStats struct {
	evaluated, limited, wouldLimit, failed atomic.Uint64
}

// RuleCounts are one rule's counts. WouldLimit is a shadow rule (or any rule
// under the kill switch) over its limit; Failed is a call that took the
// rule's fail_mode.
type RuleCounts struct {
	ID         string `json:"id"`
	Evaluated  uint64 `json:"evaluated"`
	Limited    uint64 `json:"limited"`
	WouldLimit uint64 `json:"would_limit"`
	Failed     uint64 `json:"failed"`
}

// Counters lists every count in r, like Totals.Counters.
func (r *RuleCounts) Counters() []*uint64 {
	return []*uint64{&r.Evaluated, &r.Limited, &r.WouldLimit, &r.Failed}
}

func (s *versionStats) observe(status int, fromUpstream bool, elapsed time.Duration) {
	s.requests.Add(1)
	if status == http.StatusUnauthorized && !fromUpstream {
		s.authFailures.Add(1)
	}
	if status >= 500 {
		if fromUpstream {
			s.upstream5xx.Add(1)
		} else {
			s.edge5xx.Add(1)
		}
	}
	ms := float64(elapsed) / float64(time.Millisecond)
	i := 0
	for i < len(LatencyBoundsMS) && ms > LatencyBoundsMS[i] {
		i++
	}
	s.latency[i].Add(1)
}

func (s *versionStats) counts() StatsCounts {
	c := StatsCounts{Version: s.version, Requests: s.requests.Load(), Edge5xx: s.edge5xx.Load(), Upstream5xx: s.upstream5xx.Load(), AuthFailures: s.authFailures.Load(), LatencyMS: make([]uint64, len(s.latency))}
	for i := range s.latency {
		c.LatencyMS[i] = s.latency[i].Load()
	}
	for i := range s.rules {
		r := &s.rules[i]
		c.RateLimit = append(c.RateLimit, RuleCounts{ID: s.ruleIDs[i], Evaluated: r.evaluated.Load(), Limited: r.limited.Load(), WouldLimit: r.wouldLimit.Load(), Failed: r.failed.Load()})
	}
	return c
}

// delta returns counts since the last call. Counters only grow, so plain
// subtraction is exact.
func (s *versionStats) delta() StatsCounts {
	now := s.counts()
	d := StatsCounts{Version: now.Version, Totals: now.since(s.last.Totals)}
	for i, r := range now.RateLimit {
		if s.last.RateLimit != nil {
			rc := r.Counters()
			for j, p := range s.last.RateLimit[i].Counters() {
				*rc[j] -= *p
			}
		}
		d.RateLimit = append(d.RateLimit, r)
	}
	s.last = now
	d.TopLimited = s.top.drain()
	return d
}

const (
	// topSample: one limited request in topSample updates the top-K, so an
	// attack can't serialize on its mutex.
	topSample   = 16
	topCapacity = 256
	topReported = 20
)

// sampleTop picks the sampled requests; tests replace it.
var sampleTop = func() bool { return rand.Uint32()%topSample == 0 } //nolint:gosec // sampling needs no cryptographic randomness

// topKeys finds the most-limited subjects with Space-Saving (Metwally,
// Agrawal, El Abbadi, "Efficient Computation of Frequent and Top-k Elements
// in Data Streams", 2005): at most topCapacity entries; a new subject
// replaces the smallest and inherits its count. Any subject limited more
// than 1/topCapacity of the time stays tracked, and counts never
// underestimate.
type topKeys struct {
	mu sync.Mutex
	m  map[string]*TopCount
}

// TopCount is one subject. Limited is estimated from the sample.
type TopCount struct {
	Rule    string `json:"rule"`
	Key     string `json:"key"`
	Display string `json:"display"`
	Limited uint64 `json:"limited"`
}

func (t *topKeys) add(key, rule, display string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.m[key]; e != nil {
		e.Limited += topSample
		return
	}
	if t.m == nil {
		t.m = map[string]*TopCount{}
	}
	var base uint64
	if len(t.m) == topCapacity {
		var minKey string
		for k, e := range t.m {
			if minKey == "" || e.Limited < t.m[minKey].Limited {
				minKey = k
			}
		}
		base = t.m[minKey].Limited
		delete(t.m, minKey)
	}
	t.m[key] = &TopCount{Rule: rule, Key: key, Display: display, Limited: base + topSample}
}

// drain returns the top subjects since the last drain and starts over.
func (t *topKeys) drain() []TopCount {
	t.mu.Lock()
	m := t.m
	t.m = nil
	t.mu.Unlock()
	out := make([]TopCount, 0, len(m))
	for _, e := range m {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b TopCount) int { return cmp.Or(cmp.Compare(b.Limited, a.Limited), cmp.Compare(a.Key, b.Key)) })
	return out[:min(len(out), topReported)]
}

// statsRegistry keeps one versionStats per version until its final delta is
// reported. Only snapshot swaps and the reporter lock it, never requests.
type statsRegistry struct {
	mu   sync.Mutex
	byV  map[int64]*versionStats
	live map[int64]bool
}

func newStatsRegistry() *statsRegistry {
	return &statsRegistry{byV: map[int64]*versionStats{}, live: map[int64]bool{}}
}

// use returns the stats for the given live configs, creating them as needed.
// Versions no longer live stay until the reporter sends their last delta.
func (g *statsRegistry) use(cs ...*snapshot.Compiled) []*versionStats {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.live = map[int64]bool{}
	out := make([]*versionStats, len(cs))
	for i, c := range cs {
		v := c.Config.Version
		s, ok := g.byV[v]
		if !ok {
			// A version number always names the same config, so its rules
			// never change under these counters.
			s = &versionStats{version: v, rules: make([]ruleStats, len(c.Config.RateLimitRules))}
			for _, r := range c.Config.RateLimitRules {
				s.ruleIDs = append(s.ruleIDs, r.ID)
			}
			g.byV[v] = s
		}
		g.live[v] = true
		out[i] = s
	}
	return out
}

// deltas returns every version's delta and forgets retired versions.
func (g *statsRegistry) deltas() []StatsCounts {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []StatsCounts
	for v, s := range g.byV {
		out = append(out, s.delta())
		if !g.live[v] {
			delete(g.byV, v)
		}
	}
	return out
}

// StatsReport is what each replica posts to admin every interval.
type StatsReport struct {
	Instance            string  `json:"instance"`
	ConfigSource        string  `json:"config_source"`
	BootstrapAgeSeconds int64   `json:"bootstrap_age_seconds"`
	IntervalSeconds     float64 `json:"interval_seconds"`
	// MaxSchema is the highest config schema this build reads; admin won't
	// publish a higher one while this edge is live.
	MaxSchema int `json:"max_schema"`
	// Deployment is snapshot.Deployment.Fingerprint of this edge's
	// deployment config, which must match admin's.
	Deployment string        `json:"deployment"`
	Versions   []StatsCounts `json:"versions"`
}

// ReportAnswer is admin's reply to a stats report.
type ReportAnswer struct {
	// FleetSize is the number of edges admin saw reporting in the last
	// minute, this one included.
	FleetSize int `json:"fleet_size"`
}

// reporter pushes stats to admin. A failed report is dropped, never retried
// or queued: the next one carries fresh deltas and memory stays bounded.
type reporter struct {
	url, token, instance string
	deployment           string // fingerprint
	interval             time.Duration
	client               *http.Client
	reg                  *statsRegistry
	store                *store
	m                    *metrics
	log                  *slog.Logger
}

func (rp *reporter) run(ctx context.Context) {
	t := time.NewTicker(rp.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			guard(rp.m, rp.log, "stats reporter", func() { rp.report(ctx) })
		}
	}
}

func (rp *reporter) report(ctx context.Context) {
	rep := StatsReport{Instance: rp.instance, IntervalSeconds: rp.interval.Seconds(), MaxSchema: snapshot.SupportedSchema, Deployment: rp.deployment, Versions: rp.reg.deltas()}
	if ld := rp.store.load(); ld != nil {
		rep.ConfigSource = ld.source
		rep.BootstrapAgeSeconds = int64(ld.bootstrapAge / time.Second)
	}
	body, _ := json.Marshal(rep) // StatsReport has only marshalable fields
	// The URL was validated at startup, so the request can't fail to build.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, rp.url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rp.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rp.client.Do(req)
	if err != nil {
		rp.drop(err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		rp.drop(fmt.Errorf("admin answered %d", resp.StatusCode))
		return
	}
	var a ReportAnswer
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&a) == nil && a.FleetSize > 0 {
		rp.store.fleet.Store(int64(a.FleetSize))
	}
}

func (rp *reporter) drop(err error) {
	rp.m.statsDropped.Add(1)
	rp.log.Warn("stats report dropped", "error", err.Error())
}

// guard runs one iteration of a background loop. A panic there would kill
// the process, so it is recovered, logged and counted instead.
func guard(m *metrics, log *slog.Logger, what string, f func()) {
	defer func() {
		if v := recover(); v != nil {
			m.backgroundPanics.Add(1)
			log.Error("background panic recovered", "loop", what, "panic", fmt.Sprint(v))
		}
	}()
	f()
}
