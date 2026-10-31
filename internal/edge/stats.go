package edge

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
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
	version int64
	// codes counts finished requests by origin (edge, upstream) and status
	// slot. One add per request; requests, 5xx and auth failures are derived.
	codes   [2][maxCodeSlot + 1]atomic.Uint64
	latency [len(LatencyBoundsMS) + 1]atomic.Uint64
	// causes counts upstream failures by upstreamCause, on the error path.
	causes [len(UpstreamCauses)]atomic.Uint64
	// rules counts each rate-limit rule, by index.
	rules   []ruleStats
	ruleIDs []string
	top     topKeys
	// outcomes counts each config rule, then each request-header rule, by
	// index; outcomeIDs names them in the same order.
	outcomes   []ruleOutcome
	outcomeIDs []RuleOutcome
	nConfig    int
	// wouldTop tracks log-only (shadow) limits apart from top, so log-only
	// rules never evict the subjects real limits report.
	wouldTop topKeys

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

// maxCodeSlot holds every status above 599, which net/http accepts from an
// upstream (any three digits). Slot 0 is a request that got no response.
const maxCodeSlot = 600

// codeSlot is the status's slot in versionStats.codes.
func codeSlot(status int) int { return min(status, maxCodeSlot) }

// originOf is the first index of versionStats.codes: 0 the edge, 1 the upstream.
func originOf(fromUpstream bool) int {
	if fromUpstream {
		return 1
	}
	return 0
}

// StatusCodes count requests by status slot, apart by who answered.
type StatusCodes struct {
	Edge     map[int]uint64 `json:"edge,omitempty"`
	Upstream map[int]uint64 `json:"upstream,omitempty"`
}

// since is c minus an earlier reading, keeping only the codes that grew.
func (c StatusCodes) since(prev StatusCodes) StatusCodes {
	return StatusCodes{Edge: countsSince(c.Edge, prev.Edge), Upstream: countsSince(c.Upstream, prev.Upstream)}
}

// countsSince keeps the keys of now that grew since prev, by how much.
func countsSince[K comparable](now, prev map[K]uint64) map[K]uint64 {
	var d map[K]uint64
	for code, n := range now {
		if n > prev[code] {
			if d == nil {
				d = map[K]uint64{}
			}
			d[code] = n - prev[code]
		}
	}
	return d
}

// StatsCounts are one config version's counts since the previous report.
type StatsCounts struct {
	Version int64 `json:"version"`
	Totals        // flattened in JSON
	// StatusCodes is sparse: only codes seen since the previous report.
	StatusCodes StatusCodes `json:"status_codes,omitzero"`
	// UpstreamErrors is sparse: the edge's upstream failures by cause name.
	UpstreamErrors map[string]uint64 `json:"upstream_errors,omitempty"`
	RateLimit      []RuleCounts      `json:"rate_limit_rules,omitempty"`
	// TopLimited are the most-limited subjects this interval, which the
	// guard leaves out when comparing cohorts.
	TopLimited []TopCount `json:"top_limited,omitempty"`
	// Rules are the config and request-header rules' outcomes.
	Rules []RuleOutcome `json:"rules,omitempty"`
}

type ruleStats struct {
	evaluated, limited, wouldLimit, failed atomic.Uint64
	// capped counts requests the rule matched but the per-request cap
	// skipped. Reported, so admin can show a rule pushed past the cap.
	capped atomic.Uint64
	// expired counts requests the rule matched after its expires_at.
	// Only /metrics exports it.
	expired atomic.Uint64
}

// ruleOutcomeNames are the outcome labels of edge_ratelimit_rule_total, in
// the order ruleStats.load returns them.
var ruleOutcomeNames = [...]string{"evaluated", "limited", "would_limit", "failed", "capped", "expired"}

const numRuleOutcomes = len(ruleOutcomeNames)

func (r *ruleStats) load() [numRuleOutcomes]uint64 {
	return [...]uint64{r.evaluated.Load(), r.limited.Load(), r.wouldLimit.Load(), r.failed.Load(), r.capped.Load(), r.expired.Load()}
}

// RuleCounts are one rule's counts. WouldLimit is a shadow rule (or any rule
// under the kill switch) over its limit; Failed is a call that took the
// rule's fail_mode; Capped is a match the per-request cap skipped.
type RuleCounts struct {
	ID         string `json:"id"`
	Evaluated  uint64 `json:"evaluated"`
	Limited    uint64 `json:"limited"`
	WouldLimit uint64 `json:"would_limit"`
	Failed     uint64 `json:"failed"`
	Capped     uint64 `json:"capped,omitempty"`
}

// Counters lists every count in r, like Totals.Counters.
func (r *RuleCounts) Counters() []*uint64 {
	return []*uint64{&r.Evaluated, &r.Limited, &r.WouldLimit, &r.Failed, &r.Capped}
}

// ruleOutcome counts the requests one config or request-header rule matched
// and how they ended. It fills a cache line, so adds to a hot rule don't
// contend with its neighbours'.
type ruleOutcome struct {
	matched, edge5xx, upstream5xx, authFailures, blocked, wouldBlock atomic.Uint64
	_                                                                [16]byte
}

// RuleOutcome is how the requests one config or request-header rule matched
// ended. Admin's notifications compare it with the rule's own past.
type RuleOutcome struct {
	Phase        string `json:"phase"`
	ID           string `json:"id"`
	Matched      uint64 `json:"matched"`
	Edge5xx      uint64 `json:"edge_5xx"`
	Upstream5xx  uint64 `json:"upstream_5xx"`
	AuthFailures uint64 `json:"auth_failures"`
	// Blocked and WouldBlock count the requests this config rule's block
	// setting decided, as block and as log.
	Blocked    uint64 `json:"blocked"`
	WouldBlock uint64 `json:"would_block"`
}

// Counters lists every count in r, like Totals.Counters.
func (r *RuleOutcome) Counters() []*uint64 {
	return []*uint64{&r.Matched, &r.Edge5xx, &r.Upstream5xx, &r.AuthFailures, &r.Blocked, &r.WouldBlock}
}

func (o *ruleOutcome) add(status int, fromUpstream bool) {
	o.matched.Add(1)
	switch {
	case status == http.StatusUnauthorized && !fromUpstream:
		o.authFailures.Add(1)
	case status >= 500 && fromUpstream:
		o.upstream5xx.Add(1)
	case status >= 500:
		o.edge5xx.Add(1)
	}
}

// observe counts one finished request. config and headers are the indexes
// of the config and request-header rules it matched.
func (s *versionStats) observe(status int, fromUpstream bool, elapsed time.Duration, config, headers []int) {
	for _, i := range config {
		s.outcomes[i].add(status, fromUpstream)
	}
	for _, i := range headers {
		s.outcomes[s.nConfig+i].add(status, fromUpstream)
	}
	s.codes[originOf(fromUpstream)][codeSlot(status)].Add(1)
	ms := float64(elapsed) / float64(time.Millisecond)
	i := 0
	for i < len(LatencyBoundsMS) && ms > LatencyBoundsMS[i] {
		i++
	}
	s.latency[i].Add(1)
}

// block counts the outcome of config rule i's block setting.
func (s *versionStats) block(i int, blocked bool) {
	if blocked {
		s.outcomes[i].blocked.Add(1)
	} else {
		s.outcomes[i].wouldBlock.Add(1)
	}
}

func (s *versionStats) counts() StatsCounts {
	c := StatsCounts{Version: s.version, LatencyMS: make([]uint64, len(s.latency))}
	var codes [2]map[int]uint64
	for origin := range s.codes {
		for code := range s.codes[origin] {
			n := s.codes[origin][code].Load()
			if n == 0 {
				continue
			}
			if codes[origin] == nil {
				codes[origin] = map[int]uint64{}
			}
			codes[origin][code] = n
			c.Requests += n
			switch {
			case code >= 500 && origin == 1:
				c.Upstream5xx += n
			case code >= 500:
				c.Edge5xx += n
			}
		}
	}
	// Only the edge's own 401s are auth failures; an upstream 401 is its answer.
	c.AuthFailures = codes[0][http.StatusUnauthorized]
	c.StatusCodes = StatusCodes{Edge: codes[0], Upstream: codes[1]}
	for i := range s.causes {
		if n := s.causes[i].Load(); n > 0 {
			if c.UpstreamErrors == nil {
				c.UpstreamErrors = map[string]uint64{}
			}
			c.UpstreamErrors[UpstreamCauses[i]] = n
		}
	}
	for i := range s.latency {
		c.LatencyMS[i] = s.latency[i].Load()
	}
	for i := range s.rules {
		r := &s.rules[i]
		c.RateLimit = append(c.RateLimit, RuleCounts{ID: s.ruleIDs[i], Evaluated: r.evaluated.Load(), Limited: r.limited.Load(), WouldLimit: r.wouldLimit.Load(), Failed: r.failed.Load(),
			Capped: r.capped.Load()})
	}
	for i := range s.outcomes {
		o, r := &s.outcomes[i], s.outcomeIDs[i]
		r.Matched, r.Edge5xx, r.Upstream5xx, r.AuthFailures = o.matched.Load(), o.edge5xx.Load(), o.upstream5xx.Load(), o.authFailures.Load()
		r.Blocked, r.WouldBlock = o.blocked.Load(), o.wouldBlock.Load()
		c.Rules = append(c.Rules, r)
	}
	return c
}

// delta returns counts since the last call. Counters only grow, so plain
// subtraction is exact.
func (s *versionStats) delta() StatsCounts {
	now := s.counts()
	d := StatsCounts{Version: now.Version, Totals: now.since(s.last.Totals), StatusCodes: now.StatusCodes.since(s.last.StatusCodes),
		UpstreamErrors: countsSince(now.UpstreamErrors, s.last.UpstreamErrors)}
	for i, r := range now.RateLimit {
		if s.last.RateLimit != nil {
			rc := r.Counters()
			for j, p := range s.last.RateLimit[i].Counters() {
				*rc[j] -= *p
			}
		}
		d.RateLimit = append(d.RateLimit, r)
	}
	for i, r := range now.Rules {
		if s.last.Rules != nil {
			rc := r.Counters()
			for j, p := range s.last.Rules[i].Counters() {
				*rc[j] -= *p
			}
		}
		d.Rules = append(d.Rules, r)
	}
	s.last = now
	d.TopLimited = s.top.drain()
	for _, t := range s.wouldTop.drain() {
		t.WouldLimit, t.Limited = t.Limited, 0
		d.TopLimited = append(d.TopLimited, t)
	}
	return d
}

const (
	// TopSample: one limited request in TopSample updates the top-K, so an
	// attack can't serialize on its mutex. Admin allows for the sampling
	// error it puts in the estimates.
	TopSample   = 16
	topCapacity = 256
	topReported = 20
)

// sampleTop picks the sampled requests; tests replace it.
var sampleTop = func() bool { return rand.Uint32()%TopSample == 0 } //nolint:gosec // sampling needs no cryptographic randomness

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

// TopCount is one subject. Limited and WouldLimit (log-only rules) are
// estimated from the sample. Err is the count it inherited when it took an
// evicted subject's slot: its own count is at least the estimate less Err.
type TopCount struct {
	Rule       string `json:"rule"`
	Key        string `json:"key"`
	Display    string `json:"display"`
	Limited    uint64 `json:"limited"`
	WouldLimit uint64 `json:"would_limit,omitempty"`
	Err        uint64 `json:"err,omitempty"`
}

func (t *topKeys) add(key, rule, display string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.m[key]; e != nil {
		e.Limited += TopSample
		return
	}
	if t.m == nil {
		t.m = map[string]*TopCount{}
	}
	var base uint64
	if len(t.m) == topCapacity {
		var minE *TopCount
		for _, e := range t.m {
			if minE == nil || e.Limited < minE.Limited {
				minE = e
			}
		}
		base = minE.Limited
		delete(t.m, minE.Key)
	}
	t.m[key] = &TopCount{Rule: rule, Key: key, Display: display, Limited: base + TopSample, Err: base}
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
// reported. Only snapshot swaps, the reporter and scrapes lock it, never
// requests.
type statsRegistry struct {
	mu   sync.Mutex
	byV  map[int64]*versionStats
	live map[int64]bool
	// latency and rules hold the counts of versions already forgotten, so
	// the totals /metrics exports never go down. rules keeps only IDs some
	// version in byV still has, so it is bounded by the held versions' rules.
	latency [len(LatencyBoundsMS) + 1]uint64
	rules   map[string]*[numRuleOutcomes]uint64
}

func newStatsRegistry() *statsRegistry {
	return &statsRegistry{byV: map[int64]*versionStats{}, live: map[int64]bool{}, rules: map[string]*[numRuleOutcomes]uint64{}}
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
			for _, r := range c.Config.ConfigRules {
				s.outcomeIDs = append(s.outcomeIDs, RuleOutcome{Phase: "config", ID: r.ID})
			}
			for _, r := range c.Config.RequestHeaderRules {
				s.outcomeIDs = append(s.outcomeIDs, RuleOutcome{Phase: "request_headers", ID: r.ID})
			}
			s.nConfig = len(c.Config.ConfigRules)
			s.outcomes = make([]ruleOutcome, len(s.outcomeIDs))
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
			g.retire(s)
			delete(g.byV, v)
		}
	}
	g.prune()
	return out
}

// retire folds a forgotten version's counts into the registry's totals.
// g.mu is held.
func (g *statsRegistry) retire(s *versionStats) {
	for i := range s.latency {
		g.latency[i] += s.latency[i].Load()
	}
	for i := range s.rules {
		c := g.rules[s.ruleIDs[i]]
		if c == nil {
			c = new([numRuleOutcomes]uint64)
			g.rules[s.ruleIDs[i]] = c
		}
		for j, n := range s.rules[i].load() {
			c[j] += n
		}
	}
}

// prune drops folded rule counts no held version has, so rules renamed or
// removed across publishes don't pile up series. g.mu is held.
func (g *statsRegistry) prune() {
	for id := range g.rules {
		held := false
		for _, s := range g.byV {
			held = held || slices.Contains(s.ruleIDs, id)
		}
		if !held {
			delete(g.rules, id)
		}
	}
}

// writeTo writes the latency histogram and per-rule rate-limit counts, held
// versions plus forgotten ones, in Prometheus text format. The histogram has
// no _sum: the edge keeps only bucket counts.
func (g *statsRegistry) writeTo(w io.Writer) {
	g.mu.Lock()
	lat := g.latency
	rules := make(map[string][numRuleOutcomes]uint64, len(g.rules))
	for id, c := range g.rules {
		rules[id] = *c
	}
	for _, s := range g.byV {
		for i := range s.latency {
			lat[i] += s.latency[i].Load()
		}
		for i := range s.rules {
			c := rules[s.ruleIDs[i]]
			for j, n := range s.rules[i].load() {
				c[j] += n
			}
			rules[s.ruleIDs[i]] = c
		}
	}
	// Written unlocked, so a slow scraper never holds up a snapshot swap.
	g.mu.Unlock()
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	p("# TYPE edge_request_duration_seconds histogram\n")
	var n uint64
	for i, b := range LatencyBoundsMS {
		n += lat[i]
		p("edge_request_duration_seconds_bucket{le=%q} %d\n", strconv.FormatFloat(b/1000, 'g', -1, 64), n)
	}
	n += lat[len(LatencyBoundsMS)]
	p("edge_request_duration_seconds_bucket{le=\"+Inf\"} %d\nedge_request_duration_seconds_count %d\n", n, n)
	p("# TYPE edge_ratelimit_rule_total counter\n")
	for _, id := range slices.Sorted(maps.Keys(rules)) {
		for j, c := range rules[id] {
			p("edge_ratelimit_rule_total{rule=%q,outcome=%q} %d\n", id, ruleOutcomeNames[j], c)
		}
	}
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
	Deployment string `json:"deployment"`
	// Upstream is this edge's UPSTREAM_URL, shown read-only in admin.
	Upstream string        `json:"upstream"`
	Versions []StatsCounts `json:"versions"`
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
	upstream             string
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
	rep := StatsReport{Instance: rp.instance, IntervalSeconds: rp.interval.Seconds(), MaxSchema: snapshot.SupportedSchema, Deployment: rp.deployment, Upstream: rp.upstream, Versions: rp.reg.deltas()}
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
