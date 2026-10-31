package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// NotifySettings configure anomaly notifications. They are saved on their
// own, like the guard's, so turning off a noisy rule's alert needs no
// publish.
type NotifySettings struct {
	Enabled bool `json:"enabled"`
	// Each check compares the last Window with the Baseline before it.
	Window   snapshot.Duration `json:"window"`
	Baseline snapshot.Duration `json:"baseline"`
	// An anomaly notifies after FireAfter checks in a row trip, and
	// resolves after ResolveAfter checks in a row pass. Checks run every
	// minute.
	FireAfter    int                     `json:"fire_after"`
	ResolveAfter int                     `json:"resolve_after"`
	Signals      map[string]NotifySignal `json:"signals"`
	// Rules replace a signal's settings for one rule, by rule ID and then
	// signal.
	Rules map[string]map[string]NotifySignal `json:"rules"`
}

// NotifySignal is one check's settings. Factor is relative to the
// baseline; the others are absolute.
type NotifySignal struct {
	Mode        string  `json:"mode"`     // notify | off
	Severity    string  `json:"severity"` // critical | warning | info
	Factor      float64 `json:"factor,omitempty"`
	Floor       float64 `json:"floor,omitempty"`
	FloorMS     float64 `json:"floor_ms,omitempty"`
	MaxShare    float64 `json:"max_share,omitempty"`
	MinRequests uint64  `json:"min_requests,omitempty"`
	// MinEvents is the least counted requests (5xx, failed token checks) a
	// share signal needs, so a few errors in a quiet window don't trip it.
	MinEvents uint64 `json:"min_events,omitempty"`
}

func defaultNotify() NotifySettings {
	m := snapshot.Duration(time.Minute)
	n := func(sev string, factor, floor float64, min uint64) NotifySignal {
		return NotifySignal{Mode: "notify", Severity: sev, Factor: factor, Floor: floor, MinRequests: min}
	}
	share := func(sev string, factor, floor float64, min, events uint64) NotifySignal {
		s := n(sev, factor, floor, min)
		s.MinEvents = events
		return s
	}
	return NotifySettings{
		Enabled: true, Window: 5 * m, Baseline: 60 * m, FireAfter: 2, ResolveAfter: 5,
		Signals: map[string]NotifySignal{
			"traffic_drop":       n("warning", 3, 0, 300),
			"traffic_surge":      n("warning", 5, 0, 1000),
			"edge_5xx_ratio":     share("critical", 2, 0.01, 200, 20),
			"upstream_5xx_ratio": share("critical", 2, 0.02, 200, 20),
			"auth_failure_ratio": share("warning", 2, 0.05, 200, 20),
			// p99 of fewer than 1000 requests is its 10 slowest, too few to
			// judge a latency bound by.
			"p99_latency":             {Mode: "notify", Severity: "warning", Factor: 1.5, FloorMS: 100, MinRequests: 1000},
			"rule_stopped_matching":   n("warning", 0, 0, 100),
			"rule_match_surge":        n("info", 5, 0, 500),
			"rule_edge_5xx_ratio":     share("warning", 2, 0.01, 100, 10),
			"rule_upstream_5xx_ratio": share("warning", 2, 0.05, 100, 10),
			"rule_auth_failure_ratio": share("warning", 2, 0.1, 100, 10),
			"rule_block_spike":        n("warning", 3, 0.01, 100),
			"rule_would_block":        n("info", 0, 0, 1),
			"rule_fail_mode":          n("critical", 0, 0, 1),
			"rule_subject_dominates":  {Mode: "notify", Severity: "warning", MaxShare: 0.5, MinRequests: 100},
			// The autopilot's own events, found from its state, not traffic.
			"autopilot_enforced":         {Mode: "notify", Severity: "info"},
			"autopilot_rolled_back":      {Mode: "notify", Severity: "warning"},
			"autopilot_budget_exhausted": {Mode: "notify", Severity: "warning"},
			"autopilot_agent_down":       {Mode: "notify", Severity: "warning"},
			"autopilot_needs_person":     {Mode: "notify", Severity: "warning"},
			"autopilot_note_contested":   {Mode: "notify", Severity: "warning"},
		},
		Rules: map[string]map[string]NotifySignal{},
	}
}

// notifyCheck is one signal: the phases it watches ("" is the whole fleet),
// the settings it needs unless off, and the check itself.
type notifyCheck struct {
	phases []string
	ok     func(NotifySignal) bool
	needs  string
	check  func(s NotifySignal, w, b *span, id string) (bool, string)
}

var (
	allPhases   = []string{string(expr.PhaseConfig), string(expr.PhaseRateLimit), string(expr.PhaseRequestHeaders)}
	outcomeOnly = []string{string(expr.PhaseConfig), string(expr.PhaseRequestHeaders)}
	limitOnly   = []string{string(expr.PhaseRateLimit)}
	// blockPhases have rules that refuse requests: rate limits and config
	// rules with a block setting.
	blockPhases = []string{string(expr.PhaseConfig), string(expr.PhaseRateLimit)}
	fleetOnly   = []string{""}

	factorMin   = notifyNeeds(func(s NotifySignal) bool { return s.Factor > 1 && s.MinRequests > 0 }, "factor above 1, min_requests of at least 1")
	relativeMin = notifyNeeds(func(s NotifySignal) bool { return s.Factor >= 1 && s.Floor >= 0 && s.Floor <= 1 && s.MinRequests > 0 },
		"factor of at least 1, floor from 0 to 1, min_requests of at least 1")
	minOnly = notifyNeeds(func(s NotifySignal) bool { return s.MinRequests > 0 }, "min_requests of at least 1")
)

func notifyNeeds(ok func(NotifySignal) bool, needs string) notifyCheck {
	return notifyCheck{ok: ok, needs: needs}
}

func (c notifyCheck) on(phases []string, check func(s NotifySignal, w, b *span, id string) (bool, string)) notifyCheck {
	c.phases, c.check = phases, check
	return c
}

// notifyChecks has one entry for each signal in defaultNotify.
var notifyChecks = map[string]notifyCheck{
	"traffic_drop": factorMin.on(fleetOnly, func(s NotifySignal, w, b *span, _ string) (bool, string) {
		want := b.scaled(w, b.Requests)
		return want >= float64(s.MinRequests) && float64(w.Requests) < want/s.Factor,
			fmt.Sprintf("%d requests in the last %s, against about %.0f in the %s before", w.Requests, w.length(), want, b.length())
	}),
	"traffic_surge": factorMin.on(fleetOnly, func(s NotifySignal, w, b *span, _ string) (bool, string) {
		want := b.scaled(w, b.Requests)
		return w.Requests >= s.MinRequests && float64(w.Requests) > s.Factor*want,
			fmt.Sprintf("%d requests in the last %s, against about %.0f in the %s before", w.Requests, w.length(), want, b.length())
	}),
	"edge_5xx_ratio":     relativeMin.on(fleetOnly, shareCheck("5xx the edge sent", func(t *edge.Totals) (uint64, uint64) { return t.Edge5xx, t.Requests })),
	"upstream_5xx_ratio": relativeMin.on(fleetOnly, shareCheck("5xx from the upstream", func(t *edge.Totals) (uint64, uint64) { return t.Upstream5xx, t.Requests })),
	"auth_failure_ratio": relativeMin.on(fleetOnly, shareCheck("requests failing their token check", func(t *edge.Totals) (uint64, uint64) { return t.AuthFailures, t.Requests })),
	"p99_latency": notifyNeeds(func(s NotifySignal) bool { return s.Factor >= 1 && s.FloorMS >= 0 && s.MinRequests > 0 },
		"factor of at least 1, floor_ms not negative, min_requests of at least 1").on(fleetOnly, func(s NotifySignal, w, b *span, _ string) (bool, string) {
		now, before := (&cohort{Totals: w.Totals}).p99(), (&cohort{Totals: b.Totals}).p99()
		return w.Requests >= s.MinRequests && now > max(s.FloorMS, s.Factor*before),
			fmt.Sprintf("p99 latency up to %gms in the last %s, against up to %gms in the %s before", now, w.length(), before, b.length())
	}),
	"rule_stopped_matching": minOnly.on(allPhases, func(s NotifySignal, w, b *span, id string) (bool, string) {
		// The window requests the rule was live for, so a canary rule is judged by the canary's requests.
		// A rule no edge reports in the window is expected at its share of all requests, so it still notifies.
		// A listed rule whose versions served no requests is expected to match none.
		want := b.expected(id, w.live[id])
		if _, listed := w.live[id]; !listed {
			want = ratio(b.matched(id), b.Requests) * float64(w.Requests)
		}
		// A rule live for too little of the baseline has no share to judge yet.
		return b.scaled(w, b.live[id]) >= float64(s.MinRequests) && want >= float64(s.MinRequests) && w.matched(id) == 0,
			fmt.Sprintf("Matched no requests in the last %s, though its share of requests in the %s before gives about %.0f", w.length(), b.length(), want)
	}),
	"rule_match_surge": factorMin.on(allPhases, func(s NotifySignal, w, b *span, id string) (bool, string) {
		got, want := w.matched(id), b.expected(id, w.live[id])
		// A baseline that was quiet, or held the rule only briefly or not at all, as when it was just published,
		// gives the rule no share to judge: traffic starting from nothing is traffic_surge alone.
		return b.scaled(w, b.live[id]) >= float64(s.MinRequests) && got >= s.MinRequests && float64(got) > s.Factor*want,
			fmt.Sprintf("Matched %d requests in the last %s, against about %.0f at its share of requests in the %s before", got, w.length(), want, b.length())
	}),
	"rule_edge_5xx_ratio": relativeMin.on(outcomeOnly, outcomeShare("of its requests got a 5xx from the edge",
		func(o *edge.RuleOutcome) uint64 { return o.Edge5xx }, func(t *edge.Totals) uint64 { return t.Edge5xx })),
	"rule_upstream_5xx_ratio": relativeMin.on(outcomeOnly, outcomeShare("of its requests got a 5xx from the upstream",
		func(o *edge.RuleOutcome) uint64 { return o.Upstream5xx }, func(t *edge.Totals) uint64 { return t.Upstream5xx })),
	"rule_auth_failure_ratio": relativeMin.on([]string{string(expr.PhaseConfig)}, outcomeShare("of its requests failed their token check",
		func(o *edge.RuleOutcome) uint64 { return o.AuthFailures }, func(t *edge.Totals) uint64 { return t.AuthFailures })),
	"rule_block_spike": relativeMin.on(blockPhases, func(s NotifySignal, w, b *span, id string) (bool, string) {
		wr, br := w.blocking(id), b.blocking(id)
		now, before := ratio(wr.Limited, wr.Evaluated), ratio(br.Limited, br.Evaluated)
		return wr.Evaluated >= s.MinRequests && now > max(s.Floor, s.Factor*before),
			fmt.Sprintf("Blocked %s of the requests it checked in the last %s, against %s in the %s before", pct(now), w.length(), pct(before), b.length())
	}),
	"rule_would_block": minOnly.on(blockPhases, func(s NotifySignal, w, _ *span, id string) (bool, string) {
		n := w.blocking(id).WouldLimit
		return n >= s.MinRequests, fmt.Sprintf("Would have blocked %d requests in the last %s: it is set to log only, or the kill switch is on", n, w.length())
	}),
	"rule_fail_mode": minOnly.on(limitOnly, func(s NotifySignal, w, _ *span, id string) (bool, string) {
		n := w.limit(id).Failed
		return n >= s.MinRequests, fmt.Sprintf("%d requests took its fail mode in the last %s: Valkey did not answer", n, w.length())
	}),
	"rule_subject_dominates": notifyNeeds(func(s NotifySignal) bool { return isRatio(s.MaxShare) && s.MinRequests > 0 },
		"max_share above 0 and at most 1, min_requests of at least 1").on(limitOnly, func(s NotifySignal, w, _ *span, id string) (bool, string) {
		limited := w.limit(id).Limited
		who, n := w.topSubject(id)
		// Subjects are counted from a sample, so the estimate can pass the total.
		share := min(ratio(n, limited), 1)
		return limited >= s.MinRequests && share > s.MaxShare,
			fmt.Sprintf("%s got about %s of its %d blocks in the last %s", who, pct(share), limited, w.length())
	}),
	"autopilot_enforced":         autopilotCheck,
	"autopilot_rolled_back":      autopilotCheck,
	"autopilot_budget_exhausted": autopilotCheck,
	"autopilot_agent_down":       autopilotCheck,
	"autopilot_needs_person":     autopilotCheck,
	"autopilot_note_contested":   autopilotCheck,
}

// autopilotCheck is an autopilot signal. Its phase is no rule's, so the
// traffic checks never evaluate it; autopilotFindings does.
var autopilotCheck = notifyCheck{phases: []string{autopilotPhase}, ok: func(NotifySignal) bool { return true }}

const autopilotPhase = "autopilot"

var notifyNames = slices.Sorted(maps.Keys(notifyChecks))

// shareCheck trips when a share of all requests is over factor times its
// share in the baseline and over the floor.
func shareCheck(what string, get func(*edge.Totals) (uint64, uint64)) func(NotifySignal, *span, *span, string) (bool, string) {
	return func(s NotifySignal, w, b *span, _ string) (bool, string) {
		wn, wd := get(&w.Totals)
		bn, bd := get(&b.Totals)
		now, before := ratio(wn, wd), ratio(bn, bd)
		return wd >= s.MinRequests && wn >= s.MinEvents && now > max(s.Floor, s.Factor*before),
			fmt.Sprintf("%s: %s of requests in the last %s, against %s in the %s before", what, pct(now), w.length(), pct(before), b.length())
	}
}

// outcomeShare is shareCheck for the requests one rule matched. The rule's
// share must also be over factor times the fleet's share in the same
// window: a rise every rule shares, such as an upstream outage, notifies
// once as the fleet signal, while one concentrated on the rule still
// notifies here.
func outcomeShare(what string, get func(*edge.RuleOutcome) uint64, fleet func(*edge.Totals) uint64) func(NotifySignal, *span, *span, string) (bool, string) {
	return func(s NotifySignal, w, b *span, id string) (bool, string) {
		wo, bo := w.outcome(id), b.outcome(id)
		now, before, all := ratio(get(&wo), wo.Matched), ratio(get(&bo), bo.Matched), ratio(fleet(&w.Totals), w.Requests)
		return wo.Matched >= s.MinRequests && get(&wo) >= s.MinEvents && now > max(s.Floor, s.Factor*before, s.Factor*all),
			fmt.Sprintf("%s %s in the last %s, against %s in the %s before and %s of all requests", pct(now), what, w.length(), pct(before), b.length(), pct(all))
	}
}

func pct(v float64) string { return fmt.Sprintf("%.1f%%", 100*v) }

func (n NotifySettings) problems() []expr.Issue {
	var errs []expr.Issue
	add := func(p, m string) { errs = append(errs, expr.Issue{Path: p, Msg: m}) }
	// Whole minutes: stats are kept per minute, and a span of part of one
	// scales its counts wrong.
	if n.Window < snapshot.Duration(time.Minute) || n.Window > snapshot.Duration(time.Hour) || time.Duration(n.Window)%time.Minute != 0 {
		add("window", "window must be whole minutes from 1m to 1h")
	}
	if n.Baseline < n.Window || n.Baseline > snapshot.Duration(24*time.Hour) || time.Duration(n.Baseline)%time.Minute != 0 {
		add("baseline", "baseline must be whole minutes, at least the window and at most 24h")
	}
	if n.FireAfter < 1 || n.FireAfter > 60 || n.ResolveAfter < 1 || n.ResolveAfter > 60 {
		add("fire_after", "fire_after and resolve_after must be 1 to 60 checks")
	}
	signal := func(path, name string, s NotifySignal) {
		c, ok := notifyChecks[name]
		switch {
		case !ok:
			add(path, "unknown signal")
		case s.Mode != "notify" && s.Mode != "off":
			add(path+".mode", "must be notify or off")
		case s.Mode == "off":
		case s.Severity != "critical" && s.Severity != "warning" && s.Severity != "info":
			add(path+".severity", "must be critical, warning or info")
		case !c.ok(s):
			add(path, "needs "+c.needs)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(n.Signals)) {
		signal("signals."+name, name, n.Signals[name])
	}
	for _, name := range notifyNames {
		if _, ok := n.Signals[name]; !ok {
			add("signals."+name, "is required; set mode off to turn it off")
		}
	}
	if len(n.Rules) > snapshot.MaxListLen*3 {
		add("rules", fmt.Sprintf("at most %d rules", snapshot.MaxListLen*3))
	}
	for _, id := range slices.Sorted(maps.Keys(n.Rules)) {
		if id == "" || len(id) > 64 {
			add("rules", "rule IDs must be 1 to 64 characters")
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(n.Rules[id])) {
			if c, ok := notifyChecks[name]; ok && slices.Equal(c.phases, fleetOnly) {
				add("rules."+id+"."+name, "is a fleet signal; it can't be set per rule")
				continue
			}
			signal("rules."+id+"."+name, name, n.Rules[id][name])
		}
	}
	return errs
}

// signalFor is the settings a signal uses for a rule: the rule's own, or
// the default.
func (n NotifySettings) signalFor(id, name string) NotifySignal {
	if s, ok := n.Rules[id][name]; ok {
		return s
	}
	return n.Signals[name]
}

func loadNotify(ctx context.Context, q querier) (NotifySettings, error) {
	n := defaultNotify()
	var b []byte
	err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key = 'notifications'").Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return n, nil
	}
	if err != nil {
		return n, err
	}
	// Rules is replaced, not merged, so a removed override stays removed.
	n.Rules = nil
	err = json.Unmarshal(b, &n)
	if n.Rules == nil {
		n.Rules = map[string]map[string]NotifySignal{}
	}
	return n, err
}

// span is the stats of every version over a time range, summed.
type span struct {
	minutes int
	edge.Totals
	limits   map[string]*edge.RuleCounts
	outcomes map[string]*edge.RuleOutcome
	// live is the requests of the minutes and versions whose reports
	// list each rule. Edges list every rule of their version, matched or
	// not, so a rule missing from a report was not live there.
	live map[string]uint64
	// top is each rate-limit rule's blocks by subject key, with the
	// subject's display name.
	top map[string]map[string]*edge.TopCount
}

func newSpan(minutes int) *span {
	return &span{minutes: minutes, limits: map[string]*edge.RuleCounts{}, outcomes: map[string]*edge.RuleOutcome{}, live: map[string]uint64{},
		top: map[string]map[string]*edge.TopCount{}}
}

func (s *span) add(r statsRow) {
	addTotals(&s.Totals, r.Totals)
	// Rule IDs are unique across phases and a row lists each once.
	for _, rc := range r.RateLimit {
		s.live[rc.ID] += r.Requests
		if s.limits[rc.ID] == nil {
			s.limits[rc.ID] = &edge.RuleCounts{ID: rc.ID}
		}
		addRule(s.limits[rc.ID], rc)
	}
	for _, ro := range r.Rules {
		s.live[ro.ID] += r.Requests
		if s.outcomes[ro.ID] == nil {
			s.outcomes[ro.ID] = &edge.RuleOutcome{Phase: ro.Phase, ID: ro.ID}
		}
		addOutcome(s.outcomes[ro.ID], ro)
	}
	for _, t := range r.TopLimited {
		if s.top[t.Rule] == nil {
			s.top[t.Rule] = map[string]*edge.TopCount{}
		}
		if e := s.top[t.Rule][t.Key]; e != nil {
			e.Limited += t.Limited
		} else {
			tc := t
			s.top[t.Rule][t.Key] = &tc
		}
	}
}

// length is the span's length in words, such as "5 minutes" or "hour".
func (s *span) length() string {
	n, unit := s.minutes, "minute"
	if n%60 == 0 {
		n, unit = n/60, "hour"
	}
	if n == 1 {
		return unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// scaled is n, counted over s, scaled to w's length.
func (s *span) scaled(w *span, n uint64) float64 {
	return float64(n) * float64(w.minutes) / float64(s.minutes)
}

func (s *span) limit(id string) edge.RuleCounts {
	if r := s.limits[id]; r != nil {
		return *r
	}
	return edge.RuleCounts{}
}

// blocking is a rule's refusals as rate-limit counts. A config rule checks
// every request while it is live, so its evaluated count is the requests of
// the minutes and versions that list it.
func (s *span) blocking(id string) edge.RuleCounts {
	if o := s.outcomes[id]; o != nil && o.Phase == string(expr.PhaseConfig) {
		return edge.RuleCounts{ID: id, Evaluated: s.live[id], Limited: o.Blocked, WouldLimit: o.WouldBlock}
	}
	return s.limit(id)
}

func (s *span) outcome(id string) edge.RuleOutcome {
	if o := s.outcomes[id]; o != nil {
		return *o
	}
	return edge.RuleOutcome{}
}

// matched is the requests a rule of any phase matched.
func (s *span) matched(id string) uint64 {
	return s.limit(id).Evaluated + s.outcome(id).Matched
}

// expected is the matches a rule would have in n requests at its share of
// the requests s served while it was live, so a fleet-wide change in
// traffic moves it too and notifies once, as traffic_surge or traffic_drop,
// and a rule published partway through s, or only on a canary, is judged
// by its own minutes and versions.
func (s *span) expected(id string, n uint64) float64 {
	return ratio(s.matched(id), s.live[id]) * float64(n)
}

func (s *span) topSubject(id string) (string, uint64) {
	var best *edge.TopCount
	for _, t := range s.top[id] {
		if best == nil || t.Limited > best.Limited || t.Limited == best.Limited && t.Key < best.Key {
			best = t
		}
	}
	if best == nil {
		return "", 0
	}
	return best.Display, best.Limited
}

// finding is one check of one signal for one subject.
type finding struct {
	Signal, Rule, Phase, Severity, Summary string
	Tripped                                bool
}

// subject is a rule the live versions have, or the fleet (ID "").
type subject struct{ ID, Phase string }

// liveRules lists every rule of the active and canary versions.
func (s *Server) liveRules(ctx context.Context) ([]subject, error) {
	rows, err := s.db.Query(ctx, "SELECT config FROM config_versions WHERE status IN ('active', 'canary')")
	if err != nil {
		return nil, err
	}
	cs, err := pgx.CollectRows(rows, pgx.RowTo[snapshot.Config])
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []subject
	add := func(id string, p expr.Phase) {
		if !seen[id] {
			seen[id] = true
			out = append(out, subject{id, string(p)})
		}
	}
	for _, c := range cs {
		for _, r := range c.ConfigRules {
			add(r.ID, expr.PhaseConfig)
		}
		for _, r := range c.RateLimitRules {
			add(r.ID, expr.PhaseRateLimit)
		}
		for _, r := range c.RequestHeaderRules {
			add(r.ID, expr.PhaseRequestHeaders)
		}
	}
	return out, nil
}

// ownTransition reports a signal an autopilot rule trips by design: it
// starts blocking after logging only, and stops matching when the attack
// ends. autopilot_enforced and autopilot_rolled_back report those.
func ownTransition(rule, signal string) bool {
	return strings.HasPrefix(rule, overlayPrefix) && (signal == "rule_block_spike" || signal == "rule_stopped_matching")
}

// evaluateNotify runs every signal that is on against w and b.
func evaluateNotify(n NotifySettings, w, b *span, rules []subject) []finding {
	var out []finding
	for _, sub := range append([]subject{{}}, rules...) {
		for _, name := range notifyNames {
			c := notifyChecks[name]
			sig := n.signalFor(sub.ID, name)
			if sig.Mode != "notify" || !slices.Contains(c.phases, sub.Phase) || ownTransition(sub.ID, name) {
				continue
			}
			tripped, summary := c.check(sig, w, b, sub.ID)
			out = append(out, finding{Signal: name, Rule: sub.ID, Phase: sub.Phase, Severity: sig.Severity, Summary: summary, Tripped: tripped})
		}
	}
	return out
}

// anomaly is one row of the anomalies table.
type anomaly struct {
	ID         int64      `json:"id"`
	Signal     string     `json:"signal"`
	Rule       string     `json:"rule"`
	Phase      string     `json:"phase"`
	Severity   string     `json:"severity"`
	State      string     `json:"state"`
	Tripped    int        `json:"tripped"`
	Passed     int        `json:"passed"`
	StartedAt  time.Time  `json:"started_at"`
	FiredAt    *time.Time `json:"fired_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
	NotifiedAt *time.Time `json:"notified_at"`
	Summary    string     `json:"summary"`
}

const anomalyCols = "id, signal, rule, phase, severity, state, tripped, passed, started_at, fired_at, resolved_at, notified_at, summary"

// notifyLag leaves out minutes edges may still be reporting: they report
// every 10s and admin writes every 10s.
const notifyLag = 30 * time.Second

// runNotify checks every signal and moves anomalies through pending,
// firing and resolved, then sends the firing and recently resolved ones to
// Alertmanager. The leader runs it every minute.
func (s *Server) runNotify(ctx context.Context) error {
	if err := s.checkAnomalies(ctx); err != nil {
		// Gauges from the last good check would look current while it fails.
		s.met.gauges.Store(nil)
		return err
	}
	return s.sendAnomalies(ctx)
}

// checkAnomalies records one round of findings and refreshes the leader's
// gauges from it.
func (s *Server) checkAnomalies(ctx context.Context) error {
	n, err := loadNotify(ctx, s.db)
	if err != nil {
		return err
	}
	var found []finding
	if n.Enabled {
		if found, err = s.findAnomalies(ctx, n); err != nil {
			return err
		}
	}
	if err := s.recordAnomalies(ctx, n, found); err != nil {
		return err
	}
	return s.refreshLeaderGauges(ctx)
}

func (s *Server) findAnomalies(ctx context.Context, n NotifySettings) ([]finding, error) {
	end := s.now().Add(-notifyLag).UTC().Truncate(time.Minute)
	from := end.Add(-time.Duration(n.Window))
	rows, err := s.statsWhere(ctx, s.db, "minute >= $1 AND minute < $2", from.Add(-time.Duration(n.Baseline)), end)
	if err != nil {
		return nil, err
	}
	w, b := newSpan(int(time.Duration(n.Window)/time.Minute)), newSpan(int(time.Duration(n.Baseline)/time.Minute))
	for _, r := range rows {
		if r.Minute.Before(from) {
			b.add(r)
		} else {
			w.add(r)
		}
	}
	rules, err := s.liveRules(ctx)
	if err != nil {
		return nil, err
	}
	ap, err := s.autopilotFindings(ctx, n)
	return append(evaluateNotify(n, w, b, rules), ap...), err
}

// autopilotFindings are the autopilot's signals in effect now. Each is
// found again on every check while it holds; when it stops, its anomaly
// has no finding and resolves.
func (s *Server) autopilotFindings(ctx context.Context, n NotifySettings) ([]finding, error) {
	set, err := loadAutopilot(ctx, s.db)
	if err != nil || set.Mode == "off" {
		return nil, err
	}
	now := s.now()
	var out []finding
	add := func(signal, rule, summary string) {
		if sig := n.signalFor(rule, signal); sig.Mode == "notify" {
			out = append(out, finding{Signal: signal, Rule: rule, Phase: autopilotPhase, Severity: sig.Severity, Summary: summary, Tripped: true})
		}
	}
	// No LIMIT: a rule that dropped out would resolve while it still holds.
	// max_enforcing and the hour's rollbacks of those rules bound the rows.
	rows, err := s.db.Query(ctx, `SELECT id, state FROM autopilot_rules WHERE state = 'enforcing' OR state = 'rolled_back' AND ended_at > $1 ORDER BY id`, now.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	var id, state string
	if _, err := pgx.ForEachRow(rows, []any{&id, &state}, func() error {
		if state == "enforcing" {
			add("autopilot_enforced", id, "An autopilot rule is blocking")
		} else {
			add("autopilot_rolled_back", id, "The guard rolled back an autopilot rule that blocked too much")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	rs, err := s.runners(ctx, s.db)
	if err != nil {
		return nil, err
	}
	var ever bool
	if err := s.db.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_runners)").Scan(&ever); err != nil {
		return nil, err
	}
	if live, _ := s.connected(rs); len(live) == 0 && ever {
		add("autopilot_agent_down", "", "No autopilot runner has been seen in the last 2 minutes; autopilot rules still expire on the edges")
	}
	u, err := s.autopilotUsage(ctx, s.db)
	if err != nil {
		return nil, err
	}
	// A full budget is news only when it held work back: a proposal it
	// refused in the last hour, or a case waiting for the hour's runs. A
	// full sensor budget alone is normal, since sensors renew. min picks
	// budget_enforcing first, the one that can leave an attack unblocked.
	var refused string
	if err := s.db.QueryRow(ctx, `SELECT COALESCE(min(c->>'name'), '') FROM autopilot_proposals p, jsonb_array_elements(p.checks) c
		WHERE NOT p.accepted AND p.created_at > $1 AND c->>'name' IN ('budget_enforcing', 'budget_sensors') AND c->>'ok' = 'false'`, now.Add(-time.Hour)).Scan(&refused); err != nil {
		return nil, err
	}
	var queued bool
	if err := s.db.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_cases WHERE state = 'queued')").Scan(&queued); err != nil {
		return nil, err
	}
	switch {
	case refused == "budget_enforcing":
		add("autopilot_budget_exhausted", "", fmt.Sprintf("The enforcing budget refused a proposal in the last hour (%d of %d in use)", u.Enforcing, set.MaxEnforcing))
	case refused == "budget_sensors":
		add("autopilot_budget_exhausted", "", fmt.Sprintf("The sensors budget refused a proposal in the last hour (%d of %d in use)", u.Sensors, set.MaxSensors))
	case queued && u.CasesHour >= set.CasesPerHour:
		add("autopilot_budget_exhausted", "", fmt.Sprintf("The cases_hour budget is used up (%d of %d); a case waits", u.CasesHour, set.CasesPerHour))
	}
	// An attack needs a person when no enforce proposal on its case was
	// accepted, or one was but observe mode waits for approval. A case on an
	// autopilot rule that already enforces does not: that rule blocks it, and
	// the duplicate check refuses a second one. Nor does a case whose own
	// enforce rule a person approved or that enforces now. No LIMIT: a case
	// that dropped out would resolve while it still needs a person, and the
	// hour bounds the rows, since cases close after runs and cases_per_hour
	// allows at most 200 runs an hour.
	rows, err = s.db.Query(ctx, `SELECT c.id, c.state, c.verdict, p.accepted FROM autopilot_cases c
		CROSS JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM autopilot_proposals p WHERE p.case_id = c.id AND p.action = 'enforce' AND p.accepted) AS accepted) p
		WHERE c.closed_at > $1 AND (c.state = 'failed' OR c.verdict = 'unsure'
			OR c.verdict = 'attack' AND (NOT p.accepted OR $2 <> 'auto')
				AND NOT EXISTS (SELECT 1 FROM autopilot_rules r WHERE (r.id = c.rule OR r.case_id = c.id)
					AND (r.enforcing_since IS NOT NULL OR r.approved_by IS NOT NULL) AND r.ended_at IS NULL))
		ORDER BY c.id DESC`, now.Add(-time.Hour), set.Mode)
	if err != nil {
		return nil, err
	}
	var caseID int64
	var verdict *string
	var accepted bool
	if _, err := pgx.ForEachRow(rows, []any{&caseID, &state, &verdict, &accepted}, func() error {
		why := "The autopilot was unsure; a person needs to look"
		switch {
		case state == "failed":
			why = "The autopilot runner did not finish the case; a person needs to look"
		case verdict != nil && *verdict == "attack" && accepted:
			why = "The autopilot found an attack; its enforce rule waits for a person's approval"
		case verdict != nil && *verdict == "attack":
			why = "The autopilot found an attack but none of its rules was accepted; a person needs to look"
		}
		add("autopilot_needs_person", fmt.Sprintf("case %d", caseID), why)
		return nil
	}); err != nil {
		return nil, err
	}
	// Contests come from re-run cases, so the same budget bounds these rows.
	rows, err = s.db.Query(ctx, `SELECT DISTINCT note_id FROM autopilot_note_revisions WHERE change = 'contested' AND at > $1 ORDER BY note_id`, now.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	var note int64
	if _, err := pgx.ForEachRow(rows, []any{&note}, func() error {
		add("autopilot_note_contested", fmt.Sprintf("note %d", note), "A case re-run without an autopilot note got another verdict, so the note is unconfirmed again")
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// recordAnomalies applies one round of findings. An open anomaly with no
// finding (its rule was removed, its signal turned off) passes at once.
func (s *Server) recordAnomalies(ctx context.Context, n NotifySettings, found []finding) error {
	return dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT "+anomalyCols+" FROM anomalies WHERE state <> 'resolved' FOR UPDATE")
		if err != nil {
			return err
		}
		open, err := pgx.CollectRows(rows, pgx.RowToStructByPos[anomaly])
		if err != nil {
			return err
		}
		byKey := map[[2]string]*anomaly{}
		for i := range open {
			byKey[[2]string{open[i].Signal, open[i].Rule}] = &open[i]
		}
		now := s.now()
		for _, f := range found {
			key := [2]string{f.Signal, f.Rule}
			a := byKey[key]
			delete(byKey, key)
			switch {
			case a == nil && f.Tripped:
				a = &anomaly{Signal: f.Signal, Rule: f.Rule, Phase: f.Phase, State: "pending", StartedAt: now}
				err = tx.QueryRow(ctx, `INSERT INTO anomalies (signal, rule, phase, severity, state, tripped, passed, started_at, summary, details)
					VALUES ($1, $2, $3, $4, 'pending', 0, 0, $5, $6, '{}') RETURNING id`, f.Signal, f.Rule, f.Phase, f.Severity, now, f.Summary).Scan(&a.ID)
				if err == nil {
					err = s.trip(ctx, tx, n, a, f, now)
				}
			case a == nil:
			case f.Tripped:
				err = s.trip(ctx, tx, n, a, f, now)
			default:
				err = s.pass(ctx, tx, n.ResolveAfter, a, now)
			}
			if err != nil {
				return err
			}
		}
		for _, a := range byKey {
			if err := s.pass(ctx, tx, 1, a, now); err != nil {
				return err
			}
		}
		return nil
	}))
}

// trip counts a tripped check and fires the anomaly after fire_after.
func (s *Server) trip(ctx context.Context, tx pgx.Tx, n NotifySettings, a *anomaly, f finding, now time.Time) error {
	a.Tripped++
	// Severity labels the Alertmanager alert, so it is kept once the alert
	// fires: a new value would start a second alert and orphan the first.
	if a.State == "pending" {
		a.Severity = f.Severity
	}
	fire := a.State == "pending" && a.Tripped >= n.FireAfter
	if fire {
		a.State, a.FiredAt = "firing", &now
	}
	if _, err := tx.Exec(ctx, "UPDATE anomalies SET state = $2, tripped = $3, passed = 0, fired_at = $4, severity = $5, summary = $6 WHERE id = $1",
		a.ID, a.State, a.Tripped, a.FiredAt, a.Severity, f.Summary); err != nil || !fire {
		return err
	}
	s.log.Warn("anomaly firing", "signal", a.Signal, "rule", a.Rule, "summary", f.Summary)
	return s.auditAnomaly(ctx, tx, "anomaly.fire", a, f.Summary)
}

// pass counts a passed check. A pending anomaly never notified, so it is
// dropped; a firing one resolves after resolveAfter.
func (s *Server) pass(ctx context.Context, tx pgx.Tx, resolveAfter int, a *anomaly, now time.Time) error {
	if a.State == "pending" {
		_, err := tx.Exec(ctx, "DELETE FROM anomalies WHERE id = $1", a.ID)
		return err
	}
	a.Passed++
	resolve := a.Passed >= resolveAfter
	if resolve {
		a.State, a.ResolvedAt = "resolved", &now
	}
	if _, err := tx.Exec(ctx, "UPDATE anomalies SET state = $2, passed = $3, resolved_at = $4 WHERE id = $1", a.ID, a.State, a.Passed, a.ResolvedAt); err != nil || !resolve {
		return err
	}
	s.log.Info("anomaly resolved", "signal", a.Signal, "rule", a.Rule)
	return s.auditAnomaly(ctx, tx, "anomaly.resolve", a, a.Summary)
}

func (s *Server) auditAnomaly(ctx context.Context, tx pgx.Tx, action string, a *anomaly, summary string) error {
	target := "fleet"
	if a.Rule != "" {
		target = "rule " + a.Rule
	}
	return admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: "system:notifications", Action: action, Target: target,
		Details: map[string]any{"anomaly": a.ID, "signal": a.Signal, "summary": summary}})
}

// triageHold is how long a non-critical anomaly the autopilot is
// investigating waits for its verdict before it is sent anyway.
// ponytail: a constant; make it a notification setting if 10m proves wrong.
const triageHold = 10 * time.Minute

// triagedAnomaly is an anomaly with the newest autopilot case opened for it.
type triagedAnomaly struct {
	anomaly
	CaseID      *int64  `json:"case_id"`
	CaseState   *string `json:"case_state"`
	CaseVerdict *string `json:"case_verdict"`
	// Withheld is why admin does not send it: own_rule, investigating or
	// benign. Empty when it is sent.
	Withheld string `json:"withheld" db:"-"`
}

// withheld is why admin does not send an anomaly yet, or "". One already
// sent keeps being sent until it resolves, so Alertmanager sees it end. A
// benign verdict holds back only info: traffic an attacker shapes could
// talk the model into one, so a warning is only delayed for the verdict.
func (a triagedAnomaly) withheld(handles bool, now time.Time) string {
	open := a.CaseState != nil && (*a.CaseState == "queued" || *a.CaseState == "running")
	// A case opens for these on the autopilot's next run, which can come
	// after this send, so one that fired just now waits for it too.
	coming := a.CaseState == nil && slices.Contains(anomalySignals, a.Signal)
	switch {
	case a.NotifiedAt != nil || a.Phase == autopilotPhase:
		return ""
	// An autopilot rule's would-block and dominant-subject anomalies are its
	// own input: it opens a case from them and notifies what it concludes.
	// A critical one is sent at once.
	case handles && strings.HasPrefix(a.Rule, overlayPrefix) && a.Severity != "critical" && slices.Contains(overlaySignals, a.Signal):
		return "own_rule"
	case handles && a.CaseVerdict != nil && *a.CaseVerdict == "benign" && a.Severity == "info":
		return "benign"
	case handles && (open || coming) && a.Severity != "critical" && a.FiredAt != nil && now.Sub(*a.FiredAt) < triageHold:
		return "investigating"
	}
	return ""
}

// autopilotHandles says whether the autopilot is on with a runner
// connected, so it works the anomalies it opens cases for.
func (s *Server) autopilotHandles(ctx context.Context) (bool, error) {
	set, err := loadAutopilot(ctx, s.db)
	if err != nil || set.Mode == "off" {
		return false, err
	}
	rs, err := s.runners(ctx, s.db)
	if err != nil {
		return false, err
	}
	live, _ := s.connected(rs)
	return len(live) > 0, nil
}

// triaged lists the anomalies matching cond, which may end in ORDER BY and
// LIMIT, ordered by order, each with its newest case and why it is
// withheld.
func (s *Server) triaged(ctx context.Context, cond, order string, args ...any) ([]triagedAnomaly, error) {
	handles, err := s.autopilotHandles(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT a.*, c.id, c.state, c.verdict FROM (SELECT `+anomalyCols+` FROM anomalies WHERE `+cond+`) a
		LEFT JOIN LATERAL (SELECT id, state, verdict FROM autopilot_cases WHERE anomaly_id = a.id ORDER BY id DESC LIMIT 1) c ON true
		ORDER BY a.`+order, args...)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[triagedAnomaly])
	if err != nil {
		return nil, err
	}
	now := s.now()
	for i := range list {
		list[i].Withheld = list[i].withheld(handles, now)
	}
	return list, nil
}

// verdictLine is a closed case's number and verdict. The summary stays
// out: the model writes it after reading client-controlled traffic.
func verdictLine(a triagedAnomaly) string {
	return fmt.Sprintf("Autopilot case %d: %s.", *a.CaseID, *a.CaseVerdict)
}

// resolvedResend is how long a resolved anomaly is still sent, so
// Alertmanager sends its resolved notification even after a restart.
const resolvedResend = 5 * time.Minute

// amAlert is an alert in Alertmanager's API v2.
type amAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
}

// sendAnomalies posts every firing anomaly, and those resolved within
// resolvedResend, to Alertmanager. Alertmanager expects firing alerts to be
// sent again until they resolve
// (https://prometheus.io/docs/alerting/latest/alerts_api/); an endsAt three
// checks ahead keeps one missed send from resolving them. A failed send is
// logged and left to the next check: nothing queues.
func (s *Server) sendAnomalies(ctx context.Context) error {
	if s.cfg.AlertmanagerURL == "" {
		return nil
	}
	now := s.now()
	// A resolved anomaly is sent only if its firing was: Alertmanager has
	// nothing to resolve otherwise.
	list, err := s.triaged(ctx, "state = 'firing' OR state = 'resolved' AND resolved_at > $1 AND notified_at IS NOT NULL", "id", now.Add(-resolvedResend))
	if err != nil {
		return err
	}
	alerts := make([]amAlert, 0, len(list))
	ids := make([]int64, 0, len(list))
	for _, a := range list {
		if a.Withheld != "" {
			continue
		}
		labels := map[string]string{"alertname": alertName(a.Signal), "service": "edge-proxy", "signal": a.Signal, "severity": a.Severity}
		if a.Rule != "" {
			labels["rule"], labels["phase"] = a.Rule, a.Phase
		}
		end := now.Add(3 * time.Minute)
		if a.ResolvedAt != nil {
			end = *a.ResolvedAt
		}
		// The verdict goes in the description, which a relay to chat shows;
		// an annotation it doesn't know may be dropped.
		desc := a.Summary
		if a.CaseVerdict != nil {
			desc += "\n" + verdictLine(a)
		}
		alerts = append(alerts, amAlert{Labels: labels, StartsAt: *a.FiredAt, EndsAt: end,
			Annotations: map[string]string{"summary": a.title(), "description": desc}})
		ids = append(ids, a.ID)
	}
	if len(alerts) == 0 {
		return nil
	}
	body, _ := json.Marshal(alerts) // amAlert has only marshalable fields
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.cfg.AlertmanagerURL, "/")+"/api/v2/alerts", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.alertClient.Do(req)
	if err != nil {
		if ctx.Err() == nil { // stepping down is not a failed send
			s.met.notifyFailed.Add(1)
		}
		return fmt.Errorf("alertmanager: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		s.met.notifyFailed.Add(1)
		return fmt.Errorf("alertmanager answered %d", resp.StatusCode)
	}
	s.met.notifySent.Add(1)
	_, err = s.db.Exec(ctx, "UPDATE anomalies SET notified_at = $1 WHERE id = ANY($2)", now, ids)
	return err
}

// alertName is the signal in Alertmanager's alert-name style:
// rule_block_spike is EdgeProxyRuleBlockSpike.
func alertName(signal string) string {
	var b strings.Builder
	b.WriteString("EdgeProxy")
	for w := range strings.SplitSeq(signal, "_") {
		b.WriteString(strings.ToUpper(w[:1]) + w[1:])
	}
	return b.String()
}

var signalTitles = map[string]string{
	"traffic_drop":               "Traffic dropped",
	"traffic_surge":              "Traffic surged",
	"edge_5xx_ratio":             "More 5xx from the edge",
	"upstream_5xx_ratio":         "More 5xx from the upstream",
	"auth_failure_ratio":         "More failed token checks",
	"p99_latency":                "p99 latency rose",
	"rule_stopped_matching":      "Rule stopped matching",
	"rule_match_surge":           "Rule matches surged",
	"rule_edge_5xx_ratio":        "More 5xx from the edge on a rule",
	"rule_upstream_5xx_ratio":    "More 5xx from the upstream on a rule",
	"rule_auth_failure_ratio":    "More failed token checks on a rule",
	"rule_block_spike":           "Rule blocking more",
	"rule_would_block":           "Log-only rule would block",
	"rule_fail_mode":             "Rule in fail mode",
	"rule_subject_dominates":     "One client gets most of a rule's blocks",
	"autopilot_enforced":         "An autopilot rule is blocking",
	"autopilot_rolled_back":      "An autopilot rule was rolled back",
	"autopilot_budget_exhausted": "An autopilot budget is used up",
	"autopilot_agent_down":       "The autopilot runner is down",
	"autopilot_needs_person":     "An autopilot case needs a person",
	"autopilot_note_contested":   "An autopilot note was contested",
}

func (a anomaly) title() string {
	if a.Rule == "" {
		return "Edge proxy: " + signalTitles[a.Signal]
	}
	return fmt.Sprintf("Edge proxy: %s (%s)", signalTitles[a.Signal], a.Rule)
}

func (s *Server) notifyRoutes() {
	s.handle("GET /api/settings/notifications", "config.read", func(w http.ResponseWriter, r *http.Request, _ *principal) error {
		n, err := loadNotify(r.Context(), s.db)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, n)
	})
	s.handle("PUT /api/settings/notifications", "settings.manage", func(w http.ResponseWriter, r *http.Request, p *principal) error {
		var n NotifySettings
		if err := readJSON(w, r, &n); err != nil {
			return err
		}
		if n.Rules == nil {
			n.Rules = map[string]map[string]NotifySignal{}
		}
		if errs := n.problems(); errs != nil {
			return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid notification settings", Errors: errs}
		}
		ctx := r.Context()
		err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
			before, err := loadNotify(ctx, tx)
			if err != nil {
				return admindb.Event{}, err
			}
			_, err = tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('notifications', $1, $2)
				ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = $2`, n, s.now())
			return admindb.Event{Action: "settings.notifications", Details: map[string]any{"before": before, "after": n}}, err
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
	s.handle("GET /api/anomalies", "stats.read", s.listAnomalies)
}

func (s *Server) listAnomalies(w http.ResponseWriter, r *http.Request, _ *principal) error {
	list, err := s.triaged(r.Context(), "state <> 'resolved' OR resolved_at > $1 ORDER BY started_at DESC, id LIMIT 200", "started_at DESC, a.id", s.now().Add(-7*24*time.Hour))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"alertmanager": s.cfg.AlertmanagerURL != "", "anomalies": orEmpty(list)})
}
