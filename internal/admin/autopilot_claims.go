package admin

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// A note's claim is a predicate over a metric admin keeps, so admin can
// recompute it on its own data whenever the note is written or used.

// noteScope is what a note is about: the fleet, a host or route admin has
// observed, or a live rate-limit rule.
type noteScope struct {
	Kind     string `json:"kind"`
	Host     string `json:"host,omitempty"`
	Method   string `json:"method,omitempty"`
	Template string `json:"template,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

// key names the scope; the per-scope note limit counts by it.
func (sc noteScope) key() string {
	switch sc.Kind {
	case "global":
		return "global"
	case "host":
		return "host:" + sc.Host
	case "route":
		return fmt.Sprintf("route:%s %s %s", sc.Host, sc.Method, sc.Template)
	case "rule":
		return "rule:" + sc.Rule
	}
	return ""
}

// claimWindow is exactly one of the last minutes before now, or the same
// UTC hours every day.
type claimWindow struct {
	LastMinutes int   `json:"last_minutes,omitempty"`
	DailyUTC    []int `json:"daily_utc,omitempty"`
}

func (w claimWindow) minutes() int {
	if w.LastMinutes > 0 {
		return w.LastMinutes
	}
	return (w.DailyUTC[1] - w.DailyUTC[0]) * 60
}

type noteClaim struct {
	Metric string      `json:"metric"`
	Window claimWindow `json:"window"`
	Op     string      `json:"op"`
	Value  float64     `json:"value"`
	// Subject is the IP or CIDR subject_limited counts.
	Subject string `json:"subject,omitempty"`
}

func (c noteClaim) holds(v float64) bool {
	if c.Op == "<=" {
		return v <= c.Value
	}
	return v >= c.Value
}

// noteEffect is what a confirmed note may change, by kind.
type noteEffect struct {
	Key             []string `json:"key,omitempty"`
	MaxBlockShare   float64  `json:"max_block_share,omitempty"`
	RequireJWTClaim bool     `json:"require_jwt_claim,omitempty"`
}

// claimSource is the table and form a metric is read from.
type claimSource int

const (
	fromFleet claimSource = iota // edge_stats_minute totals
	fromRule                     // edge_stats_minute rate_limit[] of the scope's rule
	fromTop                      // edge_stats_minute top_limited, sampled
	fromRoute                    // observed_route_hour
)

type claimMetric struct {
	source claimSource
	scopes []string
}

var claimMetrics = map[string]claimMetric{
	"requests":         {fromFleet, []string{"global"}},
	"auth_failures":    {fromFleet, []string{"global"}},
	"upstream_5xx":     {fromFleet, []string{"global"}},
	"rule_evaluated":   {fromRule, []string{"rule"}},
	"rule_limited":     {fromRule, []string{"rule"}},
	"rule_would_limit": {fromRule, []string{"rule"}},
	// Top subjects are sampled and only those over a limit are kept, so
	// they give lower bounds.
	"rule_subjects":   {fromTop, []string{"rule"}},
	"subject_limited": {fromTop, []string{"rule"}},
	"route_requests":  {fromRoute, []string{"route", "host"}},
	"route_4xx":       {fromRoute, []string{"route", "host"}},
	"route_5xx":       {fromRoute, []string{"route", "host"}},
}

// Claim window bounds: six hours of minutes, and an hour of top subjects,
// which a minute row holds up to 50 of.
const (
	maxClaimMinutes = 360
	maxTopMinutes   = 60
	baselineDays    = 14
)

// claimProblem is why a claim or effect is outside the catalog, or "".
func claimProblem(kind string, sc noteScope, c noteClaim, e *noteEffect, maxShare float64) string {
	m, ok := claimMetrics[c.Metric]
	switch {
	case !ok:
		return fmt.Sprintf("claim.metric %q is not one admin keeps; use one of %s", c.Metric, strings.Join(slices.Sorted(maps.Keys(claimMetrics)), ", "))
	case !slices.Contains(m.scopes, sc.Kind):
		return fmt.Sprintf("claim.metric %s applies to %s scopes", c.Metric, strings.Join(m.scopes, " and "))
	}
	w := c.Window
	switch {
	case (w.LastMinutes != 0) == (w.DailyUTC != nil):
		return "claim.window needs exactly one of last_minutes or daily_utc"
	case w.DailyUTC != nil && (len(w.DailyUTC) != 2 || w.DailyUTC[0] < 0 || w.DailyUTC[0] >= w.DailyUTC[1] || w.DailyUTC[1] > 24):
		return "claim.window.daily_utc is [from, to] in whole UTC hours, 0 <= from < to <= 24"
	case w.LastMinutes < 0 || w.minutes() > maxClaimMinutes:
		return fmt.Sprintf("claim.window is at most %d minutes", maxClaimMinutes)
	case m.source == fromTop && w.minutes() > maxTopMinutes:
		return fmt.Sprintf("claim.window on %s is at most %d minutes", c.Metric, maxTopMinutes)
	case m.source == fromRoute && w.minutes()%60 != 0:
		return "claim.window on a route metric is whole hours"
	}
	switch {
	case c.Op != ">=" && c.Op != "<=":
		return "claim.op is >= or <="
	case m.source == fromTop && c.Op != ">=":
		return fmt.Sprintf("claim.op on %s, a sampled lower bound, is >=", c.Metric)
	case math.IsNaN(c.Value) || math.IsInf(c.Value, 0) || c.Value < 0:
		return "claim.value is a number of at least 0"
	case c.Op == ">=" && c.Value == 0:
		return "claim.value of a >= claim is above 0; every count is at least 0"
	}
	if _, ok := claimSubject(c); (c.Metric == "subject_limited") != ok || c.Subject != "" && !ok {
		return "claim.subject is an IP or CIDR, given for subject_limited only"
	}
	switch kind {
	case "key_preference":
		// Only parts a client can't choose, named as a rule's key names them.
		part := func(k string) bool {
			name, ok := strings.CutPrefix(k, "jwt_claim:")
			return k == "ip" || ok && name != "" && len(name) <= snapshot.MaxNameArg && !expr.HasControl(name) && utf8.ValidString(name)
		}
		if e == nil || len(e.Key) == 0 || len(e.Key) > snapshot.MaxKeyParts || e.MaxBlockShare != 0 || e.RequireJWTClaim || !slices.ContainsFunc(e.Key, part) ||
			slices.ContainsFunc(e.Key, func(k string) bool { return !part(k) }) {
			return fmt.Sprintf("effect of a key_preference is key: 1 to %d key parts, each ip or jwt_claim:<name>", snapshot.MaxKeyParts)
		}
	case "collateral_risk":
		share := e != nil && e.MaxBlockShare != 0
		if e == nil || len(e.Key) > 0 || share == e.RequireJWTClaim || share && (e.MaxBlockShare < 0.001 || e.MaxBlockShare >= maxShare) {
			return fmt.Sprintf("effect of a collateral_risk is one of max_block_share from 0.001 to under max_block_share %s, or require_jwt_claim true", fmtFloat(maxShare))
		}
	default:
		if e != nil {
			return fmt.Sprintf("a %s note has no effect", kind)
		}
	}
	// Its bar applies in its window each day, measured from the window's start.
	if kind == "expected_pattern" && w.DailyUTC == nil {
		return "claim.window of an expected_pattern is daily_utc: the hours the pattern recurs each day"
	}
	return ""
}

// tight reports whether c says something about what admin found, observed,
// rather than holding whatever the traffic does: a floor of at least half
// of it, or a ceiling of at most twice it. Only a tight claim anchors a
// note. The factor of 2 is a choice: a usual day's swing passes it.
func tight(c noteClaim, observed float64) bool {
	if c.Op == "<=" {
		return c.Value <= 2*math.Max(observed, 1)
	}
	return c.Value > 0 && c.Value >= observed/2
}

func claimSubject(c noteClaim) (netip.Prefix, bool) {
	if c.Subject == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(c.Subject); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(c.Subject); err == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), true
	}
	return netip.Prefix{}, false
}

// inside reports whether sub lies inside p.
func inside(p, sub netip.Prefix) bool { return p.Bits() <= sub.Bits() && p.Contains(sub.Addr()) }

// span is the claim's current window at now: the last minutes before it,
// or the latest daily occurrence that ended by it. Route metrics count by
// the hour, so their windows end on one.
func (c noteClaim) span(now time.Time) (time.Time, time.Time) {
	at := now.UTC().Truncate(time.Minute)
	if claimMetrics[c.Metric].source == fromRoute {
		at = now.UTC().Truncate(time.Hour)
	}
	if c.Window.LastMinutes > 0 {
		return at.Add(-time.Duration(c.Window.LastMinutes) * time.Minute), at
	}
	day := at.Truncate(24 * time.Hour)
	if day.Add(time.Duration(c.Window.DailyUTC[1]) * time.Hour).After(at) {
		day = day.Add(-24 * time.Hour)
	}
	return day.Add(time.Duration(c.Window.DailyUTC[0]) * time.Hour), day.Add(time.Duration(c.Window.DailyUTC[1]) * time.Hour)
}

// claimDay is a claim's metric over its window on one day: k days before
// the window evaluated, 0 being the window itself.
type claimDay struct {
	present                     bool
	value                       float64
	requests, subjects, minutes int64
	estimated                   bool
}

// evalClaim reads the claim's metric over [from, to) and the same window on
// each of the days before it.
func (s *Server) evalClaim(ctx context.Context, q querier, sc noteScope, c noteClaim, from, to time.Time, days int) ([]claimDay, error) {
	out := make([]claimDay, days+1)
	m := claimMetrics[c.Metric]
	if m.source == fromRoute {
		rows, err := q.Query(ctx, `SELECT k, count(h.hour), coalesce(sum(h.requests), 0)::bigint, coalesce(sum(h.status[5]), 0)::bigint,
			coalesce(sum(h.status[6]), 0)::bigint, coalesce(sum(h.estimated), 0)::bigint, count(DISTINCT h.hour)
			FROM generate_series(0, $3::int) k
			LEFT JOIN (observed_route_hour h JOIN observed_routes r ON r.id = h.route_id AND r.host = $4 AND ($5 = '' OR r.method = $5 AND r.template = $6))
				ON h.hour >= $1::timestamptz - k * interval '24 hours' AND h.hour < $2::timestamptz - k * interval '24 hours'
			GROUP BY k ORDER BY k`, from, to, days, sc.Host, sc.Method, sc.Template)
		if err != nil {
			return nil, err
		}
		var k int
		var n, requests, c4, c5, est, hours int64
		_, err = pgx.ForEachRow(rows, []any{&k, &n, &requests, &c4, &c5, &est, &hours}, func() error {
			d := claimDay{present: n > 0, requests: requests, minutes: hours * 60, estimated: est > 0}
			d.value = float64(map[string]int64{"route_requests": requests, "route_4xx": c4, "route_5xx": c5}[c.Metric])
			out[k] = d
			return nil
		})
		return out, err
	}
	rows, err := q.Query(ctx, `SELECT k, count(m.minute), coalesce(sum(m.requests), 0)::bigint, coalesce(sum(m.auth_failures), 0)::bigint,
		coalesce(sum(m.upstream_5xx), 0)::bigint, coalesce(sum((e->>'evaluated')::bigint), 0)::bigint, coalesce(sum((e->>'limited')::bigint), 0)::bigint,
		coalesce(sum((e->>'would_limit')::bigint), 0)::bigint, count(DISTINCT m.minute)
		FROM generate_series(0, $4::int) k
		LEFT JOIN edge_stats_minute m ON m.minute >= $1::timestamptz - k * interval '24 hours' AND m.minute < $2::timestamptz - k * interval '24 hours'
		LEFT JOIN LATERAL (SELECT x FROM jsonb_array_elements(m.rate_limit) x WHERE x->>'id' = $3 LIMIT 1) r(e) ON true
		GROUP BY k ORDER BY k`, from, to, sc.Rule, days)
	if err != nil {
		return nil, err
	}
	var k int
	var n, requests, auth, up5xx, evaluated, limited, would, minutes int64
	if _, err := pgx.ForEachRow(rows, []any{&k, &n, &requests, &auth, &up5xx, &evaluated, &limited, &would, &minutes}, func() error {
		d := claimDay{present: n > 0, requests: requests, minutes: minutes}
		switch m.source {
		case fromFleet:
			d.value = float64(map[string]int64{"requests": requests, "auth_failures": auth, "upstream_5xx": up5xx}[c.Metric])
		default:
			d.requests = evaluated
			d.value = float64(map[string]int64{"rule_evaluated": evaluated, "rule_limited": limited, "rule_would_limit": would}[c.Metric])
		}
		d.estimated = m.source == fromTop
		out[k] = d
		return nil
	}); err != nil {
		return nil, err
	}
	if m.source != fromTop {
		return out, nil
	}
	// Each key's limited count is at least what the edge counted for it
	// less the error it inherited from the keys it displaced. OFFSET 0 keeps
	// the planner from flattening the per-day subquery: flattened, it can
	// expand the top subjects of every minute kept before filtering by
	// day, which over 15 days of 1,000 subjects a row takes seconds.
	rows, err = q.Query(ctx, `SELECT k, max(t->>'display'), sum((t->>'limited')::bigint + coalesce((t->>'would_limit')::bigint, 0)
			- least(coalesce((t->>'err')::bigint, 0), (t->>'limited')::bigint + coalesce((t->>'would_limit')::bigint, 0)))::bigint
		FROM generate_series(0, $4::int) k
		CROSS JOIN LATERAL (SELECT top_limited FROM edge_stats_minute
			WHERE minute >= $1::timestamptz - k * interval '24 hours' AND minute < $2::timestamptz - k * interval '24 hours' OFFSET 0) m
		CROSS JOIN LATERAL jsonb_array_elements(m.top_limited) t
		WHERE t->>'rule' = $3 GROUP BY k, t->>'key'`, from, to, sc.Rule, days)
	if err != nil {
		return nil, err
	}
	subject, _ := claimSubject(c)
	var display string
	var bound int64
	_, err = pgx.ForEachRow(rows, []any{&k, &display, &bound}, func() error {
		if bound <= 0 {
			return nil
		}
		out[k].subjects++
		if c.Metric == "rule_subjects" {
			out[k].value++
		} else if p, ok := subjectPrefix(display); ok && inside(subject, p) {
			out[k].value += float64(bound)
		}
		return nil
	})
	return out, err
}

// noteSample is how much data the claim's value stands on.
type noteSample struct {
	Requests int64 `json:"requests"`
	Subjects int64 `json:"subjects"`
	Minutes  int64 `json:"minutes"`
}

// baseline is the claim's metric on the days before, as admin computed it.
type baseline struct {
	Days     int      `json:"days"`
	Present  int      `json:"present"`
	Median   float64  `json:"median"`
	P95      float64  `json:"p95"`
	MAD      float64  `json:"mad"`
	Ratio    float64  `json:"ratio"`
	Z        *float64 `json:"z"`
	HeldDays int      `json:"held_days"`
}

// noteStats is what admin attaches to an observed note when it is written.
type noteStats struct {
	Metric    string     `json:"metric"`
	Precision string     `json:"precision"`
	From      time.Time  `json:"from"`
	To        time.Time  `json:"to"`
	Value     float64    `json:"value"`
	Sample    noteSample `json:"sample"`
	Baseline  *baseline  `json:"baseline"`
	Holds     bool       `json:"holds"`
}

// baselineOf is value against days, the metric on each day present: the
// median (the mean of the two middle values for an even count), p95 by
// nearest rank, the median absolute deviation, the ratio to the median and
// the robust z. With a MAD of 0, z uses the mean absolute deviation; with
// that 0 too, z is 0 at the median and undefined elsewhere.
func baselineOf(value float64, days []float64, held int) *baseline {
	if len(days) == 0 {
		return nil
	}
	sorted := slices.Sorted(slices.Values(days))
	median := func(xs []float64) float64 {
		n := len(xs)
		if n%2 == 1 {
			return xs[n/2]
		}
		return (xs[n/2-1] + xs[n/2]) / 2
	}
	med := median(sorted)
	dev := make([]float64, len(sorted))
	var sum float64
	for i, x := range sorted {
		dev[i] = math.Abs(x - med)
		sum += dev[i]
	}
	slices.Sort(dev)
	b := &baseline{Days: baselineDays, Present: len(days), Median: med, P95: sorted[int(math.Ceil(0.95*float64(len(sorted))))-1],
		MAD: median(dev), Ratio: value / math.Max(med, 1), HeldDays: held}
	var z float64
	switch meanAD := sum / float64(len(dev)); {
	case b.MAD > 0:
		z = (value - med) / (1.4826 * b.MAD)
	case meanAD > 0:
		z = (value - med) / (1.2533 * meanAD)
	case value == med:
		z = 0
	default:
		return b
	}
	b.Z = &z
	return b
}

// statsOf is the stats of a claim evaluated over days: days[0] is its
// window, the rest the days before.
func statsOf(c noteClaim, from, to time.Time, days []claimDay) noteStats {
	cur := days[0]
	st := noteStats{Metric: c.Metric, Precision: "exact", From: from, To: to, Value: cur.value, Holds: cur.present && c.holds(cur.value),
		Sample: noteSample{Requests: cur.requests, Subjects: cur.subjects, Minutes: cur.minutes}}
	if cur.estimated {
		st.Precision = "estimate"
	}
	var vals []float64
	held := 0
	for _, d := range days[1:] {
		if d.present {
			vals = append(vals, d.value)
			if c.holds(d.value) {
				held++
			}
		}
	}
	st.Baseline = baselineOf(cur.value, vals, held)
	return st
}

// matchNow evaluates the claim's current window. A note with no claim, a
// hypothesis, always matches.
func (s *Server) matchNow(ctx context.Context, q querier, n apNote) (bool, *float64, error) {
	if n.Claim == nil {
		return true, nil, nil
	}
	from, to := n.Claim.span(s.now())
	days, err := s.evalClaim(ctx, q, n.Scope, *n.Claim, from, to, 0)
	if err != nil {
		return false, nil, err
	}
	v := days[0].value
	return days[0].present && n.Claim.holds(v), &v, nil
}

// noteLinks are the inputs for links to the admin pages that show the
// claim's data; the UI builds the links.
func noteLinks(sc noteScope, c noteClaim, from, to time.Time) map[string]any {
	l := map[string]any{"page": "stats", "from": from, "to": to, "from_ms": from.UnixMilli(), "to_ms": to.UnixMilli()}
	switch sc.Kind {
	case "route", "host":
		l["page"], l["host"] = "route", sc.Host
		if sc.Kind == "route" {
			l["method"], l["template"] = sc.Method, sc.Template
		}
		if s, ok := strings.CutPrefix(c.Metric, "route_"); ok && s != "requests" {
			l["status"] = s
		}
	case "rule":
		l["page"], l["rule"] = "rule", sc.Rule
	}
	return l
}
