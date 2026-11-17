package admin

import (
	"context"
	"math"
	"slices"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// signalDays is how many previous days a signal's baseline reads, and
// minSignalDays how many of them must have data before it is used.
const (
	signalDays    = 7
	minSignalDays = 3
)

// signalScoped returns the client signals n requires, as groups of which a
// request must carry at least one: an eq condition is a group of one, an in
// list is one group, and ANDed conditions give several groups. Conditions
// count when positive and direct or in a positive "and" group. A negated
// condition or an "or" requires no signal.
func signalScoped(n expr.Node) [][]string {
	if !n.IsGroup() {
		if n.Field != expr.SignalsField {
			return nil
		}
		switch n.Operator {
		case "eq":
			return [][]string{{n.Value.One}}
		case "in":
			return [][]string{slices.Clone(n.Value.List)}
		}
		return nil
	}
	if n.Combinator != "and" || n.Not {
		return nil
	}
	var out [][]string
	for _, c := range n.Rules {
		out = append(out, signalScoped(c)...)
	}
	return out
}

// sharedScope is the stat indexes of the signal groups a shared-key rule is
// scoped to, or nil when the rule is not one: a shared key whose expression
// requires no signal would limit every client on the bucket.
func sharedScope(r snapshot.RateLimitRule) [][]int {
	if !snapshot.SharedKey(r.Key) {
		return nil
	}
	var out [][]int
	for _, g := range signalScoped(r.Expression) {
		var idx []int
		for _, name := range g {
			if i := slices.IndexFunc(expr.Signals, func(d expr.SignalDef) bool { return d.Name == name }); i >= 0 {
				idx = append(idx, i)
			}
		}
		if idx != nil {
			out = append(out, idx)
		}
	}
	return out
}

// signalBaseline is the median per-minute count of the requests that carry a
// group's signals, over the same clock window on each of the previous 7
// days, summed across replicas and versions. A group matches a request with
// any of its signals, so its minute is the sum of their counts, which
// over-counts a request with several: the safe side for a collateral bound.
// Across groups, which are ANDed, the lowest baseline is used. With fewer
// than 3 days of data a group uses the median over the 60 minutes before
// from. Only rows whose array covers the group's highest index count: rows
// stored before edges reported a signal would read as zero flagged traffic.
// known is false when no group has a qualifying minute, so the baseline is
// unmeasured, not 0. Minutes with no stored row are not counted as zeros,
// which also keeps the baseline high.
func (s *Server) signalBaseline(ctx context.Context, q querier, groups [][]int, from, to time.Time) (perMinute float64, days int, known bool, err error) {
	for _, g := range groups {
		ix := make([]int, len(g)) // 1-based array subscripts
		for k, i := range g {
			ix[k] = i + 1
		}
		hi := slices.Max(ix)
		var d, n int
		var v float64
		err = q.QueryRow(ctx, `SELECT count(DISTINCT k), coalesce(percentile_cont(0.5) WITHIN GROUP (ORDER BY v), 0)::float8 FROM (
				SELECT k, m.minute, sum((SELECT sum(m.client_signals[g]) FROM unnest($3::int[]) g))::float8 v
				FROM generate_series(1, $4::int) k
				JOIN edge_stats_minute m ON m.minute >= $1::timestamptz - k * interval '24 hours' AND m.minute < $2::timestamptz - k * interval '24 hours'
					AND cardinality(m.client_signals) >= $5
				GROUP BY k, m.minute) t`, from, to, ix, signalDays, hi).Scan(&d, &v)
		if err != nil {
			return 0, 0, false, err
		}
		if d < minSignalDays {
			d = 0
			err = q.QueryRow(ctx, `SELECT count(*), coalesce(percentile_cont(0.5) WITHIN GROUP (ORDER BY v), 0)::float8 FROM (
					SELECT sum((SELECT sum(client_signals[g]) FROM unnest($2::int[]) g))::float8 v FROM edge_stats_minute
					WHERE minute >= $1::timestamptz - interval '60 minutes' AND minute < $1::timestamptz AND cardinality(client_signals) >= $3 GROUP BY minute) t`, from, ix, hi).Scan(&n, &v)
			if err != nil {
				return 0, 0, false, err
			}
			if n == 0 {
				continue
			}
		}
		if !known || v < perMinute {
			perMinute, days = v, d
		}
		known = true
	}
	return perMinute, days, known, nil
}

// fleetPerMinute is the fleet's median requests per minute over the 60
// minutes before from.
func (s *Server) fleetPerMinute(ctx context.Context, q querier, from time.Time) (float64, error) {
	var v float64
	err := q.QueryRow(ctx, `SELECT coalesce(percentile_cont(0.5) WITHIN GROUP (ORDER BY v), 0)::float8 FROM (
			SELECT sum(requests)::float8 v FROM edge_stats_minute
			WHERE minute >= $1::timestamptz - interval '60 minutes' AND minute < $1::timestamptz GROUP BY minute) t`, from).Scan(&v)
	return v, err
}

// sharedBound is what a shared-key rule can cost the clients outside the
// attack: the rule's bucket holds the whole fleet on one fingerprint, so
// its limited count is mostly the attack. Only as many requests as the
// signal's normal traffic carries, in each minute the rule limited, are
// counted as collateral.
type sharedBound struct {
	baseline float64
	days     int
	known    bool
	tripped  int
}

// newSharedBound reads the baseline for [from, to) and counts the minutes
// of rows in which the rule had a nonzero count by pick.
func (s *Server) newSharedBound(ctx context.Context, q querier, groups [][]int, id string, rows []statsRow, from, to time.Time, pick func(edge.RuleCounts) uint64) (sharedBound, error) {
	minutes := map[time.Time]bool{}
	for _, r := range rows {
		for _, rc := range r.RateLimit {
			if rc.ID == id && pick(rc) > 0 {
				minutes[r.Minute] = true
			}
		}
	}
	b, days, known, err := s.signalBaseline(ctx, q, groups, from, to)
	return sharedBound{baseline: b, days: days, known: known, tripped: len(minutes)}, err
}

// collateral is n limited requests less what the attack contributed:
// at most the baseline for each minute the rule limited. With no measured
// baseline there is no bound: all n counts.
func (b sharedBound) collateral(n uint64) uint64 {
	if !b.known {
		return n
	}
	return uint64(math.Min(float64(n), float64(b.tripped)*b.baseline))
}

func (b sharedBound) add(numbers map[string]any) {
	numbers["signal_baseline_per_minute"], numbers["baseline_days"], numbers["baseline_known"], numbers["tripped_minutes"] = b.baseline, b.days, b.known, b.tripped
}
