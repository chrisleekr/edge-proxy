package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// GuardSettings configure the rollback guard.
type GuardSettings struct {
	Enabled          bool              `json:"enabled"`
	Window           snapshot.Duration `json:"window"`
	MinRequests      uint64            `json:"min_requests"`
	EvaluateEvery    snapshot.Duration `json:"evaluate_every"`
	MaxAutoRollbacks int               `json:"max_auto_rollbacks_per_publish"`
	// StepMinTime is the least time each canary step runs.
	StepMinTime snapshot.Duration `json:"step_min_time"`
	Signals     map[string]Signal `json:"signals"`
}

// Signal is one guard check. Factor is relative to the baseline; Floor,
// FloorMS, MinRatio and MaxRatio are absolute.
type Signal struct {
	Mode        string            `json:"mode"` // rollback | alert | off
	Factor      float64           `json:"factor,omitempty"`
	Floor       float64           `json:"floor,omitempty"`
	FloorMS     float64           `json:"floor_ms,omitempty"`
	MinRatio    float64           `json:"min_ratio,omitempty"`
	MaxRatio    float64           `json:"max_ratio,omitempty"`
	MaxVsShadow float64           `json:"max_vs_shadow,omitempty"`
	After       snapshot.Duration `json:"after,omitempty"`
}

// defaultGuard: roll back on signals only config causes,
// alert on signals an attack can cause too.
func defaultGuard() GuardSettings {
	m := snapshot.Duration(time.Minute)
	return GuardSettings{
		Enabled: true, Window: 10 * m, MinRequests: 1000, EvaluateEvery: m / 2, MaxAutoRollbacks: 1, StepMinTime: 5 * m,
		Signals: map[string]Signal{
			"fleet_adoption":               {Mode: "rollback", MinRatio: 0.9, After: 2 * m},
			"edge_5xx_ratio":               {Mode: "rollback", Factor: 2.0, Floor: 0.01},
			"upstream_5xx_ratio":           {Mode: "rollback", Factor: 2.0, Floor: 0.02},
			"changed_rule_limited_ratio":   {Mode: "rollback", MaxRatio: 0.05, MaxVsShadow: 3.0},
			"unchanged_rule_limited_ratio": {Mode: "alert", Factor: 3.0},
			"p99_latency":                  {Mode: "alert", Factor: 1.5, FloorMS: 50},
			"auth_failure_ratio":           {Mode: "alert", Factor: 2.0, Floor: 0.02},
		},
	}
}

// signalCheck is the thresholds a signal needs unless it is off, and what
// the error message says it wants. Without them a signal never trips (a
// missing min_ratio) or trips on any traffic (a factor of 0).
type signalCheck struct {
	ok    func(Signal) bool
	needs string
}

// signalChecks has one entry for each signal evaluate computes; a test
// checks the two agree.
var signalChecks = map[string]signalCheck{
	"fleet_adoption":               {func(s Signal) bool { return isRatio(s.MinRatio) && s.After >= 0 }, "min_ratio above 0 and at most 1, after not negative"},
	"edge_5xx_ratio":               relativeRatio,
	"upstream_5xx_ratio":           relativeRatio,
	"auth_failure_ratio":           relativeRatio,
	"p99_latency":                  {func(s Signal) bool { return s.Factor >= 1 && s.FloorMS >= 0 }, "factor of at least 1, floor_ms not negative"},
	"changed_rule_limited_ratio":   {func(s Signal) bool { return isRatio(s.MaxRatio) && s.MaxVsShadow >= 1 }, "max_ratio above 0 and at most 1, max_vs_shadow of at least 1"},
	"unchanged_rule_limited_ratio": {func(s Signal) bool { return s.Factor >= 1 }, "factor of at least 1"},
}

var relativeRatio = signalCheck{func(s Signal) bool { return s.Factor >= 1 && s.Floor >= 0 && s.Floor <= 1 }, "factor of at least 1, floor from 0 to 1"}

func isRatio(v float64) bool { return v > 0 && v <= 1 }

var signalNames = slices.Sorted(maps.Keys(signalChecks))

func (g GuardSettings) problems() []expr.Issue {
	var errs []expr.Issue
	add := func(p, m string) { errs = append(errs, expr.Issue{Path: p, Msg: m}) }
	if g.Window < snapshot.Duration(time.Minute) || g.EvaluateEvery < snapshot.Duration(time.Second) || g.StepMinTime < 0 {
		add("window", "window must be at least 1m, evaluate_every at least 1s, step_min_time not negative")
	}
	if g.MinRequests == 0 || g.MaxAutoRollbacks < 0 {
		add("min_requests", "min_requests must be at least 1 and max_auto_rollbacks_per_publish not negative")
	}
	for _, name := range slices.Sorted(maps.Keys(g.Signals)) {
		if _, ok := signalChecks[name]; !ok {
			add("signals."+name, "unknown signal")
		}
	}
	for _, name := range signalNames {
		s, ok := g.Signals[name]
		switch {
		case !ok:
			add("signals."+name, "is required; set mode off to disable it")
		case s.Mode != "rollback" && s.Mode != "alert" && s.Mode != "off":
			add("signals."+name+".mode", "must be rollback, alert or off")
		case s.Mode != "off" && !signalChecks[name].ok(s):
			add("signals."+name, "needs "+signalChecks[name].needs)
		}
	}
	return errs
}

// guardFor is the guard that judges v: its per-publish override, or the
// global settings.
func guardFor(ctx context.Context, q querier, v *versionRow) (GuardSettings, error) {
	if v.GuardOverride != nil {
		return *v.GuardOverride, nil
	}
	return loadGuard(ctx, q)
}

func loadGuard(ctx context.Context, q querier) (GuardSettings, error) {
	g := defaultGuard()
	var b []byte
	err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key = 'guard'").Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, nil
	}
	if err != nil {
		return g, err
	}
	err = json.Unmarshal(b, &g)
	return g, err
}

func (s *Server) guardRoutes() {
	s.handle("GET /api/settings/guard", "config.read", func(w http.ResponseWriter, r *http.Request, _ *principal) error {
		g, err := loadGuard(r.Context(), s.db)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, g)
	})
	s.handle("PUT /api/settings/guard", "settings.manage", func(w http.ResponseWriter, r *http.Request, p *principal) error {
		var g GuardSettings
		if err := readJSON(w, r, &g); err != nil {
			return err
		}
		if errs := g.problems(); errs != nil {
			return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid guard settings", Errors: errs}
		}
		ctx := r.Context()
		err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
			before, err := loadGuard(ctx, tx)
			if err != nil {
				return admindb.Event{}, err
			}
			_, err = tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('guard', $1, $2)
				ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = $2`, g, s.now())
			return admindb.Event{Action: "settings.guard", Details: map[string]any{"before": before, "after": g}}, err
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

// cohort is one version's totals over the comparison window, with the
// most-limited subjects left out of rule counts.
type cohort struct {
	edge.Totals
	rules map[string]*edge.RuleCounts
}

func (s *Server) cohort(ctx context.Context, version int64, from, to time.Time) (*cohort, error) {
	// Uses the (version, minute) index: only this version's minutes are
	// read and decoded.
	rows, err := s.statsWhere(ctx, "version = $1 AND minute >= $2 AND minute < $3", version, from, to)
	if err != nil {
		return nil, err
	}
	c := &cohort{rules: map[string]*edge.RuleCounts{}}
	for _, r := range rows {
		addTotals(&c.Totals, r.Totals)
		// Estimates per rule and subject, summed across replicas.
		top := map[string]map[string]uint64{}
		for _, t := range r.TopLimited {
			if top[t.Rule] == nil {
				top[t.Rule] = map[string]uint64{}
			}
			top[t.Rule][t.Key] += t.Limited
		}
		for _, rc := range r.RateLimit {
			sum := c.rules[rc.ID]
			if sum == nil {
				sum = &edge.RuleCounts{ID: rc.ID}
				c.rules[rc.ID] = sum
			}
			var heavy uint64
			for _, est := range top[rc.ID] {
				if float64(est) >= heavyShare*float64(rc.Limited) {
					heavy += est
				}
			}
			rc.Limited -= min(rc.Limited, heavy)
			addRule(sum, rc)
		}
	}
	return c, nil
}

// heavyShare: a subject is left out of a cohort's limited count only when it
// holds at least this share of a rule's limited requests in a minute, as an
// attacker would. Many clients limited a little each are the over-blocking
// the guard must catch, and their sampled estimates (16 per sample) would
// otherwise add up to the whole count.
const heavyShare = 0.05

func ratio(n, d uint64) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

// p99 is the upper bound of the bucket holding the 99th percentile.
func (c *cohort) p99() float64 {
	var total uint64
	for _, n := range c.LatencyMS {
		total += n
	}
	var seen uint64
	for i, n := range c.LatencyMS {
		seen += n
		if float64(seen) >= 0.99*float64(total) {
			if i < len(edge.LatencyBoundsMS) {
				return edge.LatencyBoundsMS[i]
			}
			return 2 * edge.LatencyBoundsMS[len(edge.LatencyBoundsMS)-1]
		}
	}
	return 0
}

// signalResult is one evaluated signal.
type signalResult struct {
	Value    float64 `json:"value"`
	Baseline float64 `json:"baseline"`
	Tripped  bool    `json:"tripped"`
	Mode     string  `json:"mode"`
	Detail   string  `json:"detail,omitempty"`
}

// evaluate compares subject against baseline. changed lists rule IDs that
// differ between the two configs.
func evaluate(g GuardSettings, sub, base *cohort, changed map[string]bool, adoption float64, sinceStart time.Duration) map[string]signalResult {
	out := map[string]signalResult{}
	rel := func(name string, v, b float64, floor float64) {
		sig := g.Signals[name]
		out[name] = signalResult{Value: v, Baseline: b, Mode: sig.Mode, Tripped: v > b*sig.Factor && v > floor}
	}
	rel("edge_5xx_ratio", ratio(sub.Edge5xx, sub.Requests), ratio(base.Edge5xx, base.Requests), g.Signals["edge_5xx_ratio"].Floor)
	rel("upstream_5xx_ratio", ratio(sub.Upstream5xx, sub.Requests), ratio(base.Upstream5xx, base.Requests), g.Signals["upstream_5xx_ratio"].Floor)
	rel("auth_failure_ratio", ratio(sub.AuthFailures, sub.Requests), ratio(base.AuthFailures, base.Requests), g.Signals["auth_failure_ratio"].Floor)
	rel("p99_latency", sub.p99(), base.p99(), g.Signals["p99_latency"].FloorMS)

	fa := g.Signals["fleet_adoption"]
	out["fleet_adoption"] = signalResult{Value: adoption, Baseline: fa.MinRatio, Mode: fa.Mode, Tripped: sinceStart >= time.Duration(fa.After) && adoption < fa.MinRatio}

	ch, un := g.Signals["changed_rule_limited_ratio"], g.Signals["unchanged_rule_limited_ratio"]
	chRes := signalResult{Mode: ch.Mode, Baseline: ch.MaxRatio}
	unRes := signalResult{Mode: un.Mode}
	// worst reports the rule with the highest ratio, but a rule that tripped
	// always wins over one that did not, so a trip names its own rule and
	// numbers rather than a busier rule that is fine.
	worst := func(r *signalResult, id string, v, baseline float64, tripped bool) {
		if (tripped && !r.Tripped) || (tripped == r.Tripped && v > r.Value) {
			r.Value, r.Baseline, r.Detail, r.Tripped = v, baseline, id, tripped
		}
	}
	for _, id := range slices.Sorted(maps.Keys(sub.rules)) {
		rc := sub.rules[id]
		v := ratio(rc.Limited, rc.Evaluated)
		b := base.rules[id]
		if changed[id] {
			// Too tight in absolute terms, or far tighter than the shadow
			// estimate taken while the rule was only logging.
			shadow := 0.0
			if b != nil {
				shadow = ratio(b.WouldLimit, b.Evaluated)
			}
			worst(&chRes, id, v, ch.MaxRatio, v > ch.MaxRatio || (shadow > 0 && v > shadow*ch.MaxVsShadow))
			continue
		}
		if b == nil {
			continue
		}
		bv := ratio(b.Limited, b.Evaluated)
		worst(&unRes, id, v, bv, bv > 0 && v > bv*un.Factor)
	}
	out["changed_rule_limited_ratio"], out["unchanged_rule_limited_ratio"] = chRes, unRes
	for name, r := range out {
		if r.Mode == "off" {
			r.Tripped = false
			out[name] = r
		}
	}
	return out
}

// changedRules lists rate-limit rule IDs added or changed from a to b.
func changedRules(a, b *snapshot.Config) map[string]bool {
	d := semanticDiff(a, b).Phases["rate_limit_rules"]
	m := map[string]bool{}
	for _, id := range d.Added {
		m[id] = true
	}
	for _, c := range d.Changed {
		m[c.ID] = true
	}
	return m
}

// Guard decisions, stored on the version as guard_outcome.decision.
const (
	decisionInsufficient = "insufficient_data" // a cohort is below min_requests
	decisionOK           = "ok"
	decisionAlert        = "alert"
	decisionRollback     = "rollback"
)

// guardOutcome is stored on the version it judged.
type guardOutcome struct {
	At       time.Time `json:"at"`
	Decision string    `json:"decision"` // one of the decision constants
	// Baseline is the version the signals were compared with, so the UI can
	// name it.
	Baseline int64                   `json:"baseline_version"`
	Signals  map[string]signalResult `json:"signals,omitempty"`
}

// runGuard judges the canary, or the active version within its window after
// publish, and acts. The leader runs it.
func (s *Server) runGuard(ctx context.Context) error {
	now := s.now()
	c, err := loadCanary(ctx, s.db)
	if err != nil {
		return err
	}
	if c != nil {
		// Keep edges on the candidate while admin is alive, whether or not
		// the guard is judging it. expires_at is in the snapshot ETag, so
		// renewing on every run would make every edge download an unchanged
		// snapshot each time. Renew once half the lease is gone, or two ticks
		// before it would lapse when ticks are further apart.
		renewBelow := max(canaryLease/2, 2*time.Duration(s.guardEvery.Load()))
		if _, err := s.db.Exec(ctx, "UPDATE canary SET expires_at = $1 WHERE expires_at < $2", now.Add(canaryLease), now.Add(renewBelow)); err != nil {
			return err
		}
	}
	av, err := activeVersion(ctx, s.db)
	if err != nil || av == nil {
		return err
	}
	active, err := s.loadVersion(ctx, s.db, *av)
	if err != nil {
		return err
	}
	subject := active
	if c != nil {
		if subject, err = s.loadVersion(ctx, s.db, c.Version); err != nil {
			return err
		}
	}
	g, err := guardFor(ctx, s.db, subject)
	if err != nil || !g.Enabled {
		return err
	}
	var baseline *versionRow
	var from, to, baseFrom, baseTo time.Time
	var started time.Time
	if c != nil {
		baseline, started = active, c.StartedAt
		from, to = maxTime(c.StepStartedAt, now.Add(-time.Duration(g.Window))), now
		baseFrom, baseTo = from, to // both cohorts over the same minutes
	} else {
		if now.Sub(active.PublishedAt) > time.Duration(g.Window) {
			return nil // outside the watch window after publish
		}
		started = active.PublishedAt
		prev, err := s.previousVersion(ctx, active)
		if err != nil || prev == nil {
			return err
		}
		baseline = prev
		from, to = active.PublishedAt, now
		baseFrom, baseTo = active.PublishedAt.Add(-time.Duration(g.Window)), active.PublishedAt
	}
	sub, err := s.cohort(ctx, subject.Version, from.Truncate(time.Minute), to)
	if err != nil {
		return err
	}
	base, err := s.cohort(ctx, baseline.Version, baseFrom.Truncate(time.Minute), baseTo)
	if err != nil {
		return err
	}
	out := guardOutcome{At: now, Decision: decisionInsufficient, Baseline: baseline.Version}
	if sub.Requests >= g.MinRequests && base.Requests >= g.MinRequests {
		adoption, err := s.adoption(ctx, subject.Version, now)
		if err != nil {
			return err
		}
		out.Signals = evaluate(g, sub, base, changedRules(&baseline.Config, &subject.Config), adoption, now.Sub(started))
		out.Decision = decisionOK
		for _, r := range out.Signals {
			if r.Tripped && out.Decision == decisionOK {
				out.Decision = decisionAlert
			}
			if r.Tripped && r.Mode == "rollback" {
				out.Decision = decisionRollback
			}
		}
	}
	return s.act(ctx, g, subject, baseline, c, out)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// previousVersion is the version active before v.
func (s *Server) previousVersion(ctx context.Context, v *versionRow) (*versionRow, error) {
	var prev int64
	err := s.db.QueryRow(ctx, "SELECT version FROM config_versions WHERE version < $1 AND status IN ('superseded', 'rolled_back') ORDER BY version DESC LIMIT 1", v.Version).Scan(&prev)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.loadVersion(ctx, s.db, prev)
}

// adoption is the share of live edges that loaded version v.
func (s *Server) adoption(ctx context.Context, v int64, now time.Time) (float64, error) {
	var live, have uint64
	err := s.db.QueryRow(ctx, "SELECT count(*), count(*) FILTER (WHERE $1 = ANY(versions)) FROM fleet WHERE last_seen > $2", v, now.Add(-fleetWindow)).Scan(&live, &have)
	return ratio(have, live), err
}

// act records the outcome and, for a tripped rollback signal, aborts the
// canary or rolls the version back. A revert or rollback is never rolled
// back: it only alerts.
func (s *Server) act(ctx context.Context, g GuardSettings, subject, baseline *versionRow, c *canaryRow, out guardOutcome) error {
	return dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", publishLock); err != nil {
			return err
		}
		// runGuard read this state before the lock. If an operator changed it
		// since, the judgment is stale; the next run judges the new state.
		var canaryV, activeV *int64
		if err := tx.QueryRow(ctx, "SELECT (SELECT version FROM canary), (SELECT version FROM config_versions WHERE status = 'active')").Scan(&canaryV, &activeV); err != nil {
			return err
		}
		canaryMoved := c != nil && (canaryV == nil || *canaryV != c.Version)
		activeMoved := c == nil && (canaryV != nil || activeV == nil || *activeV != subject.Version)
		if canaryMoved || activeMoved {
			return nil
		}
		var rollbacks int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM config_versions WHERE source = 'guard_rollback' AND based_on = $1 AND version > $2",
			baseline.Version, subject.Version).Scan(&rollbacks); err != nil {
			return err
		}
		mayRollBack := subject.Source != "revert" && subject.Source != "guard_rollback" && rollbacks < g.MaxAutoRollbacks
		if out.Decision == decisionRollback && !mayRollBack {
			out.Decision = decisionAlert
		}
		if _, err := tx.Exec(ctx, "UPDATE config_versions SET guard_outcome = $1 WHERE version = $2", out, subject.Version); err != nil {
			return err
		}
		var prev guardOutcome
		_ = json.Unmarshal(subject.GuardOutcome, &prev) // null before the first run
		// An alert is raised when it starts, not on every run.
		newAlert := out.Decision == decisionAlert && prev.Decision != decisionAlert
		if out.Decision != decisionRollback && !newAlert {
			return nil
		}
		details := map[string]any{"version": subject.Version, "baseline": baseline.Version, "signals": out.Signals}
		action := "guard.alert"
		if out.Decision == decisionRollback {
			if c != nil {
				action = "guard.canary_abort"
				if _, err := s.endCanary(ctx, tx, c, "rolled_back", "", nil); err != nil {
					return err
				}
			} else {
				action = "guard.rollback"
				p := &principal{actor: "system:guard"}
				v, err := s.publishTx(ctx, tx, p, publishReq{config: &baseline.Config, tests: baseline.Tests, source: "guard_rollback", basedOn: &baseline.Version,
					message: fmt.Sprintf("Guard rolled back version %d", subject.Version), override: "guard rollback restores a version that ran before"})
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, "UPDATE config_versions SET status = 'rolled_back' WHERE version = $1", subject.Version); err != nil {
					return err
				}
				details["rollback_version"] = v
			}
		}
		s.log.Error("guard tripped", "action", action, "version", subject.Version)
		return admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: "system:guard", Action: action, Target: fmt.Sprintf("version %d", subject.Version), Details: details})
	}))
}
