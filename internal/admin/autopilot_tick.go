package admin

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// Tick timing. Variables so tests can shorten them.
var (
	autopilotEvery = 30 * time.Second
	// renewRecent: an enforcing rule is renewed only if it limited within
	// this long, so a rule the attack has moved past runs out.
	renewRecent = 10 * time.Minute
	sweepEvery  = time.Hour
	reviewEvery = 24 * time.Hour
)

// anomalySignals open a case when they fire. A sensor's would-block or
// dominant subject is the autopilot's own early warning; on a person's
// rule it is already handled by that rule.
var anomalySignals = []string{"traffic_surge", "auth_failure_ratio", "rule_auth_failure_ratio", "rule_match_surge"}

// overlaySignals are the signals on an autopilot rule that open a case.
var overlaySignals = []string{"rule_would_block", "rule_subject_dominates"}

// runAutopilot is the leader's autopilot job: it releases lapsed leases,
// cancels stale cases, opens new ones while a runner is connected, and
// moves rules through their states with at most one publish.
func (s *Server) runAutopilot(ctx context.Context) error {
	set, err := loadAutopilot(ctx, s.db)
	if err != nil {
		return err
	}
	// The newest runner stays, so a runner gone for over a day still reads
	// as down rather than as never set up.
	if _, err := s.db.Exec(ctx, `DELETE FROM autopilot_runners WHERE last_seen < $1
		AND id <> (SELECT id FROM autopilot_runners ORDER BY last_seen DESC, id LIMIT 1)`, s.now().Add(-24*time.Hour)); err != nil {
		return err
	}
	if err := s.expireCases(ctx); err != nil {
		return err
	}
	if set.Mode == "off" {
		return nil
	}
	if err := s.noteJobs(ctx); err != nil {
		return err
	}
	if err := s.openAutoCases(ctx, set); err != nil {
		return err
	}
	// A refused publish is tried again with less. First without new rules,
	// which are rejected with the reason (compile on 422; schema or
	// deployment on 409), so a stuck proposal never holds back renewals.
	// Then, on a 409, with removals only, which wait on no edge. A 422
	// without new rules would refuse removals too, since what remains
	// already ran.
	gate, why := tickAll, ""
	for {
		err = s.tickRules(ctx, gate, why)
		p, ok := errors.AsType[*problem](err)
		switch {
		case ok && gate == tickAll && p.Status == http.StatusUnprocessableEntity:
			gate, why = tickNoNew, "compile"
		case ok && gate == tickAll && p.Status == http.StatusConflict:
			gate, why = tickNoNew, cmp.Or(p.held, "deployment")
		case ok && gate == tickNoNew && p.Status == http.StatusConflict:
			gate = tickRemovals
		default:
			return err
		}
		s.log.Warn("autopilot publish refused; publishing less", "error", errText(err), "gate", int(gate))
	}
}

// rejectedFor is why a proposed rule left the queue in a tick without new
// rules, by what refused the publish.
var rejectedFor = map[string]string{
	"compile":    "it no longer compiles with the live rules",
	"schema":     "it needs a config schema a live edge can't read",
	"deployment": "a live edge runs other deployment settings",
}

// tickGate is what one tick may publish.
type tickGate int

const (
	tickRemovals tickGate = iota // expiries, adoptions and rollbacks only
	tickNoNew                    // also renewals; proposed rules are rejected with the reason they were refused
	tickAll                      // also new rules and enforcing
)

// expireCases requeues a running case whose lease lapsed, once; after the
// last attempt the case fails and needs a person. A case queued past
// queuedMax is cancelled.
func (s *Server) expireCases(ctx context.Context) error {
	var failed, cancelled []string
	err := dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		now := s.now()
		// FOR NO KEY UPDATE: a search holding the audit lock still records a
		// use that references the case.
		rows, err := tx.Query(ctx, "SELECT id, kind, attempts, run_id FROM autopilot_cases WHERE state = 'running' AND lease_until < $1 FOR NO KEY UPDATE", now)
		if err != nil {
			return err
		}
		type lapsed struct {
			ID       int64
			Kind     string
			Attempts int
			RunID    *int64
		}
		list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[lapsed])
		if err != nil {
			return err
		}
		for _, c := range list {
			action, state := "autopilot.case_release", "queued"
			if c.Attempts >= maxAttempts {
				action, state = "autopilot.case_close", "failed"
				failed = append(failed, c.Kind)
				_, err = tx.Exec(ctx, "UPDATE autopilot_cases SET state = 'failed', lease_until = NULL, closed_at = $2, summary = $3 WHERE id = $1",
					c.ID, now, fmt.Sprintf("the runner's lease lapsed on all %d attempts; a person needs to look", maxAttempts))
			} else {
				_, err = tx.Exec(ctx, "UPDATE autopilot_cases SET state = 'queued', lease_until = NULL WHERE id = $1", c.ID)
			}
			if err != nil {
				return err
			}
			if err := admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: "system:autopilot", Action: action, Target: fmt.Sprintf("case %d", c.ID),
				Details: map[string]any{"state": state, "reason": "the lease lapsed", "run_id": c.RunID, "attempts": c.Attempts}}); err != nil {
				return err
			}
		}
		cancelled, err = s.cancelCases(ctx, tx, "system:autopilot", "state = 'queued' AND created_at < $3", "no runner claimed it within an hour", now.Add(-queuedMax))
		return err
	}))
	if err != nil {
		return err
	}
	for _, k := range failed {
		s.met.autopilot.caseClosed(k, "failed")
	}
	for _, k := range cancelled {
		s.met.autopilot.caseClosed(k, "cancelled")
	}
	return nil
}

// openAutoCases opens cases for firing anomalies, the sweep and review
// when they are due and ablations of confirmed notes, only while a runner
// is connected.
func (s *Server) openAutoCases(ctx context.Context, set AutopilotSettings) error {
	rs, err := s.runners(ctx, s.db)
	if err != nil {
		return err
	}
	if live, _ := s.connected(rs); len(live) == 0 {
		return nil
	}
	return dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		now := s.now()
		// An autopilot rule's anomaly opens no case while one on the same rule
		// and signal closed benign within max_ttl, one renewal of the sensor:
		// the verdict stands until then.
		rows, err := tx.Query(ctx, `SELECT id, signal, rule, summary FROM anomalies a WHERE state = 'firing'
			AND (signal = ANY($1) OR (signal = ANY($2) AND rule LIKE 'ap-%'
				AND NOT EXISTS (SELECT 1 FROM autopilot_cases c JOIN anomalies p ON p.id = c.anomaly_id
					WHERE p.rule = a.rule AND p.signal = a.signal AND c.verdict = 'benign' AND c.closed_at > $3)))
			AND NOT EXISTS (SELECT 1 FROM autopilot_cases c WHERE c.anomaly_id = a.id) ORDER BY id LIMIT 20`,
			anomalySignals, overlaySignals, now.Add(-time.Duration(set.MaxTTL)))
		if err != nil {
			return err
		}
		type firing struct {
			ID                    int64
			Signal, Rule, Summary string
		}
		list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[firing])
		if err != nil {
			return err
		}
		for _, a := range list {
			c := caseIn{Kind: "anomaly", DedupeKey: fmt.Sprintf("anomaly:%d", a.ID), AnomalyID: &a.ID,
				Brief: map[string]any{"kind": "anomaly", "signal": a.Signal, "rule": a.Rule, "summary": untrusted(a.Summary)}}
			if a.Rule != "" {
				c.Rule = &a.Rule
			}
			if _, _, err := s.openCase(ctx, tx, c, "system:autopilot"); err != nil {
				return err
			}
		}
		u, err := s.autopilotUsage(ctx, tx)
		if err != nil {
			return err
		}
		for _, due := range []struct {
			kind  string
			every time.Duration
			ask   string
		}{
			{"sweep", sweepEvery, "Find observed routes no rule watches, such as login, search, export and routes with id segments, and propose sensors for them."},
			{"review", reviewEvery, "Review the autopilot rules: retire sensors that never fire or whose cases keep closing benign, so sweeps have room; " +
				"flag rules that keep renewing; and summarize the day. " +
				"Re-check the notes with search_notes, and merge notes on the same topic into one with record_learning merges."},
		} {
			// A sweep only proposes sensors, so it waits while the sensor
			// budget is full; the daily review retires sensors to make room.
			if due.kind == "sweep" && u.Sensors >= set.MaxSensors {
				continue
			}
			var recent bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_cases WHERE kind = $1 AND created_at > $2)", due.kind, now.Add(-due.every)).Scan(&recent); err != nil {
				return err
			}
			if recent {
				continue
			}
			// Keyed by the hour, so a sweep still running doesn't hold back the next.
			c := caseIn{Kind: due.kind, DedupeKey: due.kind + ":" + now.UTC().Truncate(time.Hour).Format(time.RFC3339), Question: due.ask,
				Brief: map[string]any{"kind": due.kind, "question": due.ask}}
			if _, _, err := s.openCase(ctx, tx, c, "system:autopilot"); err != nil {
				return err
			}
		}
		return s.openAblations(ctx, tx)
	}))
}

// tickRules moves every autopilot rule one step and publishes the overlay
// they make, once, when it differs from the active version's. Renewals,
// new rules and enforcing wait for a canary to end and for
// min_publish_interval since the last autopilot publish; removals wait
// only for the canary, which no publish can pass. gate limits the step.
func (s *Server) tickRules(ctx context.Context, gate tickGate, why string) error {
	var after []func()
	var published bool
	err := s.autopilotTx(ctx, func(tx pgx.Tx) error {
		// Read under the locks, so a kill switch committed since is seen.
		set, err := loadAutopilot(ctx, tx)
		if err != nil || set.Mode == "off" {
			return err
		}
		now := s.now()
		active, err := s.activeConfig(ctx, tx)
		if err != nil || active == nil {
			return err
		}
		canary, err := loadCanary(ctx, tx)
		if err != nil {
			return err
		}
		var last *time.Time
		if err := tx.QueryRow(ctx, "SELECT max(published_at) FROM config_versions WHERE source = 'autopilot'").Scan(&last); err != nil {
			return err
		}
		renewals := gate >= tickNoNew && canary == nil && (last == nil || now.Sub(*last) >= time.Duration(set.MinPublishInterval))
		additions := renewals && gate == tickAll
		g, err := loadGuard(ctx, tx)
		if err != nil {
			return err
		}
		rules, err := s.loadRules(ctx, tx, "state IN ('proposed', 'observing', 'enforcing', 'adopted')")
		if err != nil {
			return err
		}
		ex, err := activeExclusions(ctx, tx, now)
		if err != nil {
			return err
		}
		excluding := map[int64]bool{}
		for _, e := range ex {
			excluding[e.ID] = true
		}
		base := baseIDs(baseOf(active))
		inOverlay := rateLimitIDSet(&snapshot.Config{RateLimitRules: overlayOf(active, now)})
		var changes []ruleChange
		change := func(r apRule, next apRule, reason, actor, action string, numbers map[string]any) {
			changes = append(changes, ruleChange{from: r.State, next: next, reason: reason, actor: actor, action: action, numbers: numbers})
		}
		var summary []string
		renewIfDue := func(r apRule) error {
			c, err := s.renew(ctx, tx, set, r)
			if c != nil {
				changes = append(changes, *c)
				summary = append(summary, "renew "+r.ID)
			}
			return err
		}
		for _, r := range rules {
			plain := strings.TrimPrefix(r.ID, overlayPrefix)
			switch {
			case r.State == "adopted":
				// A revert past the adopt dropped the person's copy and brought
				// the autopilot rule back.
				if inOverlay[r.ID] && !base[plain] {
					next := r
					next.State, next.Outcome, next.EndedAt = "observing", nil, nil
					if r.EnforcingSince != nil {
						next.State = "enforcing"
					}
					change(r, next, "a revert dropped the adopted copy", "system:autopilot", "autopilot.restore", nil)
				}
			case r.State != "proposed" && base[plain]:
				change(r, ended(r, "adopted", "adopted", now), "a person adopted it", "system:autopilot", "autopilot.adopt", nil)
			case r.State != "proposed" && r.ExpiresAt != nil && !r.ExpiresAt.After(now):
				change(r, ended(r, "expired", "expired", now), "it reached its expiry", "system:autopilot", "autopilot.expire", nil)
				summary = append(summary, "expire "+r.ID)
			// Its expression still leaves out a client a person no longer
			// excludes; the sweep can watch the route again without it. An
			// enforcing rule keeps blocking until it ends.
			case r.Kind == "sensor" && r.State == "observing" && slices.ContainsFunc(r.Exclusions, func(id int64) bool { return !excluding[id] }):
				change(r, ended(r, "retired", "retired", now), "an exclusion it carries was revoked or expired", "system:autopilot", "autopilot.retire",
					map[string]any{"exclusions": r.Exclusions})
				summary = append(summary, "retire "+r.ID)
			case r.State == "proposed" && gate == tickNoNew:
				// Only a new rule can be refused where live rules that
				// already passed are not, so it leaves the queue.
				change(r, ended(r, "rejected", "rejected", now), rejectedFor[why], "system:autopilot", "autopilot.reject", map[string]any{"reason": why})
				after = append(after, func() { s.met.autopilot.rejected(why) })
			case r.State == "proposed":
				if !additions {
					continue
				}
				next := r
				exp := now.Add(time.Duration(r.TTLSeconds) * time.Second).Truncate(time.Second)
				next.State, next.LiveSince, next.ExpiresAt = "observing", &now, &exp
				change(r, next, "the proposal was accepted", "system:autopilot", "autopilot.observe", nil)
				summary = append(summary, "observe "+r.ID)
			case r.State == "enforcing":
				c, err := s.ruleGuard(ctx, tx, g, set, r)
				if err != nil {
					return err
				}
				if c != nil {
					if c.next.State == "rolled_back" && canary != nil {
						// No publish passes a canary: the rule stays on the
						// edges until it ends.
						c.numbers["published"], c.numbers["waits_for_canary"] = false, canary.Version
					}
					changes = append(changes, *c)
					if c.next.State == "rolled_back" {
						summary = append(summary, "roll back "+r.ID)
						after = append(after, func() { s.met.guardActed("rollback") })
						continue
					}
					after = append(after, func() { s.met.guardActed("alert") })
					r = c.next
				}
				if renewals {
					if err := renewIfDue(r); err != nil {
						return err
					}
				}
			case r.State == "observing" && r.Kind == "enforce":
				observe, err := s.observeFor(ctx, tx, set, r)
				if err != nil {
					return err
				}
				ready := additions && (set.Mode == "auto" || r.ApprovedBy != nil) && now.Sub(*r.LiveSince) >= observe
				if !ready {
					continue
				}
				// Its ttl counts from here: observing and the wait for a publish
				// would otherwise leave it too little to renew while it blocks.
				exp := minTime(now.Add(time.Duration(r.TTLSeconds)*time.Second), s.lifetimeEnd(ctx, tx, set, r)).Truncate(time.Second)
				if !exp.After(now) {
					// max_lifetime was lowered while it observed.
					change(r, ended(r, "expired", "expired", now), "it reached max_lifetime before it could enforce", "system:autopilot", "autopilot.expire", nil)
					summary = append(summary, "expire "+r.ID)
					continue
				}
				reason, numbers, shadow, err := s.enforceCheck(ctx, tx, set, r)
				if err != nil {
					return err
				}
				if reason != "" {
					change(r, ended(r, "rejected", "rejected", now), reason, "system:autopilot", "autopilot.reject", numbers)
					after = append(after, func() { s.met.autopilot.rejected(reason) })
					continue
				}
				next := r
				next.State, next.EnforcingSince, next.ShadowRatio, next.ExpiresAt = "enforcing", &now, &shadow, &exp
				change(r, next, "its shadow counts confirm the attack within the budgets", "system:autopilot", "autopilot.enforce", numbers)
				summary = append(summary, "enforce "+r.ID)
			case r.State == "observing" && renewals:
				if err := renewIfDue(r); err != nil {
					return err
				}
			}
		}
		// The overlay the rules now make, against the one published.
		final := map[string]apRule{}
		for _, r := range rules {
			final[r.ID] = r
		}
		for _, c := range changes {
			final[c.next.ID] = c.next
		}
		var desired []snapshot.RateLimitRule
		for _, r := range rules {
			if n := final[r.ID]; n.State == "observing" || n.State == "enforcing" {
				desired = append(desired, n.published())
			}
		}
		var current []snapshot.RateLimitRule
		for _, r := range active.RateLimitRules {
			if isOverlay(r.ID) {
				current = append(current, r)
			}
		}
		var version *int64
		if canary == nil && !sameOverlay(current, desired) {
			if len(summary) == 0 {
				summary = []string{"remove rules that ended"}
			}
			v, err := s.publishOverlayTx(ctx, tx, desired, "Autopilot: "+strings.Join(summary, ", "), subOverlay(desired, current))
			if err != nil {
				return err
			}
			version, published = &v, true
		}
		return s.applyChanges(ctx, tx, changes, version)
	})
	if err != nil {
		return err
	}
	if published {
		s.met.published("autopilot")
	}
	for _, f := range after {
		f()
	}
	return nil
}

// sameOverlay reports whether two overlays run the same rules: the same ids
// with the same action and expiry.
func sameOverlay(a, b []snapshot.RateLimitRule) bool {
	return len(a) == len(b) && subOverlay(a, b)
}

// subOverlay reports whether every rule of a runs in b as it is.
func subOverlay(a, b []snapshot.RateLimitRule) bool {
	for _, r := range a {
		i := slices.IndexFunc(b, func(o snapshot.RateLimitRule) bool { return o.ID == r.ID })
		if i < 0 || b[i].Action != r.Action || !b[i].ExpiresAt.Equal(r.ExpiresAt) {
			return false
		}
	}
	return true
}

// lifetimeEnd is when r must end: max_lifetime after it went live, or after
// the sensor it cites did, whichever is earlier.
func (s *Server) lifetimeEnd(ctx context.Context, q querier, set AutopilotSettings, r apRule) time.Time {
	start := *r.LiveSince
	if r.Cites != nil {
		var cited time.Time
		if err := q.QueryRow(ctx, "SELECT live_since FROM autopilot_rules WHERE id = $1", *r.Cites).Scan(&cited); err == nil && cited.Before(start) {
			start = cited
		}
	}
	return start.Add(time.Duration(set.MaxLifetime))
}

// renew extends a rule a quarter of whose ttl is left: a sensor always,
// an enforcing rule only while it still limits. A rule never runs past
// max_lifetime after it went live, counted from the sensor it cites.
func (s *Server) renew(ctx context.Context, q querier, set AutopilotSettings, r apRule) (*ruleChange, error) {
	now := s.now()
	ttl := time.Duration(r.TTLSeconds) * time.Second
	if r.ExpiresAt == nil || r.LiveSince == nil || r.ExpiresAt.Sub(now) >= ttl/4 {
		return nil, nil
	}
	newTTL := time.Duration(set.MaxTTL)
	if r.State == "enforcing" {
		newTTL = time.Duration(set.DefaultTTL)
		var limited uint64
		rows, err := s.statsWhere(ctx, q, "minute >= $1", now.Add(-renewRecent).Truncate(time.Minute))
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			for _, rc := range row.RateLimit {
				if rc.ID == r.ID {
					limited += rc.Limited
				}
			}
		}
		if limited == 0 {
			return nil, nil
		}
	} else if r.Kind != "sensor" {
		return nil, nil
	}
	exp := minTime(now.Add(newTTL), s.lifetimeEnd(ctx, q, set, r)).Truncate(time.Second)
	if !exp.After(*r.ExpiresAt) {
		return nil, nil
	}
	next := r
	next.ExpiresAt, next.TTLSeconds = &exp, int(newTTL/time.Second)
	return &ruleChange{from: r.State, next: next, reason: "it is still needed near its expiry", actor: "system:autopilot", action: "autopilot.renew"}, nil
}

// ruleGuard judges an enforcing rule during the guard window after it
// started blocking, from every version since then. It trips when the rule
// limits far more than its shadow estimate, or more of the fleet's requests
// than max_block_share. The most-limited subjects are left out, as the
// version guard leaves them out.
func (s *Server) ruleGuard(ctx context.Context, q querier, g GuardSettings, set AutopilotSettings, r apRule) (*ruleChange, error) {
	sig := g.Signals["changed_rule_limited_ratio"]
	now := s.now()
	if !g.Enabled || sig.Mode == "off" || r.EnforcingSince == nil || now.Sub(*r.EnforcingSince) > time.Duration(g.Window) {
		return nil, nil
	}
	c, err := s.cohortWhere(ctx, q, "minute >= $1 AND minute < $2", r.EnforcingSince.Truncate(time.Minute), now)
	if err != nil || c.Requests < g.MinRequests {
		return nil, err
	}
	rc := c.rules[r.ID]
	if rc == nil {
		return nil, nil
	}
	shadow := 0.0
	if r.ShadowRatio != nil {
		shadow = *r.ShadowRatio
	}
	// With no shadow estimate, as when every shadow limit went to heavy
	// subjects, the absolute ratio applies, as for a person's rule.
	bound := sig.MaxRatio
	if shadow > 0 {
		bound = shadow * sig.MaxVsShadow
	}
	notes, err := citedNotes(ctx, q, r.ProposalID)
	if err != nil {
		return nil, err
	}
	maxShare := blockShare(set, notes)
	limitedRatio, fleetShare := ratio(rc.Limited, rc.Evaluated), ratio(rc.Limited, c.Requests)
	numbers := map[string]any{"limited_ratio": limitedRatio, "shadow_ratio": shadow, "max_vs_shadow": sig.MaxVsShadow, "bound": bound, "fleet_share": fleetShare,
		"max_block_share": maxShare, "fleet_requests": c.Requests}
	if !(limitedRatio > bound || fleetShare > maxShare) {
		return nil, nil
	}
	if sig.Mode == "rollback" {
		return &ruleChange{from: r.State, next: ended(r, "rolled_back", "rolled_back", now), reason: "it blocked more than its shadow counts or the fleet budget allow",
			actor: "system:guard", action: "autopilot.rollback", numbers: numbers}, nil
	}
	if r.GuardAlertedAt != nil {
		return nil, nil
	}
	next := r
	next.GuardAlertedAt = &now
	return &ruleChange{from: r.State, next: next, reason: "it blocked more than its shadow counts or the fleet budget allow", actor: "system:guard", action: "guard.alert", numbers: numbers}, nil
}
