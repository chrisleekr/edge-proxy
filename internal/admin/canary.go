package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
)

// canaryLease is how long edges keep a candidate without admin: the leader
// extends it once less than half, or less than two guard ticks, is left, so
// if admin disappears edges go back to active within this time.
const canaryLease = 10 * time.Minute

type canaryRow struct {
	Version       int64     `json:"version"`
	Percent       float64   `json:"percent"`
	StartedAt     time.Time `json:"started_at"`
	StepStartedAt time.Time `json:"step_started_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func loadCanary(ctx context.Context, q querier) (*canaryRow, error) {
	var c canaryRow
	err := q.QueryRow(ctx, "SELECT version, percent::float8, started_at, step_started_at, expires_at FROM canary").Scan(&c.Version, &c.Percent, &c.StartedAt, &c.StepStartedAt, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &c, err
}

func (s *Server) canaryRoutes() {
	s.handle("GET /api/canary", "config.read", s.getCanary)
	s.handle("POST /api/canary/step", "canary.manage", s.stepCanary)
	s.handle("POST /api/canary/promote", "canary.manage", s.promoteCanary)
	s.handle("POST /api/canary/abort", "canary.manage", s.abortCanary)
}

func (s *Server) getCanary(w http.ResponseWriter, r *http.Request, _ *principal) error {
	c, err := loadCanary(r.Context(), s.db)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"canary": c})
}

func validPercent(p float64) bool { return p >= 0.01 && p <= 99.99 }

// stepCanary widens the candidate's share. Each step needs the guard's
// minimum time and requests first.
func (s *Server) stepCanary(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Percent float64 `json:"percent"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	ctx := r.Context()
	return s.canaryChange(ctx, w, p, func(tx pgx.Tx, c *canaryRow, g GuardSettings) (admindb.Event, error) {
		if !validPercent(in.Percent) || in.Percent <= c.Percent {
			return admindb.Event{}, fail(http.StatusUnprocessableEntity, fmt.Sprintf("percent must be above %.2f and at most 99.99", c.Percent))
		}
		if err := s.stepReady(ctx, tx, c, g); err != nil {
			return admindb.Event{}, err
		}
		now := s.now()
		_, err := tx.Exec(ctx, "UPDATE canary SET percent = $1, step_started_at = $2, expires_at = $3", in.Percent, now, now.Add(canaryLease))
		return admindb.Event{Action: "canary.step", Target: fmt.Sprintf("version %d", c.Version), Details: map[string]any{"from": c.Percent, "to": in.Percent}}, err
	})
}

// stepReady refuses to move on before the step ran long enough on enough
// requests to judge it.
func (s *Server) stepReady(ctx context.Context, q querier, c *canaryRow, g GuardSettings) error {
	if ran := s.now().Sub(c.StepStartedAt); ran < time.Duration(g.StepMinTime) {
		return fail(http.StatusConflict, fmt.Sprintf("this step has run %s; wait at least %s", ran.Round(time.Second), time.Duration(g.StepMinTime)))
	}
	var n uint64
	if err := q.QueryRow(ctx, "SELECT coalesce(sum(requests), 0)::bigint FROM edge_stats_minute WHERE version = $1 AND minute >= $2",
		c.Version, c.StepStartedAt.Truncate(time.Minute)).Scan(&n); err != nil {
		return err
	}
	if n < g.MinRequests {
		return fail(http.StatusConflict, fmt.Sprintf("this step has %d requests; wait for %d", n, g.MinRequests))
	}
	return nil
}

func (s *Server) promoteCanary(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	return s.canaryChange(ctx, w, p, func(tx pgx.Tx, c *canaryRow, g GuardSettings) (admindb.Event, error) {
		if err := s.stepReady(ctx, tx, c, g); err != nil {
			return admindb.Event{}, err
		}
		return s.endCanary(ctx, tx, c, "active", "canary.promote", nil)
	})
}

func (s *Server) abortCanary(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	if in.Reason == "" {
		return fail(http.StatusUnprocessableEntity, "reason is required")
	}
	ctx := r.Context()
	return s.canaryChange(ctx, w, p, func(tx pgx.Tx, c *canaryRow, _ GuardSettings) (admindb.Event, error) {
		if _, err := tx.Exec(ctx, "UPDATE config_versions SET abort_reason = $1 WHERE version = $2", in.Reason, c.Version); err != nil {
			return admindb.Event{}, err
		}
		return s.endCanary(ctx, tx, c, "rolled_back", "canary.abort", map[string]any{"reason": in.Reason})
	})
}

// endCanary makes the candidate active (promote) or rolls it back (abort).
func (s *Server) endCanary(ctx context.Context, tx pgx.Tx, c *canaryRow, status, action string, details map[string]any) (admindb.Event, error) {
	if status == "active" {
		if _, err := tx.Exec(ctx, "UPDATE config_versions SET status = 'superseded' WHERE status = 'active'"); err != nil {
			return admindb.Event{}, err
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE config_versions SET status = $1 WHERE version = $2", status, c.Version); err != nil {
		return admindb.Event{}, err
	}
	_, err := tx.Exec(ctx, "DELETE FROM canary")
	return admindb.Event{Action: action, Target: fmt.Sprintf("version %d", c.Version), Details: details}, err
}

// canaryChange runs fn on the running canary, audited.
func (s *Server) canaryChange(ctx context.Context, w http.ResponseWriter, p *principal, fn func(pgx.Tx, *canaryRow, GuardSettings) (admindb.Event, error)) error {
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", publishLock); err != nil {
			return admindb.Event{}, err
		}
		c, err := loadCanary(ctx, tx)
		if err != nil {
			return admindb.Event{}, err
		}
		if c == nil {
			return admindb.Event{}, fail(http.StatusConflict, "no canary is running")
		}
		v, err := s.loadVersion(ctx, tx, c.Version)
		if err != nil {
			return admindb.Event{}, err
		}
		g, err := guardFor(ctx, tx, v)
		if err != nil {
			return admindb.Event{}, err
		}
		return fn(tx, c, g)
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
