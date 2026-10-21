package admin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/jwks"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// leaderLock is held on a dedicated connection by the replica running
// background jobs.
const leaderLock = 0x6c656164 // "lead"

// Job intervals. Variables so tests can shorten them.
var (
	leaderRetry   = 10 * time.Second
	leaderPing    = 5 * time.Second
	jwksEvery     = 10 * time.Minute
	auditEvery    = 5 * time.Minute
	retentionDays = 30
)

// lead runs background jobs while this replica holds the leader lock.
func (s *Server) lead(ctx context.Context, dsn string) {
	for ctx.Err() == nil {
		if err := s.leadOnce(ctx, dsn); err != nil {
			s.log.Warn("leader loop", "error", err.Error())
		}
		select {
		case <-ctx.Done():
		case <-time.After(leaderRetry):
		}
	}
}

// leadOnce holds the lock on its own connection, outside the pool. If that
// connection drops, Postgres releases the lock, and the jobs stop before
// another replica can take over.
func (s *Server) leadOnce(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return noURL(err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", leaderLock).Scan(&got); err != nil || !got {
		return err
	}
	s.log.Info("leading background jobs")
	jobs, stop := context.WithCancel(ctx)
	pinged := make(chan struct{})
	// Runs before the Close above: the conn isn't safe for concurrent use.
	defer func() { stop(); <-pinged }()
	go func() {
		defer close(pinged)
		t := time.NewTicker(leaderPing)
		defer t.Stop()
		for {
			select {
			case <-jobs.Done():
				return
			case <-t.C:
				if conn.Ping(jobs) != nil {
					s.log.Warn("leader connection lost; stopping jobs")
					stop()
					return
				}
			}
		}
	}()
	s.runJobs(jobs)
	return nil
}

func (s *Server) runJobs(ctx context.Context) {
	g, _ := loadGuard(ctx, s.db) // defaults on error
	s.guardEvery.Store(int64(g.EvaluateEvery))
	guard := time.NewTicker(time.Duration(g.EvaluateEvery))
	keys := time.NewTicker(jwksEvery)
	audit := time.NewTicker(auditEvery)
	daily := time.NewTicker(24 * time.Hour)
	defer guard.Stop()
	defer keys.Stop()
	defer audit.Stop()
	defer daily.Stop()
	job := func(name string, f func(context.Context) error) {
		if err := f(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("background job failed", "job", name, "error", err.Error())
		}
	}
	job("jwks", s.refreshKeys)
	job("audit", s.verifyAudit)
	for {
		select {
		case <-ctx.Done():
			return
		case <-guard.C:
			job("guard", s.runGuard)
		case <-keys.C:
			job("jwks", s.refreshKeys)
		case <-audit.C:
			job("audit", s.verifyAudit)
		case <-daily.C:
			job("retention", s.dropOldStats)
			job("audit full", s.fullAuditVerify)
		}
	}
}

// refreshKeys fetches every issuer's JWKS: issuers of the
// draft, the active version and any canary. Only a changed key set is
// written, and that change is audited.
func (s *Server) refreshKeys(ctx context.Context) error {
	configs, err := s.liveConfigs(ctx)
	if err != nil {
		return err
	}
	seen := map[snapshot.KeySource]bool{}
	for _, c := range configs {
		for _, is := range c.Auth.Issuers {
			src := snapshot.KeySource{IssuerID: is.ID, JWKSURL: is.JWKSURL}
			if seen[src] {
				continue
			}
			seen[src] = true
			if err := s.refreshIssuer(ctx, is); err != nil {
				// One IdP down must not stop the others.
				s.log.Warn("jwks fetch failed; keeping the last good keys", "issuer", is.ID, "error", err.Error())
			}
		}
	}
	return nil
}

func (s *Server) refreshIssuer(ctx context.Context, is snapshot.Issuer) error {
	b, err := s.jwks.Fetch(ctx, is.JWKSURL)
	if err != nil {
		return err
	}
	set, err := jwks.Parse(b)
	if err != nil {
		return err
	}
	var stored []byte
	err = s.db.QueryRow(ctx, "SELECT jwks FROM jwks_keys WHERE issuer_id = $1 AND jwks_url = $2", is.ID, is.JWKSURL).Scan(&stored)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if bytes.Equal(stored, b) {
		return nil
	}
	return s.change(ctx, "system:jwks", func(tx pgx.Tx) (admindb.Event, error) {
		_, err := tx.Exec(ctx, `INSERT INTO jwks_keys (issuer_id, jwks_url, fetched_at, jwks) VALUES ($1, $2, $3, $4)
			ON CONFLICT (issuer_id, jwks_url) DO UPDATE SET fetched_at = $3, jwks = $4`, is.ID, is.JWKSURL, s.now(), b)
		return admindb.Event{Action: "jwks.keys_changed", Target: is.ID, Details: map[string]any{"jwks_url": is.JWKSURL, "keys": set.Len(), "first": stored == nil}}, err
	})
}

// liveConfigs are the draft, active and canary configs.
func (s *Server) liveConfigs(ctx context.Context) ([]*snapshot.Config, error) {
	var out []*snapshot.Config
	d, err := s.loadDraft(ctx, s.db, false)
	if err != nil {
		return nil, err
	}
	if d != nil {
		out = append(out, &d.Config)
	}
	rows, err := s.db.Query(ctx, "SELECT config FROM config_versions WHERE status IN ('active', 'canary')")
	if err != nil {
		return nil, err
	}
	cs, err := pgx.CollectRows(rows, pgx.RowTo[snapshot.Config])
	for i := range cs {
		out = append(out, &cs[i])
	}
	return out, err
}

// verifyAudit checks new audit rows and writes an anchor to the log stream,
// which catches deletion of the newest rows.
func (s *Server) verifyAudit(ctx context.Context) error {
	seq, mac, err := admindb.VerifyAudit(ctx, s.db, s.cfg.Audit, s.auditSeq, s.auditMAC)
	if err != nil {
		return s.auditBroken(ctx, err)
	}
	s.auditSeq, s.auditMAC = seq, mac
	s.log.Info("audit anchor", "seq", seq, "hmac", hex.EncodeToString(mac))
	return nil
}

func (s *Server) fullAuditVerify(ctx context.Context) error {
	seq, _, err := admindb.VerifyAudit(ctx, s.db, s.cfg.Audit, 0, nil)
	if err != nil {
		return s.auditBroken(ctx, err)
	}
	return s.change(ctx, "system:audit", func(pgx.Tx) (admindb.Event, error) {
		return admindb.Event{Action: "audit.verify", Details: map[string]any{"verified_to": seq, "full": true}}, nil
	})
}

// auditBroken raises the critical alert and records the result.
func (s *Server) auditBroken(ctx context.Context, err error) error {
	b, ok := errors.AsType[*admindb.ChainBreak](err)
	if !ok {
		return err
	}
	s.log.Error("audit chain broken", "seq", b.Seq, "reason", b.Reason)
	_ = s.change(ctx, "system:audit", func(pgx.Tx) (admindb.Event, error) {
		return admindb.Event{Action: "audit.verify", Details: map[string]any{"broken_at": b.Seq, "reason": b.Reason}}, nil
	})
	return err
}

// dropOldStats keeps 30 days of per-minute stats and route hours, and
// drops edges and routes not seen as long: replaced pods report under new
// names.
func (s *Server) dropOldStats(ctx context.Context) error {
	cutoff := s.now().AddDate(0, 0, -retentionDays)
	if _, err := s.db.Exec(ctx, "DELETE FROM edge_stats_minute WHERE minute < $1", cutoff); err != nil {
		return err
	}
	if _, err := s.db.Exec(ctx, "DELETE FROM fleet WHERE last_seen < $1", cutoff); err != nil {
		return err
	}
	if _, err := s.db.Exec(ctx, "DELETE FROM observed_route_hour WHERE hour < $1", cutoff); err != nil {
		return err
	}
	// A route with no hours left has not been seen within retention.
	_, err := s.db.Exec(ctx, "DELETE FROM observed_routes r WHERE NOT EXISTS (SELECT 1 FROM observed_route_hour h WHERE h.route_id = r.id)")
	return err
}

func (s *Server) auditRoutes() {
	s.handle("GET /api/audit", "audit.read", s.listAudit)
	// POST: both write an audit row, and cross-origin protection lets any
	// site trigger a GET.
	s.handle("POST /api/audit/verify", "audit.read", s.verifyAuditNow)
	s.handle("POST /api/audit/export", "audit.read", s.exportAudit)
}

type auditView struct {
	Seq        int64     `json:"seq"`
	OccurredAt time.Time `json:"occurred_at"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Target     string    `json:"target"`
	Details    []byte    `json:"-"`
	KeyID      string    `json:"key_id"`
	HMAC       []byte    `json:"-"`
}

// listAudit pages newest first, filtered by actor, action or target, which
// match exactly, and mentions, which matches part of the target or details,
// such as a rule ID inside a save's changes.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, _ *principal) error {
	q := r.URL.Query()
	before := int64(1 << 62)
	if v := q.Get("before"); v != "" {
		if _, err := fmt.Sscan(v, &before); err != nil {
			return fail(http.StatusBadRequest, "before must be a seq")
		}
	}
	rows, err := s.db.Query(r.Context(), `SELECT seq, occurred_at, actor, action, target, details::text, key_id, hmac FROM audit_events
		WHERE seq < $1 AND ($2 = '' OR actor = $2) AND ($3 = '' OR action = $3) AND ($4 = '' OR target = $4)
		AND ($5 = '' OR strpos(target, $5) > 0 OR strpos(details::text, $5) > 0)
		ORDER BY seq DESC LIMIT 100`, before, q.Get("actor"), q.Get("action"), q.Get("target"), q.Get("mentions"))
	if err != nil {
		return err
	}
	return writeAuditRows(w, rows, false, s.log)
}

// writeAuditRows streams rows as a JSON array, so an export of the whole
// append-only table holds one row in memory at a time. A read error after
// the first byte aborts the response, so a client never takes a cut-off
// export for a complete one.
func writeAuditRows(w http.ResponseWriter, rows pgx.Rows, withHMAC bool, log *slog.Logger) error {
	type out struct {
		auditView
		Details any    `json:"details"`
		HMAC    string `json:"hmac,omitempty"`
	}
	defer rows.Close()
	var v auditView
	var details string
	enc := json.NewEncoder(w)
	n := 0
	for rows.Next() {
		if err := rows.Scan(&v.Seq, &v.OccurredAt, &v.Actor, &v.Action, &v.Target, &details, &v.KeyID, &v.HMAC); err != nil {
			return abortAfter(n, err, log)
		}
		if n == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, "[")
		} else {
			_, _ = io.WriteString(w, ",")
		}
		n++
		o := out{auditView: v, Details: rawJSON(details)}
		if withHMAC {
			o.HMAC = hex.EncodeToString(v.HMAC)
		}
		if err := enc.Encode(o); err != nil {
			return abortAfter(n, err, log)
		}
	}
	if err := rows.Err(); err != nil {
		return abortAfter(n, err, log)
	}
	if n == 0 {
		return writeJSON(w, http.StatusOK, []any{})
	}
	_, _ = io.WriteString(w, "]")
	return nil
}

// abortAfter returns err while nothing is written, so it becomes a problem
// response; after that, it logs err and aborts the connection.
func abortAfter(written int, err error, log *slog.Logger) error {
	if written == 0 {
		return err
	}
	log.Error("audit rows cut off", "error", err.Error())
	panic(http.ErrAbortHandler)
}

type rawJSON string

func (r rawJSON) MarshalJSON() ([]byte, error) { return []byte(r), nil }

func (s *Server) verifyAuditNow(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	seq, _, err := admindb.VerifyAudit(ctx, s.db, s.cfg.Audit, 0, nil)
	res := map[string]any{"verified_to": seq, "ok": err == nil}
	if b, ok := errors.AsType[*admindb.ChainBreak](err); ok {
		res["broken_at"], res["reason"] = b.Seq, b.Reason
	} else if err != nil {
		return err
	}
	if err := s.change(ctx, p.actor, func(pgx.Tx) (admindb.Event, error) {
		return admindb.Event{Action: "audit.verify", Details: res}, nil
	}); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, res)
}

// exportAudit returns rows with their HMACs, so a copy can be checked
// elsewhere. Each export is itself audited.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	if err := s.change(ctx, p.actor, func(pgx.Tx) (admindb.Event, error) {
		return admindb.Event{Action: "audit.export"}, nil
	}); err != nil {
		return err
	}
	rows, err := s.db.Query(ctx, "SELECT seq, occurred_at, actor, action, target, details::text, key_id, hmac FROM audit_events ORDER BY seq")
	if err != nil {
		return err
	}
	return writeAuditRows(w, rows, true, s.log)
}
