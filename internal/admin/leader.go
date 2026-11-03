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
	"slices"
	"strings"
	"sync"
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
	jwksEvery     = 10 * time.Minute // also refreshes the verified crawler ranges
	auditEvery    = 5 * time.Minute
	notifyEvery   = time.Minute
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
	s.met.leader.Store(true)
	defer func() { s.met.leader.Store(false); s.met.gauges.Store(nil) }()
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
	notify := time.NewTicker(notifyEvery)
	autopilot := time.NewTicker(autopilotEvery)
	defer autopilot.Stop()
	defer notify.Stop()
	defer guard.Stop()
	defer keys.Stop()
	defer audit.Stop()
	defer daily.Stop()
	// A job cut short by stepping down is not a failure.
	job := func(j jobKind, f func(context.Context) error) {
		if err := f(ctx); err != nil && ctx.Err() == nil {
			s.met.jobFailures[j].Add(1)
			s.log.Error("background job failed", "job", jobNames[j], "error", err.Error())
		}
	}
	job(jobJWKS, s.refreshKeys)
	job(jobVerifiedBots, s.refreshBots)
	job(jobAudit, s.verifyAudit)
	for {
		select {
		case <-ctx.Done():
			return
		case <-guard.C:
			job(jobGuard, s.runGuard)
		case <-notify.C:
			job(jobNotify, s.runNotify)
		case <-autopilot.C:
			job(jobAutopilot, s.runAutopilot)
		case <-keys.C:
			job(jobJWKS, s.refreshKeys)
			job(jobVerifiedBots, s.refreshBots)
		case <-audit.C:
			job(jobAudit, s.verifyAudit)
		case <-daily.C:
			job(jobRetention, s.dropOldStats)
			job(jobAuditFull, s.fullAuditVerify)
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

// botsMaxBytes caps one crawler range list. Google's are tens of KB.
const botsMaxBytes = 512 << 10

// refreshBots fetches every VERIFIED_BOT_SOURCES list. Only a changed set is
// written, and that change is audited; a source no longer configured is
// dropped. A failed fetch keeps the last good set: losing it would turn
// every crawler exemption off.
func (s *Server) refreshBots(ctx context.Context) error {
	srcs := s.cfg.VerifiedBotSources
	// One goroutine per source, at most MaxBotSources as LoadConfig checks,
	// so slow sources cost one client timeout in total, not one each.
	fetched := make([][]string, len(srcs))
	errs := make([]error, len(srcs))
	var wg sync.WaitGroup
	for i, src := range srcs {
		wg.Go(func() { fetched[i], errs[i] = s.fetchBotSource(ctx, src) })
	}
	wg.Wait()
	// Written one after another, so the audit chain stays in order.
	for i, src := range srcs {
		err := errs[i]
		if err == nil {
			err = s.storeBotSource(ctx, src, fetched[i])
		}
		if err != nil {
			s.log.Warn("verified bot ranges fetch failed; keeping the last good set", "source", src, "error", err.Error())
		}
	}
	rows, err := s.db.Query(ctx, "SELECT source_url FROM verified_bot_sets")
	if err != nil {
		return err
	}
	stored, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, src := range stored {
		if slices.Contains(s.cfg.VerifiedBotSources, src) {
			continue
		}
		if err := s.change(ctx, "system:verified_bots", func(tx pgx.Tx) (admindb.Event, error) {
			_, err := tx.Exec(ctx, "DELETE FROM verified_bot_sets WHERE source_url = $1", src)
			return admindb.Event{Action: "verified_bots.removed", Target: src}, err
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) fetchBotSource(ctx context.Context, src string) ([]string, error) {
	b, err := s.jwks.FetchMax(ctx, src, botsMaxBytes)
	if err != nil {
		return nil, err
	}
	return parseRanges(b)
}

func (s *Server) storeBotSource(ctx context.Context, src string, prefixes []string) error {
	var stored []string
	err := s.db.QueryRow(ctx, "SELECT prefixes FROM verified_bot_sets WHERE source_url = $1", src).Scan(&stored)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if slices.Equal(stored, prefixes) {
		return nil
	}
	return s.change(ctx, "system:verified_bots", func(tx pgx.Tx) (admindb.Event, error) {
		_, err := tx.Exec(ctx, `INSERT INTO verified_bot_sets (source_url, fetched_at, prefixes) VALUES ($1, $2, $3)
			ON CONFLICT (source_url) DO UPDATE SET fetched_at = $2, prefixes = $3`, src, s.now(), prefixes)
		added, removed := prefixDiff(stored, prefixes)
		return admindb.Event{Action: "verified_bots.changed", Target: src, Details: map[string]any{
			"prefixes": len(prefixes), "first": stored == nil, "added": added, "removed": removed,
		}}, err
	})
}

// auditPrefixes bounds the added and removed lists in one audit row;
// "prefixes" is the new list's size.
const auditPrefixes = 50

// prefixDiff walks two sorted prefix lists and returns up to auditPrefixes
// prefixes only in fetched and only in stored.
func prefixDiff(stored, fetched []string) (added, removed []string) {
	added, removed = []string{}, []string{}
	i, j := 0, 0
	for i < len(stored) || j < len(fetched) {
		switch {
		case j == len(fetched) || i < len(stored) && stored[i] < fetched[j]:
			if len(removed) < auditPrefixes {
				removed = append(removed, stored[i])
			}
			i++
		case i == len(stored) || fetched[j] < stored[i]:
			if len(added) < auditPrefixes {
				added = append(added, fetched[j])
			}
			j++
		default:
			i++
			j++
		}
	}
	return added, removed
}

// parseRanges reads a range list in the format Google publishes for its
// crawlers (https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot)
// and returns its prefixes canonical, sorted and unique.
func parseRanges(b []byte) ([]string, error) {
	var doc struct {
		Prefixes []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, errors.New("range list is not JSON in the expected format")
	}
	var out []string
	for _, p := range doc.Prefixes {
		if (p.IPv4 != "") == (p.IPv6 != "") {
			return nil, fmt.Errorf("range list has an entry without exactly one of ipv4Prefix and ipv6Prefix: %q", p.IPv4+p.IPv6)
		}
		pf, err := snapshot.BotPrefix(p.IPv4+p.IPv6, p.IPv6 != "")
		if err != nil {
			return nil, fmt.Errorf("range list has an invalid prefix: %w", err)
		}
		out = append(out, pf.String())
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) < 1 || len(out) > snapshot.MaxBotSetPrefixes {
		return nil, fmt.Errorf("range list has %d prefixes; 1 to %d are allowed", len(out), snapshot.MaxBotSetPrefixes)
	}
	return out, nil
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
	s.met.auditVerifyFailures.Add(1)
	s.log.Error("audit chain broken", "seq", b.Seq, "reason", b.Reason)
	_ = s.change(ctx, "system:audit", func(pgx.Tx) (admindb.Event, error) {
		return admindb.Event{Action: "audit.verify", Details: map[string]any{"broken_at": b.Seq, "reason": b.Reason}}, nil
	})
	return err
}

// dropOldStats keeps 30 days of per-minute stats, route hours and resolved
// anomalies, and drops edges and routes not seen as long: replaced pods
// report under new names.
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
	if _, err := s.db.Exec(ctx, "DELETE FROM anomalies WHERE resolved_at < $1", cutoff); err != nil {
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

// maxAuditActions is above every action the admin UI asks for at once.
const maxAuditActions = 50

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
	var since time.Time // zero: from the first event
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return fail(http.StatusBadRequest, "since must be an RFC 3339 time")
		}
		since = t
	}
	// action is one action or a comma-separated list of them, capped so a
	// query string cannot make the server split and match an unbounded list.
	if strings.Count(q.Get("action"), ",") >= maxAuditActions {
		return fail(http.StatusBadRequest, fmt.Sprintf("action takes at most %d actions", maxAuditActions))
	}
	rows, err := s.db.Query(r.Context(), `SELECT seq, occurred_at, actor, action, target, details::text, key_id, hmac FROM audit_events
		WHERE seq < $1 AND ($2 = '' OR actor = $2) AND ($3 = '' OR action = ANY(string_to_array($3, ','))) AND ($4 = '' OR target = $4)
		AND ($5 = '' OR strpos(target, $5) > 0 OR strpos(details::text, $5) > 0) AND occurred_at >= $6
		ORDER BY seq DESC LIMIT 100`, before, q.Get("actor"), q.Get("action"), q.Get("target"), q.Get("mentions"), since)
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
		s.met.auditVerifyFailures.Add(1)
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
