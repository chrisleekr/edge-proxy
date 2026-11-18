package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

const (
	// denylistEvery is the leader's check for due sources.
	denylistEvery = time.Minute
	// denylistRetry is how long after an attempt a source is fetched again.
	denylistRetry = time.Hour
	// denylistMaxBytes bounds one downloaded list.
	denylistMaxBytes = 32 << 20
	// denylistFetchTimeout covers a large list on a slow link.
	denylistFetchTimeout = time.Minute
	// maxDenylistSources bounds the lists: an edge set holds at most this many.
	maxDenylistSources = expr.MaxIPLists
	// banLifts bounds the lifts one edge response carries (the edge sets no
	// limit; a lift is about 45 bytes), so a bulk lift inside one poll
	// interval is not cut. Lifts older than banLiftKeep are never sent, as no
	// ban outlasts it.
	banLifts    = 10_000
	banLiftKeep = 24 * time.Hour
	// banLiftShown is how long a lifted ban stays on the Banned IPs list:
	// edges apply a lift on their next poll, about a minute.
	banLiftShown = 5 * time.Minute
	// maxBansListed bounds GET /api/bans.
	maxBansListed = 500
	// Bounds on the text of a reported ban, in characters. The edge cuts host
	// and path by bytes, so a cut may add a replacement character.
	maxBanRule, maxBanHost, maxBanPath = 200, 255, 128
	// maxBanSpan bounds a reported ban's length, well over the longest ban.
	maxBanSpan = 7 * 24 * time.Hour
	// banClockSkew is how far past now plus maxBanSpan a ban may end, for an
	// edge whose clock runs ahead.
	banClockSkew = time.Hour
)

func (s *Server) denylistRoutes() {
	s.handle("GET /api/denylists", "stats.read", s.listDenylists)
	s.handle("GET /api/denylists/lookup", "stats.read", s.lookupDenylists)
	s.handle("POST /api/denylists", "denylists.manage", s.addDenylist)
	s.handle("PATCH /api/denylists/{id}", "denylists.manage", s.setDenylist)
	s.handle("DELETE /api/denylists/{id}", "denylists.manage", s.removeDenylist)
	s.handle("POST /api/denylists/{id}/refresh", "denylists.manage", s.refreshDenylist)
	s.handle("GET /api/bans", "stats.read", s.listBans)
	s.handle("POST /api/bans/lift", "denylists.manage", s.liftBan)
	s.handle("GET /v1/denylist", permEdge, s.denylist)
}

// parseList reads a plain text IP list: one IP or CIDR per line, text after
// the first space, tab, ; or # ignored. A bare IP becomes a /32 or /128.
// Entries wider than /16 (IPv4) or /32 (IPv6), or /8 and /16 on a wide list,
// are skipped and counted: one wide entry must not turn a whole list into
// noise or an outage. A 4-in-6 entry is skipped too. The
// result is canonical, in plain text order (which prefixDiff relies on) and
// unique. A list with no usable entry is an error: it is an HTML page or
// another mistake, and the last good set must stay.
func parseList(b []byte, wide bool) (out []string, skipped int, err error) {
	min4, min6 := 16, 32
	if wide {
		min4, min6 = 8, 16
	}
	s := string(b)
	for len(s) > 0 {
		var line string
		line, s, _ = strings.Cut(s, "\n")
		if i := strings.IndexAny(line, " \t;#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cidr := line
		a, perr := netip.ParseAddr(line)
		if perr == nil {
			cidr = line + "/" + strconv.Itoa(a.BitLen())
		}
		p, perr := netip.ParsePrefix(cidr)
		if perr != nil || p.Addr().Is4In6() || p.Addr().Is4() && p.Bits() < min4 || p.Addr().Is6() && p.Bits() < min6 {
			skipped++
			continue
		}
		out = append(out, p.Masked().String())
	}
	if len(out) == 0 {
		return nil, skipped, errors.New("the list has no IP address or CIDR range in it")
	}
	slices.Sort(out)
	return slices.Compact(out), skipped, nil
}

// denylistLoop fetches due sources every denylistEvery until ctx ends. It
// runs apart from the other leader jobs: a slow list must not delay a guard
// rollback.
func (s *Server) denylistLoop(ctx context.Context, job func(jobKind, func(context.Context) error)) {
	t := time.NewTicker(denylistEvery)
	defer t.Stop()
	for {
		job(jobDenylists, s.refreshDenylists)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// refreshDenylists fetches each enabled source that was never attempted,
// was last attempted over denylistRetry ago or was cleared by Refresh. One
// after another, so at most one list is in memory. A failed fetch keeps the
// last good set and is recorded in the source's status; only a Postgres
// failure is returned, after the other sources are done.
func (s *Server) refreshDenylists(ctx context.Context) error {
	rows, err := s.db.Query(ctx, `SELECT d.id, d.url, d.wide FROM denylist_sources d LEFT JOIN denylist_status st ON st.source_id = d.id
		WHERE d.enabled AND (st.last_attempt_at IS NULL OR st.last_attempt_at < $1) ORDER BY d.id`, s.now().Add(-denylistRetry))
	if err != nil {
		return err
	}
	type due struct {
		ID   int64
		URL  string
		Wide bool
	}
	todo, err := pgx.CollectRows(rows, pgx.RowToStructByPos[due])
	if err != nil {
		return err
	}
	var failed []error
	for _, d := range todo {
		if ctx.Err() != nil {
			break
		}
		var skipped int
		list, err := s.fetchDenylist(ctx, d.URL)
		if err == nil {
			var prefixes []string
			if prefixes, skipped, err = parseList(list, d.Wide); err == nil {
				if err = s.storeDenylist(ctx, d.ID, d.URL, prefixes); err != nil {
					// Postgres failed, not the source: its status stays as it was.
					failed = append(failed, fmt.Errorf("denylist source %s: %w", d.URL, err))
					continue
				}
			}
		}
		if err != nil {
			s.log.Warn("ip list fetch failed; keeping the last good set", "source", d.URL, "error", err.Error())
		}
		if err := s.recordDenylist(ctx, d.ID, skipped, err); err != nil {
			failed = append(failed, fmt.Errorf("denylist source %s: %w", d.URL, err))
		}
	}
	return errors.Join(failed...)
}

func (s *Server) fetchDenylist(ctx context.Context, url string) ([]byte, error) {
	return s.lists.FetchMax(ctx, url, denylistMaxBytes)
}

// storeDenylist writes a changed list and audits it. An unchanged one writes
// nothing, so the edge ETag and the audit log stay still. A source removed
// while it was fetched is skipped.
func (s *Server) storeDenylist(ctx context.Context, id int64, url string, prefixes []string) error {
	var stored *string
	err := s.db.QueryRow(ctx, "SELECT prefixes FROM denylist_sets WHERE source_id = $1", id).Scan(&stored)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	text := strings.Join(prefixes, "\n")
	if stored != nil && *stored == text {
		return nil
	}
	err = s.change(ctx, "system:denylist", func(tx pgx.Tx) (admindb.Event, error) {
		tag, err := tx.Exec(ctx, `INSERT INTO denylist_sets (source_id, fetched_at, entries, prefixes)
			SELECT id, $2, $3, $4 FROM denylist_sources WHERE id = $1
			ON CONFLICT (source_id) DO UPDATE SET fetched_at = $2, entries = $3, prefixes = $4`, id, s.now(), len(prefixes), text)
		if err != nil {
			return admindb.Event{}, err
		}
		if tag.RowsAffected() == 0 {
			return admindb.Event{}, errNoAudit
		}
		var old []string
		if stored != nil {
			old = strings.Split(*stored, "\n")
		}
		added, removed := prefixDiff(old, prefixes)
		return admindb.Event{Action: "denylist.changed", Target: url, Details: map[string]any{
			"entries": len(prefixes), "first": stored == nil, "added": added, "removed": removed,
		}}, nil
	})
	if errors.Is(err, errNoAudit) {
		return nil
	}
	return err
}

// recordDenylist stores one attempt: a success resets the failures in a row.
func (s *Server) recordDenylist(ctx context.Context, id int64, skipped int, failed error) error {
	now := s.now()
	if failed == nil {
		_, err := s.db.Exec(ctx, `INSERT INTO denylist_status (source_id, last_attempt_at, last_success_at, failures, last_error, skipped)
			SELECT id, $2, $2, 0, NULL, $3 FROM denylist_sources WHERE id = $1
			ON CONFLICT (source_id) DO UPDATE SET last_attempt_at = $2, last_success_at = $2, failures = 0, last_error = NULL, skipped = $3`, id, now, skipped)
		return err
	}
	_, err := s.db.Exec(ctx, `INSERT INTO denylist_status (source_id, last_attempt_at, failures, last_error)
		SELECT id, $2, 1, $3 FROM denylist_sources WHERE id = $1
		ON CONFLICT (source_id) DO UPDATE SET last_attempt_at = $2, failures = denylist_status.failures + 1, last_error = $3`, id, now, boundErr(failed))
	return err
}

type denylistSource struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	Enabled       bool       `json:"enabled"`
	Wide          bool       `json:"wide"`
	AddedBy       string     `json:"added_by"`
	AddedAt       time.Time  `json:"added_at"`
	Entries       int        `json:"entries"`
	FetchedAt     *time.Time `json:"fetched_at"`
	LastAttemptAt *time.Time `json:"last_attempt_at"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	Failures      int        `json:"failures"`
	LastError     string     `json:"last_error"`
	// Skipped counts entries of the last fetch that were not usable.
	Skipped int `json:"skipped"`
}

func (s *Server) listDenylists(w http.ResponseWriter, r *http.Request, _ *principal) error {
	rows, err := s.db.Query(r.Context(), `SELECT d.id, d.name, d.url, d.enabled, d.wide, d.added_by, d.added_at, COALESCE(s.entries, 0), s.fetched_at,
		st.last_attempt_at, st.last_success_at, COALESCE(st.failures, 0), COALESCE(st.last_error, ''), COALESCE(st.skipped, 0)
		FROM denylist_sources d LEFT JOIN denylist_sets s ON s.source_id = d.id LEFT JOIN denylist_status st ON st.source_id = d.id ORDER BY d.enabled DESC, d.name`)
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[denylistSource])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, orEmpty(list))
}

func (s *Server) addDenylist(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		Wide bool   `json:"wide"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	if !expr.ValidListName(in.Name) {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid list", Errors: []expr.Issue{{Path: "name", Msg: "must be 1 to 63 lowercase letters, digits and hyphens, not starting with a hyphen"}}}
	}
	if !validSourceURL(in.URL) {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid list", Errors: []expr.Issue{{Path: "url", Msg: fmt.Sprintf("must be an https address of at most %d characters, with no query, credentials or fragment", snapshot.MaxBotSourceLen)}}}
	}
	ctx := r.Context()
	var id int64
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		// Serializes adds, so the cap cannot race.
		if _, err := tx.Exec(ctx, "LOCK TABLE denylist_sources IN SHARE ROW EXCLUSIVE MODE"); err != nil {
			return admindb.Event{}, err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM denylist_sources").Scan(&n); err != nil {
			return admindb.Event{}, err
		}
		if n >= maxDenylistSources {
			return admindb.Event{}, fail(http.StatusUnprocessableEntity, fmt.Sprintf("There are %d lists already; remove one first.", maxDenylistSources))
		}
		err := tx.QueryRow(ctx, "INSERT INTO denylist_sources (name, url, wide, added_by, added_at) VALUES ($1, $2, $3, $4, $5) RETURNING id", in.Name, in.URL, in.Wide, p.actor, s.now()).Scan(&id)
		return admindb.Event{Action: "denylist.source_added", Target: in.URL, Details: map[string]any{"name": in.Name, "wide": in.Wide}}, err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": in.Name, "url": in.URL})
}

// sourceID reads the {id} of a list route; no list has an id that is not a
// positive number.
func sourceID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		return 0, fail(http.StatusNotFound, "no such list")
	}
	return id, nil
}

func (s *Server) setDenylist(w http.ResponseWriter, r *http.Request, p *principal) error {
	id, err := sourceID(r)
	if err != nil {
		return err
	}
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	if in.Enabled == nil {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid list", Errors: []expr.Issue{{Path: "enabled", Msg: "is required"}}}
	}
	ctx := r.Context()
	err = s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		var url string
		var was bool
		err := tx.QueryRow(ctx, "SELECT url, enabled FROM denylist_sources WHERE id = $1 FOR UPDATE", id).Scan(&url, &was)
		if errors.Is(err, pgx.ErrNoRows) {
			return admindb.Event{}, fail(http.StatusNotFound, "no such list")
		}
		if err != nil {
			return admindb.Event{}, err
		}
		if was == *in.Enabled {
			return admindb.Event{}, errNoAudit
		}
		if _, err := tx.Exec(ctx, "UPDATE denylist_sources SET enabled = $2 WHERE id = $1", id, *in.Enabled); err != nil {
			return admindb.Event{}, err
		}
		return admindb.Event{Action: map[bool]string{true: "denylist.source_enabled", false: "denylist.source_disabled"}[*in.Enabled], Target: url}, nil
	})
	if err != nil && !errors.Is(err, errNoAudit) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) removeDenylist(w http.ResponseWriter, r *http.Request, p *principal) error {
	id, err := sourceID(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	err = s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		var url string
		err := tx.QueryRow(ctx, "DELETE FROM denylist_sources WHERE id = $1 RETURNING url", id).Scan(&url)
		if errors.Is(err, pgx.ErrNoRows) {
			return admindb.Event{}, fail(http.StatusNotFound, "no such list")
		}
		return admindb.Event{Action: "denylist.source_removed", Target: url}, err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// refreshDenylist makes a source due: the leader fetches it on its next
// check, within a minute. Fetch status is telemetry, so it writes no audit row.
func (s *Server) refreshDenylist(w http.ResponseWriter, r *http.Request, _ *principal) error {
	id, err := sourceID(r)
	if err != nil {
		return err
	}
	var exists bool
	if err := s.db.QueryRow(r.Context(), "SELECT EXISTS (SELECT 1 FROM denylist_sources WHERE id = $1)", id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return fail(http.StatusNotFound, "no such list")
	}
	if _, err := s.db.Exec(r.Context(), "UPDATE denylist_status SET last_attempt_at = NULL WHERE source_id = $1", id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// lookupDenylists says which enabled lists hold an address. It scans the
// stored text of each list in turn: an admin action, on no request path.
func (s *Server) lookupDenylists(w http.ResponseWriter, r *http.Request, _ *principal) error {
	ip, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
	if err != nil {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid address", Errors: []expr.Issue{{Path: "ip", Msg: "must be an IPv4 or IPv6 address"}}}
	}
	ip = ip.Unmap()
	ctx := r.Context()
	type src struct {
		ID   int64
		Name string
		URL  string
	}
	type hit struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		URL    string `json:"url"`
		Prefix string `json:"prefix"`
	}
	hits := []hit{}
	// One snapshot, so a list turned off or removed between the reads cannot
	// be half seen. Lists are still read one at a time to bound memory.
	err = pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT d.id, d.name, d.url FROM denylist_sources d JOIN denylist_sets s ON s.source_id = d.id WHERE d.enabled ORDER BY d.name")
		if err != nil {
			return err
		}
		srcs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[src])
		if err != nil {
			return err
		}
		for _, d := range srcs {
			var text string
			if err := tx.QueryRow(ctx, "SELECT prefixes FROM denylist_sets WHERE source_id = $1", d.ID).Scan(&text); err != nil {
				return err
			}
			for line := range strings.Lines(text) {
				// Stored prefixes were written by parseList, so they parse.
				if p, err := netip.ParsePrefix(strings.TrimSpace(line)); err == nil && p.Contains(ip) {
					hits = append(hits, hit{d.ID, d.Name, d.URL, p.String()})
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, hits)
}

type banView struct {
	IP        string    `json:"ip"`
	Rule      string    `json:"rule"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	StartedAt time.Time `json:"started_at"`
	EndsAt    time.Time `json:"ends_at"`
	Edge      string    `json:"edge"`
	// LiftPending is set after a lift, until edges have had time to apply it.
	LiftPending bool `json:"lift_pending"`
}

// listBans returns the bans still running on any edge, and those lifted a
// moment ago, newest first.
func (s *Server) listBans(w http.ResponseWriter, r *http.Request, _ *principal) error {
	now := s.now()
	rows, err := s.db.Query(r.Context(), `SELECT ip, rule, host, path, started_at, ends_at, replica, lifted_at IS NOT NULL FROM bans
		WHERE ends_at > $1 AND (lifted_at IS NULL OR lifted_at > $2) ORDER BY started_at DESC, ip, replica LIMIT $3`, now, now.Add(-banLiftShown), maxBansListed)
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[banView])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, orEmpty(list))
}

// liftBan ends a ban on every edge. The address is masked as the edges key
// bans, so an IPv6 address lifts its whole /64.
func (s *Server) liftBan(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		IP string `json:"ip"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(in.IP))
	if err != nil {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid address", Errors: []expr.Issue{{Path: "ip", Msg: "must be an IPv4 or IPv6 address"}}}
	}
	key := ratelimit.BanKey(ip.Unmap()).String()
	ctx := r.Context()
	err = s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		// Serializes lifts, so ids commit in order: the ETag is max(id), and a
		// lower id committing after a higher one would leave edges on a 304.
		if _, err := tx.Exec(ctx, "LOCK TABLE ban_lifts IN EXCLUSIVE MODE"); err != nil {
			return admindb.Event{}, err
		}
		now := s.now()
		if _, err := tx.Exec(ctx, "INSERT INTO ban_lifts (ip, lifted_at, actor) VALUES ($1, $2, $3)", key, now, p.actor); err != nil {
			return admindb.Event{}, err
		}
		_, err := tx.Exec(ctx, "UPDATE bans SET lifted_at = $2 WHERE ip = $1 AND ends_at > $2", key, now)
		return admindb.Event{Action: "ban.lifted", Target: key}, err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// recordBans upserts an edge's reported bans: a renewal updates the row. A
// ban is marked lifted by the latest lift of its address after the ban
// started, whether the lift came before or after this report. Applied in
// order, so the last report of an address wins.
func (s *Server) recordBans(ctx context.Context, replica string, bans []edge.BanReport) error {
	if len(bans) == 0 {
		return nil
	}
	var b pgx.Batch
	for _, x := range bans {
		b.Queue(`INSERT INTO bans (replica, ip, rule, host, path, started_at, ends_at, lifted_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, (SELECT max(lifted_at) FROM ban_lifts WHERE ip = $2 AND lifted_at > $6))
			ON CONFLICT (replica, ip) DO UPDATE SET rule = $3, host = $4, path = $5, started_at = $6, ends_at = $7,
				lifted_at = (SELECT max(lifted_at) FROM ban_lifts WHERE ip = $2 AND lifted_at > $6)`,
			replica, x.IP, x.Rule, x.Host, x.Path, time.UnixMilli(x.Start), time.UnixMilli(x.End))
	}
	res := s.edgeDB.SendBatch(ctx, &b)
	for range bans {
		if _, err := res.Exec(); err != nil {
			_ = res.Close()
			return err
		}
	}
	return res.Close()
}

// bansOK reports whether every reported ban is one an edge can send: at most
// MaxBanReports, each with a ban key address, bounded text without NUL and a
// span within maxBanSpan, ending no later than now plus maxBanSpan and
// banClockSkew: a far future time breaks the JSON of GET /api/bans and
// outlives retention.
func bansOK(bans []edge.BanReport, now time.Time) bool {
	latest := now.Add(maxBanSpan + banClockSkew).UnixMilli()
	if len(bans) > edge.MaxBanReports {
		return false
	}
	for _, b := range bans {
		ip, err := netip.ParseAddr(b.IP)
		if err != nil || ratelimit.BanKey(ip) != ip || ip.Is4In6() ||
			!textFits(b.Rule, maxBanRule) || !textFits(b.Host, maxBanHost) || !textFits(b.Path, maxBanPath) ||
			b.Start <= 0 || b.End < b.Start || b.End-b.Start > maxBanSpan.Milliseconds() || b.End > latest {
			return false
		}
	}
	return true
}

// textFits says whether s has at most n characters and no NUL, which
// Postgres text refuses.
func textFits(s string, n int) bool {
	return utf8.RuneCountInString(s) <= n && !strings.ContainsRune(s, 0)
}

// denylistState is everything the edge response reads except the lifts'
// ages, in one cheap row. Row versions change on every write.
const denylistState = `SELECT format('%s|%s|%s',
	(SELECT string_agg(concat_ws(',', id, enabled, xmin), ';' ORDER BY id) FROM denylist_sources),
	(SELECT string_agg(concat_ws(',', source_id, xmin), ';' ORDER BY source_id) FROM denylist_sets),
	(SELECT COALESCE(max(id), 0) FROM ban_lifts))`

// denylistTag is the ETag of the response.
func denylistTag(ctx context.Context, q querier) (string, error) {
	var state string
	if err := q.QueryRow(ctx, denylistState).Scan(&state); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(state))
	return `"` + hex.EncodeToString(sum[:16]) + `"`, nil
}

// denylist serves GET /v1/denylist: the enabled lists by name, and the lifts
// of the last day. Separate from the snapshot, so list churn never makes
// edges recompile their config.
func (s *Server) denylist(w http.ResponseWriter, r *http.Request, _ *principal) error {
	ctx := r.Context()
	tag, err := denylistTag(ctx, s.edgeDB)
	if err != nil {
		return err
	}
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	var out edge.DenylistResponse
	err = pgx.BeginTxFunc(ctx, s.edgeDB, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if tag, err = denylistTag(ctx, tx); err != nil {
			return err
		}
		if out.Lists, out.Dropped, err = servedLists(ctx, tx); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT ip, floor(extract(epoch FROM lifted_at) * 1000)::bigint FROM ban_lifts WHERE lifted_at > $1 ORDER BY id DESC LIMIT $2", s.now().Add(-banLiftKeep), banLifts)
		if err != nil {
			return err
		}
		out.Lifts, err = pgx.CollectRows(rows, pgx.RowToStructByPos[edge.BanLift])
		return err
	})
	if err != nil {
		return err
	}
	// Empty slices, so the body says [] and not null.
	out.Lists, out.Dropped, out.Lifts = orEmpty(out.Lists), orEmpty(out.Dropped), orEmpty(out.Lifts)
	w.Header().Set("ETag", tag)
	return writeJSON(w, http.StatusOK, out)
}

// servedLists returns the enabled, fetched lists in the order they were
// added, whole: past edge.MaxDenylistPrefixes a list is left out entirely
// and named in dropped_lists, since part of a list would match less than its name.
func servedLists(ctx context.Context, q querier) (out []edge.IPList, dropped []string, err error) {
	rows, err := q.Query(ctx, "SELECT d.id, d.name, s.entries FROM denylist_sources d JOIN denylist_sets s ON s.source_id = d.id WHERE d.enabled ORDER BY d.id")
	if err != nil {
		return nil, nil, err
	}
	type src struct {
		ID      int64
		Name    string
		Entries int
	}
	srcs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[src])
	if err != nil {
		return nil, nil, err
	}
	total := 0
	for _, x := range srcs {
		if total+x.Entries > edge.MaxDenylistPrefixes {
			dropped = append(dropped, x.Name)
			continue
		}
		var text string
		if err := q.QueryRow(ctx, "SELECT prefixes FROM denylist_sets WHERE source_id = $1", x.ID).Scan(&text); err != nil {
			return nil, nil, err
		}
		total += x.Entries
		out = append(out, edge.IPList{Name: x.Name, Prefixes: strings.Split(text, "\n")})
	}
	return out, dropped, nil
}

// ipListWarnings warns once for each list name a rule of c compares
// client.ip_lists with that matches no one: the list does not exist, is off,
// is not downloaded yet or is left out of the edge response for passing the
// entry cap. Off matters most, since the defaults ship off and an exclusion
// naming an off list excludes nobody. A rule reading client.denylisted is
// warned about always: it matches every list that is on, monitors included.
// Whether lists exist is admin state, not config, so Compile stays pure and
// this is only a warning.
func (s *Server) ipListWarnings(ctx context.Context, q querier, c *snapshot.Config) ([]expr.Issue, error) {
	if !snapshot.ReadsField(c, expr.IPListsField) && !snapshot.ReadsField(c, expr.DenylistedField) {
		return nil, nil
	}
	rows, err := q.Query(ctx, "SELECT d.name, d.enabled, s.entries FROM denylist_sources d LEFT JOIN denylist_sets s ON s.source_id = d.id ORDER BY d.id")
	if err != nil {
		return nil, err
	}
	type state struct {
		Name    string
		Enabled bool
		Entries *int
	}
	states, err := pgx.CollectRows(rows, pgx.RowToStructByPos[state])
	if err != nil {
		return nil, err
	}
	// The same cut as servedLists: a list that would pass the cap is left out.
	const (
		off = iota
		leftOut
		on
	)
	have := map[string]int{}
	anyOn := false
	total := 0
	for _, x := range states {
		switch {
		case !x.Enabled || x.Entries == nil:
			have[x.Name] = off
		case total+*x.Entries > edge.MaxDenylistPrefixes:
			have[x.Name] = leftOut
		default:
			total += *x.Entries
			have[x.Name], anyOn = on, true
		}
	}
	var out []expr.Issue
	warn := func(path string, c *snapshot.Config) {
		if snapshot.ReadsField(c, expr.DenylistedField) {
			msg := "reads client.denylisted, which matches every IP list that is on, including provider, crawler and monitor lists. Name the lists with client.ip_lists."
			if !anyOn {
				msg = "reads client.denylisted, but no IP list is on and downloaded, so it matches no one. Turn one on in IP lists."
			}
			out = append(out, expr.Issue{Path: path, Msg: msg})
		}
		for _, name := range snapshot.IPListNames(c) {
			switch st, ok := have[name]; {
			case !ok:
				out = append(out, expr.Issue{Path: path, Msg: fmt.Sprintf("names IP list %q, which does not exist, so it matches no one.", name)})
			case st == off:
				out = append(out, expr.Issue{Path: path, Msg: fmt.Sprintf("names IP list %q, which is off or not downloaded yet, so it matches no one until you turn it on in IP lists.", name)})
			case st == leftOut:
				out = append(out, expr.Issue{Path: path, Msg: fmt.Sprintf("names IP list %q, which is on but left out because the lists that are on pass 500,000 entries, so it matches no one.", name)})
			}
		}
	}
	for i := range c.ConfigRules {
		warn(fmt.Sprintf("config.config_rules[%d].expression", i), &snapshot.Config{ConfigRules: c.ConfigRules[i : i+1]})
	}
	for i := range c.RateLimitRules {
		warn(fmt.Sprintf("config.rate_limit_rules[%d].expression", i), &snapshot.Config{RateLimitRules: c.RateLimitRules[i : i+1]})
	}
	for i := range c.RequestHeaderRules {
		warn(fmt.Sprintf("config.request_header_rules[%d].expression", i), &snapshot.Config{RequestHeaderRules: c.RequestHeaderRules[i : i+1]})
	}
	return out, nil
}
