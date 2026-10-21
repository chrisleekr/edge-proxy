package admin

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

const (
	// maxReport bounds one stats report body.
	maxReport = 1 << 20
	// fleetWindow: an edge that reported within it counts toward fleet_size.
	fleetWindow = time.Minute
	// maxTopPerMinute bounds the most-limited subjects kept per version and
	// minute; reports carry at most 20 each.
	maxTopPerMinute = 1000
	// maxLatencyBuckets bounds a reported histogram; the edge sends 14.
	maxLatencyBuckets = 64
	// maxCount is far above what one edge serves between reports, and low
	// enough that sums never overflow the bigint columns.
	maxCount = 1 << 40
)

func (s *Server) edgeRoutes() {
	s.handle("GET /v1/snapshot", permEdge, s.snapshot)
	s.handle("POST /v1/edge/report", permEdge, s.report)
	s.handle("GET /api/fleet", "stats.read", s.fleet)
	s.handle("GET /api/stats", "stats.read", s.stats)
}

// envelope builds what edges load: active, any canary, fleet size and keys.
func (s *Server) envelope(ctx context.Context, q querier) (*snapshot.Envelope, error) {
	av, err := activeVersion(ctx, q)
	if err != nil {
		return nil, err
	}
	if av == nil {
		return nil, fail(http.StatusServiceUnavailable, "nothing published yet")
	}
	active, err := s.loadVersion(ctx, q, *av)
	if err != nil {
		return nil, err
	}
	env := &snapshot.Envelope{Active: &active.Config}
	configs := []*snapshot.Config{&active.Config}
	c, err := loadCanary(ctx, q)
	if err != nil {
		return nil, err
	}
	if c != nil {
		cand, err := s.loadVersion(ctx, q, c.Version)
		if err != nil {
			return nil, err
		}
		env.Candidate, env.CanaryPercent, env.CanaryExpiresAt = &cand.Config, c.Percent, c.ExpiresAt.UTC()
		configs = append(configs, &cand.Config)
	}
	if err := q.QueryRow(ctx, "SELECT count(*) FROM fleet WHERE last_seen > $1", s.now().Add(-fleetWindow)).Scan(&env.FleetSize); err != nil {
		return nil, err
	}
	env.Keys, err = issuerKeys(ctx, q, configs...)
	return env, err
}

// snapshotState is everything envelope reads except the fleet size, in one
// cheap row. Published versions never change, so their numbers stand for
// their configs, and a key row's xmin changes on every write. The fleet
// size is left out: edges coming and going would make every edge download
// and recompile an unchanged snapshot. Report answers carry it instead.
const snapshotState = `SELECT format('%s|%s|%s',
	(SELECT version FROM config_versions WHERE status = 'active'),
	(SELECT concat_ws(',', version, percent, expires_at) FROM canary),
	(SELECT string_agg(concat_ws(',', issuer_id, jwks_url, xmin), ';' ORDER BY issuer_id, jwks_url) FROM jwks_keys))`

// snapshot serves GET /v1/snapshot. Every edge polls it, so
// the ETag comes from snapshotState and an unchanged snapshot answers 304
// after one query, with no transaction and no configs loaded. A changed one
// is read in one repeatable-read transaction, which keeps the tag and the
// body in step.
func (s *Server) snapshot(w http.ResponseWriter, r *http.Request, _ *principal) error {
	ctx := r.Context()
	tag, err := snapshotTag(ctx, s.edgeDB)
	if err != nil {
		return err
	}
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	var env *snapshot.Envelope
	err = pgx.BeginTxFunc(ctx, s.edgeDB, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if tag, err = snapshotTag(ctx, tx); err != nil {
			return err
		}
		env, err = s.envelope(ctx, tx)
		return err
	})
	if err != nil {
		return err
	}
	env.ExportedAt = s.now().UTC()
	w.Header().Set("ETag", tag)
	return writeJSON(w, http.StatusOK, env)
}

func snapshotTag(ctx context.Context, q querier) (string, error) {
	var state string
	if err := q.QueryRow(ctx, snapshotState).Scan(&state); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(state))
	return `"` + hex.EncodeToString(sum[:16]) + `"`, nil
}

// report ingests one edge's stats. It returns once the
// fleet row is written; counts are summed in memory and flushed per minute.
func (s *Server) report(w http.ResponseWriter, r *http.Request, _ *principal) error {
	var rep edge.StatsReport
	if err := decodeOne(json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReport)), &rep, "invalid report"); err != nil {
		return err
	}
	if rep.Instance == "" || len(rep.Instance) > 128 || len(rep.Versions) > 8 {
		return fail(http.StatusUnprocessableEntity, "instance must be 1 to 128 characters, with at most 8 versions")
	}
	versions := []int64{}
	for _, v := range rep.Versions {
		if !countsOK(v) {
			return fail(http.StatusUnprocessableEntity, fmt.Sprintf("counts must be below %d", uint64(maxCount)))
		}
		if !textOK(v) {
			return fail(http.StatusUnprocessableEntity, "rule IDs, keys and displays must not contain NUL")
		}
		versions = append(versions, v.Version)
	}
	if len(rep.Deployment) > 64 {
		return fail(http.StatusUnprocessableEntity, "deployment must be at most 64 characters")
	}
	if len(rep.Upstream) > 2048 || strings.ContainsRune(rep.Upstream, 0) {
		return fail(http.StatusUnprocessableEntity, "upstream must be at most 2048 characters, without NUL")
	}
	_, err := s.edgeDB.Exec(r.Context(), `INSERT INTO fleet (instance, last_seen, config_source, bootstrap_age_seconds, versions, max_schema, deployment, upstream) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (instance) DO UPDATE SET last_seen = $2, config_source = $3, bootstrap_age_seconds = $4, versions = $5, max_schema = $6, deployment = $7, upstream = $8`,
		rep.Instance, s.now(), rep.ConfigSource, rep.BootstrapAgeSeconds, versions, max(rep.MaxSchema, 1), rep.Deployment, rep.Upstream)
	if err != nil {
		return err
	}
	s.agg.add(s.now(), rep.Versions)
	var a edge.ReportAnswer
	if err := s.edgeDB.QueryRow(r.Context(), "SELECT count(*) FROM fleet WHERE last_seen > $1", s.now().Add(-fleetWindow)).Scan(&a.FleetSize); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, a)
}

func countsOK(c edge.StatsCounts) bool {
	n := c.Counters()
	for i := range c.RateLimit {
		n = append(n, c.RateLimit[i].Counters()...)
	}
	for i := range c.TopLimited {
		n = append(n, &c.TopLimited[i].Limited, &c.TopLimited[i].WouldLimit)
	}
	return !slices.ContainsFunc(n, func(v *uint64) bool { return *v >= maxCount })
}

// textOK rejects NUL, which Postgres refuses in jsonb: one in the minute's
// batch would drop every edge's stats for that minute.
func textOK(c edge.StatsCounts) bool {
	s := []string{}
	for _, r := range c.RateLimit {
		s = append(s, r.ID)
	}
	for _, t := range c.TopLimited {
		s = append(s, t.Rule, t.Key, t.Display)
	}
	return !slices.ContainsFunc(s, func(v string) bool { return strings.ContainsRune(v, 0) })
}

// checkSchema refuses a config the oldest live edge can't read; that edge
// would keep its old snapshot and the fleet would split.
func (s *Server) checkSchema(ctx context.Context, q querier, schema int) error {
	var oldest int
	var instance string
	err := q.QueryRow(ctx, "SELECT max_schema, instance FROM fleet WHERE last_seen > $1 ORDER BY max_schema, instance LIMIT 1",
		s.now().Add(-fleetWindow)).Scan(&oldest, &instance)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if schema > oldest {
		return fail(http.StatusConflict, fmt.Sprintf("edge %s reads config schema up to %d; upgrade it before publishing schema %d", instance, oldest, schema))
	}
	return nil
}

// checkDeployment refuses to publish while a live edge runs with different
// deployment settings than admin validates against: that edge would reject
// the config and keep its old snapshot. Edges that predate
// the fingerprint report "" and are not checked.
func (s *Server) checkDeployment(ctx context.Context, q querier) error {
	var instance string
	err := q.QueryRow(ctx, "SELECT instance FROM fleet WHERE last_seen > $1 AND deployment <> '' AND deployment <> $2 ORDER BY instance LIMIT 1",
		s.now().Add(-fleetWindow), s.cfg.Deployment.Fingerprint()).Scan(&instance)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return fail(http.StatusConflict, fmt.Sprintf("edge %s runs with different deployment settings than admin; CLIENT_IP_SOURCE, VIEWER_HEADERS, INGRESS_SECRET_HEADER and ALLOW_REGEX must match", instance))
}

// minuteAgg sums one version's reports within one minute.
type minuteAgg struct {
	edge.Totals
	rules     map[string]*edge.RuleCounts
	ruleOrder []string
	top       map[string]*edge.TopCount
}

type aggKey struct {
	minute  time.Time
	version int64
}

// aggregator holds this replica's sums until they are flushed.
type aggregator struct {
	mu sync.Mutex
	m  map[aggKey]*minuteAgg
}

func (a *aggregator) add(now time.Time, counts []edge.StatsCounts) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// The minute is taken under the lock, so nothing is added to a minute
	// after flush has written it.
	minute := now.UTC().Truncate(time.Minute)
	for _, c := range counts {
		k := aggKey{minute, c.Version}
		m := a.m[k]
		if m == nil {
			m = &minuteAgg{rules: map[string]*edge.RuleCounts{}, top: map[string]*edge.TopCount{}}
			a.m[k] = m
		}
		t := c.Totals
		t.LatencyMS = t.LatencyMS[:min(len(t.LatencyMS), maxLatencyBuckets)]
		addTotals(&m.Totals, t)
		for _, rc := range c.RateLimit {
			sum := m.rules[rc.ID]
			if sum == nil {
				if len(m.rules) >= snapshot.MaxListLen*3 {
					continue
				}
				sum = &edge.RuleCounts{ID: rc.ID}
				m.rules[rc.ID] = sum
				m.ruleOrder = append(m.ruleOrder, rc.ID)
			}
			addRule(sum, rc)
		}
		for _, t := range c.TopLimited {
			if e := m.top[t.Key]; e != nil {
				e.Limited += t.Limited
				e.WouldLimit += t.WouldLimit
			} else if len(m.top) < maxTopPerMinute {
				tc := t
				m.top[t.Key] = &tc
			}
		}
	}
}

// take returns every minute held. The minutes before now, which no report
// can add to anymore, are removed; the current one is copied, since reports
// keep adding to it while flush writes it.
func (a *aggregator) take(now time.Time) map[aggKey]*minuteAgg {
	a.mu.Lock()
	defer a.mu.Unlock()
	cur := now.UTC().Truncate(time.Minute)
	out := map[aggKey]*minuteAgg{}
	for k, m := range a.m {
		if k.minute.Before(cur) {
			out[k] = m
			delete(a.m, k)
			continue
		}
		c := &minuteAgg{Totals: m.Totals, rules: map[string]*edge.RuleCounts{}, ruleOrder: slices.Clone(m.ruleOrder), top: map[string]*edge.TopCount{}}
		c.LatencyMS = slices.Clone(m.LatencyMS)
		for id, r := range m.rules {
			rc := *r
			c.rules[id] = &rc
		}
		for key, t := range m.top {
			tc := *t
			c.top[key] = &tc
		}
		out[k] = c
	}
	return out
}

// flush writes every minute held in one batch, the current one so far
// included, so stats are at most one flush behind. Each write replaces the
// row with the minute's running sum. On failure finished minutes are
// dropped: stats never block or grow memory.
func (s *Server) flush(ctx context.Context, now time.Time) error {
	done := s.agg.take(now)
	if len(done) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for k, m := range done {
		rules := make([]*edge.RuleCounts, 0, len(m.ruleOrder))
		for _, id := range m.ruleOrder {
			rules = append(rules, m.rules[id])
		}
		top := make([]*edge.TopCount, 0, len(m.top))
		for _, t := range m.top {
			top = append(top, t)
		}
		slices.SortFunc(top, func(a, b *edge.TopCount) int { return cmp.Compare(b.Limited+b.WouldLimit, a.Limited+a.WouldLimit) })
		b.Queue(`INSERT INTO edge_stats_minute (minute, version, replica, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (minute, version, replica) DO UPDATE SET requests = EXCLUDED.requests, edge_5xx = EXCLUDED.edge_5xx,
				upstream_5xx = EXCLUDED.upstream_5xx, auth_failures = EXCLUDED.auth_failures, latency_ms = EXCLUDED.latency_ms,
				rate_limit = EXCLUDED.rate_limit, top_limited = EXCLUDED.top_limited`,
			k.minute, k.version, s.replica, m.Requests, m.Edge5xx, m.Upstream5xx, m.AuthFailures, m.LatencyMS, rules, top)
	}
	if err := s.edgeDB.SendBatch(ctx, b).Close(); err != nil {
		return fmt.Errorf("stats flush dropped %d minutes: %w", len(done), err)
	}
	return nil
}

func (s *Server) fleet(w http.ResponseWriter, r *http.Request, _ *principal) error {
	rows, err := s.db.Query(r.Context(), "SELECT instance, last_seen, config_source, bootstrap_age_seconds, versions, upstream FROM fleet ORDER BY instance")
	if err != nil {
		return err
	}
	type item struct {
		Instance     string    `json:"instance"`
		LastSeen     time.Time `json:"last_seen"`
		ConfigSource string    `json:"config_source"`
		BootstrapAge int64     `json:"bootstrap_age_seconds"`
		Versions     []int64   `json:"versions"`
		Upstream     string    `json:"upstream"`
		Live         bool      `json:"live"`
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (item, error) {
		var it item
		err := row.Scan(&it.Instance, &it.LastSeen, &it.ConfigSource, &it.BootstrapAge, &it.Versions, &it.Upstream)
		it.Live = it.LastSeen.After(s.now().Add(-fleetWindow))
		return it, err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, list)
}

// statsRow is one version's totals for one minute, summed across replicas.
type statsRow struct {
	Minute  time.Time `json:"minute"`
	Version int64     `json:"version"`
	edge.Totals
	RateLimit  []edge.RuleCounts `json:"rate_limit_rules"`
	TopLimited []edge.TopCount   `json:"top_limited"`
}

// statsWhere returns per-minute totals for the rows cond selects. cond is
// always a constant in this package; values go in args.
func (s *Server) statsWhere(ctx context.Context, cond string, args ...any) ([]statsRow, error) {
	rows, err := s.db.Query(ctx, `SELECT minute, version, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited
		FROM edge_stats_minute WHERE `+cond+` ORDER BY minute, version, replica`, args...)
	if err != nil {
		return nil, err
	}
	parts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[statsRow])
	if err != nil {
		return nil, err
	}
	return mergeReplicas(parts), nil
}

// mergeReplicas sums rows with the same minute and version.
func mergeReplicas(parts []statsRow) []statsRow {
	var out []statsRow
	for _, p := range parts {
		if n := len(out); n > 0 && out[n-1].Minute.Equal(p.Minute) && out[n-1].Version == p.Version {
			o := &out[n-1]
			addTotals(&o.Totals, p.Totals)
			for _, rc := range p.RateLimit {
				if j := slices.IndexFunc(o.RateLimit, func(x edge.RuleCounts) bool { return x.ID == rc.ID }); j >= 0 {
					addRule(&o.RateLimit[j], rc)
				} else {
					o.RateLimit = append(o.RateLimit, rc)
				}
			}
			// Readers sum subjects by key, so duplicates across replicas are fine.
			o.TopLimited = append(o.TopLimited, p.TopLimited...)
			continue
		}
		out = append(out, p)
	}
	return out
}

// addTotals adds o into t. Latency buckets add by index and t grows to fit,
// so replicas with different histograms keep every bucket.
func addTotals(t *edge.Totals, o edge.Totals) {
	if n := len(o.LatencyMS) - len(t.LatencyMS); n > 0 {
		t.LatencyMS = append(t.LatencyMS, make([]uint64, n)...)
	}
	tc := t.Counters()
	for i, p := range o.Counters() {
		*tc[i] += *p
	}
}

func addRule(dst *edge.RuleCounts, o edge.RuleCounts) {
	dc := dst.Counters()
	for i, p := range o.Counters() {
		*dc[i] += *p
	}
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request, _ *principal) error {
	minutes := 60
	if v := r.URL.Query().Get("minutes"); v != "" {
		if _, err := fmt.Sscan(v, &minutes); err != nil || minutes < 1 || minutes > 30*24*60 {
			return fail(http.StatusBadRequest, "minutes must be 1 to 43200")
		}
	}
	rows, err := s.statsWhere(r.Context(), "minute >= $1", s.now().Add(-time.Duration(minutes)*time.Minute))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, orEmpty(rows))
}
