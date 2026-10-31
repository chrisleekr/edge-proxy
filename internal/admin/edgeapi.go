package admin

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
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
	// maxTopPerStep is the most-limited subjects /api/stats keeps per
	// version, step and rule, as many as one report carries.
	maxTopPerStep = 20
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
	if err != nil {
		return nil, err
	}
	// Edges reading schema 3 decode strictly and would reject the field. A
	// config that reads client.verified_bot needs schema 4, and publish waits
	// for every live edge to read that.
	if slices.ContainsFunc(configs, func(c *snapshot.Config) bool { return snapshot.ReadsField(c, expr.VerifiedBotField) }) {
		rows, err := q.Query(ctx, "SELECT source_url, prefixes FROM verified_bot_sets ORDER BY source_url")
		if err != nil {
			return nil, err
		}
		env.VerifiedBots, err = pgx.CollectRows(rows, pgx.RowToStructByPos[snapshot.BotSet])
		if err != nil {
			return nil, err
		}
	}
	return env, nil
}

// snapshotState is everything envelope reads except the fleet size, in one
// cheap row. Published versions never change, so their numbers stand for
// their configs, and a key row's xmin changes on every write. The fleet
// size is left out: edges coming and going would make every edge download
// and recompile an unchanged snapshot. Report answers carry it instead.
const snapshotState = `SELECT format('%s|%s|%s|%s',
	(SELECT version FROM config_versions WHERE status = 'active'),
	(SELECT concat_ws(',', version, percent, expires_at) FROM canary),
	(SELECT string_agg(concat_ws(',', issuer_id, jwks_url, xmin), ';' ORDER BY issuer_id, jwks_url) FROM jwks_keys),
	(SELECT string_agg(concat_ws(',', source_url, xmin), ';' ORDER BY source_url) FROM verified_bot_sets))`

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
func (s *Server) report(w http.ResponseWriter, r *http.Request, _ *principal) (err error) {
	// The edge never resends, so a report counts as accepted once ingested
	// even if the answer then fails.
	ingested := false
	defer func() {
		_, invalid := errors.AsType[*problem](err)
		switch {
		case ingested:
			s.met.reportsAccepted.Add(1)
		case invalid:
			s.met.reportsInvalid.Add(1)
		default:
			s.met.reportsErr.Add(1)
		}
	}()
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
		if !codesOK(v.StatusCodes) {
			return fail(http.StatusUnprocessableEntity, fmt.Sprintf("status codes must be 0 to 600, with counts below %d", uint64(maxCount)))
		}
		if !causesOK(v.UpstreamErrors) {
			return fail(http.StatusUnprocessableEntity, fmt.Sprintf("upstream errors must be by %s, with counts below %d", strings.Join(edge.UpstreamCauses[:], ", "), uint64(maxCount)))
		}
		if !textOK(v) {
			return fail(http.StatusUnprocessableEntity, "rule IDs, keys and displays must not contain NUL")
		}
		if slices.ContainsFunc(v.Rules, func(r edge.RuleOutcome) bool { return r.Phase != "config" && r.Phase != "request_headers" }) {
			return fail(http.StatusUnprocessableEntity, "rule phases must be config or request_headers")
		}
		versions = append(versions, v.Version)
	}
	if len(rep.Deployment) > 64 {
		return fail(http.StatusUnprocessableEntity, "deployment must be at most 64 characters")
	}
	if len(rep.Upstream) > 2048 || strings.ContainsRune(rep.Upstream, 0) {
		return fail(http.StatusUnprocessableEntity, "upstream must be at most 2048 characters, without NUL")
	}
	_, err = s.edgeDB.Exec(r.Context(), `INSERT INTO fleet (instance, last_seen, config_source, bootstrap_age_seconds, versions, max_schema, deployment, upstream) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (instance) DO UPDATE SET last_seen = $2, config_source = $3, bootstrap_age_seconds = $4, versions = $5, max_schema = $6, deployment = $7, upstream = $8`,
		rep.Instance, s.now(), rep.ConfigSource, rep.BootstrapAgeSeconds, versions, max(rep.MaxSchema, 1), rep.Deployment, rep.Upstream)
	if err != nil {
		return err
	}
	s.agg.add(s.now(), rep.Versions)
	ingested = true
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
		n = append(n, &c.TopLimited[i].Limited, &c.TopLimited[i].WouldLimit, &c.TopLimited[i].Err)
	}
	for i := range c.Rules {
		n = append(n, c.Rules[i].Counters()...)
	}
	return !slices.ContainsFunc(n, func(v *uint64) bool { return *v >= maxCount })
}

// codesOK accepts the slots an edge counts: 0 for no response, 100 to 599,
// and 600 for any code above 599.
func codesOK(c edge.StatusCodes) bool {
	for _, m := range []map[int]uint64{c.Edge, c.Upstream} {
		for code, n := range m {
			if code < 0 || code > 600 || n >= maxCount {
				return false
			}
		}
	}
	return true
}

// causesOK accepts the edge's cause names only, so the stored object stays
// six keys at most.
func causesOK(c map[string]uint64) bool {
	for cause, n := range c {
		if !slices.Contains(edge.UpstreamCauses[:], cause) || n >= maxCount {
			return false
		}
	}
	return true
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
	for _, r := range c.Rules {
		s = append(s, r.ID)
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
		p := fail(http.StatusConflict, fmt.Sprintf("edge %s reads config schema up to %d; upgrade it before publishing a config that needs schema %d", instance, oldest, schema))
		p.held = "schema"
		return p
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
	p := fail(http.StatusConflict, fmt.Sprintf("edge %s runs with different deployment settings than admin; CLIENT_IP_SOURCE, VIEWER_HEADERS, INGRESS_SECRET_HEADER and ALLOW_REGEX must match", instance))
	p.held = "deployment"
	return p
}

// minuteAgg sums one version's reports within one minute.
type minuteAgg struct {
	edge.Totals
	codes     edge.StatusCodes
	causes    map[string]uint64
	rules     map[string]*edge.RuleCounts
	ruleOrder []string
	top       map[string]*edge.TopCount
	// outcomes are the config and request-header rules, by ID.
	outcomes     map[string]*edge.RuleOutcome
	outcomeOrder []string
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
			m = &minuteAgg{rules: map[string]*edge.RuleCounts{}, top: map[string]*edge.TopCount{}, outcomes: map[string]*edge.RuleOutcome{}}
			a.m[k] = m
		}
		t := c.Totals
		t.LatencyMS = t.LatencyMS[:min(len(t.LatencyMS), maxLatencyBuckets)]
		addTotals(&m.Totals, t)
		addCodes(&m.codes, c.StatusCodes)
		m.causes = addCodeCounts(m.causes, c.UpstreamErrors)
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
		for _, ro := range c.Rules {
			sum := m.outcomes[ro.ID]
			if sum == nil {
				if len(m.outcomes) >= snapshot.MaxListLen*3 {
					continue
				}
				sum = &edge.RuleOutcome{Phase: ro.Phase, ID: ro.ID}
				m.outcomes[ro.ID] = sum
				m.outcomeOrder = append(m.outcomeOrder, ro.ID)
			}
			addOutcome(sum, ro)
		}
		for _, t := range c.TopLimited {
			if e := m.top[t.Key]; e != nil {
				e.Limited += t.Limited
				e.WouldLimit += t.WouldLimit
				e.Err += t.Err
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
		c := &minuteAgg{Totals: m.Totals, rules: map[string]*edge.RuleCounts{}, ruleOrder: slices.Clone(m.ruleOrder), top: map[string]*edge.TopCount{},
			outcomes: map[string]*edge.RuleOutcome{}, outcomeOrder: slices.Clone(m.outcomeOrder)}
		c.LatencyMS = slices.Clone(m.LatencyMS)
		c.codes = edge.StatusCodes{Edge: maps.Clone(m.codes.Edge), Upstream: maps.Clone(m.codes.Upstream)}
		c.causes = maps.Clone(m.causes)
		for id, r := range m.rules {
			rc := *r
			c.rules[id] = &rc
		}
		for key, t := range m.top {
			tc := *t
			c.top[key] = &tc
		}
		for id, o := range m.outcomes {
			oc := *o
			c.outcomes[id] = &oc
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
		outcomes := make([]*edge.RuleOutcome, 0, len(m.outcomeOrder))
		for _, id := range m.outcomeOrder {
			outcomes = append(outcomes, m.outcomes[id])
		}
		top := make([]*edge.TopCount, 0, len(m.top))
		for _, t := range m.top {
			top = append(top, t)
		}
		slices.SortFunc(top, func(a, b *edge.TopCount) int { return cmp.Compare(b.Limited+b.WouldLimit, a.Limited+a.WouldLimit) })
		// codes is a struct, so it encodes as an object even with no codes;
		// causes is never nil, for the same reason.
		causes := m.causes
		if causes == nil {
			causes = map[string]uint64{}
		}
		b.Queue(`INSERT INTO edge_stats_minute (minute, version, replica, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited, rules, status_codes, upstream_errors)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (minute, version, replica) DO UPDATE SET requests = EXCLUDED.requests, edge_5xx = EXCLUDED.edge_5xx,
				upstream_5xx = EXCLUDED.upstream_5xx, auth_failures = EXCLUDED.auth_failures, latency_ms = EXCLUDED.latency_ms,
				rate_limit = EXCLUDED.rate_limit, top_limited = EXCLUDED.top_limited, rules = EXCLUDED.rules, status_codes = EXCLUDED.status_codes,
				upstream_errors = EXCLUDED.upstream_errors`,
			k.minute, k.version, s.replica, m.Requests, m.Edge5xx, m.Upstream5xx, m.AuthFailures, m.LatencyMS, rules, top, outcomes, m.codes, causes)
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
	RateLimit  []edge.RuleCounts  `json:"rate_limit_rules"`
	TopLimited []edge.TopCount    `json:"top_limited"`
	Rules      []edge.RuleOutcome `json:"rules"`
	// StatusCodes are requests by status code, apart by who answered.
	StatusCodes edge.StatusCodes `json:"status_codes"`
	// UpstreamErrors are the edge's upstream failures by cause.
	UpstreamErrors map[string]uint64 `json:"upstream_errors"`
}

// statsWhere returns per-minute totals for the rows cond selects. cond is
// always a constant in this package; values go in args.
func (s *Server) statsWhere(ctx context.Context, q querier, cond string, args ...any) ([]statsRow, error) {
	rows, err := s.queryStats(ctx, q, cond, args...)
	if err != nil {
		return nil, err
	}
	parts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[statsRow])
	if err != nil {
		return nil, err
	}
	return mergeReplicas(parts), nil
}

// queryStats selects stored rows in minute, version and replica order.
func (s *Server) queryStats(ctx context.Context, q querier, cond string, args ...any) (pgx.Rows, error) {
	return q.Query(ctx, `SELECT minute, version, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited, rules, status_codes, upstream_errors
		FROM edge_stats_minute WHERE `+cond+` ORDER BY minute, version, replica`, args...)
}

// mergeReplicas sums rows with the same minute and version.
func mergeReplicas(parts []statsRow) []statsRow {
	var out []statsRow
	for _, p := range parts {
		if n := len(out); n > 0 && out[n-1].Minute.Equal(p.Minute) && out[n-1].Version == p.Version {
			o := &out[n-1]
			addTotals(&o.Totals, p.Totals)
			addCodes(&o.StatusCodes, p.StatusCodes)
			o.UpstreamErrors = addCodeCounts(o.UpstreamErrors, p.UpstreamErrors)
			for _, rc := range p.RateLimit {
				if j := slices.IndexFunc(o.RateLimit, func(x edge.RuleCounts) bool { return x.ID == rc.ID }); j >= 0 {
					addRule(&o.RateLimit[j], rc)
				} else {
					o.RateLimit = append(o.RateLimit, rc)
				}
			}
			for _, ro := range p.Rules {
				if j := slices.IndexFunc(o.Rules, func(x edge.RuleOutcome) bool { return x.ID == ro.ID }); j >= 0 {
					addOutcome(&o.Rules[j], ro)
				} else {
					o.Rules = append(o.Rules, ro)
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

// addCodes adds o into c, by origin and code.
func addCodes(c *edge.StatusCodes, o edge.StatusCodes) {
	c.Edge, c.Upstream = addCodeCounts(c.Edge, o.Edge), addCodeCounts(c.Upstream, o.Upstream)
}

func addCodeCounts[K comparable](dst, src map[K]uint64) map[K]uint64 {
	if dst == nil && len(src) > 0 {
		dst = make(map[K]uint64, len(src))
	}
	for code, n := range src {
		dst[code] += n
	}
	return dst
}

func addRule(dst *edge.RuleCounts, o edge.RuleCounts) {
	dc := dst.Counters()
	for i, p := range o.Counters() {
		*dc[i] += *p
	}
}

func addOutcome(dst *edge.RuleOutcome, o edge.RuleOutcome) {
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
	step := 0 // none: one row per stored minute
	if v := r.URL.Query().Get("step"); v != "" {
		if _, err := fmt.Sscan(v, &step); err != nil || step < 1 || 24*60%step != 0 {
			return fail(http.StatusBadRequest, "step must be a number of minutes that divides a day, such as 5 or 60")
		}
	}
	since := s.now().Add(-time.Duration(minutes) * time.Minute)
	var rows []statsRow
	var err error
	if step > 0 {
		d := time.Duration(step) * time.Minute
		// From a step boundary, so the first bucket is whole too.
		rows, err = s.statsByStep(r.Context(), since.Truncate(d), d)
	} else {
		rows, err = s.statsWhere(r.Context(), s.db, "minute >= $1", since)
	}
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, orEmpty(rows))
}

// statsByStep sums rows from since into one per version and step. It folds
// rows as it reads them, so memory holds the finished buckets' totals and
// one bucket in progress, not every stored minute. Steps divide a day, so
// buckets start at UTC midnight and line up across requests.
func (s *Server) statsByStep(ctx context.Context, since time.Time, step time.Duration) ([]statsRow, error) {
	rows, err := s.queryStats(ctx, s.db, "minute >= $1", since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out, cur []statsRow // cur: the bucket being read, one row per version
	flush := func() {
		slices.SortFunc(cur, func(a, b statsRow) int { return cmp.Compare(a.Version, b.Version) })
		for _, b := range cur {
			b.TopLimited = topPerRule(b.TopLimited, maxTopPerStep)
			out = append(out, b)
		}
		cur = nil
	}
	for rows.Next() {
		p, err := pgx.RowToStructByPos[statsRow](rows)
		if err != nil {
			return nil, err
		}
		// Rows come in minute order, so a later bucket means this one is complete.
		p.Minute = p.Minute.Truncate(step)
		if len(cur) > 0 && !cur[0].Minute.Equal(p.Minute) {
			flush()
		}
		j := slices.IndexFunc(cur, func(b statsRow) bool { return b.Version == p.Version })
		if j < 0 {
			cur = append(cur, p)
			continue
		}
		cur[j] = mergeReplicas([]statsRow{cur[j], p})[0]
		if len(cur[j].TopLimited) > maxTopPerMinute {
			// Approximate, like the edge's own top-k: a subject cut here
			// and limited again later in the bucket loses its earlier count.
			// Cut per rule, so a busy rule cannot push out a quiet rule's
			// clients; memory stays at rules x 50 per version.
			cur[j].TopLimited = topPerRule(cur[j].TopLimited, maxTopPerMinute/maxTopPerStep)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	flush()
	return out, nil
}

// topPerRule keeps each rule's limit most limited subjects, so Stats
// filtered to a quiet rule still lists its clients beside a busy rule's.
func topPerRule(top []edge.TopCount, limit int) []edge.TopCount {
	kept := map[string]int{}
	return slices.DeleteFunc(topBySubject(top, len(top)), func(t edge.TopCount) bool {
		kept[t.Rule]++
		return kept[t.Rule] > limit
	})
}

// topBySubject sums subjects by rule and key and keeps the limit with the
// most limited and would-limit requests.
func topBySubject(top []edge.TopCount, limit int) []edge.TopCount {
	type subject struct{ rule, key string }
	sums := map[subject]*edge.TopCount{}
	for _, t := range top {
		k := subject{t.Rule, t.Key}
		if e := sums[k]; e != nil {
			e.Limited += t.Limited
			e.WouldLimit += t.WouldLimit
			e.Err += t.Err
		} else {
			sums[k] = &t
		}
	}
	out := make([]edge.TopCount, 0, len(sums))
	for _, t := range sums {
		out = append(out, *t)
	}
	slices.SortFunc(out, func(a, b edge.TopCount) int {
		return cmp.Or(cmp.Compare(b.Limited+b.WouldLimit, a.Limited+a.WouldLimit), cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.Key, b.Key))
	})
	return out[:min(len(out), limit)]
}
