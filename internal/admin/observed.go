package admin

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/edge"
)

// Observed routes are built from the edges' access log lines, which a log
// shipper posts to admin. The edge does no extra work for them.

const (
	maxIngestBody = 4 << 20
	maxIngestLine = 64 << 10
	// ingestSlots bounds concurrent ingests; past it the shipper gets 429
	// and retries, so a burst never piles up in admin's memory.
	ingestSlots = 2
	maxShapes   = 20
	maxRuleKeys = 200
	maxPatterns = 200
	// maxPattern and maxPatternSegs bound a pattern, and so any stored
	// template, which a pattern must be able to group.
	maxPattern     = 512
	maxPatternSegs = 32
	// maxShape bounds a query shape; longer ones are summed under otherKey.
	maxShape = 256
	// otherKey sums counts past a cap. No rule ID, query key or decision
	// can be "*".
	otherKey = "*"
	// lateLine: a line's own time is used for its hour within this window,
	// so a shipper that catches up after an outage files lines correctly.
	lateLine = 48 * time.Hour
)

// Route caps. Variables so tests can shorten them.
var (
	// maxRoutes bounds stored routes; traffic for routes past it is counted
	// under overflowRoute.
	maxRoutes = 5000
	// maxErrorRoutes bounds routes seen only with error answers, apart
	// from maxRoutes.
	maxErrorRoutes = 500
	// maxPendingRoutes bounds the route hours held between flushes.
	maxPendingRoutes = 10_000
)

// overflowRoute collects traffic for routes past maxRoutes.
var overflowRoute = routeKey{host: "*", method: "*", template: "*"}

// notRoutes are rejections of the request line itself: they say nothing
// about a route, and scanners send them in any shape.
var notRoutes = map[string]bool{"path": true, "method": true}

func (s *Server) observedRoutes() {
	s.handle("POST /v1/logs/access", permLogs, s.ingestAccess)
	s.handle("GET /api/observed-routes", "stats.read", s.listObserved)
	s.handle("DELETE /api/observed-routes", "routes.manage", s.deleteAllObserved)
	s.handle("GET /api/observed-routes/{id}", "stats.read", s.getObserved)
	s.handle("DELETE /api/observed-routes/{id}", "routes.manage", s.deleteObserved)
	s.handle("GET /api/observed-routes/{id}/flow", "config.read", s.routeFlow)
	s.handle("GET /api/observed-routes/{id}/condition", "config.read", s.routeCondition)
	s.handle("GET /api/route-patterns", "stats.read", s.listPatterns)
	s.handle("POST /api/route-patterns", "routes.manage", s.createPattern)
	s.handle("DELETE /api/route-patterns/{id}", "routes.manage", s.deletePattern)
}

// accessLine is the part of an edge access line routes use.
type accessLine struct {
	Time          time.Time `json:"time"`
	Msg           string    `json:"msg"`
	Method        string    `json:"http.request.method"`
	Host          string    `json:"server.address"`
	Path          string    `json:"url.path"`
	Status        int       `json:"http.response.status_code"`
	Decision      string    `json:"edge.decision"`
	DurationMS    float64   `json:"duration_ms"`
	QueryKeys     []string  `json:"edge.query_keys"`
	Version       int64     `json:"edge.config_version"`
	ConfigRules   []string  `json:"edge.config_rules"`
	RateLimitRule string    `json:"edge.rate_limit_rule"`
	// SampleRate is set on allowed lines the edge logged at a rate below 1.
	SampleRate float64 `json:"edge.sample_rate"`
	// UpstreamErrorKind is why the edge got no answer from the upstream.
	UpstreamErrorKind string `json:"edge.upstream_error_kind"`
}

// usable reports whether the line describes a request on a route. Text
// containing NUL is refused: Postgres rejects it in jsonb and would fail
// the whole flush.
func (l *accessLine) usable() bool {
	text := append([]string{l.Method, l.Host, l.Path, l.Decision, l.RateLimitRule}, l.ConfigRules...)
	text = append(text, l.QueryKeys...)
	return l.Msg == "access" && !notRoutes[l.Decision] &&
		l.Method != "" && len(l.Method) <= 16 && strings.IndexFunc(l.Method, func(r rune) bool { return r <= ' ' || r >= 0x7f }) < 0 &&
		l.Host != "" && len(l.Host) <= 253 && strings.HasPrefix(l.Path, "/") && len(l.Path) <= 4096 &&
		l.Status >= 0 && l.Status < 600 && l.DurationMS >= 0 && len(l.Decision) <= 64 && l.SampleRate >= 0 && l.SampleRate <= 1 &&
		!slices.ContainsFunc(text, func(v string) bool { return strings.ContainsRune(v, 0) })
}

// maxLineWeight bounds how many requests one sampled line can stand for.
const maxLineWeight = 1_000_000

// weightDraw rounds a sampled line's weight. A variable so tests can choose
// the outcome.
var weightDraw = rand.Float64

// sampled reports whether the line stands for more than one request: the
// edge logs only a share of allowed, non-5xx requests when sampling.
func (l *accessLine) sampled() bool {
	return l.SampleRate > 0 && l.SampleRate < 1 && l.Decision == "allow" && l.Status < 500
}

// weight is how many requests the line stands for: 1/rate for a sampled
// line, rounded up or down at random so the expected sum is exact.
func (l *accessLine) weight() int64 {
	if !l.sampled() {
		return 1
	}
	w := min(1/l.SampleRate, maxLineWeight)
	n := int64(w)
	if weightDraw() < w-float64(n) {
		n++
	}
	return n
}

// hour is the hour the line belongs to: its own time when plausible.
func (l *accessLine) hour(now time.Time) time.Time {
	t := l.Time
	if t.IsZero() || t.Before(now.Add(-lateLine)) || t.After(now.Add(5*time.Minute)) {
		t = now
	}
	return t.UTC().Truncate(time.Hour)
}

func (s *Server) ingestAccess(w http.ResponseWriter, r *http.Request, _ *principal) error {
	select {
	case s.ingest <- struct{}{}:
		defer func() { <-s.ingest }()
	default:
		s.met.logBusy.Add(1)
		return fail(http.StatusTooManyRequests, "busy; send the batch again")
	}
	pats, err := s.routePatterns(r.Context())
	if err != nil {
		return err
	}
	// Lines are counted only once the whole body is read, so a failed
	// request adds nothing and a resent batch is not counted twice.
	br := bufio.NewReaderSize(http.MaxBytesReader(w, r.Body, maxIngestBody), maxIngestLine)
	var lines []accessLine // bounded by maxIngestBody
	skipped := 0
	for {
		b, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// An over-long line is skipped alone; the edge can log a path up
			// to its header limit.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			skipped++
			b = nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				return fail(http.StatusRequestEntityTooLarge, fmt.Sprintf("body is larger than %d bytes", maxIngestBody))
			}
			return err
		}
		if b = bytes.TrimSpace(b); len(b) > 0 {
			var l accessLine
			if json.Unmarshal(b, &l) != nil || !l.usable() {
				skipped++
			} else {
				lines = append(lines, l)
			}
		}
		if err != nil {
			break
		}
	}
	now := s.now()
	for i := range lines {
		l := &lines[i]
		s.routeAgg.add(l.hour(now), l.route(pats), l, now)
	}
	accepted := len(lines)
	s.met.linesAccepted.Add(uint64(accepted))
	s.met.linesRejected.Add(uint64(skipped))
	return writeJSON(w, http.StatusAccepted, map[string]int{"accepted": accepted, "skipped": skipped})
}

// route is the line's route. A template or query shape too long for any
// pattern to group is attacker-shaped data, not a route, so it is counted as
// not grouped.
func (l *accessLine) route(pats []routePattern) routeKey {
	k := routeKey{host: l.Host, method: l.Method, template: templatePath(l.Host, l.Path, pats)}
	if len(k.template) > maxPattern || strings.Count(k.template, "/") > maxPatternSegs {
		return overflowRoute
	}
	return k
}

// --- Templates ---

// templatePath groups a path: the first matching operator pattern, or each
// segment that looks like an identifier replaced by a placeholder.
func templatePath(host, path string, pats []routePattern) string {
	segs := strings.Split(path, "/")[1:]
	for _, p := range pats {
		if (p.Host == "" || p.Host == host) && segmentsMatch(p.segs, segs) {
			return p.template()
		}
	}
	for i, s := range segs {
		segs[i] = segmentTemplate(s)
	}
	return "/" + strings.Join(segs, "/")
}

// segmentTemplate names what an identifier-like segment holds. Long
// segments are data rather than names, whatever they contain, and one with
// "@" is likely an email address. Query key names go through it too: a key
// can carry a token.
func segmentTemplate(s string) string {
	switch {
	case s == "":
		return s
	case all(s, isDigit):
		return "{id}"
	case isUUID(s):
		return "{uuid}"
	case len(s) >= 16 && all(s, isHex):
		return "{hex}"
	case len(s) > 64 || strings.Contains(s, "@") || len(s) >= 20 && all(s, isTokenByte) && strings.ContainsFunc(s, isDigitRune) && strings.ContainsFunc(s, isLetter):
		return "{token}"
	case strings.Contains(s, "."):
		// A file name such as app.3f9a1c2b7d.js carries its hash between
		// dots; versions such as v1.2 stay as they are.
		parts := strings.Split(s, ".")
		for i, p := range parts {
			switch {
			case len(p) >= 4 && all(p, isDigit):
				parts[i] = "{id}"
			case isUUID(p):
				parts[i] = "{uuid}"
			case len(p) >= 8 && all(p, isHex) && strings.ContainsFunc(p, isDigitRune):
				parts[i] = "{hex}"
			}
		}
		return strings.Join(parts, ".")
	}
	return s
}

func all(s string, f func(byte) bool) bool {
	for i := range len(s) {
		if !f(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool     { return c >= '0' && c <= '9' }
func isDigitRune(r rune) bool { return r >= '0' && r <= '9' }
func isLetter(r rune) bool    { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }
func isHex(c byte) bool       { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func isTokenByte(c byte) bool { return isDigit(c) || isLetter(rune(c)) || c == '-' || c == '_' }
func isUUIDDash(i int) bool   { return i == 8 || i == 13 || i == 18 || i == 23 }
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := range len(s) {
		if isUUIDDash(i) != (s[i] == '-') || s[i] != '-' && !isHex(s[i]) {
			return false
		}
	}
	return true
}

// routePattern is an operator grouping; "*" in segs stands for one segment.
type routePattern struct {
	ID        int64     `json:"id"`
	Host      string    `json:"host"`
	Pattern   string    `json:"pattern"`
	CreatedAt time.Time `json:"created_at"`
	segs      []string
}

// template is the route template a pattern groups under.
func (p routePattern) template() string { return strings.ReplaceAll(p.Pattern, "*", "{*}") }

// segmentsMatch reports whether pattern segments match path or template
// segments. "*" matches any one non-empty segment.
func segmentsMatch(pat, segs []string) bool {
	if len(pat) != len(segs) {
		return false
	}
	for i, p := range pat {
		if p == "*" && segs[i] == "" || p != "*" && p != segs[i] {
			return false
		}
	}
	return true
}

// patternProblem says what is wrong with a pattern, or "".
func patternProblem(host, pattern string) string {
	segs := strings.Split(pattern, "/")
	switch {
	case len(host) > 253 || host != strings.ToLower(host) || strings.ContainsAny(host, " /*\x00"):
		return "host must be empty for every host, or one lowercase host name"
	case !strings.HasPrefix(pattern, "/") || len(pattern) > maxPattern || len(segs) > maxPatternSegs+1 || strings.ContainsRune(pattern, 0):
		return "pattern must start with / and have at most 32 segments and 512 characters"
	case !slices.Contains(segs, "*"):
		return `pattern must have a segment that is just "*"`
	case slices.ContainsFunc(segs, func(s string) bool { return s != "*" && strings.Contains(s, "*") }):
		return `"*" must be a whole segment`
	}
	return ""
}

// routePatterns returns the patterns, most specific first: host patterns
// before every-host ones, then more literal segments first.
func (s *Server) routePatterns(ctx context.Context) ([]routePattern, error) {
	if p := s.patterns.Load(); p != nil {
		return *p, nil
	}
	return s.loadPatterns(ctx, s.db)
}

func (s *Server) loadPatterns(ctx context.Context, q querier) ([]routePattern, error) {
	rows, err := q.Query(ctx, "SELECT id, host, pattern, created_at FROM route_patterns")
	if err != nil {
		return nil, err
	}
	pats, err := pgx.CollectRows(rows, pgx.RowToStructByPos[routePattern])
	if err != nil {
		return nil, err
	}
	sortPatterns(pats)
	s.patterns.Store(&pats)
	return pats, nil
}

// sortPatterns orders patterns most specific first: host patterns before
// every-host ones, then more literal segments first.
func sortPatterns(pats []routePattern) {
	literal := func(p routePattern) int { return len(p.segs) - strings.Count(p.Pattern, "*") }
	for i := range pats {
		pats[i].segs = strings.Split(pats[i].Pattern, "/")[1:]
	}
	slices.SortFunc(pats, func(a, b routePattern) int {
		return cmp.Or(cmp.Compare(b.Host, a.Host), cmp.Compare(literal(b), literal(a)), cmp.Compare(a.ID, b.ID))
	})
}

// --- In-memory totals ---

type routeKey struct{ host, method, template string }

type hourRoute struct {
	hour  time.Time
	route routeKey
}

// routeTotals are one route's counts within one hour since the last flush.
type routeTotals struct {
	requests, versioned int64
	estimated           int64
	status              [6]int64
	codes               map[int]int64 // by status code; usable lines are below 600
	causes              map[string]int64
	latency             []int64
	decisions, config   map[string]int64
	rateLimit, shapes   map[string]int64
	first, last         time.Time
}

// routeAggregator holds deltas until the next flush takes them.
type routeAggregator struct {
	mu sync.Mutex
	m  map[hourRoute]*routeTotals
}

func newRouteAggregator() *routeAggregator {
	return &routeAggregator{m: map[hourRoute]*routeTotals{}}
}

func newRouteTotals(first time.Time) *routeTotals {
	return &routeTotals{latency: make([]int64, len(edge.LatencyBoundsMS)+1), first: first, last: first, codes: map[int]int64{}, causes: map[string]int64{},
		decisions: map[string]int64{}, config: map[string]int64{}, rateLimit: map[string]int64{}, shapes: map[string]int64{}}
}

func (a *routeAggregator) add(hour time.Time, k routeKey, l *accessLine, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	hk := hourRoute{hour, k}
	if a.m[hk] == nil && len(a.m) >= maxPendingRoutes {
		hk.route = overflowRoute // at most one more entry per hour
	}
	t := a.m[hk]
	if t == nil {
		t = newRouteTotals(now)
		a.m[hk] = t
	}
	t.last = now
	w := l.weight()
	t.requests += w
	if l.sampled() {
		t.estimated += w
	}
	if l.Version != 0 {
		t.versioned += w
	}
	t.status[l.Status/100] += w
	t.codes[l.Status] += w
	// Only the edge's own cause names, so a shipper can't grow the map.
	if slices.Contains(edge.UpstreamCauses[:], l.UpstreamErrorKind) {
		t.causes[l.UpstreamErrorKind] += w
	}
	i := 0
	for i < len(edge.LatencyBoundsMS) && l.DurationMS > edge.LatencyBoundsMS[i] {
		i++
	}
	t.latency[i] += w
	addCapped(t.decisions, l.Decision, w, maxRuleKeys)
	for _, id := range l.ConfigRules {
		addCapped(t.config, id, w, maxRuleKeys)
	}
	if l.RateLimitRule != "" {
		addCapped(t.rateLimit, l.RateLimitRule, w, maxRuleKeys)
	}
	keys := make([]string, len(l.QueryKeys))
	for i, q := range l.QueryKeys {
		keys[i] = segmentTemplate(q)
	}
	shape := strings.Join(keys, "&")
	if len(shape) > maxShape {
		shape = otherKey
	}
	addCapped(t.shapes, shape, w, maxShapes)
}

// addCapped adds n under k, or under otherKey once m holds limit keys.
func addCapped(m map[string]int64, k string, n int64, limit int) {
	if _, ok := m[k]; !ok && len(m) >= limit {
		k = otherKey
	}
	m[k] += n
}

func (a *routeAggregator) take() map[hourRoute]*routeTotals {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.m
	a.m = map[hourRoute]*routeTotals{}
	return m
}

// flushRoutes adds the held deltas to Postgres. Every replica adds to the
// same rows, so no row is read back and rewritten. On failure the deltas
// are dropped: route stats never block or grow memory.
func (s *Server) flushRoutes(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, flushTimeout)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// SHARE conflicts with createPattern's SHARE ROW EXCLUSIVE but not with
	// other flushes, so no pattern is created between loading the patterns
	// and writing routes it would have merged.
	if _, err := tx.Exec(ctx, "LOCK TABLE route_patterns IN SHARE MODE"); err != nil {
		return err
	}
	pats, err := s.loadPatterns(ctx, tx)
	if err != nil {
		return err
	}
	held := s.routeAgg.take()
	if len(held) == 0 {
		return nil
	}
	// A pattern created since these lines arrived, here or on another
	// replica, groups them now; otherwise they would bring back the routes
	// it merged.
	for k, t := range held {
		tmpl := templatePath(k.route.host, k.route.template, pats)
		if k.route == overflowRoute || tmpl == k.route.template {
			continue
		}
		delete(held, k)
		nk := hourRoute{k.hour, routeKey{k.route.host, k.route.method, tmpl}}
		if held[nk] == nil {
			held[nk] = t
		} else {
			held[nk].merge(t)
		}
	}
	if err := s.capRoutes(ctx, held); err != nil {
		return fmt.Errorf("route flush dropped %d route hours: %w", len(held), err)
	}
	// Rows are locked in byte order on every replica, as mergeIntoPattern
	// locks them, so flushes and pattern creates never deadlock.
	b := &pgx.Batch{}
	for _, k := range slices.SortedFunc(maps.Keys(held), func(a, b hourRoute) int {
		return cmp.Or(cmp.Compare(a.route.host, b.route.host), cmp.Compare(a.route.method, b.route.method),
			cmp.Compare(a.route.template, b.route.template), a.hour.Compare(b.hour))
	}) {
		t := held[k]
		b.Queue(`WITH r AS (
				INSERT INTO observed_routes (host, method, template, first_seen, last_seen, errors_only) VALUES ($1, $2, $3, $4, $5, $16)
				ON CONFLICT (host, method, template) DO UPDATE SET last_seen = greatest(observed_routes.last_seen, EXCLUDED.last_seen),
					errors_only = observed_routes.errors_only AND EXCLUDED.errors_only
				RETURNING id)
			INSERT INTO observed_route_hour AS h (route_id, hour, requests, versioned, status, latency_ms, decisions, config_rules, rate_limit_rules, query_shapes, estimated, status_codes, upstream_errors)
			SELECT id, $6, $7, $8, $9::bigint[], $10::bigint[], $11::jsonb, $12::jsonb, $13::jsonb, $14::jsonb, $15, $17::jsonb, $18::jsonb FROM r
			ON CONFLICT (route_id, hour) DO UPDATE SET requests = h.requests + EXCLUDED.requests, versioned = h.versioned + EXCLUDED.versioned,
				estimated = h.estimated + EXCLUDED.estimated, status_codes = add_counts(h.status_codes, EXCLUDED.status_codes, 600),
				upstream_errors = add_counts(h.upstream_errors, EXCLUDED.upstream_errors, 20),
				status = add_counts(h.status, EXCLUDED.status), latency_ms = add_counts(h.latency_ms, EXCLUDED.latency_ms),
				decisions = add_counts(h.decisions, EXCLUDED.decisions, 200), config_rules = add_counts(h.config_rules, EXCLUDED.config_rules, 200),
				rate_limit_rules = add_counts(h.rate_limit_rules, EXCLUDED.rate_limit_rules, 200), query_shapes = add_counts(h.query_shapes, EXCLUDED.query_shapes, 20)`,
			k.route.host, k.route.method, k.route.template, t.first, t.last,
			k.hour, t.requests, t.versioned, t.status[:], t.latency, t.decisions, t.config, t.rateLimit, t.shapes, t.estimated, t.errorsOnly(), t.codes, t.causes)
	}
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return fmt.Errorf("route flush dropped %d route hours: %w", len(held), err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("route flush dropped %d route hours: %w", len(held), err)
	}
	return nil
}

// capRoutes moves totals to overflowRoute for a new route past its budget,
// or for an errors-only route's first success when the main budget is
// spent. Replicas flushing at once can
// each spend the remaining budget, so the table can overshoot by that much.
func (s *Server) capRoutes(ctx context.Context, held map[hourRoute]*routeTotals) error {
	var hosts, methods, templates []string
	for k := range held {
		hosts, methods, templates = append(hosts, k.route.host), append(methods, k.route.method), append(templates, k.route.template)
	}
	var stored, storedErrors int
	if err := s.db.QueryRow(ctx, "SELECT count(*) FILTER (WHERE NOT errors_only), count(*) FILTER (WHERE errors_only) FROM observed_routes").Scan(&stored, &storedErrors); err != nil {
		return err
	}
	rows, err := s.db.Query(ctx, `SELECT host, method, template, errors_only FROM observed_routes
		WHERE (host, method, template) IN (SELECT * FROM unnest($1::text[], $2::text[], $3::text[]))`, hosts, methods, templates)
	if err != nil {
		return err
	}
	// known maps each stored or admitted route to whether it is errors only.
	known := map[routeKey]bool{}
	var k routeKey
	var errorsOnly bool
	if _, err := pgx.ForEachRow(rows, []any{&k.host, &k.method, &k.template, &errorsOnly}, func() error { known[k] = errorsOnly; return nil }); err != nil {
		return err
	}
	budget, errBudget := maxRoutes-stored, maxErrorRoutes-storedErrors
	for _, hk := range slices.SortedFunc(maps.Keys(held), func(a, b hourRoute) int { return cmp.Compare(held[b].requests, held[a].requests) }) {
		t := held[hk]
		wasErrors, ok := known[hk.route]
		switch {
		case hk.route == overflowRoute, ok && (!wasErrors || t.errorsOnly()):
			continue
		// A route seen only with errors takes from its own budget: a
		// scanner's 404s and rejections must not fill the table. Its first
		// success moves it to the main budget, or a 404 then a 200 on
		// made-up paths would grow the table past both.
		case t.errorsOnly() && errBudget > 0:
			errBudget--
			known[hk.route] = true
			continue
		case !t.errorsOnly() && budget > 0:
			budget--
			known[hk.route] = false
			continue
		}
		delete(held, hk)
		o := hourRoute{hk.hour, overflowRoute}
		if held[o] == nil {
			held[o] = newRouteTotals(t.first)
		}
		held[o].merge(t)
	}
	return nil
}

// errorsOnly reports whether every answer in these totals was an error.
func (t *routeTotals) errorsOnly() bool { return t.status[1]+t.status[2]+t.status[3] == 0 }

func (t *routeTotals) merge(o *routeTotals) {
	t.requests += o.requests
	t.versioned += o.versioned
	t.estimated += o.estimated
	for i := range t.status {
		t.status[i] += o.status[i]
	}
	for code, n := range o.codes {
		t.codes[code] += n
	}
	for c, n := range o.causes {
		t.causes[c] += n
	}
	for i := range t.latency {
		t.latency[i] += o.latency[i]
	}
	for _, p := range [][2]map[string]int64{{t.decisions, o.decisions}, {t.config, o.config}, {t.rateLimit, o.rateLimit}} {
		for k, n := range p[1] {
			addCapped(p[0], k, n, maxRuleKeys)
		}
	}
	for k, n := range o.shapes {
		addCapped(t.shapes, k, n, maxShapes)
	}
	t.first, t.last = minTime(t.first, o.first), maxTime(t.last, o.last)
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// --- Reading ---

// routeStats are one route's totals over a time range.
type routeStats struct {
	ID        int64     `json:"id"`
	Host      string    `json:"host"`
	Method    string    `json:"method"`
	Template  string    `json:"template"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Requests  int64     `json:"requests"`
	Versioned int64     `json:"-"`
	// Estimated is the part of Requests counted from sampled lines.
	Estimated int64 `json:"estimated"`
	// ErrorsOnly is set while the route has only ever been answered with
	// errors.
	ErrorsOnly     bool             `json:"errors_only"`
	Status         []int64          `json:"status"`
	LatencyMS      []int64          `json:"latency_ms_buckets"`
	Decisions      map[string]int64 `json:"decisions"`
	ConfigRules    map[string]int64 `json:"config_rules"`
	RateLimitRules map[string]int64 `json:"rate_limit_rules"`
	QueryShapes    map[string]int64 `json:"query_shapes"`
	P50MS          float64          `json:"p50_ms"`
	P95MS          float64          `json:"p95_ms"`
}

const routeStatsSelect = `SELECT r.id, r.host, r.method, r.template, r.first_seen, r.last_seen, r.errors_only,
	sum(h.requests)::bigint, sum(h.versioned)::bigint, sum(h.estimated)::bigint, sum_counts(h.status), sum_counts(h.latency_ms),
	add_counts(sum_counts(h.decisions), '{}', 200), add_counts(sum_counts(h.config_rules), '{}', 200),
	add_counts(sum_counts(h.rate_limit_rules), '{}', 200), add_counts(sum_counts(h.query_shapes), '{}', 20)
	FROM observed_routes r JOIN observed_route_hour h ON h.route_id = r.id`

func scanRouteStats(row pgx.CollectableRow) (routeStats, error) {
	var r routeStats
	err := row.Scan(&r.ID, &r.Host, &r.Method, &r.Template, &r.FirstSeen, &r.LastSeen, &r.ErrorsOnly, &r.Requests, &r.Versioned, &r.Estimated,
		&r.Status, &r.LatencyMS, &r.Decisions, &r.ConfigRules, &r.RateLimitRules, &r.QueryShapes)
	r.P50MS, r.P95MS = quantileMS(r.LatencyMS, 0.5), quantileMS(r.LatencyMS, 0.95)
	return r, err
}

// quantileMS is the upper bound of the latency bucket holding quantile q.
func quantileMS(buckets []int64, q float64) float64 {
	var total int64
	for _, n := range buckets {
		total += n
	}
	var seen int64
	for i, n := range buckets {
		seen += n
		if total > 0 && float64(seen) >= q*float64(total) {
			if i < len(edge.LatencyBoundsMS) {
				return edge.LatencyBoundsMS[i]
			}
			return 2 * edge.LatencyBoundsMS[len(edge.LatencyBoundsMS)-1]
		}
	}
	return 0
}

// since reads ?hours= (default 24, at most the retention) as the start of
// the range, on an hour boundary.
func (s *Server) since(r *http.Request) (time.Time, error) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > retentionDays*24 {
			return time.Time{}, fail(http.StatusBadRequest, fmt.Sprintf("hours must be 1 to %d", retentionDays*24))
		}
		hours = n
	}
	return s.now().UTC().Truncate(time.Hour).Add(-time.Duration(hours-1) * time.Hour), nil
}

// routeSuggestion proposes a pattern for many sibling routes.
type routeSuggestion struct {
	Host    string `json:"host"`
	Pattern string `json:"pattern"`
	Routes  int    `json:"routes"`
}

// minSiblings is how many literal routes under one parent make a pattern
// worth suggesting.
const minSiblings = 20

func (s *Server) listObserved(w http.ResponseWriter, r *http.Request, _ *principal) error {
	since, err := s.since(r)
	if err != nil {
		return err
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 {
			return fail(http.StatusBadRequest, "limit must be a positive integer")
		}
	}
	rows, err := s.db.Query(r.Context(), routeStatsSelect+` WHERE h.hour >= $1 GROUP BY r.id ORDER BY sum(h.requests) DESC, r.id`, since)
	if err != nil {
		return err
	}
	all, err := pgx.CollectRows(rows, scanRouteStats)
	if err != nil {
		return err
	}
	out := struct {
		Since       time.Time         `json:"since"`
		Routes      []routeStats      `json:"routes"`
		NotGrouped  int64             `json:"not_grouped"`
		Logged      int64             `json:"logged_requests"`
		Estimated   int64             `json:"estimated_requests"`
		Reported    int64             `json:"reported_requests"`
		Suggestions []routeSuggestion `json:"suggestions"`
		// More counts the routes limit left out.
		More      int `json:"more"`
		MaxRoutes int `json:"max_routes"`
		MaxErrors int `json:"max_error_routes"`
	}{Since: since, Routes: []routeStats{}, MaxRoutes: maxRoutes, MaxErrors: maxErrorRoutes}
	for _, rs := range all {
		out.Logged += rs.Versioned
		out.Estimated += rs.Estimated
		if (routeKey{rs.Host, rs.Method, rs.Template}) == overflowRoute {
			out.NotGrouped = rs.Requests
			continue
		}
		out.Routes = append(out.Routes, rs)
	}
	if err := s.db.QueryRow(r.Context(), "SELECT coalesce(sum(requests), 0)::bigint FROM edge_stats_minute WHERE minute >= $1", since).Scan(&out.Reported); err != nil {
		return err
	}
	pats, err := s.routePatterns(r.Context())
	if err != nil {
		return err
	}
	out.Suggestions = suggestPatterns(out.Routes, pats)
	if limit > 0 && len(out.Routes) > limit {
		out.More, out.Routes = len(out.Routes)-limit, out.Routes[:limit]
	}
	return writeJSON(w, http.StatusOK, out)
}

// suggestPatterns finds parents with at least minSiblings literal children
// that no pattern covers yet, such as many /blog/<slug> routes.
func suggestPatterns(routes []routeStats, pats []routePattern) []routeSuggestion {
	type parent struct{ host, path string }
	kids := map[parent]map[string]bool{}
	for _, r := range routes {
		i := strings.LastIndexByte(r.Template, '/')
		last := r.Template[i+1:]
		if last == "" || strings.HasPrefix(last, "{") {
			continue
		}
		p := parent{r.Host, r.Template[:i]}
		if kids[p] == nil {
			kids[p] = map[string]bool{}
		}
		kids[p][last] = true
	}
	out := []routeSuggestion{}
	for p, k := range kids {
		pattern := p.path + "/*"
		taken := slices.ContainsFunc(pats, func(x routePattern) bool { return x.Pattern == pattern && (x.Host == "" || x.Host == p.host) })
		if len(k) >= minSiblings && !taken {
			out = append(out, routeSuggestion{Host: p.host, Pattern: pattern, Routes: len(k)})
		}
	}
	slices.SortFunc(out, func(a, b routeSuggestion) int {
		return cmp.Or(cmp.Compare(b.Routes, a.Routes), cmp.Compare(a.Host, b.Host), cmp.Compare(a.Pattern, b.Pattern))
	})
	return out
}

// routeID reads the {id} path value.
func routeID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		return 0, fail(http.StatusNotFound, "no such route")
	}
	return id, nil
}

// loadRoute returns a route's identity, or 404.
func (s *Server) loadRoute(ctx context.Context, q querier, id int64) (routeKey, error) {
	var k routeKey
	err := q.QueryRow(ctx, "SELECT host, method, template FROM observed_routes WHERE id = $1", id).Scan(&k.host, &k.method, &k.template)
	if errors.Is(err, pgx.ErrNoRows) || k == overflowRoute {
		return k, fail(http.StatusNotFound, "no such route")
	}
	return k, err
}

func (s *Server) getObserved(w http.ResponseWriter, r *http.Request, _ *principal) error {
	id, err := routeID(r)
	if err != nil {
		return err
	}
	since, err := s.since(r)
	if err != nil {
		return err
	}
	k, err := s.loadRoute(r.Context(), s.db, id)
	if err != nil {
		return err
	}
	rows, err := s.db.Query(r.Context(), routeStatsSelect+` WHERE r.id = $1 AND h.hour >= $2 GROUP BY r.id`, id, since)
	if err != nil {
		return err
	}
	found, err := pgx.CollectRows(rows, scanRouteStats)
	if err != nil {
		return err
	}
	type point struct {
		Hour     time.Time        `json:"hour"`
		Requests int64            `json:"requests"`
		Status   []int64          `json:"status"`
		Decision map[string]int64 `json:"decisions"`
	}
	rows, err = s.db.Query(r.Context(), `SELECT hour, requests, status, decisions FROM observed_route_hour WHERE route_id = $1 AND hour >= $2 ORDER BY hour`, id, since)
	if err != nil {
		return err
	}
	series, err := pgx.CollectRows(rows, pgx.RowToStructByPos[point])
	if err != nil {
		return err
	}
	out := struct {
		routeStats
		// StatusCodes are answers by code, weighted like Status, and
		// UpstreamErrors the edge's failures by cause. Only the detail reads
		// them: summing them for every route would slow the list.
		StatusCodes    map[int]int64    `json:"status_codes"`
		UpstreamErrors map[string]int64 `json:"upstream_errors"`
		Since          time.Time        `json:"since"`
		Series         []point          `json:"series"`
	}{Since: since, Series: orEmpty(series)}
	if err := s.db.QueryRow(r.Context(), "SELECT coalesce(sum_counts(status_codes), '{}'), coalesce(sum_counts(upstream_errors), '{}') FROM observed_route_hour WHERE route_id = $1 AND hour >= $2", id, since).
		Scan(&out.StatusCodes, &out.UpstreamErrors); err != nil {
		return err
	}
	if len(found) == 1 {
		out.routeStats = found[0]
	} else {
		// Seen before the range, quiet within it.
		out.routeStats = routeStats{ID: id, Host: k.host, Method: k.method, Template: k.template, Status: []int64{},
			LatencyMS: []int64{}, Decisions: map[string]int64{}, ConfigRules: map[string]int64{}, RateLimitRules: map[string]int64{}, QueryShapes: map[string]int64{}}
		if err := s.db.QueryRow(r.Context(), "SELECT first_seen, last_seen FROM observed_routes WHERE id = $1", id).Scan(&out.FirstSeen, &out.LastSeen); err != nil {
			return err
		}
	}
	return writeJSON(w, http.StatusOK, out)
}

// routeName is how audit rows and messages name a route.
func (k routeKey) String() string { return k.method + " " + k.host + k.template }

func (s *Server) deleteObserved(w http.ResponseWriter, r *http.Request, p *principal) error {
	id, err := routeID(r)
	if err != nil {
		return err
	}
	err = s.change(r.Context(), p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		k, err := s.loadRoute(r.Context(), tx, id)
		if err != nil {
			return admindb.Event{}, err
		}
		_, err = tx.Exec(r.Context(), "DELETE FROM observed_routes WHERE id = $1", id)
		return admindb.Event{Action: "route.delete", Target: k.String()}, err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) deleteAllObserved(w http.ResponseWriter, r *http.Request, p *principal) error {
	err := s.change(r.Context(), p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		tag, err := tx.Exec(r.Context(), "DELETE FROM observed_routes")
		return admindb.Event{Action: "route.delete_all", Details: map[string]any{"routes": tag.RowsAffected()}}, err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// --- Patterns ---

func (s *Server) listPatterns(w http.ResponseWriter, r *http.Request, _ *principal) error {
	pats, err := s.loadPatterns(r.Context(), s.db)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, orEmpty(pats))
}

// createPattern stores a pattern and merges the routes it covers into one,
// in the same transaction, so their history stays together.
func (s *Server) createPattern(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Host    string `json:"host"`
		Pattern string `json:"pattern"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	if why := patternProblem(in.Host, in.Pattern); why != "" {
		return fail(http.StatusUnprocessableEntity, why)
	}
	ctx := r.Context()
	pat := routePattern{Host: in.Host, Pattern: in.Pattern, segs: strings.Split(in.Pattern, "/")[1:]}
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		// One create at a time: the count check and the merge read what the
		// previous create wrote.
		if _, err := tx.Exec(ctx, "LOCK TABLE route_patterns IN SHARE ROW EXCLUSIVE MODE"); err != nil {
			return admindb.Event{}, err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM route_patterns").Scan(&n); err != nil {
			return admindb.Event{}, err
		}
		if n >= maxPatterns {
			return admindb.Event{}, fail(http.StatusUnprocessableEntity, fmt.Sprintf("at most %d patterns are allowed", maxPatterns))
		}
		if err := tx.QueryRow(ctx, "INSERT INTO route_patterns (host, pattern, created_at) VALUES ($1, $2, $3) RETURNING id", in.Host, in.Pattern, s.now()).Scan(&pat.ID); err != nil {
			return admindb.Event{}, err
		}
		merged, err := mergeIntoPattern(ctx, tx, pat)
		return admindb.Event{Action: "route_pattern.create", Target: patternName(pat), Details: map[string]any{"merged_routes": merged}}, err
	})
	if err != nil {
		return err
	}
	if _, err := s.loadPatterns(ctx, s.db); err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]int64{"id": pat.ID})
}

func patternName(p routePattern) string {
	if p.Host == "" {
		return "every host " + p.Pattern
	}
	return p.Host + p.Pattern
}

// mergeIntoPattern folds every route the pattern covers into the pattern's
// route, per host and method, and returns how many routes it folded.
func mergeIntoPattern(ctx context.Context, tx pgx.Tx, pat routePattern) (int, error) {
	// A route moves only if ingest would now group it under pat: a more
	// specific pattern keeps its routes. Rows are locked in the order flushes
	// lock them: byte order, whatever the database collation.
	prows, err := tx.Query(ctx, "SELECT id, host, pattern, created_at FROM route_patterns")
	if err != nil {
		return 0, err
	}
	pats, err := pgx.CollectRows(prows, pgx.RowToStructByPos[routePattern])
	if err != nil {
		return 0, err
	}
	sortPatterns(pats)
	rows, err := tx.Query(ctx, `SELECT id, host, method, template FROM observed_routes WHERE ($1 = '' OR host = $1) AND template <> '*'
		ORDER BY host COLLATE "C", method COLLATE "C", template COLLATE "C" FOR UPDATE`, pat.Host)
	if err != nil {
		return 0, err
	}
	groups := map[routeKey][]int64{}
	var id int64
	var k routeKey
	if _, err := pgx.ForEachRow(rows, []any{&id, &k.host, &k.method, &k.template}, func() error {
		if k.template != pat.template() && templatePath(k.host, k.template, pats) == pat.template() {
			target := routeKey{k.host, k.method, pat.template()}
			groups[target] = append(groups[target], id)
		}
		return nil
	}); err != nil {
		return 0, err
	}
	merged := 0
	for target, ids := range groups {
		var tid int64
		err := tx.QueryRow(ctx, `INSERT INTO observed_routes (host, method, template, first_seen, last_seen, errors_only)
			SELECT $1, $2, $3, min(first_seen), max(last_seen), bool_and(errors_only) FROM observed_routes WHERE id = ANY($4)
			ON CONFLICT (host, method, template) DO UPDATE SET first_seen = least(observed_routes.first_seen, EXCLUDED.first_seen),
				last_seen = greatest(observed_routes.last_seen, EXCLUDED.last_seen), errors_only = observed_routes.errors_only AND EXCLUDED.errors_only
			RETURNING id`, target.host, target.method, target.template, ids).Scan(&tid)
		if err != nil {
			return 0, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO observed_route_hour AS h (route_id, hour, requests, versioned, status, latency_ms, decisions, config_rules, rate_limit_rules, query_shapes, estimated, status_codes, upstream_errors)
			SELECT $1, hour, sum(requests), sum(versioned), sum_counts(status), sum_counts(latency_ms), add_counts(sum_counts(decisions), '{}', 200),
				add_counts(sum_counts(config_rules), '{}', 200), add_counts(sum_counts(rate_limit_rules), '{}', 200), add_counts(sum_counts(query_shapes), '{}', 20), sum(estimated),
				sum_counts(status_codes), sum_counts(upstream_errors)
			FROM observed_route_hour WHERE route_id = ANY($2) GROUP BY hour
			ON CONFLICT (route_id, hour) DO UPDATE SET requests = h.requests + EXCLUDED.requests, versioned = h.versioned + EXCLUDED.versioned,
				estimated = h.estimated + EXCLUDED.estimated, status_codes = add_counts(h.status_codes, EXCLUDED.status_codes, 600),
				upstream_errors = add_counts(h.upstream_errors, EXCLUDED.upstream_errors, 20),
				status = add_counts(h.status, EXCLUDED.status), latency_ms = add_counts(h.latency_ms, EXCLUDED.latency_ms),
				decisions = add_counts(h.decisions, EXCLUDED.decisions, 200), config_rules = add_counts(h.config_rules, EXCLUDED.config_rules, 200),
				rate_limit_rules = add_counts(h.rate_limit_rules, EXCLUDED.rate_limit_rules, 200), query_shapes = add_counts(h.query_shapes, EXCLUDED.query_shapes, 20)`,
			tid, ids)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM observed_routes WHERE id = ANY($1)", ids); err != nil {
			return 0, err
		}
		merged += len(ids)
	}
	return merged, nil
}

func (s *Server) deletePattern(w http.ResponseWriter, r *http.Request, p *principal) error {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return fail(http.StatusNotFound, "no such pattern")
	}
	err = s.change(r.Context(), p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		var pat routePattern
		err := tx.QueryRow(r.Context(), "DELETE FROM route_patterns WHERE id = $1 RETURNING host, pattern", id).Scan(&pat.Host, &pat.Pattern)
		if errors.Is(err, pgx.ErrNoRows) {
			err = fail(http.StatusNotFound, "no such pattern")
		}
		return admindb.Event{Action: "route_pattern.delete", Target: patternName(pat)}, err
	})
	if err != nil {
		return err
	}
	if _, err := s.loadPatterns(r.Context(), s.db); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
