package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// A real edge loads its policy from admin and reports back: the snapshot
// and report formats can't drift apart.
func TestEdgeRunsOnAdmin(t *testing.T) {
	h, pub := published(t)
	plain := httptest.NewServer(h.s.Handler()) // the edge's admin client trusts the system pool only
	t.Cleanup(plain.Close)
	cfg, err := edge.LoadConfig(env(map[string]string{
		"ADMIN_URL": plain.URL, "EDGE_SERVICE_TOKEN": h.edgeToken(pub), "STATS_INTERVAL": "50ms", "POLL_INTERVAL": "50ms",
		"CLIENT_IP_SOURCE": "cloudfront", "TRUSTED_PROXIES": "127.0.0.1/32", "UPSTREAM_URL": "http://127.0.0.1:1",
		"INSTANCE": "edge-a", "DRAIN_DELAY": "1ms",
	}))
	if err != nil {
		t.Fatal(err)
	}
	pubL, _ := net.Listen("tcp", "127.0.0.1:0")
	inL, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- edge.New(cfg, slog.New(slog.DiscardHandler), nil).Run(ctx, pubL, inL) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, func() bool {
		resp, err := http.Get("http://" + inL.Addr().String() + "/readyz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == 200
	})
	waitFor(t, func() bool {
		var n int
		_ = h.db.QueryRow(t.Context(), "SELECT count(*) FROM fleet WHERE instance = 'edge-a' AND versions = '{1}' AND config_source = 'admin'").Scan(&n)
		return n == 1
	})
	// A new version reaches the edge on its next poll.
	c := testConfig()
	c.RateLimitRules[0].Limit = 7
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	waitFor(t, func() bool {
		var n int
		_ = h.db.QueryRow(t.Context(), "SELECT count(*) FROM fleet WHERE instance = 'edge-a' AND 2 = ANY(versions)").Scan(&n)
		return n == 1
	})
}

func TestSnapshotEndpoint(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	e := h.client()
	e.token = h.edgeToken(pub)
	status(t, e.do("GET", "/v1/snapshot", nil), 503) // nothing published: edges use cache or bootstrap
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v1"), 201)

	resp := e.do("GET", "/v1/snapshot", nil)
	tag := resp.Header.Get("ETag")
	var env snapshot.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil || env.Active.Version != 1 || env.ExportedAt.IsZero() || tag == "" {
		t.Fatalf("envelope %+v, tag %q, %v", env, tag, err)
	}
	status(t, e.do("GET", "/v1/snapshot", nil, "If-None-Match", tag), 304)
	status(t, pub.do("GET", "/v1/snapshot", nil), 403) // users aren't edges
	status(t, h.client().do("GET", "/v1/snapshot", nil), 401)
}

func TestReportsAreAggregated(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	rep := func(instance string, requests uint64, top ...edge.TopCount) {
		t.Helper()
		status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: instance, ConfigSource: "admin", Upstream: "https://lb.internal:443", Versions: []edge.StatsCounts{{
			Version: 1, Requests: requests, Edge5xx: 1, AuthFailures: 2, LatencyMS: []uint64{requests, 0, 1},
			RateLimit:  []edge.RuleCounts{{ID: "login", Evaluated: requests, Limited: 1}},
			TopLimited: top,
			Rules:      []edge.RuleOutcome{{Phase: "config", ID: "admin-route", Matched: requests, Upstream5xx: 1, AuthFailures: 1}},
		}}}), 200)
	}
	// k3 is a log-only rule's subject: its would-limit estimates sum apart from limited.
	rep("edge-a", 10, edge.TopCount{Rule: "login", Key: "k1", Display: "198.51.100.7", Limited: 16},
		edge.TopCount{Rule: "search", Key: "k3", Display: "198.51.100.9", WouldLimit: 16})
	rep("edge-b", 5, edge.TopCount{Rule: "login", Key: "k1", Display: "198.51.100.7", Limited: 32},
		edge.TopCount{Rule: "search", Key: "k3", Display: "198.51.100.9", WouldLimit: 16})
	status(t, e.do("POST", "/v1/edge/report", map[string]any{"instance": ""}), 422)
	status(t, e.do("POST", "/v1/edge/report", "not json"), 400)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Deployment: strings.Repeat("f", 65)}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Upstream: "https://lb\x00"}), 422)
	// A count no edge can reach would overflow the minute's sums and fail
	// the batch insert, dropping every edge's stats for that minute.
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, Requests: 1 << 63}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, LatencyMS: []uint64{1 << 63}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, RateLimit: []edge.RuleCounts{{ID: "login", Limited: 1 << 63}}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, TopLimited: []edge.TopCount{{Key: "k", Limited: 1 << 63}}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, TopLimited: []edge.TopCount{{Key: "k", WouldLimit: 1 << 63}}}}}), 422)
	// Postgres refuses NUL in jsonb; one in the batch would fail it the same way.
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, TopLimited: []edge.TopCount{{Rule: "login", Key: "k2", Display: "q=\x00", Limited: 1}}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, RateLimit: []edge.RuleCounts{{ID: "lo\x00gin", Limited: 1}}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, Rules: []edge.RuleOutcome{{Phase: "config", ID: "a\x00", Matched: 1}}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, Rules: []edge.RuleOutcome{{Phase: "config", ID: "a", Matched: 1 << 63}}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, Rules: []edge.RuleOutcome{{Phase: "rate_limit", ID: "a", Matched: 1}}}}}), 422)
	fleet := decode[[]struct {
		Instance string
		Upstream string
		Live     bool
	}](t, pub.do("GET", "/api/fleet", nil))
	if len(fleet) != 2 || !fleet[0].Live || fleet[0].Upstream != "https://lb.internal:443" {
		t.Fatalf("fleet %+v", fleet)
	}
	if env := decode[snapshot.Envelope](t, e.do("GET", "/v1/snapshot", nil)); env.FleetSize != 2 {
		t.Fatalf("fleet size %d", env.FleetSize)
	}
	// Each answer carries the live fleet size; an edge joining doesn't
	// change the snapshot, so no edge downloads and recompiles it.
	tag := e.do("GET", "/v1/snapshot", nil).Header.Get("ETag")
	if a := decode[edge.ReportAnswer](t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c"})); a.FleetSize != 3 {
		t.Fatalf("answer %+v", a)
	}
	status(t, e.do("GET", "/v1/snapshot", nil, "If-None-Match", tag), 304)
	// Every refused report above counts as invalid: the edge sent it wrong.
	h.wantMetrics(`admin_edge_reports_total{result="accepted"} 3`, `admin_edge_reports_total{result="invalid"} 14`, `admin_edge_reports_total{result="error"} 0`)

	h.advance(time.Minute)
	if err := h.s.flush(t.Context(), h.now()); err != nil {
		t.Fatal(err)
	}
	rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=5", nil))
	if len(rows) != 1 || rows[0].Requests != 15 || rows[0].Edge5xx != 2 || rows[0].AuthFailures != 4 || !slices.Equal(rows[0].LatencyMS, []uint64{15, 0, 2}) ||
		rows[0].RateLimit[0] != (edge.RuleCounts{ID: "login", Evaluated: 15, Limited: 2}) || len(rows[0].TopLimited) != 2 || rows[0].TopLimited[0].Limited != 48 ||
		rows[0].TopLimited[1] != (edge.TopCount{Rule: "search", Key: "k3", Display: "198.51.100.9", WouldLimit: 32}) ||
		len(rows[0].Rules) != 1 || rows[0].Rules[0] != (edge.RuleOutcome{Phase: "config", ID: "admin-route", Matched: 15, Upstream5xx: 2, AuthFailures: 2}) {
		t.Fatalf("stats %+v", rows)
	}
	status(t, pub.do("GET", "/api/stats?minutes=0", nil), 400)

	// Old minutes, and edges gone as long, are dropped after 30 days.
	h.advance(31 * 24 * time.Hour)
	if err := h.s.dropOldStats(t.Context()); err != nil {
		t.Fatal(err)
	}
	var n, f int
	_ = h.db.QueryRow(t.Context(), "SELECT count(*) FROM edge_stats_minute").Scan(&n)
	_ = h.db.QueryRow(t.Context(), "SELECT count(*) FROM fleet").Scan(&f)
	if n != 0 || f != 0 {
		t.Fatalf("kept %d stats rows and %d fleet rows", n, f)
	}

	// With Postgres unreachable, a valid report fails on admin's side and
	// counts as an error, not as invalid.
	gone, err := pgxpool.New(t.Context(), h.s.cfg.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	gone.Close()
	h.s.edgeDB = gone
	b, _ := json.Marshal(edge.StatsReport{Instance: "edge-a", ConfigSource: "admin"})
	if err := h.s.report(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/edge/report", strings.NewReader(string(b))), nil); err == nil {
		t.Fatal("report stored with Postgres unreachable")
	}
	h.wantMetrics(`admin_edge_reports_total{result="accepted"} 3`, `admin_edge_reports_total{result="invalid"} 14`, `admin_edge_reports_total{result="error"} 1`)
}

// Reports carry status codes by origin. Admin sums them across edges on
// /api/stats, still accepts an edge that sends none, and refuses a code or
// count no edge can produce, which would otherwise fail the minute's insert.
func TestReportStatusCodes(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	report := func(instance string, requests uint64, codes any) *http.Response {
		t.Helper()
		v := map[string]any{"version": 1, "requests": requests, "latency_ms_buckets": []uint64{requests}}
		if codes != nil {
			v["status_codes"] = codes
		}
		return e.do("POST", "/v1/edge/report", map[string]any{"instance": instance, "config_source": "admin", "versions": []any{v}})
	}
	status(t, report("edge-a", 3, map[string]any{"edge": map[string]uint64{"502": 2}, "upstream": map[string]uint64{"200": 1}}), 200)
	// 0 is a request that got no answer, 600 any code above 599.
	status(t, report("edge-b", 5, map[string]any{"edge": map[string]uint64{"0": 1, "502": 1}, "upstream": map[string]uint64{"200": 1, "503": 1, "600": 1}}), 200)
	status(t, report("edge-c", 3, nil), 200) // an edge from before status codes
	status(t, report("edge-d", 1, map[string]any{"upstream": map[string]uint64{"601": 1}}), 422)
	status(t, report("edge-d", 3, map[string]any{"edge": map[string]uint64{"502": maxCount}}), 422)
	h.wantMetrics(`admin_edge_reports_total{result="accepted"} 3`, `admin_edge_reports_total{result="invalid"} 2`)

	h.advance(time.Minute)
	if err := h.s.flush(t.Context(), h.now()); err != nil {
		t.Fatal(err)
	}
	rows := decode[[]struct {
		Requests    uint64                       `json:"requests"`
		StatusCodes map[string]map[string]uint64 `json:"status_codes"`
	}](t, pub.do("GET", "/api/stats?minutes=5", nil))
	want := map[string]map[string]uint64{"edge": {"0": 1, "502": 3}, "upstream": {"200": 2, "503": 1, "600": 1}}
	if len(rows) != 1 || rows[0].Requests != 11 || fmt.Sprint(rows[0].StatusCodes) != fmt.Sprint(want) {
		t.Fatalf("stats %+v, want 11 requests and status codes %v", rows, want)
	}
}

// Reports carry the edge's upstream failures by cause. Admin sums them
// across edges on /api/stats, still accepts an edge that sends none, and
// refuses a cause or count no edge can produce.
func TestReportUpstreamErrorCauses(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	report := func(instance string, causes map[string]uint64) *http.Response {
		t.Helper()
		v := map[string]any{"version": 1, "requests": 3, "edge_5xx": 3, "latency_ms_buckets": []uint64{3}}
		if causes != nil {
			v["upstream_errors"] = causes
		}
		return e.do("POST", "/v1/edge/report", map[string]any{"instance": instance, "config_source": "admin", "versions": []any{v}})
	}
	status(t, report("edge-a", map[string]uint64{"dns": 2, "refused": 1}), 200)
	status(t, report("edge-b", map[string]uint64{"refused": 2, "timeout": 1}), 200)
	status(t, report("edge-c", nil), 200) // an edge from before causes were counted
	status(t, report("edge-d", map[string]uint64{"quota": 1}), 422)
	status(t, report("edge-d", map[string]uint64{"reset": maxCount}), 422)

	h.advance(time.Minute)
	if err := h.s.flush(t.Context(), h.now()); err != nil {
		t.Fatal(err)
	}
	rows := decode[[]struct {
		Requests       uint64            `json:"requests"`
		UpstreamErrors map[string]uint64 `json:"upstream_errors"`
	}](t, pub.do("GET", "/api/stats?minutes=5", nil))
	want := map[string]uint64{"dns": 2, "refused": 3, "timeout": 1}
	if len(rows) != 1 || rows[0].Requests != 9 || fmt.Sprint(rows[0].UpstreamErrors) != fmt.Sprint(want) {
		t.Fatalf("stats %+v, want 9 requests and upstream errors %v", rows, want)
	}
}

// The dashboard shows the minute in progress: each flush writes its running
// sum, and the next one replaces it rather than adding it twice.
func TestCurrentMinuteIsShownBeforeItEnds(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	report := func(requests uint64) {
		t.Helper()
		status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-a", ConfigSource: "admin", Versions: []edge.StatsCounts{{
			Version: 1, Requests: requests, LatencyMS: []uint64{requests},
			RateLimit:   []edge.RuleCounts{{ID: "login", Evaluated: requests, Limited: 1}},
			TopLimited:  []edge.TopCount{{Rule: "login", Key: "k1", Display: "198.51.100.7", Limited: 1}},
			StatusCodes: edge.StatusCodes{Upstream: map[int]uint64{200: requests}},
		}}}), 200)
	}
	requests := func() []statsRow {
		t.Helper()
		if err := h.s.flush(t.Context(), h.now()); err != nil {
			t.Fatal(err)
		}
		return decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=5", nil))
	}
	report(10)
	if rows := requests(); len(rows) != 1 || rows[0].Requests != 10 {
		t.Fatalf("after one report %+v", rows)
	}
	report(5)
	rows := requests()
	if len(rows) != 1 || rows[0].Requests != 15 || rows[0].RateLimit[0].Limited != 2 || len(rows[0].TopLimited) != 1 || rows[0].TopLimited[0].Limited != 2 ||
		rows[0].StatusCodes.Upstream[200] != 15 {
		t.Fatalf("after two reports %+v", rows)
	}
	h.advance(time.Minute)
	if rows := requests(); len(rows) != 1 || rows[0].Requests != 15 {
		t.Fatalf("after the minute ended %+v", rows)
	}
}

// During a rolling deploy that changes the edge's histogram, two replicas
// can write the same minute with different bucket counts. The merged minute
// keeps every bucket, so the guard's p99 doesn't lose the slow requests.
func TestStatsMergeKeepsEveryLatencyBucket(t *testing.T) {
	h, pub := published(t)
	h.putStats(1, 1, 10, 0, 0, []int64{10}, "[]", "[]")
	h.putStats(1, 1, 5, 0, 0, []int64{0, 0, 5}, "[]", "[]")
	rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=5", nil))
	if len(rows) != 1 || !slices.Equal(rows[0].LatencyMS, []uint64{10, 0, 5}) {
		t.Fatalf("stats %+v", rows)
	}
}

// With more than one admin replica, each writes its own row for the minute.
// /api/stats sums their status codes and upstream failure causes.
func TestStatsMergeSumsStatusCodesAcrossAdminReplicas(t *testing.T) {
	h, pub := published(t)
	minute := h.now().UTC().Truncate(time.Minute).Add(-time.Minute)
	for _, r := range []struct{ replica, codes, causes string }{
		{"admin-a", `{"edge":{"502":1}}`, `{"dns":1}`},
		{"admin-b", `{"edge":{"502":2},"upstream":{"200":5}}`, `{"dns":2,"refused":1}`},
	} {
		if _, err := h.db.Exec(t.Context(), `INSERT INTO edge_stats_minute (minute, version, replica, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited, status_codes, upstream_errors)
			VALUES ($1, 1, $2, 4, 0, 0, 0, '{4}', '[]', '[]', $3, $4)`, minute, r.replica, r.codes, r.causes); err != nil {
			t.Fatal(err)
		}
	}
	rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=5", nil))
	if len(rows) != 1 || !maps.Equal(rows[0].StatusCodes.Edge, map[int]uint64{502: 3}) || !maps.Equal(rows[0].StatusCodes.Upstream, map[int]uint64{200: 5}) ||
		!maps.Equal(rows[0].UpstreamErrors, map[string]uint64{"dns": 3, "refused": 1}) {
		t.Fatalf("stats %+v", rows)
	}
}

// Admin won't publish a schema the oldest live edge can't read; that edge
// would keep its old snapshot and the fleet would split.
func TestPublishWaitsForEdgesToReadTheSchema(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "old-edge", MaxSchema: 1}), 200)
	ctx := t.Context()
	err := pgx.BeginFunc(ctx, h.db, func(tx pgx.Tx) error { return h.s.checkSchema(ctx, tx, 2) })
	if p, ok := errors.AsType[*problem](err); !ok || p.Status != 409 || !strings.Contains(p.Detail, "edge old-edge reads config schema up to 1") {
		t.Fatalf("err %v", err)
	}
	if err := pgx.BeginFunc(ctx, h.db, func(tx pgx.Tx) error { return h.s.checkSchema(ctx, tx, 1) }); err != nil {
		t.Fatal(err)
	}
	// An edge gone longer than the fleet window no longer holds publishes back.
	h.advance(2 * time.Minute)
	if err := pgx.BeginFunc(ctx, h.db, func(tx pgx.Tx) error { return h.s.checkSchema(ctx, tx, 2) }); err != nil {
		t.Fatal(err)
	}
}

// max_inflight came with schema 3. A policy that sets it waits until every
// live edge reads schema 3, even when the policy itself is an older schema;
// the same policy without it publishes to those edges as before.
func TestPublishWithMaxInflightWaitsForEdgesThatReadIt(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "schema-2-edge", MaxSchema: 2, Deployment: h.s.cfg.Deployment.Fingerprint()}), 200)
	c := testConfig()
	c.Schema, c.Global.MaxInflight = 2, 500
	// A schema 2 policy predates the forbidden kind.
	delete(c.Global.Defaults.Responses, "forbidden")
	delete(c.Global.Responses, "forbidden")
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	if p := decode[problem](t, pub.publishDraft("lower the in-flight cap")); p.Status != 409 || !strings.Contains(p.Detail, "edge schema-2-edge reads config schema up to 2") {
		t.Fatalf("publish: %+v", p)
	}
	c.Global.MaxInflight = 0
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("same policy without it"), 201)
}

// Admin validates against its own copy of the deployment variables. If a
// live edge runs with different ones, it would reject what admin publishes,
// keep its old snapshot and never report the new version, so admin refuses.
func TestPublishWaitsForEdgesWithTheSameDeployment(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	ctx := t.Context()
	check := func() error {
		return pgx.BeginFunc(ctx, h.db, func(tx pgx.Tx) error { return h.s.checkDeployment(ctx, tx) })
	}
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-a", MaxSchema: snapshot.SupportedSchema, Deployment: h.s.cfg.Deployment.Fingerprint()}), 200)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "old-build", MaxSchema: snapshot.SupportedSchema}), 200) // predates the field
	if err := check(); err != nil {
		t.Fatalf("matching fleet: %v", err)
	}
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-b", MaxSchema: snapshot.SupportedSchema, Deployment: "0123456789abcdef"}), 200)
	if p, ok := errors.AsType[*problem](check()); !ok || p.Status != 409 || !strings.Contains(p.Detail, "edge edge-b") {
		t.Fatalf("drifted edge: %v", check())
	}
	if p := decode[problem](t, pub.publishDraft("blocked")); p.Status != 409 || !strings.Contains(p.Detail, "edge edge-b") {
		t.Fatalf("publish: %+v", p)
	}
	// A revert restores what edges already served, so an edge reporting a
	// different deployment, even a bogus one, can't block the way back.
	status(t, pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "roll back during drift"}), 201)
	// An edge gone longer than the fleet window no longer holds publishes back.
	h.advance(2 * time.Minute)
	if err := check(); err != nil {
		t.Fatal(err)
	}
}

// Admin UI work that holds every connection of the main pool, such as
// audit exports, must not hold up edges: a publish or rollback still
// reaches them, and their reports are still taken.
func TestEdgesAreServedWhileUIHoldsEveryConnection(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	edgeDB, err := pgxpool.New(t.Context(), h.db.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(edgeDB.Close)
	h.s.edgeDB = edgeDB
	for range h.db.Config().MaxConns {
		c, err := h.db.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Release)
	}
	done := make(chan [2]int, 1)
	go func() {
		snap := e.do("GET", "/v1/snapshot", nil).StatusCode
		done <- [2]int{snap, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-a"}).StatusCode}
	}()
	select {
	case got := <-done:
		if got != [2]int{200, 200} {
			t.Fatalf("snapshot and report answered %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("edge requests waited for a connection the UI holds")
	}
}

// Over a long range the dashboard asks for one row per step of minutes
// instead of one per minute: each bucket sums every replica's minutes of
// one version, and keeps the clients limited most.
func TestStatsBucketsByStep(t *testing.T) {
	h, pub := published(t)
	// 2m30s past a 5-minute boundary, so the rows below fall in two buckets.
	h.mu.Lock()
	h.clock = h.clock.UTC().Truncate(5 * time.Minute).Add(2*time.Minute + 30*time.Second)
	h.mu.Unlock()
	start := h.now().Truncate(5 * time.Minute)
	put := func(minute time.Time, version int64, replica string, requests int64, rateLimit, top string) {
		t.Helper()
		if _, err := h.db.Exec(t.Context(), `INSERT INTO edge_stats_minute (minute, version, replica, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited)
			VALUES ($1, $2, $3, $4, 1, 0, 0, $5, $6, $7)`, minute, version, replica, requests, []int64{requests}, rateLimit, top); err != nil {
			t.Fatal(err)
		}
	}
	login := func(n int) string { return fmt.Sprintf(`[{"id":"login","evaluated":%d,"limited":1}]`, n) }
	client := `[{"rule":"login","key":"k1","display":"198.51.100.7","limited":1}]`
	// Two minutes before the boundary and two after, from two replicas, for
	// two versions during a canary.
	for _, m := range []time.Time{start.Add(-2 * time.Minute), start.Add(-time.Minute), start, start.Add(time.Minute)} {
		for _, replica := range []string{"admin-a", "admin-b"} {
			put(m, 1, replica, 10, login(10), client)
			put(m, 2, replica, 1, login(1), "[]")
		}
	}

	t.Run("each bucket sums its minutes and replicas, one row per version", func(t *testing.T) {
		rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=10&step=5", nil))
		type got struct {
			minute            int64
			version           int64
			requests, edge5xx uint64
			evaluated         uint64
			latency           uint64
		}
		var have []got
		for _, r := range rows {
			g := got{minute: r.Minute.Unix(), version: r.Version, requests: r.Requests, edge5xx: r.Edge5xx}
			if len(r.RateLimit) == 1 {
				g.evaluated = r.RateLimit[0].Evaluated
			}
			if len(r.LatencyMS) > 0 {
				g.latency = r.LatencyMS[0]
			}
			have = append(have, g)
		}
		want := []got{
			{start.Add(-5 * time.Minute).Unix(), 1, 40, 4, 40, 40},
			{start.Add(-5 * time.Minute).Unix(), 2, 4, 4, 4, 4},
			{start.Unix(), 1, 40, 4, 40, 40},
			{start.Unix(), 2, 4, 4, 4, 4},
		}
		if !slices.Equal(have, want) {
			t.Fatalf("rows %+v, want %+v", have, want)
		}
	})
	t.Run("a client limited in several minutes of a bucket is one entry with their sum", func(t *testing.T) {
		rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=10&step=5", nil))
		if len(rows) == 0 || len(rows[0].TopLimited) != 1 || rows[0].TopLimited[0].Key != "k1" || rows[0].TopLimited[0].Limited != 4 {
			t.Fatalf("rows %+v", rows)
		}
	})
	t.Run("without a step each minute is its own row", func(t *testing.T) {
		if rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=10", nil)); len(rows) != 8 {
			t.Fatalf("got %d rows, want 4 minutes for 2 versions", len(rows))
		}
	})
	t.Run("a range starting inside a bucket returns that bucket whole", func(t *testing.T) {
		// 4 minutes back from 2m30s past the boundary starts 1m30s before it.
		rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=4&step=5", nil))
		if len(rows) == 0 || !rows[0].Minute.Equal(start.Add(-5*time.Minute)) || rows[0].Requests != 40 {
			t.Fatalf("rows %+v, want the bucket before the boundary with all 4 of its replica minutes", rows)
		}
	})
	t.Run("a bucket keeps the 20 most limited clients of each rule, a quiet rule's too", func(t *testing.T) {
		// signup's clients are all limited less than login's, so a cut across
		// rules would drop every one of them.
		var many []string
		for i := range 25 {
			many = append(many,
				fmt.Sprintf(`{"rule":"login","key":"m%02d","display":"203.0.113.%d","limited":%d}`, i, i, 100+i),
				fmt.Sprintf(`{"rule":"signup","key":"s%02d","display":"192.0.2.%d","limited":%d}`, i, i, 10+i))
		}
		put(start.Add(-3*time.Minute), 1, "admin-c", 1, "[]", "["+strings.Join(many, ",")+"]")
		rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=10&step=5", nil))
		if len(rows) == 0 {
			t.Fatal("no rows")
		}
		var keys []string
		for _, c := range rows[0].TopLimited {
			keys = append(keys, c.Rule+"/"+c.Key)
		}
		slices.Sort(keys)
		var want []string
		for i := 5; i < 25; i++ {
			want = append(want, fmt.Sprintf("login/m%02d", i))
		}
		for i := 5; i < 25; i++ {
			want = append(want, fmt.Sprintf("signup/s%02d", i))
		}
		if !slices.Equal(keys, want) {
			t.Fatalf("clients %v, want %v", keys, want)
		}
	})
	t.Run("a bucket whose replicas carry over 1000 clients together keeps the 20 most limited", func(t *testing.T) {
		// Each replica reports the same 20 heavy clients and 980 of its own
		// light ones, so the bucket sees 1980 clients in one minute.
		report := func(replica string) string {
			var top []string
			for i := range 20 {
				top = append(top, fmt.Sprintf(`{"rule":"login","key":"h%02d","display":"192.0.2.%d","limited":300}`, i, i))
			}
			for i := range 980 {
				top = append(top, fmt.Sprintf(`{"rule":"login","key":"%s-%03d","display":"198.51.100.%d","limited":1}`, replica, i, i%250))
			}
			return "[" + strings.Join(top, ",") + "]"
		}
		put(start.Add(time.Minute), 1, "admin-d", 1, "[]", report("d"))
		put(start.Add(time.Minute), 1, "admin-e", 1, "[]", report("e"))
		rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=10&step=5", nil))
		i := slices.IndexFunc(rows, func(r statsRow) bool { return r.Minute.Equal(start) && r.Version == 1 })
		if i < 0 {
			t.Fatalf("no bucket at %v for version 1 in %+v", start, rows)
		}
		var got []string
		for _, c := range rows[i].TopLimited {
			got = append(got, fmt.Sprintf("%s=%d", c.Key, c.Limited))
		}
		slices.Sort(got)
		var want []string
		for i := range 20 {
			want = append(want, fmt.Sprintf("h%02d=600", i))
		}
		if !slices.Equal(got, want) {
			t.Fatalf("clients %v, want %v", got, want)
		}
	})
	t.Run("a busy rule with over 1000 clients in a bucket leaves a quiet rule its 20 most limited", func(t *testing.T) {
		// Together the two replicas carry 1975 login clients, each limited
		// more than any of signup's 25.
		var f, g []string
		for i := range 1000 {
			f = append(f, fmt.Sprintf(`{"rule":"login","key":"f%03d","display":"198.51.100.%d","limited":50}`, i, i%250))
		}
		for i := range 975 {
			g = append(g, fmt.Sprintf(`{"rule":"login","key":"g%03d","display":"203.0.113.%d","limited":50}`, i, i%250))
		}
		for i := range 25 {
			g = append(g, fmt.Sprintf(`{"rule":"signup","key":"s%02d","display":"192.0.2.%d","limited":%d}`, i, i, 1+i))
		}
		put(start.Add(time.Minute), 2, "admin-f", 1, "[]", "["+strings.Join(f, ",")+"]")
		put(start.Add(time.Minute), 2, "admin-g", 1, "[]", "["+strings.Join(g, ",")+"]")
		rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=10&step=5", nil))
		i := slices.IndexFunc(rows, func(r statsRow) bool { return r.Minute.Equal(start) && r.Version == 2 })
		if i < 0 {
			t.Fatalf("no bucket at %v for version 2 in %+v", start, rows)
		}
		var got []string
		for _, c := range rows[i].TopLimited {
			if c.Rule == "signup" {
				got = append(got, fmt.Sprintf("%s=%d", c.Key, c.Limited))
			}
		}
		slices.Sort(got)
		var want []string
		for i := 5; i < 25; i++ {
			want = append(want, fmt.Sprintf("s%02d=%d", i, 1+i))
		}
		if !slices.Equal(got, want) {
			t.Fatalf("signup clients %v, want %v", got, want)
		}
	})
	for _, step := range []string{"7", "0", "x"} {
		t.Run(fmt.Sprintf("a step of %q, which does not divide a day into minutes, is refused", step), func(t *testing.T) {
			status(t, pub.do("GET", "/api/stats?minutes=10&step="+step, nil), 400)
		})
	}
}
