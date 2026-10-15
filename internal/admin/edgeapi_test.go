package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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
		"CLIENT_IP_SOURCE": "cloudfront", "TRUSTED_PROXIES": "127.0.0.1/32", "UPSTREAMS": "app=http://127.0.0.1:1,admin=http://127.0.0.1:1",
		"INSTANCE": "edge-a", "DRAIN_DELAY": "1ms",
	}))
	if err != nil {
		t.Fatal(err)
	}
	pubL, _ := net.Listen("tcp", "127.0.0.1:0")
	inL, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- edge.New(cfg, slog.New(slog.DiscardHandler)).Run(ctx, pubL, inL) }()
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
		status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: instance, ConfigSource: "admin", Versions: []edge.StatsCounts{{
			Version: 1, Requests: requests, Edge5xx: 1, AuthFailures: 2, LatencyMS: []uint64{requests, 0, 1},
			RateLimit:  []edge.RuleCounts{{ID: "login", Evaluated: requests, Limited: 1}},
			TopLimited: top,
		}}}), 200)
	}
	rep("edge-a", 10, edge.TopCount{Rule: "login", Key: "k1", Display: "198.51.100.7", Limited: 16})
	rep("edge-b", 5, edge.TopCount{Rule: "login", Key: "k1", Display: "198.51.100.7", Limited: 32})
	status(t, e.do("POST", "/v1/edge/report", map[string]any{"instance": ""}), 422)
	status(t, e.do("POST", "/v1/edge/report", "not json"), 400)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Deployment: strings.Repeat("f", 65)}), 422)
	// A count no edge can reach would overflow the minute's sums and fail
	// the batch insert, dropping every edge's stats for that minute.
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, Requests: 1 << 63}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, LatencyMS: []uint64{1 << 63}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, RateLimit: []edge.RuleCounts{{ID: "login", Limited: 1 << 63}}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, TopLimited: []edge.TopCount{{Key: "k", Limited: 1 << 63}}}}}), 422)
	// Postgres refuses NUL in jsonb; one in the batch would fail it the same way.
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, TopLimited: []edge.TopCount{{Rule: "login", Key: "k2", Display: "q=\x00", Limited: 1}}}}}), 422)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-c", Versions: []edge.StatsCounts{{Version: 1, RateLimit: []edge.RuleCounts{{ID: "lo\x00gin", Limited: 1}}}}}), 422)
	fleet := decode[[]struct {
		Instance string
		Live     bool
	}](t, pub.do("GET", "/api/fleet", nil))
	if len(fleet) != 2 || !fleet[0].Live {
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

	h.advance(time.Minute)
	if err := h.s.flush(t.Context(), h.now()); err != nil {
		t.Fatal(err)
	}
	rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=5", nil))
	if len(rows) != 1 || rows[0].Requests != 15 || rows[0].Edge5xx != 2 || rows[0].AuthFailures != 4 || !slices.Equal(rows[0].LatencyMS, []uint64{15, 0, 2}) ||
		rows[0].RateLimit[0] != (edge.RuleCounts{ID: "login", Evaluated: 15, Limited: 2}) || len(rows[0].TopLimited) != 1 || rows[0].TopLimited[0].Limited != 48 {
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
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-a", Deployment: h.s.cfg.Deployment.Fingerprint()}), 200)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "old-build"}), 200) // predates the field
	if err := check(); err != nil {
		t.Fatalf("matching fleet: %v", err)
	}
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-b", Deployment: "0123456789abcdef"}), 200)
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
