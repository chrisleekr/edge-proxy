package admin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
)

// Label values of the fixed series. Every one is exported from the start,
// at 0, so rate() sees the first event.
var (
	publishSources   = [...]string{"manual", "revert", "guard_rollback", "import", "autopilot"}
	guardActionNames = [...]string{"rollback", "canary_abort", "alert"}
	jobNames         = [...]string{"jwks", "verified_bots", "audit", "audit_full", "guard", "notifications", "retention", "autopilot"}
)

// jobKind indexes jobNames.
type jobKind int

const (
	jobJWKS jobKind = iota
	jobVerifiedBots
	jobAudit
	jobAuditFull
	jobGuard
	jobNotify
	jobRetention
	jobAutopilot
)

// adminMetrics are this replica's counters, exposed on the internal
// /metrics in Prometheus text format. All updates are atomic.
type adminMetrics struct {
	leader                                      atomic.Bool
	publishes                                   [len(publishSources)]atomic.Uint64
	guardActions                                [len(guardActionNames)]atomic.Uint64
	notifySent, notifyFailed                    atomic.Uint64
	reportsAccepted, reportsInvalid, reportsErr atomic.Uint64
	linesAccepted, linesRejected                atomic.Uint64
	logBusy                                     atomic.Uint64
	jobFailures                                 [len(jobNames)]atomic.Uint64
	auditVerifyFailures                         atomic.Uint64
	autopilot                                   autopilotMetrics
	connector                                   [len(connectorNames)][len(connectorResults)]atomic.Uint64
	// gauges is what the leader's last notification check read; nil until
	// then and after stepping down.
	gauges atomic.Pointer[leaderGauges]
}

// leaderGauges are fleet-wide values only the leader exports, so replicas
// don't each report the same fleet and a scrape never queries Postgres.
type leaderGauges struct {
	edgesLive int64
	firing    map[string]int64 // by signal
	autopilot autopilotGauges
}

// published counts a committed version by its source, one of publishSources.
func (m *adminMetrics) published(source string) {
	m.publishes[slices.Index(publishSources[:], source)].Add(1)
}

// guardActed counts a committed guard action, one of guardActionNames.
func (m *adminMetrics) guardActed(action string) {
	m.guardActions[slices.Index(guardActionNames[:], action)].Add(1)
}

// refreshLeaderGauges reads the live edges and firing anomalies for the
// leader's gauges.
func (s *Server) refreshLeaderGauges(ctx context.Context) error {
	g := &leaderGauges{firing: map[string]int64{}}
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM fleet WHERE last_seen > $1", s.now().Add(-fleetWindow)).Scan(&g.edgesLive); err != nil {
		return err
	}
	rows, err := s.db.Query(ctx, "SELECT signal, count(*) FROM anomalies WHERE state = 'firing' GROUP BY signal")
	if err != nil {
		return err
	}
	var signal string
	var n int64
	if _, err := pgx.ForEachRow(rows, []any{&signal, &n}, func() error { g.firing[signal] = n; return nil }); err != nil {
		return err
	}
	if err := s.readAutopilotGauges(ctx, &g.autopilot); err != nil {
		return err
	}
	s.met.gauges.Store(g)
	return nil
}

func (s *Server) writeMetrics(w io.Writer) {
	m := &s.met
	// A scrape that disconnects mid-write has nothing to recover.
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	p("# TYPE admin_publishes_total counter\n")
	for i := range m.publishes {
		p("admin_publishes_total{source=%q} %d\n", publishSources[i], m.publishes[i].Load())
	}
	p("# TYPE admin_guard_actions_total counter\n")
	for i := range m.guardActions {
		p("admin_guard_actions_total{action=%q} %d\n", guardActionNames[i], m.guardActions[i].Load())
	}
	p("# TYPE admin_notifications_total counter\nadmin_notifications_total{result=\"sent\"} %d\nadmin_notifications_total{result=\"failed\"} %d\n",
		m.notifySent.Load(), m.notifyFailed.Load())
	p("# TYPE admin_edge_reports_total counter\nadmin_edge_reports_total{result=\"accepted\"} %d\nadmin_edge_reports_total{result=\"invalid\"} %d\nadmin_edge_reports_total{result=\"error\"} %d\n",
		m.reportsAccepted.Load(), m.reportsInvalid.Load(), m.reportsErr.Load())
	p("# TYPE admin_log_lines_total counter\nadmin_log_lines_total{result=\"accepted\"} %d\nadmin_log_lines_total{result=\"rejected\"} %d\n",
		m.linesAccepted.Load(), m.linesRejected.Load())
	p("# TYPE admin_log_batches_busy_total counter\nadmin_log_batches_busy_total %d\n", m.logBusy.Load())
	p("# TYPE admin_background_job_failures_total counter\n")
	for i := range m.jobFailures {
		p("admin_background_job_failures_total{job=%q} %d\n", jobNames[i], m.jobFailures[i].Load())
	}
	p("# TYPE admin_audit_verify_failures_total counter\nadmin_audit_verify_failures_total %d\n", m.auditVerifyFailures.Load())
	p("# TYPE admin_trace_export_errors_total counter\nadmin_trace_export_errors_total %d\n", s.tracing.ExportErrors())
	p("# TYPE admin_connector_requests_total counter\n")
	for c := range m.connector {
		for r := range m.connector[c] {
			p("admin_connector_requests_total{connector=%q,result=%q} %d\n", connectorNames[c], connectorResults[r], m.connector[c][r].Load())
		}
	}
	m.autopilot.write(w)
	leader := 0
	if m.leader.Load() {
		leader = 1
	}
	p("# TYPE admin_leader gauge\nadmin_leader %d\n", leader)
	g := m.gauges.Load()
	if leader == 0 || g == nil {
		return
	}
	p("# TYPE admin_edges_live gauge\nadmin_edges_live %d\n", g.edgesLive)
	p("# TYPE admin_anomalies_firing gauge\n")
	for _, signal := range notifyNames {
		p("admin_anomalies_firing{signal=%q} %d\n", signal, g.firing[signal])
	}
	g.autopilot.write(w)
}

// internalHandler serves /metrics on the internal address. It has no auth
// and no session, so that address must never be reachable publicly.
func (s *Server) internalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		s.writeMetrics(w)
	})
	return mux
}
