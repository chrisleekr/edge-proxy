package edge

import (
	"fmt"
	"io"
	"sync/atomic"

	"github.com/chrisleekr/edge-proxy/internal/tracing"
)

// reason is why the edge answered a request itself instead of proxying it.
type reason int

const (
	reasonOverloaded reason = iota
	reasonStreamsOverloaded
	reasonUntrustedPeer
	reasonIngressSecret
	reasonClientIP
	reasonPath
	reasonMethod
	reasonNoSnapshot
	reasonAuth
	reasonBackstop
	reasonRateLimited
	reasonRateLimitKey
	reasonRateLimitUnavailable
	reasonPayloadTooLarge
	reasonUpstreamTimeout
	reasonUpstreamError
	reasonUpstreamTLS
	reasonBodyTimeout
	reasonBodyInvalid
	reasonClientGone
	reasonPanic
	reasonBlocked
	numReasons
)

var reasonNames = [numReasons]string{
	"overloaded", "streams_overloaded", "untrusted_peer", "ingress_secret",
	"client_ip", "path", "method", "no_snapshot", "auth", "backstop", "rate_limited", "rate_limit_key",
	"rate_limit_unavailable",
	"payload_too_large", "upstream_timeout", "upstream_error", "upstream_tls", "body_timeout", "body_invalid", "client_gone", "panic", "blocked",
}

// metrics are process-wide counters, exposed on /metrics in Prometheus text
// format. All updates are atomic adds.
type metrics struct {
	// tracing is nil when tracing is off; its counters then read 0.
	tracing *tracing.Provider

	// codes counts finished requests by origin and status slot, as
	// versionStats does: index 0 of each origin is "client left before a
	// response". Classes are derived from it.
	codes          [2][maxCodeSlot + 1]atomic.Uint64
	upstreamErrors [len(UpstreamCauses)]atomic.Uint64
	rejected       [numReasons]atomic.Uint64

	inflight, streams atomic.Int64

	logDropped, statsDropped                 atomic.Uint64
	snapshotLoads, snapshotRejected, pollErr atomic.Uint64
	backgroundPanics                         atomic.Uint64

	// Rate limiting.
	rulesCapped, backstopUntracked, localUntracked atomic.Uint64
	penaltyHits, penaltyDropped                    atomic.Uint64
	valkeyErrors, valkeyBreakerOpen                atomic.Uint64

	corsPreflight, corsPreflightDenied atomic.Uint64

	auth                    [numAuthResults]atomic.Uint64
	jwksFetches, jwksErrors atomic.Uint64

	snapshotVersion atomic.Int64
	bootstrapAge    atomic.Int64 // seconds; 0 unless serving a bootstrap file
	ready           atomic.Bool
}

func (m *metrics) writeTo(w io.Writer) {
	// A scrape that disconnects mid-write has nothing to recover.
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	// Read each counter once, so classes and codes agree within a scrape.
	var codes [2][maxCodeSlot + 1]uint64
	var classes [6]uint64
	for origin := range m.codes {
		for slot := range m.codes[origin] {
			n := m.codes[origin][slot].Load()
			codes[origin][slot] = n
			// Slot 600, any code above 599, counts as 5xx as in reports.
			classes[min(slot/100, 5)] += n
		}
	}
	p("# TYPE edge_requests_total counter\n")
	for i, n := range classes {
		class := "none"
		if i > 0 {
			class = fmt.Sprintf("%dxx", i)
		}
		p("edge_requests_total{class=%q} %d\n", class, n)
	}
	p("# TYPE edge_responses_total counter\n")
	for origin, name := range [...]string{"edge", "upstream"} {
		for slot, n := range codes[origin] {
			// The edge's own 502, 503 and 504 always have a series, so rate()
			// sees the first one; other codes stay sparse.
			if n > 0 || origin == 0 && slot >= 502 && slot <= 504 {
				p("edge_responses_total{origin=%q,code=\"%d\"} %d\n", name, slot, n)
			}
		}
	}
	p("# TYPE edge_upstream_errors_total counter\n")
	for i := range m.upstreamErrors {
		p("edge_upstream_errors_total{cause=%q} %d\n", UpstreamCauses[i], m.upstreamErrors[i].Load())
	}
	p("# TYPE edge_rejected_total counter\n")
	for i := range m.rejected {
		p("edge_rejected_total{reason=%q} %d\n", reasonNames[i], m.rejected[i].Load())
	}
	p("# TYPE edge_inflight gauge\nedge_inflight %d\n", m.inflight.Load())
	p("# TYPE edge_streams gauge\nedge_streams %d\n", m.streams.Load())
	p("# TYPE edge_log_dropped_total counter\nedge_log_dropped_total %d\n", m.logDropped.Load())
	p("# TYPE edge_stats_dropped_total counter\nedge_stats_dropped_total %d\n", m.statsDropped.Load())
	p("# TYPE edge_snapshot_loads_total counter\nedge_snapshot_loads_total %d\n", m.snapshotLoads.Load())
	p("# TYPE edge_snapshot_rejected_total counter\nedge_snapshot_rejected_total %d\n", m.snapshotRejected.Load())
	p("# TYPE edge_snapshot_poll_errors_total counter\nedge_snapshot_poll_errors_total %d\n", m.pollErr.Load())
	p("# TYPE edge_background_panics_total counter\nedge_background_panics_total %d\n", m.backgroundPanics.Load())
	p("# TYPE edge_ratelimit_rules_capped_total counter\nedge_ratelimit_rules_capped_total %d\n", m.rulesCapped.Load())
	p("# TYPE edge_backstop_untracked_total counter\nedge_backstop_untracked_total %d\n", m.backstopUntracked.Load())
	p("# TYPE edge_ratelimit_local_untracked_total counter\nedge_ratelimit_local_untracked_total %d\n", m.localUntracked.Load())
	p("# TYPE edge_ratelimit_penalty_cache_hits_total counter\nedge_ratelimit_penalty_cache_hits_total %d\n", m.penaltyHits.Load())
	p("# TYPE edge_ratelimit_penalty_cache_dropped_total counter\nedge_ratelimit_penalty_cache_dropped_total %d\n", m.penaltyDropped.Load())
	p("# TYPE edge_trace_export_errors_total counter\nedge_trace_export_errors_total %d\n", m.tracing.ExportErrors())
	p("# TYPE edge_trace_capped_total counter\nedge_trace_capped_total %d\n", m.tracing.Capped())
	p("# TYPE edge_valkey_errors_total counter\nedge_valkey_errors_total %d\n", m.valkeyErrors.Load())
	p("# TYPE edge_valkey_breaker_open_total counter\nedge_valkey_breaker_open_total %d\n", m.valkeyBreakerOpen.Load())
	p("# TYPE edge_cors_preflight_total counter\nedge_cors_preflight_total{result=\"allowed\"} %d\nedge_cors_preflight_total{result=\"denied\"} %d\n", m.corsPreflight.Load(), m.corsPreflightDenied.Load())
	p("# TYPE edge_auth_total counter\n")
	for i := authVerified; i < numAuthResults; i++ {
		p("edge_auth_total{result=%q} %d\n", authNames[i], m.auth[i].Load())
	}
	p("# TYPE edge_jwks_refresh_total counter\nedge_jwks_refresh_total{result=\"ok\"} %d\nedge_jwks_refresh_total{result=\"error\"} %d\n", m.jwksFetches.Load(), m.jwksErrors.Load())
	p("# TYPE edge_snapshot_version gauge\nedge_snapshot_version %d\n", m.snapshotVersion.Load())
	p("# TYPE edge_bootstrap_age_seconds gauge\nedge_bootstrap_age_seconds %d\n", m.bootstrapAge.Load())
	ready := 0
	if m.ready.Load() {
		ready = 1
	}
	p("# TYPE edge_ready gauge\nedge_ready %d\n", ready)
}
