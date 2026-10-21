package edge

import (
	"fmt"
	"io"
	"sync/atomic"
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
	reasonBodyTimeout
	reasonClientGone
	reasonPanic
	numReasons
)

var reasonNames = [numReasons]string{
	"overloaded", "streams_overloaded", "untrusted_peer", "ingress_secret",
	"client_ip", "path", "method", "no_snapshot", "auth", "backstop", "rate_limited", "rate_limit_key",
	"rate_limit_unavailable",
	"payload_too_large", "upstream_timeout", "upstream_error", "body_timeout", "client_gone", "panic",
}

// metrics are process-wide counters, exposed on /metrics in Prometheus text
// format. All updates are atomic adds.
type metrics struct {
	requests [6]atomic.Uint64 // by status class; index 0 is "client left before a response"
	rejected [numReasons]atomic.Uint64

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
	p("# TYPE edge_requests_total counter\n")
	for i := range m.requests {
		class := "none"
		if i > 0 {
			class = fmt.Sprintf("%dxx", i)
		}
		p("edge_requests_total{class=%q} %d\n", class, m.requests[i].Load())
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
