package edge

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"time"
)

// accessRecord is copied out of the request, so the writer goroutine never
// touches request memory.
type accessRecord struct {
	method, path, requestID, cohort, decision, rateLimitRule, auth string
	status                                                         int
	client                                                         netip.Addr
	version                                                        int64
	configRules                                                    []string
	duration                                                       time.Duration
}

// accessLog writes JSON access lines from one goroutine. When
// its buffer is full a line is dropped and counted: logging never blocks a
// request or grows memory.
type accessLog struct {
	ch     chan accessRecord
	log    *slog.Logger
	m      *metrics
	sample float64
}

func newAccessLog(log *slog.Logger, m *metrics, sample float64, size int) *accessLog {
	return &accessLog{ch: make(chan accessRecord, size), log: log, m: m, sample: sample}
}

func (a *accessLog) write(st *reqState, r *http.Request, elapsed time.Duration) {
	decision := "allow"
	if st.rejected {
		decision = reasonNames[st.reason]
	}
	// Allowed requests are sampled; rejections and 5xx are always logged.
	if decision == "allow" && st.sw.status < 500 && rand.Float64() >= a.sample { //nolint:gosec // sampling needs no cryptographic randomness
		return
	}
	rec := accessRecord{
		method: r.Method, requestID: st.requestID, cohort: st.cohort, decision: decision,
		status: st.sw.status, client: st.client.ip, duration: elapsed, rateLimitRule: st.rlRule, auth: authNames[st.auth],
		// Path only: query strings can carry tokens and are never logged.
		path: st.fields.path,
	}
	if st.ver != nil {
		rec.version = st.ver.c.Config.Version
		for _, i := range st.matched {
			rec.configRules = append(rec.configRules, st.ver.c.Config.ConfigRules[i].ID)
		}
	}
	select {
	case a.ch <- rec:
	default:
		a.m.logDropped.Add(1)
	}
}

// run writes lines until ctx ends, then drains what is buffered.
func (a *accessLog) run(ctx context.Context) {
	for {
		select {
		case rec := <-a.ch:
			guard(a.m, a.log, "access log", func() { a.emit(rec) })
		case <-ctx.Done():
			for {
				select {
				case rec := <-a.ch:
					a.emit(rec)
				default:
					return
				}
			}
		}
	}
}

// emit uses OTel HTTP semantic-convention names where they exist.
func (a *accessLog) emit(rec accessRecord) {
	attrs := []slog.Attr{
		slog.String("http.request.method", rec.method),
		slog.String("url.path", rec.path),
		slog.Int("http.response.status_code", rec.status),
		slog.String("request_id", rec.requestID),
		slog.String("edge.decision", rec.decision),
		slog.Float64("duration_ms", float64(rec.duration)/float64(time.Millisecond)),
	}
	if rec.auth != "" {
		attrs = append(attrs, slog.String("edge.auth", rec.auth))
	}
	if rec.rateLimitRule != "" {
		attrs = append(attrs, slog.String("edge.rate_limit_rule", rec.rateLimitRule))
	}
	if rec.client.IsValid() {
		attrs = append(attrs, slog.String("client.address", rec.client.String()))
	}
	if rec.version != 0 {
		attrs = append(attrs, slog.Int64("edge.config_version", rec.version), slog.String("edge.cohort", rec.cohort), slog.Any("edge.config_rules", rec.configRules))
	}
	a.log.LogAttrs(context.Background(), slog.LevelInfo, "access", attrs...)
}
