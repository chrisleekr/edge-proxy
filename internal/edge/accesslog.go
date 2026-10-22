package edge

import (
	"context"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// accessRecord is copied out of the request, so the writer goroutine never
// touches request memory.
type accessRecord struct {
	method, host, path, query, requestID, cohort, decision, rateLimitRule, auth string
	status                                                                      int
	client                                                                      netip.Addr
	version                                                                     int64
	configRules                                                                 []string
	duration                                                                    time.Duration
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

// logDraw picks which allowed requests are logged. A variable so tests can
// choose the outcome.
var logDraw = rand.Float64

func newAccessLog(log *slog.Logger, m *metrics, sample float64, size int) *accessLog {
	return &accessLog{ch: make(chan accessRecord, size), log: log, m: m, sample: sample}
}

func (a *accessLog) write(st *reqState, r *http.Request, elapsed time.Duration) {
	decision := "allow"
	if st.rejected {
		decision = reasonNames[st.reason]
	}
	// Allowed requests are sampled; rejections and 5xx are always logged.
	if decision == "allow" && st.sw.status < 500 && logDraw() >= a.sample {
		return
	}
	rec := accessRecord{
		method: r.Method, requestID: st.requestID, cohort: st.cohort, decision: decision,
		status: st.sw.status, client: st.client.ip, duration: elapsed, rateLimitRule: st.rlRule, auth: authNames[st.auth],
		path: st.fields.path, host: r.Host,
		// Parsed for key names by the writer, off the request path. Values
		// can carry tokens and are never logged.
		query: r.URL.RawQuery,
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

// run writes lines until ctx ends and nothing is buffered. Once ctx ends,
// select picks either ready case at random, so buffered lines are written
// by the same case either way and run returns only when the buffer is empty.
func (a *accessLog) run(ctx context.Context) {
	for {
		select {
		case rec := <-a.ch:
			guard(a.m, a.log, "access log", func() { a.emit(rec) })
		case <-ctx.Done():
			if len(a.ch) == 0 {
				return
			}
		}
	}
}

// paramName is what a query key must look like to be logged.
var paramName = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)

const maxQueryKeys = 32

// queryKeys returns the unique parameter names in a raw query, sorted. A
// pair without "=" can be a bare token, and an odd or long key can be a
// secret, so those, and keys past maxQueryKeys, are only counted.
func queryKeys(raw string) (keys []string, dropped int) {
	seen := map[string]bool{}
	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}
		k, _, ok := strings.Cut(pair, "=")
		k, err := url.QueryUnescape(k)
		switch {
		case !ok || err != nil || !paramName.MatchString(k):
			dropped++
		case seen[k]:
		case len(seen) == maxQueryKeys:
			dropped++
		default:
			seen[k] = true
		}
	}
	return slices.Sorted(maps.Keys(seen)), dropped
}

// emit uses OTel HTTP semantic-convention names where they exist.
func (a *accessLog) emit(rec accessRecord) {
	attrs := []slog.Attr{
		slog.String("http.request.method", rec.method),
		slog.String("server.address", hostOnly(rec.host)),
		slog.String("url.path", rec.path),
		slog.Int("http.response.status_code", rec.status),
		slog.String("request_id", rec.requestID),
		slog.String("edge.decision", rec.decision),
		slog.Float64("duration_ms", float64(rec.duration)/float64(time.Millisecond)),
	}
	keys, dropped := queryKeys(rec.query)
	if len(keys) > 0 {
		attrs = append(attrs, slog.Any("edge.query_keys", keys))
	}
	if dropped > 0 {
		attrs = append(attrs, slog.Int("edge.query_keys_dropped", dropped))
	}
	if rec.auth != "" {
		attrs = append(attrs, slog.String("edge.auth", rec.auth))
	}
	if rec.rateLimitRule != "" {
		attrs = append(attrs, slog.String("edge.rate_limit_rule", rec.rateLimitRule))
	}
	// A sampled line stands for 1/rate requests; readers scale by it.
	if a.sample < 1 && rec.decision == "allow" && rec.status < 500 {
		attrs = append(attrs, slog.Float64("edge.sample_rate", a.sample))
	}
	if rec.client.IsValid() {
		attrs = append(attrs, slog.String("client.address", rec.client.String()))
	}
	if rec.version != 0 {
		attrs = append(attrs, slog.Int64("edge.config_version", rec.version), slog.String("edge.cohort", rec.cohort), slog.Any("edge.config_rules", rec.configRules))
	}
	a.log.LogAttrs(context.Background(), slog.LevelInfo, "access", attrs...)
}
