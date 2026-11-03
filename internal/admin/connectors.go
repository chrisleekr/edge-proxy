package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Connector bounds. A call reads at most connMaxBody of the answer and
// passes the model at most connMaxSummary, under the MCP result cap.
const (
	connCallTimeout = 10 * time.Second
	connMaxBody     = 256 << 10
	connMaxSummary  = 48 << 10
	connMaxQuery    = 2000
	connMaxMessage  = 500 // runes of a log line
	connMaxPoints   = 60
)

// Label values of admin_connector_requests_total, exported from zero.
var (
	connectorNames   = [...]string{"prometheus", "grafana", "datadog"}
	connectorResults = [...]string{"ok", "error", "timeout", "too_large"}
)

// toolConnector names the connector each connector tool calls.
var toolConnector = map[string]string{
	"prom_query": "prometheus", "prom_query_range": "prometheus",
	"grafana_annotations": "grafana", "grafana_dashboards": "grafana",
	"dd_query_metrics": "datadog", "dd_search_logs": "datadog",
}

var connQueryProp = map[string]any{"type": "string", "minLength": 1, "maxLength": connMaxQuery}

func minutesWithDefault(def int) map[string]any {
	return map[string]any{"type": "integer", "minimum": 1, "maximum": mcpMaxMinutes, "description": fmt.Sprintf("how far back, in minutes; default %d", def)}
}

// configuredTools is every tool but those of connectors cfg leaves unset.
func configuredTools(cfg *Config) []mcpTool {
	on := map[string]bool{"prometheus": cfg.Prometheus.URL != "", "grafana": cfg.Grafana.URL != "", "datadog": cfg.Datadog.API != ""}
	return slices.DeleteFunc(slices.Clone(mcpTools), func(t mcpTool) bool { c := toolConnector[t.Name]; return c != "" && !on[c] })
}

// citable reports whether a successful call of t is evidence a note can
// cite: a stats read, or a connector read, which the runner alone makes.
func citable(t mcpTool) bool { return t.Perm == "stats.read" || toolConnector[t.Name] != "" }

// answerHidden is why p may not read a recorded answer of tool, or "". An
// answer holds stats, client IPs and config, which autopilot.read alone
// does not grant; a connector's can hold other services' logs and metrics,
// so it also needs autopilot.manage.
func answerHidden(p *principal, tool string) string {
	switch {
	case toolConnector[tool] != "" && (!p.can("stats.read") || !p.can("config.read") || !p.can("autopilot.manage")):
		return "needs stats.read, config.read and autopilot.manage"
	case !p.can("stats.read") || !p.can("config.read"):
		return "needs stats.read and config.read"
	}
	return ""
}

// redact hides what looks like a credential in text a connector answered.
func redact(s string) string { return credential.ReplaceAllString(s, "[redacted]") }

// connected counts one connector request by its result.
func (m *adminMetrics) connected(connector, result string) {
	c, r := slices.Index(connectorNames[:], connector), slices.Index(connectorResults[:], result)
	m.connector[c][r].Add(1)
}

// connectorDo sends one request to a connector and returns the answer's
// body. A redirect, a non-2xx status or an answer over connMaxBody is an
// error, and no error repeats a header the request carried.
func (s *Server) connectorDo(ctx context.Context, connector, method, target string, header http.Header, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = header
	req.Header.Set("Accept", "application/json")
	resp, err := s.connClient.Do(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		body, err = io.ReadAll(io.LimitReader(resp.Body, connMaxBody+1))
	}
	switch {
	case err != nil && ctx.Err() != nil:
		s.met.connected(connector, "timeout")
		return nil, ctx.Err()
	case err != nil:
		s.met.connected(connector, "error")
		// Without the URL, whose query holds what the model asked.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		s.log.Warn("connector request failed", "connector", connector, "error", err.Error())
		return nil, fail(http.StatusBadGateway, connector+" could not be reached")
	case len(body) > connMaxBody:
		s.met.connected(connector, "too_large")
		return nil, fail(http.StatusBadGateway, fmt.Sprintf("%s answered over %d KiB; ask for less, such as a narrower query or a shorter window", connector, connMaxBody>>10))
	case resp.StatusCode/100 != 2:
		s.met.connected(connector, "error")
		// Redacted before it is cut, so a cut can't leave part of a secret.
		return nil, fail(http.StatusBadGateway, fmt.Sprintf("%s answered %d: %s", connector, resp.StatusCode, untrustedText(cut(redact(string(body)), 200))))
	}
	s.met.connected(connector, "ok")
	return body, nil
}

// untrustedText is s in the untrusted wrapper as JSON, for a refusal's text:
// an upstream's error can quote label values and queries clients wrote.
func untrustedText(s string) string {
	b, _ := json.Marshal(untrusted(s)) // a string always marshals
	return string(b)
}

// cut is s cut to at most n bytes on a rune boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// cutRunes is s cut to at most n runes.
func cutRunes(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// fit builds the answer from items, dropping trailing items until it
// marshals to at most connMaxSummary. build gets how many were dropped.
func fit[T any](items []T, build func(kept []T, dropped int) map[string]any) (map[string]any, error) {
	for dropped := 0; ; dropped++ {
		out := build(items[:len(items)-dropped], dropped)
		b, err := json.Marshal(out)
		if err != nil || len(b) <= connMaxSummary || dropped == len(items) {
			return out, err
		}
	}
}

// scrub redacts every string in an answer, keys and values, so a secret in
// a label, title or log line reaches neither the model nor the run record.
func scrub(out map[string]any) (any, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var walk func(v any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			m := make(map[string]any, len(x))
			for k, e := range x {
				m[redact(k)] = walk(e)
			}
			return m
		case []any:
			for i, e := range x {
				x[i] = walk(e)
			}
			return x
		case string:
			return redact(x)
		}
		return v
	}
	return walk(v), nil
}

// connectorTool runs one connector tool and answers its summary, scrubbed.
func (s *Server) connectorTool(ctx context.Context, name string, args json.RawMessage) (any, error) {
	var out map[string]any
	var err error
	switch name {
	case "prom_query":
		out, err = s.promQuery(ctx, args)
	case "prom_query_range":
		out, err = s.promQueryRange(ctx, args)
	case "grafana_annotations":
		out, err = s.grafanaAnnotations(ctx, args)
	case "grafana_dashboards":
		out, err = s.grafanaDashboards(ctx, args)
	case "dd_query_metrics":
		out, err = s.ddQueryMetrics(ctx, args)
	case "dd_search_logs":
		out, err = s.ddSearchLogs(ctx, args)
	}
	if err != nil {
		return nil, err
	}
	out["connector"] = toolConnector[name]
	return scrub(out)
}

// queryArg checks a connector query's length.
func queryArg(q string) error {
	if q == "" || utf8.RuneCountInString(q) > connMaxQuery {
		return fail(http.StatusUnprocessableEntity, fmt.Sprintf("query is 1 to %d characters", connMaxQuery))
	}
	return nil
}

// minutesOr is minutesArg with another default.
func minutesOr(m, def int) (int, error) {
	if m == 0 {
		return def, nil
	}
	return minutesArg(m)
}

// limitArg is limit, or def when unset, refused outside 1 to max.
func limitArg(limit, def, maxLimit int) (int, error) {
	switch {
	case limit == 0:
		return def, nil
	case limit < 1 || limit > maxLimit:
		return 0, fail(http.StatusUnprocessableEntity, fmt.Sprintf("limit is 1 to %d", maxLimit))
	}
	return limit, nil
}

func bearer(token string) http.Header {
	h := http.Header{}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	return h
}

// promAnswer is Prometheus's query API envelope:
// https://prometheus.io/docs/prometheus/latest/querying/api/
type promAnswer struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

type promSeries struct {
	Metric map[string]string `json:"metric"`
	Value  []any             `json:"value"`
	Values [][]any           `json:"values"`
}

func (s *Server) prom(ctx context.Context, path string, q url.Values) (*promAnswer, error) {
	b, err := s.connectorDo(ctx, "prometheus", http.MethodGet, s.cfg.Prometheus.URL+path+"?"+q.Encode(), bearer(s.cfg.Prometheus.Token), nil)
	if err != nil {
		return nil, err
	}
	var a promAnswer
	if err := json.Unmarshal(b, &a); err != nil || a.Status != "success" {
		return nil, fail(http.StatusBadGateway, "prometheus answered something other than a successful query: "+untrustedText(cut(redact(a.Error), 200)))
	}
	return &a, nil
}

// metricsLink fills METRICS_LINK_URL, or is nil when it is unset.
func (s *Server) metricsLink(query string, from, to time.Time) any {
	if s.cfg.MetricsLinkURL == "" {
		return nil
	}
	return strings.NewReplacer("{query}", url.QueryEscape(query), "{from_ms}", strconv.FormatInt(from.UnixMilli(), 10), "{to_ms}", strconv.FormatInt(to.UnixMilli(), 10)).
		Replace(s.cfg.MetricsLinkURL)
}

func (s *Server) promQuery(ctx context.Context, args json.RawMessage) (map[string]any, error) {
	var in struct {
		Query string `json:"query"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	if err := queryArg(in.Query); err != nil {
		return nil, err
	}
	now := s.now()
	a, err := s.prom(ctx, "/api/v1/query", url.Values{"query": {in.Query}, "time": {promTime(now)}})
	if err != nil {
		return nil, err
	}
	base := map[string]any{"result_type": a.Data.ResultType, "link": s.metricsLink(in.Query, now.Add(-time.Hour), now)}
	var series []promSeries
	if a.Data.ResultType != "vector" && a.Data.ResultType != "matrix" || json.Unmarshal(a.Data.Result, &series) != nil {
		// A scalar or string: one [time, value] pair.
		var v []any
		_ = json.Unmarshal(a.Data.Result, &v)
		base["value"] = v
		base["more"] = 0
		return base, nil
	}
	items := make([]map[string]any, 0, min(len(series), 50))
	for _, ser := range series[:min(len(series), 50)] {
		item := map[string]any{"labels": untrusted(ser.Metric)}
		if a.Data.ResultType == "vector" && len(ser.Value) == 2 {
			item["value"] = ser.Value[1]
		} else {
			item["points"] = everyKth(ser.Values, connMaxPoints)
		}
		items = append(items, item)
	}
	return fit(items, func(kept []map[string]any, dropped int) map[string]any {
		out := maps.Clone(base)
		out["series"], out["more"] = kept, len(series)-len(items)+dropped
		return out
	})
}

func (s *Server) promQueryRange(ctx context.Context, args json.RawMessage) (map[string]any, error) {
	var in struct {
		Query   string `json:"query"`
		Minutes int    `json:"minutes"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	if err := queryArg(in.Query); err != nil {
		return nil, err
	}
	m, err := minutesArg(in.Minutes)
	if err != nil {
		return nil, err
	}
	// At most 60 steps across the window: a window of m minutes split
	// into 60 is m seconds a step, and never under a minute.
	step := max(60, m)
	to := s.now()
	// Start one step in, so the inclusive range has m*60/step points.
	from := to.Add(-time.Duration(m*60-step) * time.Second)
	a, err := s.prom(ctx, "/api/v1/query_range", url.Values{"query": {in.Query}, "start": {promTime(from)}, "end": {promTime(to)}, "step": {strconv.Itoa(step)}})
	if err != nil {
		return nil, err
	}
	var series []promSeries
	if err := json.Unmarshal(a.Data.Result, &series); err != nil {
		return nil, fail(http.StatusBadGateway, "prometheus answered a range query with no series list")
	}
	items := make([]map[string]any, 0, min(len(series), 10))
	for _, ser := range series[:min(len(series), 10)] {
		items = append(items, map[string]any{"labels": untrusted(ser.Metric), "points": everyKth(ser.Values, connMaxPoints)})
	}
	return fit(items, func(kept []map[string]any, dropped int) map[string]any {
		return map[string]any{"from": from.Unix(), "to": to.Unix(), "step_seconds": step, "series": kept, "more": len(series) - len(items) + dropped,
			"link": s.metricsLink(in.Query, from, to)}
	})
}

// promTime is t in Unix seconds to the millisecond, as Prometheus samples
// are stamped: a whole second could fall before the latest sample.
func promTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', 3, 64)
}

// everyKth keeps every k-th point so at most n remain.
func everyKth[T any](points []T, n int) []T {
	if len(points) <= n {
		return points
	}
	k := int(math.Ceil(float64(len(points)) / float64(n)))
	out := make([]T, 0, n)
	for i := 0; i < len(points); i += k {
		out = append(out, points[i])
	}
	return out
}

func (s *Server) grafana(ctx context.Context, path string, q url.Values, out any) error {
	b, err := s.connectorDo(ctx, "grafana", http.MethodGet, s.cfg.Grafana.URL+path+"?"+q.Encode(), bearer(s.cfg.Grafana.Token), nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fail(http.StatusBadGateway, "grafana answered something other than the list asked for")
	}
	return nil
}

// grafanaAnnotations reads GET /api/annotations:
// https://grafana.com/docs/grafana/v13.2/developer-resources/api-reference/http-api/api-legacy/annotations.md
func (s *Server) grafanaAnnotations(ctx context.Context, args json.RawMessage) (map[string]any, error) {
	var in struct {
		Minutes int      `json:"minutes"`
		Tags    []string `json:"tags"`
		Limit   int      `json:"limit"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	m, err := minutesOr(in.Minutes, 1440)
	if err != nil {
		return nil, err
	}
	limit, err := limitArg(in.Limit, 100, 100)
	if err != nil {
		return nil, err
	}
	if len(in.Tags) > 5 || slices.ContainsFunc(in.Tags, func(t string) bool { return t == "" || len(t) > 100 }) {
		return nil, fail(http.StatusUnprocessableEntity, "tags lists up to 5 tags of 1 to 100 characters")
	}
	to := s.now()
	q := url.Values{"from": {strconv.FormatInt(to.Add(-time.Duration(m)*time.Minute).UnixMilli(), 10)}, "to": {strconv.FormatInt(to.UnixMilli(), 10)},
		"limit": {strconv.Itoa(limit)}, "type": {"annotation"}, "tags": in.Tags}
	var list []struct {
		ID           int64    `json:"id"`
		DashboardUID string   `json:"dashboardUID"`
		Time         int64    `json:"time"`
		TimeEnd      int64    `json:"timeEnd"`
		Text         string   `json:"text"`
		Tags         []string `json:"tags"`
	}
	if err := s.grafana(ctx, "/api/annotations", q, &list); err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(list))
	for _, a := range list {
		var link any
		if a.DashboardUID != "" {
			link = s.cfg.Grafana.URL + "/d/" + url.PathEscape(a.DashboardUID)
		}
		items = append(items, map[string]any{"id": a.ID, "time": a.Time, "time_end": a.TimeEnd, "text": untrusted(a.Text), "tags": untrusted(orEmpty(a.Tags)),
			"dashboard_uid": a.DashboardUID, "link": link})
	}
	return fit(items, func(kept []map[string]any, dropped int) map[string]any {
		return map[string]any{"annotations": kept, "more": dropped}
	})
}

// grafanaDashboards reads GET /api/search:
// https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/folder_dashboard_search/
func (s *Server) grafanaDashboards(ctx context.Context, args json.RawMessage) (map[string]any, error) {
	var in struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(in.Query) > 200 {
		return nil, fail(http.StatusUnprocessableEntity, "query is at most 200 characters")
	}
	limit, err := limitArg(in.Limit, 20, 20)
	if err != nil {
		return nil, err
	}
	var list []struct {
		UID   string   `json:"uid"`
		Title string   `json:"title"`
		Tags  []string `json:"tags"`
	}
	if err := s.grafana(ctx, "/api/search", url.Values{"type": {"dash-db"}, "query": {in.Query}, "limit": {strconv.Itoa(limit)}}, &list); err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(list))
	for _, d := range list {
		// Built from the uid as annotation links are: the search url already
		// carries Grafana's sub-path, which GRAFANA_URL names too.
		items = append(items, map[string]any{"uid": d.UID, "title": untrusted(d.Title), "url": s.cfg.Grafana.URL + "/d/" + url.PathEscape(d.UID), "tags": untrusted(orEmpty(d.Tags))})
	}
	return fit(items, func(kept []map[string]any, dropped int) map[string]any {
		return map[string]any{"dashboards": kept, "more": dropped}
	})
}

func (s *Server) datadog(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	h := http.Header{}
	h.Set("DD-API-KEY", s.cfg.Datadog.APIKey)
	h.Set("DD-APPLICATION-KEY", s.cfg.Datadog.AppKey)
	if body != nil {
		h.Set("Content-Type", "application/json")
	}
	return s.connectorDo(ctx, "datadog", method, s.cfg.Datadog.API+path, h, body)
}

// ddQueryMetrics reads GET /api/v1/query:
// https://docs.datadoghq.com/api/latest/metrics/query-timeseries-points.md
// The answer has no link: Datadog documents no URL form for a query.
func (s *Server) ddQueryMetrics(ctx context.Context, args json.RawMessage) (map[string]any, error) {
	var in struct {
		Query   string `json:"query"`
		Minutes int    `json:"minutes"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	if err := queryArg(in.Query); err != nil {
		return nil, err
	}
	m, err := minutesArg(in.Minutes)
	if err != nil {
		return nil, err
	}
	to := s.now().Unix()
	from := to - int64(m)*60
	b, err := s.datadog(ctx, http.MethodGet, "/api/v1/query?"+url.Values{"from": {strconv.FormatInt(from, 10)}, "to": {strconv.FormatInt(to, 10)}, "query": {in.Query}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var a struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Series []struct {
			Metric    string  `json:"metric"`
			Scope     string  `json:"scope"`
			Pointlist [][]any `json:"pointlist"`
		} `json:"series"`
	}
	if err := json.Unmarshal(b, &a); err != nil || a.Status == "error" {
		return nil, fail(http.StatusBadGateway, "datadog answered something other than a successful query: "+untrustedText(cut(redact(a.Error), 200)))
	}
	items := make([]map[string]any, 0, min(len(a.Series), 10))
	for _, ser := range a.Series[:min(len(a.Series), 10)] {
		items = append(items, map[string]any{"metric": untrusted(ser.Metric), "scope": untrusted(ser.Scope), "points": everyKth(orEmpty(ser.Pointlist), connMaxPoints)})
	}
	return fit(items, func(kept []map[string]any, dropped int) map[string]any {
		return map[string]any{"from": from, "to": to, "series": kept, "more": len(a.Series) - len(items) + dropped, "link": nil}
	})
}

// ddSearchLogs reads POST /api/v2/logs/events/search:
// https://docs.datadoghq.com/api/latest/logs/search-logs-post.md
// The answer has no link: Datadog documents no URL form for a log search.
func (s *Server) ddSearchLogs(ctx context.Context, args json.RawMessage) (map[string]any, error) {
	var in struct {
		Query   string `json:"query"`
		Minutes int    `json:"minutes"`
		Limit   int    `json:"limit"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	if err := queryArg(in.Query); err != nil {
		return nil, err
	}
	m, err := minutesOr(in.Minutes, 15)
	if err != nil {
		return nil, err
	}
	limit, err := limitArg(in.Limit, 50, 50)
	if err != nil {
		return nil, err
	}
	to := s.now()
	// from and to take millisecond timestamps as strings.
	req, err := json.Marshal(map[string]any{"filter": map[string]any{"query": in.Query, "from": strconv.FormatInt(to.Add(-time.Duration(m)*time.Minute).UnixMilli(), 10),
		"to": strconv.FormatInt(to.UnixMilli(), 10)}, "sort": "-timestamp", "page": map[string]any{"limit": limit}})
	if err != nil {
		return nil, err
	}
	b, err := s.datadog(ctx, http.MethodPost, "/api/v2/logs/events/search", req)
	if err != nil {
		return nil, err
	}
	var a struct {
		Data []struct {
			Attributes struct {
				Timestamp string `json:"timestamp"`
				Service   string `json:"service"`
				Host      string `json:"host"`
				Status    string `json:"status"`
				Message   string `json:"message"`
			} `json:"attributes"`
		} `json:"data"`
		Meta struct {
			Page struct {
				After string `json:"after"`
			} `json:"page"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fail(http.StatusBadGateway, "datadog answered something other than a log list")
	}
	lines := make([]map[string]any, 0, min(len(a.Data), limit))
	for _, d := range a.Data[:min(len(a.Data), limit)] {
		at := d.Attributes
		// Redacted before it is cut, so a cut can't leave part of a secret.
		lines = append(lines, map[string]any{"timestamp": at.Timestamp, "service": at.Service, "host": at.Host, "status": at.Status,
			"message": cutRunes(redact(at.Message), connMaxMessage)})
	}
	return fit(lines, func(kept []map[string]any, dropped int) map[string]any {
		return map[string]any{"lines": untrusted(kept), "more": a.Meta.Page.After != "" || len(a.Data) > len(kept), "link": nil}
	})
}
