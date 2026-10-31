package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// MCP call bounds. Admin is fixed-size, so each token gets a few calls at a
// time, each with a deadline that also cancels its queries, a result cap
// and a window cap.
const (
	mcpCallTimeout  = 5 * time.Second
	mcpMaxInFlight  = 4
	mcpMaxActors    = 1024
	mcpMaxResult    = 64 << 10
	mcpMaxMinutes   = 14 * 24 * 60
	mcpMaxBody      = 1 << 20
	mcpMaxSimulated = 20
	mcpMaxRoutes    = 200
)

// mcpTool is one MCP tool: the permission it needs, besides the runner's
// autopilot.agent, which reaches every tool. Tools are listed here, not
// registered by type, so the tool set has a fixed hash the runs record.
type mcpTool struct {
	Name        string         `json:"name"`
	Perm        string         `json:"permission"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"input_schema"`
}

func object(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if required != nil {
		m["required"] = required
	}
	return m
}

var (
	minutesProp = map[string]any{"type": "integer", "minimum": 1, "maximum": mcpMaxMinutes, "description": "how far back, in minutes; default 60"}
	scopeProp   = map[string]any{"type": "object", "description": "kind global; host with host; route with host, method and template; or rule with rule"}
	notesProp   = map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "maxItems": 5, "description": "ids of notes search_notes served this run that the proposal relies on"}
	ruleProp    = map[string]any{"type": "object", "description": "a rate-limit rule: expression (text), algorithm, limit, period, key, on_missing_key, and optional burst, penalty, distinct_of, count_statuses (upstream statuses to count instead of requests, 1xx to 4xx), fail_mode"}
)

var mcpTools = []mcpTool{
	{"get_autopilot_state", "autopilot.read", "Mode, budgets and what they use, connected runners, the live autopilot rules with state and expiry, and the active exclusions.", object(nil)},
	{"list_cases", "autopilot.read", "Past cases and their verdicts, newest first, on one rule when rule is set.",
		object(map[string]any{"rule": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}})},
	{"list_rules", "config.read", "The active version's rules, people's and the autopilot's, with expressions as text.", object(nil)},
	{"describe_fields", "config.read", "Expression fields, rate-limit key kinds and algorithms the edge accepts.", object(nil)},
	{"get_stats", "stats.read", "Per-minute fleet, rule, status code and upstream cause counts. Windows over 360 minutes come in hourly steps.",
		object(map[string]any{"minutes": minutesProp})},
	{"get_rule_stats", "stats.read", "Evaluated, limited, would_limit, failed and capped per minute for one rate-limit rule, in hourly steps past 360 minutes, and its 50 most-limited subjects.",
		object(map[string]any{"rule": map[string]any{"type": "string"}, "minutes": minutesProp}, "rule")},
	{"list_anomalies", "stats.read", "Open and recent anomalies the notification checks found.", object(nil)},
	{"list_routes", "stats.read", "Routes observed in access logs over the last hours (default 24), busiest first, at most limit (default 50), with requests, status classes, decisions and rules; more counts the routes left out.",
		object(map[string]any{"hours": map[string]any{"type": "integer", "minimum": 1, "maximum": retentionDays * 24}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": mcpMaxRoutes}})},
	{"get_route", "stats.read", "One observed route with its hourly series.", object(map[string]any{"id": map[string]any{"type": "integer"}}, "id")},
	{"check_subject", "stats.read", "Whether an IP is in a verified crawler range or a protected subject.",
		object(map[string]any{"ip": map[string]any{"type": "string"}}, "ip")},
	{"list_versions", "config.read", "Recent versions with source, author and change summary.",
		object(map[string]any{"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}})},
	{"get_case", permAutopilot, "The case this run answers: its trigger, evidence and prior cases on the same rule.", object(nil)},
	{"validate_rule", permAutopilot, "Runs the policy and compiles a rule with the live rules, without proposing it.",
		object(map[string]any{"rule": ruleProp, "action": map[string]any{"type": "string", "enum": []string{"add_sensor", "enforce"}}, "name": map[string]any{"type": "string"},
			"ttl": map[string]any{"type": "string"}, "cites": map[string]any{"type": "string"}, "notes": notesProp}, "rule")},
	{"simulate_rule", permAutopilot, "Which rules, the candidate included, match up to 20 test requests.",
		object(map[string]any{"rule": ruleProp, "requests": map[string]any{"type": "array", "maxItems": mcpMaxSimulated, "items": map[string]any{"type": "object"}}}, "rule", "requests")},
	{"propose", permAutopilot, "Proposes add_sensor, enforce or retire. retire ends a proposed or observing sensor; enforcing rules end by expiry or a person. Admin checks the policy and budgets and answers whether it accepted the proposal and why not.",
		object(map[string]any{"action": map[string]any{"type": "string", "enum": []string{"add_sensor", "enforce", "retire"}}, "name": map[string]any{"type": "string"},
			"rule": ruleProp, "ttl": map[string]any{"type": "string"}, "rationale": map[string]any{"type": "string"}, "evidence": map[string]any{"type": "object"},
			"cites": map[string]any{"type": "string"}, "rule_id": map[string]any{"type": "string"}, "notes": notesProp}, "action", "rationale")},
	{"record_learning", permAutopilot, "Records what this case taught for later cases: a note of kind context, expected_pattern, attack_signature, collateral_risk or key_preference " +
		"on a scope (global, an observed host or route, or a live rule). An observed note has a claim admin recomputes on its own data and cites evidence ids of " +
		"stats reads of this run; a hypothesis is a context note whose statement says it is one. At most 3 a run. Admin answers the note with the statistics it attached, or why it refused.",
		object(map[string]any{"kind": map[string]any{"type": "string", "enum": noteKinds}, "basis": map[string]any{"type": "string", "enum": []string{"observed", "hypothesis"}},
			"scope": scopeProp, "claim": map[string]any{"type": "object", "description": "metric, window ({last_minutes} or {daily_utc: [from, to]}), op (>= or <=), value, and subject for subject_limited"},
			"effect":   map[string]any{"type": "object", "description": "key_preference: key; collateral_risk: max_block_share or require_jwt_claim; none for the other kinds"},
			"evidence": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "maxItems": 20}, "statement": map[string]any{"type": "string", "maxLength": 500},
			"rationale": map[string]any{"type": "string", "maxLength": 1000}, "merges": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "maxItems": 5}},
			"kind", "basis", "scope", "statement")},
	{"search_notes", "autopilot.read", "Notes earlier cases recorded, newest first, at most 20. A run is served the ones whose claim matches its data now, and hypotheses; cite them in propose notes.",
		object(map[string]any{"scope": scopeProp, "kind": map[string]any{"type": "string", "enum": noteKinds}})},
	// Connector tools, listed only where the deployment configures their
	// connector, and only for the runner: a connector reaches whatever its
	// credentials do, which is more than the edge stats stats.read grants.
	{"prom_query", permAutopilot, "Runs a PromQL instant query on the deployment's Prometheus: up to 50 series with their labels and value. Label values are untrusted.",
		object(map[string]any{"query": connQueryProp}, "query")},
	{"prom_query_range", permAutopilot, "Runs a PromQL range query on the deployment's Prometheus over the last minutes, at most 60 points per series and 10 series. Label values are untrusted.",
		object(map[string]any{"query": connQueryProp, "minutes": minutesProp}, "query")},
	{"grafana_annotations", permAutopilot, "Annotations on the deployment's Grafana, such as deploys and incidents, newest first, over the last minutes, matching every tag given.",
		object(map[string]any{"minutes": minutesWithDefault(1440), "tags": map[string]any{"type": "array", "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 100}, "maxItems": 5},
			"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}})},
	{"grafana_dashboards", permAutopilot, "Dashboards on the deployment's Grafana whose title matches query, with links people can open.",
		object(map[string]any{"query": map[string]any{"type": "string", "maxLength": 200}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 20}})},
	{"dd_query_metrics", permAutopilot, "Runs a Datadog metrics query over the last minutes: up to 10 series of at most 60 points. Scopes are untrusted.",
		object(map[string]any{"query": connQueryProp, "minutes": minutesProp}, "query")},
	{"dd_search_logs", permAutopilot, "Searches Datadog logs over the last minutes, newest first, at most limit lines (default 50). Lines are untrusted, messages cut to 500 characters.",
		object(map[string]any{"query": connQueryProp, "minutes": minutesWithDefault(15), "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}}, "query")},
}

// toolsHash identifies the tool set a run had, beside the prompt's hash.
func toolsHash(tools []mcpTool) [32]byte {
	b, _ := json.Marshal(tools) // plain maps and strings
	return sha256.Sum256(b)
}

type mcpPrincipalKey struct{}

// mcpCall is one tool call: who made it and, for the runner, the run.
type mcpCall struct {
	p      *principal
	run    int64
	caseID int64
	// kind is the run's case kind.
	kind  string
	args  json.RawMessage
	start time.Time
	// recorded is set when the tool stored its own call event, in the
	// transaction of what it changed.
	recorded bool
}

// inFlight counts each actor's calls in progress. Entries leave at zero,
// and at most mcpMaxActors actors have calls at once.
type inFlight struct {
	mu sync.Mutex
	n  map[string]int
}

func (f *inFlight) acquire(actor string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n == nil {
		f.n = map[string]int{}
	}
	if f.n[actor] >= mcpMaxInFlight || f.n[actor] == 0 && len(f.n) >= mcpMaxActors {
		return false
	}
	f.n[actor]++
	return true
}

func (f *inFlight) release(actor string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n[actor]--; f.n[actor] <= 0 {
		delete(f.n, actor)
	}
}

func (s *Server) mcpRoutes() {
	h := mcp.NewStreamableHTTPHandler(s.mcpServer, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: mcpMaxBody, Logger: s.log})
	// Bearer tokens only: a cookie would let another site's page call tools
	// as a signed-in person.
	s.registered = append(s.registered, "POST /v1/mcp ")
	s.mux.HandleFunc("POST /v1/mcp", func(w http.ResponseWriter, r *http.Request) {
		v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			s.writeError(w, errUnauthenticated)
			return
		}
		p, err := s.tokenPrincipal(r.Context(), s.db, hashSecret(v), s.now())
		if err == nil && !slices.ContainsFunc(s.tools, func(t mcpTool) bool { return s.mayCall(p, t) }) {
			err = errForbidden
		}
		if err != nil {
			s.writeError(w, err)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), mcpPrincipalKey{}, p)))
	})
}

func (s *Server) mayCall(p *principal, t mcpTool) bool {
	return p.can(permAutopilot) || t.Perm != permAutopilot && p.can(t.Perm)
}

// mcpServer is a server for one request's principal. Every tool is
// registered, so a call outside the principal's permissions gets a reason;
// tools/list shows only the ones it may call.
func (s *Server) mcpServer(r *http.Request) *mcp.Server {
	p, _ := r.Context().Value(mcpPrincipalKey{}).(*principal)
	srv := mcp.NewServer(&mcp.Implementation{Name: "edge-proxy-admin", Version: "1"}, &mcp.ServerOptions{Logger: s.log})
	run := r.Header.Get("X-Autopilot-Run")
	for _, t := range s.tools {
		srv.AddTool(&mcp.Tool{Name: t.Name, Description: t.Description, InputSchema: t.Schema}, s.mcpHandler(t, p, run))
	}
	srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if l, ok := res.(*mcp.ListToolsResult); ok && err == nil {
				l.Tools = slices.DeleteFunc(l.Tools, func(tool *mcp.Tool) bool {
					i := slices.IndexFunc(s.tools, func(t mcpTool) bool { return t.Name == tool.Name })
					return i < 0 || !s.mayCall(p, s.tools[i])
				})
			}
			return res, err
		}
	})
	return srv
}

// mcpHandler wraps a tool with its permission check, the per-actor limit,
// the deadline and the result cap, and records every call the runner
// makes as an admin event of its run.
func (s *Server) mcpHandler(t mcpTool, p *principal, runHeader string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		args := req.Params.Arguments
		if len(args) == 0 || string(args) == "null" {
			args = json.RawMessage("{}")
		}
		call := &mcpCall{p: p, args: args, start: start}
		// Here, so a call refused before learn runs is not recorded with its secret.
		if t.Name == "record_learning" && looksLikeCredential(args) {
			call.args = json.RawMessage(`{"redacted":"credential"}`)
		}
		refusal := ""
		switch {
		case p.can(permAutopilot):
			refusal = s.agentRun(ctx, runHeader, call)
		case !s.mayCall(p, t):
			refusal = fmt.Sprintf("%s needs %s", t.Name, t.Perm)
		}
		var out []byte
		if refusal == "" {
			out, refusal = s.callTool(ctx, t, call, args)
		}
		evidence := 0
		if call.run != 0 && !call.recorded {
			// Recorded after the call's own deadline, within one of its own.
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mcpCallTimeout)
			// call.args, which a tool may have redacted.
			seq, cut, err := s.recordCall(rctx, call.run, t.Name, call.args, out, refusal, time.Since(start))
			cancel()
			// A stats or connector read kept whole is evidence a note can cite by its seq.
			if err == nil && refusal == "" && citable(t) && !cut {
				evidence = seq
			}
			if err != nil {
				if !errors.Is(err, errEventCap) {
					s.log.Error("recording an MCP call failed", "tool", t.Name, "error", err.Error())
				}
				// An unrecorded answer would be invisible in the run's record.
				out, refusal = nil, "this run can't be recorded any further, so it gets no more answers: "+errText(err)
			}
		}
		if refusal != "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: refusal}}}, nil
		}
		res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}, StructuredContent: json.RawMessage(out)}
		if evidence > 0 {
			// Both forms, since an SDK may pass the model only the text or only
			// the structured result.
			var fields map[string]json.RawMessage
			if json.Unmarshal(out, &fields) == nil {
				fields["evidence_id"] = json.RawMessage(strconv.Itoa(evidence))
				b, _ := json.Marshal(fields) // raw JSON values
				res.StructuredContent = json.RawMessage(b)
			}
			res.Content = append(res.Content, &mcp.TextContent{Text: fmt.Sprintf(`{"evidence_id":%d}`, evidence)})
		}
		return res, nil
	}
}

// ablation is the call's case when it is an ablation, or 0.
func (c *mcpCall) ablation() int64 {
	if c.kind == "ablation" {
		return c.caseID
	}
	return 0
}

// agentRun checks that the runner names a run in progress and fills it in.
func (s *Server) agentRun(ctx context.Context, header string, call *mcpCall) string {
	const need = "the runner's calls need X-Autopilot-Run naming a run in progress"
	id, err := strconv.ParseInt(header, 10, 64)
	if err != nil {
		return need
	}
	err = s.db.QueryRow(ctx, "SELECT id, kind FROM autopilot_cases WHERE run_id = $1 AND state = 'running' AND lease_until >= $2", id, s.now()).Scan(&call.caseID, &call.kind)
	if err != nil {
		return fmt.Sprintf("run %d is not in progress; %s", id, need)
	}
	call.run = id
	return ""
}

// callTool runs a tool in one of its actor's in-flight slots. A panic in a
// tool answers as an error and still frees the slot.
func (s *Server) callTool(ctx context.Context, t mcpTool, call *mcpCall, args json.RawMessage) (out []byte, refusal string) {
	if !s.mcpCalls.acquire(call.p.actor) {
		return nil, fmt.Sprintf("%d calls are in flight for this token; wait for one to finish", mcpMaxInFlight)
	}
	defer s.mcpCalls.release(call.p.actor)
	defer func() {
		if v := recover(); v != nil {
			s.log.Error("MCP tool panicked", "tool", t.Name, "panic", fmt.Sprint(v))
			out, refusal = nil, "internal error"
		}
	}()
	return s.runTool(ctx, t, call, args)
}

func (s *Server) runTool(ctx context.Context, t mcpTool, call *mcpCall, args json.RawMessage) ([]byte, string) {
	timeout := mcpCallTimeout
	if toolConnector[t.Name] != "" {
		timeout = s.connTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := s.tool(ctx, t.Name, call, args)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Sprintf("%s took longer than %s; ask for less", t.Name, timeout)
		}
		if _, ok := errors.AsType[*problem](err); !ok {
			s.log.Error("MCP tool failed", "tool", t.Name, "error", err.Error())
		}
		return nil, errText(err)
	}
	out, err := json.Marshal(res)
	if err != nil {
		return nil, errText(err)
	}
	if len(out) > mcpMaxResult {
		return nil, fmt.Sprintf("the result is over %d KiB; ask for less, such as a shorter window or one rule", mcpMaxResult>>10)
	}
	return out, ""
}

// errText is what a caller is told about err: a problem's own words, never
// an internal error's.
func errText(err error) string {
	p, ok := errors.AsType[*problem](err)
	if !ok {
		return "internal error"
	}
	msg := p.Detail
	if msg == "" {
		msg = p.Title
	}
	for _, e := range p.Errors {
		msg += "; " + joinPath(e.Path, e.Msg)
	}
	return msg
}

// recordCall stores a runner's tool call as an admin event of its run and
// returns its seq and whether its payload was cut.
func (s *Server) recordCall(ctx context.Context, run int64, tool string, args json.RawMessage, out []byte, refusal string, took time.Duration) (int, bool, error) {
	var seq int
	var cut bool
	err := dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var err error
		seq, cut, err = s.callEvent(ctx, tx, run, tool, args, out, refusal, took)
		return err
	}))
	return seq, cut, err
}

// callEvent stores a tool call in tx under the run's lock and returns its
// seq and whether its payload was cut. It is refused once the run has
// reported its result, so a run's record ends there.
func (s *Server) callEvent(ctx context.Context, tx pgx.Tx, run int64, tool string, args json.RawMessage, out []byte, refusal string, took time.Duration) (int, bool, error) {
	payload := map[string]any{"tool": tool, "arguments": args, "allowed": refusal == "", "duration_ms": took.Milliseconds()}
	if refusal != "" {
		payload["refusal"] = refusal
	} else {
		payload["result"] = json.RawMessage(out)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, false, err
	}
	if err := lockRun(ctx, tx, run); err != nil {
		return 0, false, err
	}
	var seq int
	var finished bool
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(seq), 0) + 1, EXISTS (SELECT 1 FROM autopilot_run_results WHERE run_id = $1)
		FROM autopilot_run_events WHERE run_id = $1 AND source = 'admin'`, run).Scan(&seq, &finished); err != nil {
		return 0, false, err
	}
	if finished {
		return 0, false, fail(http.StatusConflict, fmt.Sprintf("run %d has reported its result", run))
	}
	return seq, len(b) > maxEventBytes, s.addEvents(ctx, tx, run, "admin", []runEvent{{Seq: seq, Kind: "tool_call", At: s.now(), Payload: b}})
}

// strict decodes a tool's arguments, refusing unknown fields.
func strict(args json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fail(http.StatusUnprocessableEntity, "invalid arguments: "+err.Error())
	}
	return nil
}

// untrusted marks a value whose strings clients wrote.
func untrusted(v any) map[string]any { return map[string]any{"untrusted": v} }

func minutesArg(m int) (int, error) {
	switch {
	case m == 0:
		return 60, nil
	case m < 1 || m > mcpMaxMinutes:
		return 0, fail(http.StatusUnprocessableEntity, fmt.Sprintf("minutes is 1 to %d (14 days)", mcpMaxMinutes))
	}
	return m, nil
}

// capWriter is a ResponseWriter for calling a handler in process. It keeps
// one byte past the result cap, so an over-size result is known without
// holding all of it.
type capWriter struct {
	header http.Header
	status int
	buf    bytes.Buffer
	over   bool
}

func (w *capWriter) Header() http.Header { return w.header }
func (w *capWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}

func (w *capWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if room := mcpMaxResult + 1 - w.buf.Len(); len(b) > room {
		w.over = true
		w.buf.Write(b[:max(room, 0)])
		return len(b), nil
	}
	return w.buf.Write(b)
}

// viaHandler calls a read handler of the admin API in process, as p, and
// returns its JSON.
func (s *Server) viaHandler(ctx context.Context, p *principal, h handlerFunc, target string, pathValues ...string) (json.RawMessage, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(pathValues); i += 2 {
		r.SetPathValue(pathValues[i], pathValues[i+1])
	}
	w := &capWriter{header: http.Header{}}
	if err := h(w, r, p); err != nil {
		return nil, err
	}
	switch {
	case w.over:
		return nil, fail(http.StatusUnprocessableEntity, fmt.Sprintf("the result is over %d KiB; ask for less", mcpMaxResult>>10))
	case w.status >= 400:
		return nil, fail(w.status, strings.TrimSpace(w.buf.String()))
	}
	return json.RawMessage(w.buf.Bytes()), nil
}

func (s *Server) tool(ctx context.Context, name string, call *mcpCall, args json.RawMessage) (any, error) {
	switch name {
	case "get_autopilot_state":
		st, err := s.autopilotState(ctx)
		if err != nil {
			return nil, err
		}
		out := modelState{autopilotState: st, Rules: []modelRule{}, Exclusions: []modelExclusion{}}
		for _, r := range st.Rules {
			out.Rules = append(out.Rules, modelRule{ruleView: r, Expression: untrusted(r.Expression), Host: untrusted(r.Host), PathPrefix: untrusted(r.PathPrefix)})
		}
		for _, e := range st.Exclusions {
			out.Exclusions = append(out.Exclusions, modelExclusion{ID: e.ID, Subject: e.Subject, Host: untrusted(e.Host), PathPrefix: untrusted(e.PathPrefix), ExpiresAt: e.ExpiresAt})
		}
		return out, nil
	case "list_cases":
		var in struct {
			Rule  string `json:"rule"`
			Limit int    `json:"limit"`
		}
		if err := strict(args, &in); err != nil {
			return nil, err
		}
		if in.Limit < 1 || in.Limit > 50 {
			in.Limit = 20
		}
		cases, err := s.casesFor(ctx, in.Rule, in.Limit, call.ablation())
		return map[string]any{"cases": modelCases(cases)}, err
	case "list_rules":
		return s.listRulesTool(ctx)
	case "describe_fields":
		raw, err := s.viaHandler(ctx, call.p, s.exprSchema, "/api/expr/schema")
		return map[string]any{"schema": raw, "key_kinds": snapshot.KeyKinds, "algorithms": snapshot.Algorithms, "max_rules_per_phase": snapshot.MaxRulesPerPhase}, err
	case "get_stats":
		var in struct {
			Minutes int `json:"minutes"`
		}
		if err := strict(args, &in); err != nil {
			return nil, err
		}
		m, err := minutesArg(in.Minutes)
		if err != nil {
			return nil, err
		}
		q := url.Values{"minutes": {strconv.Itoa(m)}}
		if m > 360 {
			q.Set("step", "60")
		}
		raw, err := s.viaHandler(ctx, call.p, s.stats, "/api/stats?"+q.Encode())
		return map[string]any{"minutes": m, "stats": untrusted(raw)}, err
	case "get_rule_stats":
		return s.ruleStatsTool(ctx, args)
	case "list_anomalies":
		raw, err := s.viaHandler(ctx, call.p, s.listAnomalies, "/api/anomalies")
		if err != nil {
			return nil, err
		}
		var list struct {
			Alertmanager bool             `json:"alertmanager"`
			Anomalies    []map[string]any `json:"anomalies"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, err
		}
		// A summary can quote a subject, which a client chose.
		for _, a := range list.Anomalies {
			a["summary"] = untrusted(a["summary"])
		}
		return list, nil
	case "list_routes":
		var in struct {
			Hours int `json:"hours"`
			Limit int `json:"limit"`
		}
		if err := strict(args, &in); err != nil {
			return nil, err
		}
		switch {
		case in.Limit == 0:
			in.Limit = 50
		case in.Limit < 1 || in.Limit > mcpMaxRoutes:
			return nil, fail(http.StatusUnprocessableEntity, fmt.Sprintf("limit is 1 to %d", mcpMaxRoutes))
		}
		q := url.Values{"limit": {strconv.Itoa(in.Limit)}}
		if in.Hours != 0 {
			q.Set("hours", strconv.Itoa(in.Hours))
		}
		raw, err := s.viaHandler(ctx, call.p, s.listObserved, "/api/observed-routes?"+q.Encode())
		return map[string]any{"routes": untrusted(raw)}, err
	case "get_route":
		var in struct {
			ID int64 `json:"id"`
		}
		if err := strict(args, &in); err != nil {
			return nil, err
		}
		raw, err := s.viaHandler(ctx, call.p, s.getObserved, "/api/observed-routes/"+strconv.FormatInt(in.ID, 10), "id", strconv.FormatInt(in.ID, 10))
		return map[string]any{"route": untrusted(raw)}, err
	case "check_subject":
		return s.checkSubject(ctx, args)
	case "list_versions":
		var in struct {
			Limit int `json:"limit"`
		}
		if err := strict(args, &in); err != nil {
			return nil, err
		}
		if in.Limit < 1 || in.Limit > 50 {
			in.Limit = 20
		}
		list, err := s.versionItems(ctx, &in.Limit)
		return map[string]any{"versions": list}, err
	case "get_case":
		return s.getCaseTool(ctx, call)
	case "validate_rule":
		var in proposeIn
		if err := strict(args, &in); err != nil {
			return nil, err
		}
		if in.Action == "" {
			in.Action = "add_sensor"
		}
		if in.Name == "" {
			in.Name = "candidate"
		}
		if err := in.sortNotes(); err != nil {
			return nil, err
		}
		set, err := loadAutopilot(ctx, s.db)
		if err != nil {
			return nil, err
		}
		notes, err := s.servedTo(ctx, s.db, call, in.Notes)
		if err != nil {
			return nil, err
		}
		c, err := s.policy(ctx, s.db, set, in, notes)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": len(c.reasons) == 0, "reasons": orEmpty(c.reasons), "checks": c.checks}, nil
	case "simulate_rule":
		return s.simulateTool(ctx, args)
	case "propose":
		var in proposeIn
		if err := strict(args, &in); err != nil {
			return nil, err
		}
		return s.propose(ctx, call, in)
	case "record_learning":
		return s.recordLearning(ctx, call, args)
	case "search_notes":
		return s.searchNotes(ctx, call, args)
	}
	if toolConnector[name] != "" {
		return s.connectorTool(ctx, name, args)
	}
	return nil, fail(http.StatusNotFound, "no tool "+name)
}

func (s *Server) listRulesTool(ctx context.Context) (any, error) {
	av, err := activeVersion(ctx, s.db)
	if err != nil || av == nil {
		return map[string]any{"version": nil, "rate_limit_rules": []any{}, "config_rules": []any{}}, err
	}
	v, err := s.loadVersion(ctx, s.db, *av)
	if err != nil {
		return nil, err
	}
	type rl struct {
		ID         string         `json:"id"`
		Autopilot  bool           `json:"autopilot"`
		Expression map[string]any `json:"expression"`
		Algorithm  string         `json:"algorithm"`
		Limit      int64          `json:"limit"`
		Period     string         `json:"period"`
		Key        []string       `json:"key"`
		Action     string         `json:"action"`
		ExpiresAt  *time.Time     `json:"expires_at,omitempty"`
	}
	type cr struct {
		ID         string            `json:"id"`
		Expression map[string]any    `json:"expression"`
		Settings   snapshot.Settings `json:"settings"`
	}
	rls, crs := []rl{}, []cr{}
	for _, r := range v.Config.RateLimitRules {
		// Expressions carry literals people and the model wrote, such as paths.
		x := rl{ID: r.ID, Autopilot: isOverlay(r.ID), Expression: untrusted(expr.Render(r.Expression)), Algorithm: r.Algorithm, Limit: r.Limit,
			Period: time.Duration(r.Period).String(), Key: r.Key, Action: r.Action}
		if !r.ExpiresAt.IsZero() {
			x.ExpiresAt = &r.ExpiresAt
		}
		rls = append(rls, x)
	}
	for _, r := range v.Config.ConfigRules {
		crs = append(crs, cr{ID: r.ID, Expression: untrusted(expr.Render(r.Expression)), Settings: r.Settings})
	}
	return map[string]any{"version": v.Version, "rate_limit_rules": rls, "config_rules": crs}, nil
}

func (s *Server) ruleStatsTool(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		Rule    string `json:"rule"`
		Minutes int    `json:"minutes"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	m, err := minutesArg(in.Minutes)
	if err != nil {
		return nil, err
	}
	// Hourly past 360 minutes, like get_stats, so the series stays small.
	step := time.Minute
	if m > 360 {
		step = time.Hour
	}
	since := s.now().Add(-time.Duration(m) * time.Minute)
	rows, err := s.db.Query(ctx, `SELECT b, sum(requests)::bigint, coalesce(sum((e->>'evaluated')::bigint), 0)::bigint, coalesce(sum((e->>'limited')::bigint), 0)::bigint,
		coalesce(sum((e->>'would_limit')::bigint), 0)::bigint, coalesce(sum((e->>'failed')::bigint), 0)::bigint, coalesce(sum((e->>'capped')::bigint), 0)::bigint
		FROM (SELECT date_bin($3::interval, minute, timestamptz 'epoch') b, requests,
			(SELECT x FROM jsonb_array_elements(rate_limit) x WHERE x->>'id' = $2 LIMIT 1) e FROM edge_stats_minute WHERE minute >= $1) m
		GROUP BY b HAVING count(e) > 0 ORDER BY b`, since, in.Rule, step)
	if err != nil {
		return nil, err
	}
	type bucket struct {
		Minute time.Time       `json:"minute"`
		Fleet  uint64          `json:"fleet_requests"`
		Rule   edge.RuleCounts `json:"counts"`
	}
	series, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (bucket, error) {
		b := bucket{Rule: edge.RuleCounts{ID: in.Rule}}
		err := row.Scan(&b.Minute, &b.Fleet, &b.Rule.Evaluated, &b.Rule.Limited, &b.Rule.WouldLimit, &b.Rule.Failed, &b.Rule.Capped)
		return b, err
	})
	if err != nil {
		return nil, err
	}
	rows, err = s.db.Query(ctx, `SELECT k, d, l, w FROM (SELECT t->>'key' k, max(t->>'display') d, sum((t->>'limited')::bigint)::bigint l,
		coalesce(sum((t->>'would_limit')::bigint), 0)::bigint w FROM edge_stats_minute, jsonb_array_elements(top_limited) t
		WHERE minute >= $1 AND t->>'rule' = $2 GROUP BY 1) s ORDER BY l + w DESC, k LIMIT 50`, since, in.Rule)
	if err != nil {
		return nil, err
	}
	top, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (edge.TopCount, error) {
		t := edge.TopCount{Rule: in.Rule}
		err := row.Scan(&t.Key, &t.Display, &t.Limited, &t.WouldLimit)
		return t, err
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"rule": in.Rule, "minutes": m, "step_minutes": int(step / time.Minute), "series": orEmpty(series), "top_subjects": untrusted(orEmpty(top))}, nil
}

func (s *Server) checkSubject(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		IP string `json:"ip"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	a, err := netip.ParseAddr(in.IP)
	if err != nil {
		return nil, fail(http.StatusUnprocessableEntity, "ip must be an IP address")
	}
	crawlers, err := s.crawlerPrefixes(ctx, s.db)
	if err != nil {
		return nil, err
	}
	set, err := loadAutopilot(ctx, s.db)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ip": a.String(), "verified_crawler": inPrefixes(crawlers, a), "protected": inPrefixes(protectedPrefixes(set), a)}, nil
}

func (s *Server) getCaseTool(ctx context.Context, call *mcpCall) (any, error) {
	rows, err := s.db.Query(ctx, "SELECT "+caseCols+" FROM autopilot_cases WHERE id = $1", call.caseID)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[caseRow])
	if err != nil {
		return nil, err
	}
	var prior []caseRow
	if c.Rule != nil {
		all, err := s.casesFor(ctx, *c.Rule, 11, call.ablation())
		if err != nil {
			return nil, err
		}
		prior = slices.DeleteFunc(all, func(o caseRow) bool { return o.ID == c.ID })
	}
	return map[string]any{"case_id": c.ID, "kind": c.Kind, "rule": c.Rule, "route_id": c.RouteID, "anomaly_id": c.AnomalyID, "question": c.Question,
		"brief": c.Brief, "attempt": c.Attempts, "prior_cases": modelCases(prior)}, nil
}

// modelState is the autopilot state as the model reads it: rule
// expressions carry literals the model and people wrote.
type modelState struct {
	*autopilotState
	Rules      []modelRule      `json:"rules"`
	Exclusions []modelExclusion `json:"exclusions"`
}

// modelExclusion is an exclusion as the model reads it. Its host and path
// may come from a sensor the model wrote; who made it and why stay with
// people.
type modelExclusion struct {
	ID         int64          `json:"id"`
	Subject    netip.Prefix   `json:"subject"`
	Host       map[string]any `json:"host"`
	PathPrefix map[string]any `json:"path_prefix"`
	ExpiresAt  *time.Time     `json:"expires_at"`
}

type modelRule struct {
	ruleView
	Expression map[string]any `json:"expression"`
	Host       map[string]any `json:"host"`
	PathPrefix map[string]any `json:"path_prefix"`
}

// modelCase is a case as the model reads it: an earlier run's summary may
// repeat what a client wrote.
type modelCase struct {
	caseRow
	Summary map[string]any `json:"summary"`
}

func modelCases(cs []caseRow) []modelCase {
	out := []modelCase{}
	for _, c := range cs {
		out = append(out, modelCase{caseRow: c, Summary: untrusted(c.Summary)})
	}
	return out
}

func (s *Server) simulateTool(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		Rule     *ruleIn       `json:"rule"`
		Requests []TestRequest `json:"requests"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	if in.Rule == nil || len(in.Requests) > mcpMaxSimulated {
		return nil, fail(http.StatusUnprocessableEntity, fmt.Sprintf("a rule and at most %d requests", mcpMaxSimulated))
	}
	n, err := expr.Parse(in.Rule.Expression)
	if err != nil {
		return nil, fail(http.StatusUnprocessableEntity, "expression: "+err.Error())
	}
	active, err := s.activeConfig(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if active == nil {
		return nil, fail(http.StatusConflict, "nothing is published yet")
	}
	r := in.Rule
	const id = overlayPrefix + "candidate"
	merged := *active
	merged.RateLimitRules = append(append(slices.Clone(baseOf(active).RateLimitRules), overlayOf(active, s.now())...), snapshot.RateLimitRule{ID: id,
		Expression: n, Algorithm: r.Algorithm, Limit: r.Limit, Period: r.Period, Burst: r.Burst, Key: r.Key, OnMissingKey: r.OnMissingKey, Action: "log",
		Penalty: r.Penalty, FailMode: "open", DistinctOf: r.DistinctOf, CountStatuses: r.CountStatuses})
	compiled, _, errs := snapshot.Compile(&merged, s.cfg.Deployment)
	if errs != nil {
		return nil, &problem{Status: http.StatusUnprocessableEntity, Title: "The rule does not compile with the live rules", Errors: errs}
	}
	results := []SimView{}
	for _, req := range in.Requests {
		res, err := simulate(compiled, req)
		if err != nil {
			return nil, fail(http.StatusUnprocessableEntity, err.Error())
		}
		results = append(results, res)
	}
	return map[string]any{"rule_id": id, "results": results}, nil
}

// proposeDone sees how the transaction of a call that records itself
// (propose, record_learning, search_notes) ended. Tests replace it to end
// the call after the commit, as a deadline can.
var proposeDone = func(err error) error { return err }

// proposeOut answers a proposal.
type proposeOut struct {
	ProposalID int64         `json:"proposal_id"`
	Accepted   bool          `json:"accepted"`
	RuleID     string        `json:"rule_id,omitempty"`
	Reasons    []string      `json:"reasons"`
	Checks     []policyCheck `json:"checks"`
}

// propose records a proposal with its policy result and audit row. The
// same proposal from the same case gets its first answer again.
func (s *Server) propose(ctx context.Context, call *mcpCall, in proposeIn) (*proposeOut, error) {
	if len(in.Rationale) > 4000 || len(in.Evidence) > 32<<10 {
		return nil, fail(http.StatusUnprocessableEntity, "rationale is at most 4000 characters and evidence at most 32 KiB")
	}
	if err := in.sortNotes(); err != nil {
		return nil, err
	}
	if call.kind == "ablation" {
		return nil, fail(http.StatusConflict, "an ablation run re-answers its case without some notes, so it proposes nothing")
	}
	canon, _ := json.Marshal(proposeIn{Action: in.Action, Name: in.Name, Rule: in.Rule, TTL: in.TTL, Cites: in.Cites, RuleID: in.RuleID, Notes: in.Notes})
	ruleSHA := sha256.Sum256(canon)
	evidence := in.Evidence
	if len(evidence) == 0 {
		evidence = json.RawMessage("{}")
	}
	evidenceSHA := sha256.Sum256(evidence)
	out := &proposeOut{Reasons: []string{}}
	counted := false
	var newID int64 // the proposal this call writes, not one it answers again
	err := s.autopilotTx(ctx, func(tx pgx.Tx) error {
		// Before any audit row, as a case result takes it.
		if err := lockRun(ctx, tx, call.run); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, "SELECT id, accepted, coalesce(rule_id, ''), checks FROM autopilot_proposals WHERE case_id = $1 AND rule_sha256 = $2", call.caseID, ruleSHA[:]).
			Scan(&out.ProposalID, &out.Accepted, &out.RuleID, &out.Checks)
		if err == nil {
			if !out.Accepted {
				out.RuleID = ""
			}
			for _, c := range out.Checks {
				if !c.OK {
					out.Reasons = append(out.Reasons, c.Name)
				}
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		set, err := loadAutopilot(ctx, tx)
		if err != nil {
			return err
		}
		if set.Mode == "off" {
			return fail(http.StatusConflict, "autopilot is off")
		}
		notes, err := s.servedTo(ctx, tx, call, in.Notes)
		if err != nil {
			return err
		}
		c, err := s.policy(ctx, tx, set, in, notes)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT nextval('autopilot_proposals_id_seq')").Scan(&out.ProposalID); err != nil {
			return err
		}
		newID = out.ProposalID
		out.Accepted, out.Checks, out.Reasons = len(c.reasons) == 0, c.checks, orEmpty(c.reasons)
		if out.Checks == nil {
			out.Checks = []policyCheck{}
		}
		var ruleID *string
		if out.Accepted {
			out.RuleID = in.RuleID
			if in.Action != "retire" {
				out.RuleID = fmt.Sprintf("%s%s-%d", overlayPrefix, in.Name, out.ProposalID)
			}
			ruleID = &out.RuleID
		}
		var ttl *int
		if in.Action != "retire" {
			sec := int(c.ttl / time.Second)
			ttl = &sec
		}
		rule := any(map[string]any{})
		if in.Rule != nil {
			rule = in.Rule
		}
		if _, err := tx.Exec(ctx, `INSERT INTO autopilot_proposals (id, case_id, run_id, action, rule_id, rule, ttl_seconds, rationale, evidence, checks, accepted, rule_sha256, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`, out.ProposalID, call.caseID, call.run, in.Action, ruleID, rule, ttl, in.Rationale,
			string(evidence), out.Checks, out.Accepted, ruleSHA[:], s.now()); err != nil {
			return err
		}
		switch {
		case out.Accepted && in.Action == "retire":
			if err := s.applyChanges(ctx, tx, []ruleChange{{from: c.target.State, next: ended(*c.target, "retired", "retired_by_review", s.now()),
				reason: in.Rationale, actor: "deployment:autopilot", action: "autopilot.retire", numbers: map[string]any{"proposal": out.ProposalID}}}, nil); err != nil {
				return err
			}
		case out.Accepted:
			kind := "sensor"
			if in.Action == "enforce" {
				kind = "enforce"
			}
			r := c.rule
			r.ID, r.ExpiresAt = out.RuleID, time.Time{}
			var cites *string
			if c.cited != nil {
				cites = &c.cited.ID
			}
			if _, err := tx.Exec(ctx, `INSERT INTO autopilot_rules (id, proposal_id, case_id, kind, state, rule, shape_sha256, ttl_seconds, cites, exclusions)
				VALUES ($1, $2, $3, $4, 'proposed', $5, $6, $7, $8, $9)`, out.RuleID, out.ProposalID, call.caseID, kind, r, c.shape[:], *ttl, cites, orEmpty(c.exclusions)); err != nil {
				return err
			}
		}
		for _, n := range in.Notes {
			if err := noteUse(ctx, tx, n, "propose", &call.run, &call.caseID, &out.ProposalID, true, nil, s.now()); err != nil {
				return err
			}
		}
		// The call event goes in this transaction: a proposal that commits
		// always has it, and one the run has no room for does not commit.
		b, err := json.Marshal(out)
		if err != nil {
			return err
		}
		if _, _, err := s.callEvent(ctx, tx, call.run, "propose", call.args, b, "", time.Since(call.start)); err != nil {
			return err
		}
		counted = true
		return admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: "deployment:autopilot", Action: "autopilot.propose", Target: fmt.Sprintf("proposal %d", out.ProposalID),
			Details: map[string]any{"case": call.caseID, "run": call.run, "action": in.Action, "rule_id": ruleID, "accepted": out.Accepted, "reasons": out.Reasons, "notes": orEmpty(in.Notes),
				"rule_sha256": hex.EncodeToString(ruleSHA[:]), "evidence_sha256": hex.EncodeToString(evidenceSHA[:])}})
	})
	err = proposeDone(err)
	if err != nil {
		// The deadline can end the call after its commit. The proposal and
		// its call event committed together then, so no refusal is recorded
		// beside them, and the proposal is counted.
		if newID != 0 && s.committed(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_proposals WHERE id = $1)", newID) {
			call.recorded = true
			s.met.autopilot.proposed(in.Action, out.Accepted, out.Reasons)
		}
		return nil, err
	}
	if counted {
		call.recorded = true
		s.met.autopilot.proposed(in.Action, out.Accepted, out.Reasons)
	}
	return out, nil
}
