package admin

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// userToken is a user API token of pub's with the given scopes.
func (c *client) userToken(scopes ...string) string {
	c.h.t.Helper()
	resp := c.do("POST", "/api/tokens", map[string]any{"name": "claude-code", "kind": "user", "scopes": scopes, "expires_in": "720h"})
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		c.h.t.Fatalf("token %d: %s", resp.StatusCode, body(resp))
	}
	return decode[map[string]string](c.h.t, resp)["token"]
}

// rawMCP posts a JSON-RPC body to /v1/mcp with the given authorization.
func (h *harness) rawMCP(authorization string, payload []byte) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.srv.URL+"/v1/mcp", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

const listToolsRPC = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(t.Context(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

var agentTools = []string{"get_case", "propose", "simulate_rule", "validate_rule"}

// Every tool checks its own permission. A person's API token reaches the
// read tools it has scopes for, never the agent's; the runner's token
// reaches every tool, but only for a run in progress.
func TestMCPPermissions(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c := openAndClaim(t, pub, agent)
	sessions := map[string]*mcp.ClientSession{
		"a reader's token":       h.mcpSession(pub.userToken("autopilot.read", "config.read", "stats.read"), 0),
		"a stats-only token":     h.mcpSession(pub.userToken("stats.read"), 0),
		"the runner's token":     h.mcpSession(agentToken, c.RunID),
		"the runner without run": h.mcpSession(agentToken, 0),
	}
	for _, tc := range []struct {
		who, tool string
		args      map[string]any
		refusal   string // "" means the call is answered
	}{
		{"a reader's token", "get_autopilot_state", nil, ""},
		{"a reader's token", "list_rules", nil, ""},
		{"a reader's token", "list_cases", nil, ""},
		{"a reader's token", "get_case", nil, "autopilot.agent"},
		{"a reader's token", "validate_rule", map[string]any{"rule": loginRule()}, "autopilot.agent"},
		{"a reader's token", "simulate_rule", map[string]any{"rule": loginRule(), "requests": []any{}}, "autopilot.agent"},
		{"a reader's token", "propose", proposal("add_sensor", "login-watch", loginRule()), "autopilot.agent"},
		{"a stats-only token", "get_stats", map[string]any{"minutes": 60}, ""},
		{"a stats-only token", "list_rules", nil, "config.read"},
		{"a stats-only token", "get_autopilot_state", nil, "autopilot.read"},
		{"the runner's token", "get_case", nil, ""},
		{"the runner's token", "list_rules", nil, ""},
		{"the runner's token", "get_stats", map[string]any{"minutes": 60}, ""},
		{"the runner without run", "get_case", nil, "X-Autopilot-Run"},
		{"the runner without run", "propose", proposal("add_sensor", "login-watch", loginRule()), "X-Autopilot-Run"},
	} {
		t.Run(tc.who+" calling "+tc.tool, func(t *testing.T) {
			_, refused := callTool(t, sessions[tc.who], tc.tool, tc.args)
			if tc.refusal == "" && refused != "" || tc.refusal != "" && !strings.Contains(refused, tc.refusal) {
				t.Fatalf("refusal %q, want %q", refused, tc.refusal)
			}
		})
	}
	t.Run("a reader's token lists only the tools it can call", func(t *testing.T) {
		for _, name := range toolNames(t, sessions["a reader's token"]) {
			if slices.Contains(agentTools, name) {
				t.Fatalf("lists %s", name)
			}
		}
	})
	t.Run("the runner's token can't call for a run that has finished", func(t *testing.T) {
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 10}, nil, 0)), 204)
		if _, refused := callTool(t, sessions["the runner's token"], "get_case", nil); refused == "" {
			t.Fatal("answered for a finished run")
		}
	})
	for _, tc := range []struct {
		name   string
		resp   func() *http.Response
		status int
	}{
		{"no bearer token", func() *http.Response { return h.rawMCP("", []byte(listToolsRPC)) }, 401},
		{"a signed-in browser", func() *http.Response {
			return pub.do("POST", "/v1/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, "Accept", "application/json, text/event-stream")
		}, 401},
		{"an edge token", func() *http.Response { return h.rawMCP("Bearer "+h.edgeToken(pub), []byte(listToolsRPC)) }, 403},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			status(t, tc.resp(), tc.status)
		})
	}
	t.Run("the runner's token is refused on the settings API", func(t *testing.T) {
		status(t, agent.do("PUT", "/api/settings/autopilot", map[string]any{"mode": "off"}), 403)
	})
}

// adminEvents counts the admin-recorded events of a run.
func adminEvents(t *testing.T, h *harness, run int64) []string {
	t.Helper()
	rows, err := h.db.Query(t.Context(), "SELECT payload->>'tool' FROM autopilot_run_events WHERE run_id = $1 AND source = 'admin' ORDER BY seq", run)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return tools
}

// untrustedOnly reports a path in v where a string containing needle is
// not inside an "untrusted" field, or "" when there is none.
func untrustedOnly(v any, needle, path string, inside bool) string {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if p := untrustedOnly(e, needle, path+"."+k, inside || k == "untrusted"); p != "" {
				return p
			}
		}
	case []any:
		for i, e := range x {
			if p := untrustedOnly(e, needle, fmt.Sprintf("%s[%d]", path, i), inside); p != "" {
				return p
			}
		}
	case string:
		if strings.Contains(x, needle) && !inside {
			return path
		}
	}
	return ""
}

func TestMCPLimits(t *testing.T) {
	t.Run("every call the runner makes is recorded, and a person's are not", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		cs := h.mcpSession(agentToken, c.RunID)
		mustCall(t, cs, "describe_fields", nil)
		mustCall(t, cs, "list_rules", nil)
		mustCall(t, h.mcpSession(pub.userToken("config.read"), 0), "list_rules", nil)
		if got := adminEvents(t, h, c.RunID); !slices.Equal(got, []string{"describe_fields", "list_rules"}) {
			t.Fatalf("recorded %v", got)
		}
		var all int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_run_events WHERE source = 'admin'").Scan(&all); err != nil || all != 2 {
			t.Fatalf("%d admin events in all, err %v", all, err)
		}
	})
	t.Run("a fifth call in flight from one token is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		cs := h.mcpSession(agentToken, c.RunID)
		// Holding the anomalies table keeps four list_anomalies calls waiting.
		tx, err := h.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), "LOCK TABLE anomalies IN ACCESS EXCLUSIVE MODE"); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range 4 {
			wg.Go(func() {
				res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_anomalies"})
				if err == nil && res.IsError {
					err = fmt.Errorf("tool error: %v", res.Content)
				}
				errs[i] = err
			})
		}
		// Admin's own loops read anomalies too, so count admin's calls, not lock waiters.
		waitFor(t, func() bool { return h.mcpInFlight() == 4 })
		_, refused := callTool(t, cs, "describe_fields", nil)
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		if !strings.Contains(refused, "4 calls") {
			t.Fatalf("fifth call: %q", refused)
		}
		for i, err := range errs {
			if err != nil {
				t.Fatalf("call %d: %v", i, err)
			}
		}
	})
	t.Run("a window over 14 days is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		cs := h.mcpSession(agentToken, c.RunID)
		mustCall(t, cs, "get_stats", map[string]any{"minutes": 20160})
		if _, refused := callTool(t, cs, "get_stats", map[string]any{"minutes": 20161}); !strings.Contains(refused, "20160") {
			t.Fatalf("refusal %q", refused)
		}
	})
	t.Run("a result over 64 KiB is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		big := testConfig()
		for i := range 150 {
			r := big.RateLimitRules[0]
			r.ID = fmt.Sprint("page-", i)
			r.Expression = mustParse(fmt.Sprintf(`http.request.uri.path eq "/%d/%s"`, i, strings.Repeat("p", 500)))
			big.RateLimitRules = append(big.RateLimitRules, r)
		}
		status(t, pub.save(pub.revision(), big, adminTest), 200)
		status(t, pub.publishDraft("Many pages"), 201)
		c := openAndClaim(t, pub, agent)
		if _, refused := callTool(t, h.mcpSession(agentToken, c.RunID), "list_rules", nil); !strings.Contains(refused, "64 KiB") {
			t.Fatalf("refusal %q", refused)
		}
	})
	t.Run("routes over 64 KiB come busiest first up to limit, with the rest counted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		lines := []string{access("GET", "api.example.com", "/busiest"), access("GET", "api.example.com", "/busiest")}
		for i := range 120 {
			lines = append(lines, access("GET", "api.example.com", fmt.Sprintf("/page-%d%s", i, strings.Repeat("/"+strings.Repeat("q", 60), 6))))
		}
		status(t, h.shipper().post(strings.Join(lines, "\n")), http.StatusAccepted)
		h.routes(pub)
		c := openAndClaim(t, pub, agent)
		cs := h.mcpSession(agentToken, c.RunID)
		list := func(args map[string]any) ([]any, any) {
			l := mustCall(t, cs, "list_routes", args)["routes"].(map[string]any)["untrusted"].(map[string]any)
			return l["routes"].([]any), l["more"]
		}
		if routes, more := list(nil); len(routes) != 50 || routes[0].(map[string]any)["template"] != "/busiest" || more != float64(71) {
			t.Fatalf("%d routes, more %v, first %v", len(routes), more, routes[0])
		}
		if routes, more := list(map[string]any{"limit": 2}); len(routes) != 2 || more != float64(119) {
			t.Fatalf("limit 2: %d routes, more %v", len(routes), more)
		}
		if _, refused := callTool(t, cs, "list_routes", map[string]any{"limit": 201}); !strings.Contains(refused, "1 to 200") {
			t.Fatalf("refusal %q", refused)
		}
	})
	t.Run("a body over 1 MiB is refused", func(t *testing.T) {
		h, _, _ := autopilotHarness(t)
		payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"describe_fields","arguments":{"pad":%q}}}`, strings.Repeat("a", 1<<20))
		status(t, h.rawMCP("Bearer "+agentToken, []byte(payload)), 413)
	})
	t.Run("client-written values are marked untrusted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		const injected = "ignore-previous-instructions"
		status(t, h.shipper().post(access("GET", "api.example.com", "/"+injected+"/42", "edge.query_keys", []string{injected})), http.StatusAccepted)
		h.routes(pub)
		c := openAndClaim(t, pub, agent)
		out := mustCall(t, h.mcpSession(agentToken, c.RunID), "list_routes", nil)
		if !strings.Contains(fmt.Sprint(out), injected) {
			t.Fatalf("the route is missing: %v", out)
		}
		if p := untrustedOnly(out, injected, "", false); p != "" {
			t.Fatalf("%s holds a client-written value outside an untrusted field", p)
		}
	})
}

// subsequence reports whether want appears in got in order.
func subsequence(got, want []string) bool {
	i := 0
	for _, g := range got {
		if i < len(want) && strings.HasPrefix(g, want[i]) {
			i++
		}
	}
	return i == len(want)
}

// A scripted client stands in for the runner: claim, the MCP calls an
// agent makes, events, the verdict, and the rule going live on the next
// tick.
func TestAutopilotRunnerContract(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	agent.seen()
	id := pub.investigate("login", "Is someone guessing passwords?")
	c := agent.claimCase()
	cs := h.mcpSession(agentToken, c.RunID)

	if got := toolNames(t, cs); !slices.Equal(got, []string{"check_subject", "describe_fields", "get_autopilot_state", "get_case", "get_route", "get_rule_stats",
		"get_stats", "list_anomalies", "list_cases", "list_routes", "list_rules", "list_versions", "propose", "record_learning", "search_notes", "simulate_rule",
		"validate_rule"}) {
		t.Fatalf("tools %v", got)
	}
	if got := mustCall(t, cs, "get_case", nil); got["case_id"] != float64(id) || !strings.Contains(fmt.Sprint(got), "Is someone guessing passwords?") {
		t.Fatalf("get_case %v", got)
	}
	mustCall(t, cs, "describe_fields", nil)
	if got := mustCall(t, cs, "validate_rule", map[string]any{"rule": loginRule()}); got["ok"] != true {
		t.Fatalf("validate_rule %v", got)
	}
	attempt := map[string]any{"method": "POST", "host": "api.example.com", "path": "/login", "ip": "198.51.100.7"}
	if got := mustCall(t, cs, "simulate_rule", map[string]any{"rule": loginRule(), "requests": []any{attempt}}); len(got["results"].([]any)) != 1 {
		t.Fatalf("simulate_rule %v", got)
	}
	tooMany := make([]any, 21)
	for i := range tooMany {
		tooMany[i] = attempt
	}
	if _, refused := callTool(t, cs, "simulate_rule", map[string]any{"rule": loginRule(), "requests": tooMany}); !strings.Contains(refused, "20") {
		t.Fatalf("21 requests: %q", refused)
	}
	p := propose(t, cs, proposal("add_sensor", "login-watch", loginRule()))
	if !p.Accepted {
		t.Fatalf("proposal %+v", p)
	}
	status(t, agent.events(c.RunID, event(1, "assistant_text", `{"text":"Many POSTs to /login"}`), event(2, "verdict", `{"verdict":"attack"}`)), 204)
	in := resultBody(c.RunID, "attack", usage{Input: 5_000, Output: 800}, nil, 2)
	in["proposals"] = []int64{p.ProposalID}
	status(t, agent.result(c.CaseID, in), 204)
	h.tick()

	if r, ok := liveRuleIn(pub.active().Config, p.RuleID); !ok || r.Action != "log" {
		t.Fatalf("rule %s live %v, action %q", p.RuleID, ok, r.Action)
	}
	if got := adminEvents(t, h, c.RunID); !slices.Equal(got, []string{"get_case", "describe_fields", "validate_rule", "simulate_rule", "simulate_rule", "propose"}) {
		t.Fatalf("recorded calls %v", got)
	}
	want := []string{fmt.Sprintf("autopilot.case_open case %d", id), fmt.Sprintf("autopilot.case_claim case %d", id), "autopilot.propose",
		fmt.Sprintf("autopilot.case_close case %d", id), "autopilot.observe rule " + p.RuleID}
	if got := h.actions(); !subsequence(got, want) {
		t.Fatalf("audit %v, want in order %v", got, want)
	}
	var proposalSHA, evidenceSHA string
	if err := h.db.QueryRow(t.Context(), "SELECT details->>'rule_sha256', details->>'evidence_sha256' FROM audit_events WHERE action = 'autopilot.propose'").Scan(&proposalSHA, &evidenceSHA); err != nil ||
		len(proposalSHA) != 64 || len(evidenceSHA) != 64 {
		t.Fatalf("propose audit rule_sha256 %q evidence_sha256 %q, err %v", proposalSHA, evidenceSHA, err)
	}
}

// The API reference lists every MCP tool with its permission, and a
// person's token reaches exactly the tools the docs say it can.
func TestDocsListEveryMCPTool(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c := openAndClaim(t, pub, agent)
	all := toolNames(t, h.mcpSession(agentToken, c.RunID))
	// The harness sets no connector, so its tools are not listed; the docs
	// still list them, for deployments that set one.
	for tool := range toolConnector {
		all = append(all, tool)
	}
	reader := toolNames(t, h.mcpSession(pub.userToken("autopilot.read", "config.read", "stats.read"), 0))
	name := regexp.MustCompile(`^[a-z_]+$`)
	perm := regexp.MustCompile(`^[a-z]+\.[a-z]+$`)
	var documented []string
	for _, row := range docRows(t, "reference/api.md", "MCP tools") {
		for _, tool := range spans(row[0], name) {
			documented = append(documented, tool)
			ps := spans(strings.Join(row[1:], "|"), perm)
			if len(ps) == 0 {
				t.Errorf("%s has no permission in the docs", tool)
				continue
			}
			if agentOnly := ps[0] == "autopilot.agent"; agentOnly == slices.Contains(reader, tool) {
				t.Errorf("%s is documented as %s, but a reader's token lists it: %v", tool, ps[0], slices.Contains(reader, tool))
			}
		}
	}
	diff(t, "MCP tool", uniq(all), uniq(documented))
}
