package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestUISmoke runs the Playwright smoke tests in a browser
// against a real admin and Postgres. It needs Node and a built UI, so it
// runs only with UI_SMOKE=1 (scripts/ci/ui.sh).
func TestUISmoke(t *testing.T) {
	if os.Getenv("UI_SMOKE") == "" {
		t.Skip("set UI_SMOKE=1 after building web/admin")
	}
	ui := os.DirFS("../../web/admin/dist/app")
	if _, err := fs.Stat(ui, "index.html"); err != nil {
		t.Fatal("build the UI first: npm run build in web/admin")
	}
	// Links to a log store need a status and a host, which route detail has
	// and an anomaly row does not.
	token := filepath.Join(t.TempDir(), "autopilot-token")
	if err := os.WriteFile(token, []byte(agentToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarnessWith(t, map[string]string{"LOG_SEARCH_URL": "https://logs.example.com/search?q=status%3A{status}%20host%3A{host}&from={from}&to={to}",
		"AUTOPILOT_TOKEN_FILE": token})
	h.s.now = time.Now // the browser acts in real time
	h.s.cfg.UI = ui
	h.s.uiRoutes()
	h.user("smoke", "admin")

	// Access lines for the Routes page: a rate limited login, and blog posts
	// enough alike for a grouping suggestion.
	lines := []string{}
	for i := range 10 {
		if i < 2 {
			lines = append(lines, access("POST", "api.example.com", "/login", "http.response.status_code", 429, "edge.decision", "rate_limited", "edge.rate_limit_rule", "login"))
			continue
		}
		lines = append(lines, access("POST", "api.example.com", "/login"))
	}
	for i := range 22 {
		lines = append(lines, access("GET", "www.example.com", fmt.Sprintf("/blog/post-%c", 'a'+i), "edge.query_keys", []string{"utm_source"}))
	}
	// And a request the edge answered 502 because the upstream refused it.
	lines = append(lines, access("GET", "api.example.com", "/orders/7", "http.response.status_code", 502, "edge.decision", "upstream_error",
		"edge.upstream_answered", false, "edge.upstream_error", "dial tcp 10.0.0.1:443: connect: connection refused", "edge.upstream_error_kind", "refused"))
	status(t, h.shipper().post(lines...), http.StatusAccepted)
	if err := h.s.flushRoutes(t.Context()); err != nil {
		t.Fatal(err)
	}
	// An hour of steady traffic, then 5 minutes with a fifth of it 5xx the
	// edge sent: two checks fire the edge 5xx anomaly for Notifications.
	// The traffic is version 2's, the flow below's first version with rule
	// login, which it adds as log only: login finds one client over its
	// limit throughout and lets it through, for the live counts on the rule
	// pages and the client's subject page. The edge samples one in 16 over
	// limit requests into the client counts, so 16 a minute is one sample.
	limits := `[{"id":"login","evaluated":50,"would_limit":16}]`
	// The edge always sends limited, so a log only rule's subjects carry 0.
	client := `[{"rule":"login","key":"k1","display":"198.51.100.7","limited":0,"would_limit":16}]`
	h.putStats(2, 65, 1000, 0, 0, []int64{1000}, limits, client)
	h.putStats(2, 5, 1000, 200, 0, []int64{1000}, limits, client)
	for range 2 {
		if err := h.s.runNotify(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	// The autopilot's leader job and a scripted runner, in real time, for
	// the autopilot pages. They start after the seed so its anomaly checks
	// see no autopilot state. t.Context ends before cleanups run, and this
	// wait is registered after the harness's, so both stop before Postgres does.
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	wg.Go(func() {
		for t.Context().Err() == nil {
			if err := h.s.runAutopilot(t.Context()); err != nil && t.Context().Err() == nil {
				t.Errorf("autopilot tick: %v", err)
			}
			wait(t.Context(), time.Second)
		}
	})
	wg.Go(func() { smokeRunner(t, h) })

	cmd := exec.Command("npx", "playwright", "test")
	cmd.Dir = "../../web/admin"
	cmd.Env = append(os.Environ(), "BASE_URL="+h.srv.URL, "SMOKE_USER=smoke", "SMOKE_PASSWORD="+goodPassword)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("playwright: %v", err)
	}
}

func wait(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// smokeRunner answers cases as the runner would, scripted. A case on a rule
// reads the case, proposes an enforce rule and calls it an attack; every
// other case is benign with no proposal. Errors fail the test without
// stopping it, since it runs beside the browser.
func smokeRunner(t *testing.T, h *harness) {
	t.Helper()
	ctx := t.Context()
	post := func(path string, in any) (*http.Response, error) {
		b, _ := json.Marshal(in)
		req, _ := http.NewRequestWithContext(ctx, "POST", h.srv.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+agentToken)
		return h.srv.Client().Do(req)
	}
	for ctx.Err() == nil {
		resp, err := post("/v1/autopilot/claim", claimBody("claude"))
		if err != nil {
			if ctx.Err() == nil {
				t.Errorf("claim: %v", err)
			}
			return
		}
		var c claimed
		err = json.NewDecoder(resp.Body).Decode(&c)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || err != nil {
			wait(ctx, 500*time.Millisecond)
			continue
		}
		var brief struct {
			Rule *string `json:"rule"`
		}
		_ = json.Unmarshal(c.Brief, &brief)
		verdict := "benign"
		if brief.Rule != nil {
			verdict = "attack"
			if err := smokePropose(ctx, h, c.RunID); err != nil {
				t.Errorf("case %d: %v", c.CaseID, err)
			}
		}
		cost := 0.42
		resp, err = post(fmt.Sprintf("/v1/autopilot/cases/%d/result", c.CaseID),
			resultBody(c.RunID, verdict, usage{Input: 12_000, Output: 900, CacheRead: 30_000, CacheWrite: 4_000}, &cost, 0))
		if err == nil {
			_ = resp.Body.Close()
		}
		if err != nil && ctx.Err() == nil {
			t.Errorf("result: %v", err)
		}
		// A refused result otherwise surfaces only as the browser test timing out.
		if err == nil && resp.StatusCode != http.StatusNoContent && ctx.Err() == nil {
			t.Errorf("case %d result: status %d", c.CaseID, resp.StatusCode)
		}
	}
}

// smokePropose reads the case, proposes an enforce rule on POSTs to /login
// per client IP and records a note citing the login rule's stats, through
// admin's MCP server as the run.
func smokePropose(ctx context.Context, h *harness, run int64) error {
	hc := *h.srv.Client()
	hc.Transport = headerTransport{base: h.srv.Client().Transport, headers: map[string]string{"Authorization": "Bearer " + agentToken, "X-Autopilot-Run": fmt.Sprint(run)}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "smoke-runner", Version: "v0"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: h.srv.URL + "/v1/mcp", HTTPClient: &hc, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = cs.Close() }()
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_case", Arguments: map[string]any{}}); err != nil {
		return err
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "propose", Arguments: proposal("enforce", "login-stuffing", loginRule())})
	if err != nil {
		return err
	}
	if res.IsError {
		return fmt.Errorf("propose refused: %v", res.Content)
	}
	// A note on what the stats showed, for the Memory pages.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_rule_stats", Arguments: map[string]any{"rule": "login", "minutes": 60}})
	if err != nil {
		return err
	}
	var read struct {
		EvidenceID int64 `json:"evidence_id"`
	}
	if res.IsError {
		b, _ := json.Marshal(res.Content)
		return fmt.Errorf("get_rule_stats refused: %s", b)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &read); err != nil || read.EvidenceID == 0 {
		return fmt.Errorf("get_rule_stats answered %s", b)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "record_learning", Arguments: map[string]any{
		"kind": "attack_signature", "basis": "observed", "scope": map[string]any{"kind": "rule", "rule": "login"},
		"claim":     map[string]any{"metric": "rule_would_limit", "window": map[string]any{"last_minutes": 60}, "op": ">=", "value": 100},
		"effect":    nil,
		"evidence":  []int64{read.EvidenceID},
		"statement": "Password guessing on login keeps one client over the limit all hour",
		"rationale": "The login rule's counts show it over the limit every minute",
	}})
	if err != nil {
		return err
	}
	if res.IsError {
		b, _ := json.Marshal(res.Content)
		return fmt.Errorf("record_learning refused: %s", b)
	}
	return nil
}
