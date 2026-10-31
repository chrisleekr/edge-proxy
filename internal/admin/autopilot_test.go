package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const agentToken = "autopilot-token-0123456789abcdefghijklmnop"

// autopilotHarness is admin with the runner's deployment token, version 1
// (testConfig) live and an admin, pub, signed in. agent is the runner.
func autopilotHarness(t *testing.T) (h *harness, pub, agent *client) {
	t.Helper()
	return autopilotHarnessWith(t, nil)
}

// autopilotHarnessWith is autopilotHarness with more deployment variables.
func autopilotHarnessWith(t *testing.T, set map[string]string) (h *harness, pub, agent *client) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "autopilot-token")
	if err := os.WriteFile(path, []byte(agentToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := map[string]string{"AUTOPILOT_TOKEN_FILE": path, "SESSION_IDLE_TIMEOUT": "48h", "SESSION_MAX_AGE": "48h"}
	maps.Copy(e, set)
	h = newHarnessWith(t, e)
	h.user("pub", "admin")
	pub = h.signedIn("pub")
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v1"), 201)
	agent = h.client()
	agent.token = agentToken
	return h, pub, agent
}

// claimBody is what the runner sends to claim a case: who it is and which
// providers it holds a credential for. wait 0s answers at once instead of
// long-polling.
func claimBody(providers ...string) map[string]any {
	return map[string]any{"runner": "runner-a", "version": "0.1.0", "sdk_version": "claude-agent-sdk 1.0.0", "providers": providers, "wait": "0s"}
}

func (c *client) claim(providers ...string) *http.Response {
	c.h.t.Helper()
	return c.do("POST", "/v1/autopilot/claim", claimBody(providers...))
}

// claimed is a claim's answer: the case, the run admin recorded for it, and
// what the runner needs to run it.
type claimed struct {
	CaseID       int64           `json:"case_id"`
	Kind         string          `json:"kind"`
	Brief        json.RawMessage `json:"brief"`
	RunID        int64           `json:"run_id"`
	Attempt      int             `json:"attempt"`
	LeaseUntil   time.Time       `json:"lease_until"`
	Provider     string          `json:"provider"`
	Model        string          `json:"model"`
	Prompt       string          `json:"prompt"`
	PromptSHA256 string          `json:"prompt_sha256"`
	ToolsSHA256  string          `json:"tools_sha256"`
	OutputSchema json.RawMessage `json:"output_schema"`
}

func (c *client) claimCase() claimed {
	c.h.t.Helper()
	resp := c.claim("claude")
	if resp.StatusCode != 200 {
		c.h.t.Fatalf("claim %d: %s", resp.StatusCode, body(resp))
	}
	return decode[claimed](c.h.t, resp)
}

// investigate opens an on-demand case on a rule and returns its id.
func (c *client) investigate(rule, question string) int64 {
	c.h.t.Helper()
	resp := c.do("POST", "/api/autopilot/cases", map[string]any{"rule": rule, "question": question})
	if resp.StatusCode != 201 {
		c.h.t.Fatalf("investigate %d: %s", resp.StatusCode, body(resp))
	}
	return decode[struct{ ID int64 }](c.h.t, resp).ID
}

// seen claims until nothing is queued, closing what it takes as benign,
// so the runner was just seen and the queue is empty.
func (c *client) seen() {
	c.h.t.Helper()
	for range 10 {
		resp := c.claim("claude")
		if resp.StatusCode == 204 {
			_ = resp.Body.Close()
			return
		}
		if resp.StatusCode != 200 {
			c.h.t.Fatalf("claim %d: %s", resp.StatusCode, body(resp))
		}
		got := decode[claimed](c.h.t, resp)
		status(c.h.t, c.result(got.CaseID, resultBody(got.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
	}
	c.h.t.Fatal("the queue did not empty")
}

// openAndClaim makes the runner seen, opens a case on login and claims it.
func openAndClaim(t *testing.T, pub, agent *client) claimed {
	t.Helper()
	agent.seen()
	id := pub.investigate("login", "Is someone guessing passwords?")
	c := agent.claimCase()
	if c.CaseID != id {
		t.Fatalf("claimed case %d, opened %d", c.CaseID, id)
	}
	return c
}

// usage is a run's token counts as the runner reports them.
type usage struct {
	Input      int64 `json:"input_tokens"`
	Output     int64 `json:"output_tokens"`
	CacheRead  int64 `json:"cache_read_tokens"`
	CacheWrite int64 `json:"cache_write_tokens"`
}

// resultBody is a finished run's verdict and telemetry. lastSeq is the
// last event seq the runner sent.
func resultBody(runID int64, verdict string, u usage, providerCost *float64, lastSeq int) map[string]any {
	return map[string]any{"run_id": runID, "status": "ok", "verdict": verdict, "summary": "Credential stuffing from one /24", "proposals": []int64{},
		"turns": 4, "tool_calls": 6, "usage": u, "provider_cost_usd": providerCost, "transcript_bytes": 1234, "transcript_sha256": hexSHA256([]byte("transcript")),
		"last_seq": lastSeq}
}

func (c *client) result(caseID int64, in map[string]any) *http.Response {
	c.h.t.Helper()
	return c.do("POST", fmt.Sprintf("/v1/autopilot/cases/%d/result", caseID), in)
}

func hexSHA256(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// autopilotSettings is GET /api/settings/autopilot as JSON fields.
func (c *client) autopilotSettings() map[string]any {
	c.h.t.Helper()
	resp := c.do("GET", "/api/settings/autopilot", nil)
	if resp.StatusCode != 200 {
		c.h.t.Fatalf("settings %d: %s", resp.StatusCode, body(resp))
	}
	return decode[map[string]any](c.h.t, resp)
}

// setAutopilot changes the given settings and saves them.
func (c *client) setAutopilot(change map[string]any) {
	c.h.t.Helper()
	s := c.autopilotSettings()
	maps.Copy(s, change)
	status(c.h.t, c.do("PUT", "/api/settings/autopilot", s), 204)
}

func durationOf(t *testing.T, v any) time.Duration {
	t.Helper()
	s, _ := v.(string)
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("duration %v: %v", v, err)
	}
	return d
}

func TestAutopilotSettings(t *testing.T) {
	h, pub, _ := autopilotHarness(t)
	h.user("vera", "viewer")
	h.user("paul", "publisher")
	vera, paul := h.signedIn("vera"), h.signedIn("paul")

	t.Run("a viewer reads the defaults", func(t *testing.T) {
		s := vera.autopilotSettings()
		if s["mode"] != "auto" || s["max_enforcing"] != float64(10) || s["max_sensors"] != float64(10) || s["max_block_share"] != 0.02 ||
			s["cases_per_hour"] != float64(20) || s["model"] != "claude-opus-5-5" || s["sweep_model"] != "claude-opus-5-5" {
			t.Fatalf("defaults %v", s)
		}
		for field, want := range map[string]time.Duration{"observe_for": 5 * time.Minute, "default_ttl": time.Hour, "max_ttl": 24 * time.Hour,
			"max_lifetime": 7 * 24 * time.Hour, "min_publish_interval": time.Minute} {
			if got := durationOf(t, s[field]); got != want {
				t.Errorf("%s %v, want %v", field, got, want)
			}
		}
		if ps, ok := s["protected_subjects"].([]any); !ok || len(ps) != 0 {
			t.Errorf("protected_subjects %v", s["protected_subjects"])
		}
	})
	many := make([]any, 201)
	for i := range many {
		many[i] = fmt.Sprintf("198.51.%d.0/24", i)
	}
	for _, tc := range []struct {
		name  string
		field string
		value any
		path  string
	}{
		{"an unknown mode", "mode", "manual", "mode"},
		{"more enforcing rules than 50", "max_enforcing", 51, "max_enforcing"},
		{"a negative enforcing budget", "max_enforcing", -1, "max_enforcing"},
		{"more sensors than 50", "max_sensors", 51, "max_sensors"},
		{"observing for under a minute", "observe_for", "30s", "observe_for"},
		{"observing for over an hour", "observe_for", "2h", "observe_for"},
		{"a default ttl over max_ttl", "default_ttl", "25h", "default_ttl"},
		{"a max_ttl over a day", "max_ttl", "25h", "max_ttl"},
		// A rule renews in its last quarter, on a tick that may publish: one
		// 30s tick plus min_publish_interval (1m here), so at least 6m.
		{"a default TTL too short to renew within one tick and the publish interval", "default_ttl", "5m", "default_ttl"},
		{"a lifetime over 30 days", "max_lifetime", "721h", "max_lifetime"},
		{"a lifetime under max_ttl", "max_lifetime", "12h", "max_lifetime"},
		{"a block share over 20%", "max_block_share", 0.5, "max_block_share"},
		{"a block share under 0.1%", "max_block_share", 0.0005, "max_block_share"},
		{"no cases an hour", "cases_per_hour", 0, "cases_per_hour"},
		{"more than 200 cases an hour", "cases_per_hour", 201, "cases_per_hour"},
		{"publishing more often than every 30s", "min_publish_interval", "10s", "min_publish_interval"},
		{"publishing less often than every 15m", "min_publish_interval", "16m", "min_publish_interval"},
		{"no model", "model", "", "model"},
		{"a model id with a space", "model", "claude opus", "model"},
		{"a sweep model id over 100 characters", "sweep_model", strings.Repeat("a", 101), "sweep_model"},
		{"a protected subject that is not a CIDR or AS number", "protected_subjects", []any{"203.0.113.0/24", "partner.example.com"}, "protected_subjects[1]"},
		{"more than 200 protected subjects", "protected_subjects", many, "protected_subjects"},
	} {
		t.Run(tc.name+" is refused at its field", func(t *testing.T) {
			s := pub.autopilotSettings()
			s[tc.field] = tc.value
			resp := pub.do("PUT", "/api/settings/autopilot", s)
			p := decode[problem](t, resp)
			if resp.StatusCode != 422 || len(p.Errors) != 1 || p.Errors[0].Path != tc.path {
				t.Fatalf("%d %+v", resp.StatusCode, p)
			}
		})
	}
	t.Run("a max_ttl too short to renew sensors within one tick and the publish interval is refused", func(t *testing.T) {
		s := pub.autopilotSettings()
		s["max_ttl"], s["default_ttl"], s["max_lifetime"] = "5m", "5m", "5m"
		resp := pub.do("PUT", "/api/settings/autopilot", s)
		p := decode[problem](t, resp)
		var paths []string
		for _, e := range p.Errors {
			paths = append(paths, e.Path)
		}
		if resp.StatusCode != 422 || !slices.Equal(paths, []string{"max_ttl", "default_ttl"}) {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
	})
	t.Run("only settings.manage saves", func(t *testing.T) {
		s := pub.autopilotSettings()
		status(t, vera.do("PUT", "/api/settings/autopilot", s), 403)
		status(t, paul.do("PUT", "/api/settings/autopilot", s), 403)
	})
	t.Run("a valid change saves and is audited", func(t *testing.T) {
		pub.setAutopilot(map[string]any{"mode": "observe", "max_enforcing": 3, "protected_subjects": []any{"203.0.113.0/24", "AS64500"}})
		s := pub.autopilotSettings()
		if s["mode"] != "observe" || s["max_enforcing"] != float64(3) || !slices.Equal(s["protected_subjects"].([]any), []any{"203.0.113.0/24", "AS64500"}) {
			t.Fatalf("saved %v", s)
		}
		var before, after string
		if err := h.db.QueryRow(t.Context(), `SELECT details->'before'->>'mode', details->'after'->>'mode' FROM audit_events
			WHERE action = 'settings.autopilot' AND actor = 'user:pub' ORDER BY seq DESC LIMIT 1`).Scan(&before, &after); err != nil || before != "auto" || after != "observe" {
			t.Fatalf("audit before %q after %q, err %v", before, after, err)
		}
	})
}

// The runner's token can do only what the runner does, and nobody else
// can act as the runner.
func TestAutopilotPermissions(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	h.user("vera", "viewer")
	h.user("ed", "editor")
	h.user("paul", "publisher")
	vera, ed, paul := h.signedIn("vera"), h.signedIn("ed"), h.signedIn("paul")
	edgeClient := h.client()
	edgeClient.token = h.edgeToken(pub)
	userToken := h.client()
	userToken.token = decode[map[string]string](t, pub.do("POST", "/api/tokens", map[string]any{"name": "mcp", "kind": "user",
		"scopes": []string{"autopilot.read", "autopilot.manage", "settings.manage", "config.read"}, "expires_in": "720h"}))["token"]

	t.Run("the runner's token claims", func(t *testing.T) {
		status(t, agent.claim("claude"), 204)
	})
	for _, tc := range []struct {
		name   string
		c      *client
		status int
	}{
		{"nobody signed in can't claim", h.client(), 401},
		{"an admin can't claim", pub, 403},
		{"an edge token can't claim", edgeClient, 403},
		{"a user API token can't claim", userToken, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status(t, tc.c.claim("claude"), tc.status)
		})
	}
	for _, tc := range []struct {
		name         string
		method, path string
		in           any
	}{
		{"the runner's token can't read the draft", "GET", "/api/draft", nil},
		{"the runner's token can't read the autopilot page", "GET", "/api/autopilot", nil},
		{"the runner's token can't read the settings", "GET", "/api/settings/autopilot", nil},
		{"the runner's token can't change the settings", "PUT", "/api/settings/autopilot", map[string]any{"mode": "auto"}},
		{"the runner's token can't open a case", "POST", "/api/autopilot/cases", map[string]any{"rule": "login"}},
		{"the runner's token can't publish", "POST", "/api/publish", map[string]any{"message": "v2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status(t, agent.do(tc.method, tc.path, tc.in), 403)
		})
	}
	t.Run("every role reads the autopilot page", func(t *testing.T) {
		for _, c := range []*client{vera, ed, paul, pub} {
			status(t, c.do("GET", "/api/autopilot", nil), 200)
		}
	})
	t.Run("a viewer or editor can't open a case or retire a rule", func(t *testing.T) {
		for _, c := range []*client{vera, ed} {
			status(t, c.do("POST", "/api/autopilot/cases", map[string]any{"rule": "login"}), 403)
			status(t, c.do("POST", "/api/autopilot/rules/ap-scraper-1/retire", map[string]any{"reason": "blocks a partner"}), 403)
		}
	})
	t.Run("a publisher opens a case", func(t *testing.T) {
		status(t, paul.do("POST", "/api/autopilot/cases", map[string]any{"rule": "login", "question": "Is this a bot?"}), 201)
	})
	t.Run("the runner acts as deployment:autopilot", func(t *testing.T) {
		c := agent.claimCase()
		var actor string
		if err := h.db.QueryRow(t.Context(), "SELECT actor FROM audit_events WHERE action = 'autopilot.case_claim' AND target = $1", fmt.Sprintf("case %d", c.CaseID)).Scan(&actor); err != nil || actor != "deployment:autopilot" {
			t.Fatalf("claim actor %q, err %v", actor, err)
		}
	})
}

// postClaim claims for one runner without the test helpers, so it can run
// in its own goroutine.
func postClaim(h *harness, runner string) (int, claimed, error) {
	b, _ := json.Marshal(map[string]any{"runner": runner, "version": "0.1.0", "sdk_version": "claude-agent-sdk 1.0.0", "providers": []string{"claude"}, "wait": "0s"})
	req, _ := http.NewRequest("POST", h.srv.URL+"/v1/autopilot/claim", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+agentToken)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		return 0, claimed{}, err
	}
	defer resp.Body.Close()
	var c claimed
	if resp.StatusCode == 200 {
		err = json.NewDecoder(resp.Body).Decode(&c)
	}
	return resp.StatusCode, c, err
}

func TestAutopilotClaim(t *testing.T) {
	t.Run("with no case a claim answers 204", func(t *testing.T) {
		_, _, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
	})
	t.Run("a claim takes the case with a lease, a run and what the runner needs", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		if c.Kind != "investigate" || c.Attempt != 1 || c.Provider != "claude" || c.Model != "claude-opus-5-5" || c.RunID == 0 ||
			c.LeaseUntil.Sub(h.now().Add(10*time.Minute)).Abs() > time.Second {
			t.Fatalf("claim %+v", c)
		}
		if c.Prompt == "" || hexSHA256([]byte(c.Prompt)) != c.PromptSHA256 || len(c.ToolsSHA256) != 64 {
			t.Fatalf("prompt %d bytes, prompt_sha256 %s, tools_sha256 %s", len(c.Prompt), c.PromptSHA256, c.ToolsSHA256)
		}
		for _, verdict := range []string{`"attack"`, `"benign"`, `"unsure"`} {
			if !bytes.Contains(c.OutputSchema, []byte(verdict)) {
				t.Fatalf("output schema lacks %s: %s", verdict, c.OutputSchema)
			}
		}
		if !bytes.Contains(c.Brief, []byte("Is someone guessing passwords?")) {
			t.Fatalf("brief %s", c.Brief)
		}
		var state string
		var attempts int
		var runID int64
		if err := h.db.QueryRow(t.Context(), "SELECT state, attempts, run_id FROM autopilot_cases WHERE id = $1", c.CaseID).Scan(&state, &attempts, &runID); err != nil ||
			state != "running" || attempts != 1 || runID != c.RunID {
			t.Fatalf("case %s attempts %d run %d, err %v", state, attempts, runID, err)
		}
		var runner, version, provider, model, promptSHA string
		if err := h.db.QueryRow(t.Context(), "SELECT runner, runner_version, provider, model, encode(prompt_sha256, 'hex') FROM autopilot_runs WHERE id = $1", c.RunID).
			Scan(&runner, &version, &provider, &model, &promptSHA); err != nil || runner != "runner-a" || version != "0.1.0" || provider != "claude" ||
			model != "claude-opus-5-5" || promptSHA != c.PromptSHA256 {
			t.Fatalf("run %s %s %s %s %s, err %v", runner, version, provider, model, promptSHA, err)
		}
	})
	t.Run("a case already running is not claimed again", func(t *testing.T) {
		_, pub, agent := autopilotHarness(t)
		openAndClaim(t, pub, agent)
		status(t, agent.claim("claude"), 204)
	})
	t.Run("two runners claiming at once take different cases", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		status(t, agent.claim("claude"), 204)
		a, b := pub.investigate("login", "Guessing passwords?"), pub.investigate("admin-route", "Scanning the admin pages?")
		var wg sync.WaitGroup
		got := make([]claimed, 2)
		codes, errs := make([]int, 2), make([]error, 2)
		for i := range 2 {
			wg.Go(func() { codes[i], got[i], errs[i] = postClaim(h, fmt.Sprint("runner-", i)) })
		}
		wg.Wait()
		ids := []int64{got[0].CaseID, got[1].CaseID}
		slices.Sort(ids)
		if errs[0] != nil || errs[1] != nil || codes[0] != 200 || codes[1] != 200 || !slices.Equal(ids, []int64{min(a, b), max(a, b)}) {
			t.Fatalf("claims %v %v %+v, errors %v", codes, ids, got, errs)
		}
	})
	t.Run("autopilot off claims nothing", func(t *testing.T) {
		_, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"mode": "off"})
		status(t, agent.claim("claude"), 204)
	})
	t.Run("a spent cases_per_hour budget claims nothing", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"cases_per_hour": 1})
		openAndClaim(t, pub, agent)
		second := pub.investigate("admin-route", "Scanning the admin pages?")
		status(t, agent.claim("claude"), 204)
		var state string
		if err := h.db.QueryRow(t.Context(), "SELECT state FROM autopilot_cases WHERE id = $1", second).Scan(&state); err != nil || state != "queued" {
			t.Fatalf("second case %s, err %v", state, err)
		}
	})
	t.Run("a runner without a credential for the model's provider is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"model": "gpt-5"})
		status(t, agent.claim("claude"), 204) // seen, with no case yet
		id := pub.investigate("login", "Guessing passwords?")
		resp := agent.claim("claude")
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, "openai") || !strings.Contains(b, "credential") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		var state string
		if err := h.db.QueryRow(t.Context(), "SELECT state FROM autopilot_cases WHERE id = $1", id).Scan(&state); err != nil || state != "queued" {
			t.Fatalf("case %s, err %v", state, err)
		}
		page := decode[struct {
			AgentConnected bool            `json:"agent_connected"`
			Credentials    map[string]bool `json:"credentials"`
			Warnings       []string        `json:"warnings"`
		}](t, pub.do("GET", "/api/autopilot", nil))
		if !page.AgentConnected || !page.Credentials["claude"] || page.Credentials["openai"] ||
			!slices.ContainsFunc(page.Warnings, func(w string) bool { return strings.Contains(w, "gpt-5") && strings.Contains(w, "openai") }) {
			t.Fatalf("autopilot page %+v", page)
		}
	})
}

// event is one runner-reported event of a run.
func event(seq int, kind string, payload string) map[string]any {
	return map[string]any{"seq": seq, "kind": kind, "at": time.Now().UTC().Format(time.RFC3339Nano), "payload": json.RawMessage(payload)}
}

func (c *client) events(runID int64, events ...map[string]any) *http.Response {
	c.h.t.Helper()
	return c.do("POST", fmt.Sprintf("/v1/autopilot/runs/%d/events", runID), map[string]any{"events": events})
}

// A last event batch that waits while the run's result is stored is refused
// once the result is in, so the result's events hash covers every event.
func TestEventsRacingTheResultAreRefused(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c := openAndClaim(t, pub, agent)
	tx, err := h.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }() //nolint:usetesting // t.Context may be cancelled
	if _, err := tx.Exec(t.Context(), "SELECT pg_advisory_xact_lock(hashtextextended('autopilot-run:' || $1::bigint, 0))", c.RunID); err != nil {
		t.Fatal(err)
	}
	done := make(chan int)
	go func() {
		resp := agent.events(c.RunID, event(1, "assistant", `{"text":"last"}`))
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	waitingOnLocks(t, h, 1)
	if _, err := tx.Exec(t.Context(), `INSERT INTO autopilot_run_results (run_id, finished_at, status, turns, tool_calls, input_tokens,
		output_tokens, cache_read_tokens, cache_write_tokens, transcript_bytes, telemetry_complete) VALUES ($1, now(), 'ok', 1, 0, 0, 0, 0, 0, 0, true)`, c.RunID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if code := <-done; code != http.StatusConflict {
		t.Fatalf("events after the result: status %d, want 409", code)
	}
	var n int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_run_events WHERE run_id = $1 AND source = 'runner'", c.RunID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d runner events stored after the result, err %v", n, err)
	}
}

// textPayload is a compact JSON payload of about n bytes.
func textPayload(n int) string { return `{"text":"` + strings.Repeat("a", n) + `"}` }

func TestAutopilotRunRecords(t *testing.T) {
	t.Run("events are stored with their size and hash", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		p1, p2 := `{"text":"Looking at login failures"}`, `{"tool":"get_case","arguments":{}}`
		status(t, agent.events(c.RunID, event(1, "assistant_text", p1), event(2, "tool_use", p2)), 204)
		rows, _ := h.db.Query(t.Context(), "SELECT seq, source, bytes, encode(payload_sha256, 'hex'), cut FROM autopilot_run_events WHERE run_id = $1 ORDER BY seq", c.RunID)
		var got []string
		for rows.Next() {
			var seq, n int
			var source, sum string
			var cut bool
			if err := rows.Scan(&seq, &source, &n, &sum, &cut); err != nil {
				t.Fatal(err)
			}
			got = append(got, fmt.Sprint(seq, source, n, sum, cut))
		}
		want := []string{fmt.Sprint(1, "runner", len(p1), hexSHA256([]byte(p1)), false), fmt.Sprint(2, "runner", len(p2), hexSHA256([]byte(p2)), false)}
		if rows.Err() != nil || !slices.Equal(got, want) {
			t.Fatalf("events %v, want %v, err %v", got, want, rows.Err())
		}
	})
	t.Run("an event over 64 KiB is cut and keeps its full size and hash", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		big := textPayload(70 << 10)
		status(t, agent.events(c.RunID, event(1, "assistant_text", big)), 204)
		var n, stored int
		var sum string
		var cut bool
		if err := h.db.QueryRow(t.Context(), "SELECT bytes, octet_length(payload::text), encode(payload_sha256, 'hex'), cut FROM autopilot_run_events WHERE run_id = $1", c.RunID).
			Scan(&n, &stored, &sum, &cut); err != nil || !cut || n != len(big) || sum != hexSHA256([]byte(big)) || stored > 64<<10 {
			t.Fatalf("cut %v, bytes %d of %d, stored %d, sha %s, err %v", cut, n, len(big), stored, sum, err)
		}
	})
	t.Run("a batch over 1 MiB is refused whole", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		var batch []map[string]any
		for i := range 20 {
			batch = append(batch, event(i+1, "assistant_text", textPayload(60<<10)))
		}
		status(t, agent.events(c.RunID, batch...), 413)
		var n int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_run_events WHERE run_id = $1", c.RunID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%d events stored, err %v", n, err)
		}
	})
	t.Run("a run keeps at most 1000 events", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		seq := 0
		for range 10 {
			var batch []map[string]any
			for range 100 {
				seq++
				batch = append(batch, event(seq, "assistant_text", `{"text":"thinking"}`))
			}
			status(t, agent.events(c.RunID, batch...), 204)
		}
		// The last batch sent again, as after a lost answer, is not refused.
		var last []map[string]any
		for i := 901; i <= 1000; i++ {
			last = append(last, event(i, "assistant_text", `{"text":"thinking"}`))
		}
		status(t, agent.events(c.RunID, last...), 204)
		status(t, agent.events(c.RunID, event(1001, "assistant_text", `{"text":"one more"}`)), 409)
		var n int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_run_events WHERE run_id = $1", c.RunID).Scan(&n); err != nil || n != 1000 {
			t.Fatalf("%d events stored, err %v", n, err)
		}
	})
	t.Run("a run keeps at most 4 MiB of events", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		seq, refused := 0, 0
		for range 6 { // 6 batches of 900 KiB: the fifth crosses 4 MiB
			var batch []map[string]any
			for range 15 {
				seq++
				batch = append(batch, event(seq, "assistant_text", textPayload(60<<10)))
			}
			if resp := agent.events(c.RunID, batch...); resp.StatusCode == 409 {
				refused++
				_ = resp.Body.Close()
			} else {
				status(t, resp, 204)
			}
		}
		var total int64
		if err := h.db.QueryRow(t.Context(), "SELECT coalesce(sum(bytes), 0) FROM autopilot_run_events WHERE run_id = $1", c.RunID).Scan(&total); err != nil || total > 4<<20 || refused != 2 {
			t.Fatalf("%d bytes stored, %d batches refused, err %v", total, refused, err)
		}
	})
	for _, tc := range []struct {
		name     string
		seqs     []int
		complete bool
	}{
		{"every event reported leaves the run complete", []int{1, 2, 3}, true},
		{"a gap in seq marks the run incomplete", []int{1, 2, 4}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			c := openAndClaim(t, pub, agent)
			var batch []map[string]any
			for _, s := range tc.seqs {
				batch = append(batch, event(s, "assistant_text", `{"text":"step"}`))
			}
			status(t, agent.events(c.RunID, batch...), 204)
			status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 10, Output: 5}, nil, tc.seqs[len(tc.seqs)-1])), 204)
			var complete bool
			if err := h.db.QueryRow(t.Context(), "SELECT telemetry_complete FROM autopilot_run_results WHERE run_id = $1", c.RunID).Scan(&complete); err != nil || complete != tc.complete {
				t.Fatalf("telemetry_complete %v, want %v, err %v", complete, tc.complete, err)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		summary string
		want    int
	}{
		// The output schema the model gets says maxLength 4000, which JSON Schema counts in characters.
		{"a 4000-character summary in a multi-byte script is accepted", strings.Repeat("가", 4000), 204},
		{"a 4001-character summary is refused", strings.Repeat("a", 4001), 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pub, agent := autopilotHarness(t)
			c := openAndClaim(t, pub, agent)
			in := resultBody(c.RunID, "benign", usage{Input: 10}, nil, 0)
			in["summary"] = tc.summary
			status(t, agent.result(c.CaseID, in), tc.want)
		})
	}
	t.Run("the result closes the case with an audit row that hashes its events", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c := openAndClaim(t, pub, agent)
		status(t, agent.events(c.RunID, event(1, "assistant_text", `{"text":"Many 401s from 203.0.113.0/24"}`), event(2, "verdict", `{"verdict":"attack"}`)), 204)
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10, Output: 5}, nil, 2)), 204)
		var state, verdict, runStatus string
		if err := h.db.QueryRow(t.Context(), "SELECT c.state, c.verdict, r.status FROM autopilot_cases c JOIN autopilot_run_results r ON r.run_id = c.run_id WHERE c.id = $1", c.CaseID).
			Scan(&state, &verdict, &runStatus); err != nil || state != "done" || verdict != "attack" || runStatus != "ok" {
			t.Fatalf("case %s %s, run %s, err %v", state, verdict, runStatus, err)
		}
		var actor, gotVerdict, eventsSHA, wantSHA string
		if err := h.db.QueryRow(t.Context(), `SELECT actor, details->>'verdict', details->>'events_sha256' FROM audit_events WHERE action = 'autopilot.case_close' AND target = $1`,
			fmt.Sprintf("case %d", c.CaseID)).Scan(&actor, &gotVerdict, &eventsSHA); err != nil {
			t.Fatal(err)
		}
		if err := h.db.QueryRow(t.Context(), "SELECT encode(sha256(string_agg(payload_sha256, ''::bytea ORDER BY id)), 'hex') FROM autopilot_run_events WHERE run_id = $1", c.RunID).
			Scan(&wantSHA); err != nil {
			t.Fatal(err)
		}
		if actor != "deployment:autopilot" || gotVerdict != "attack" || eventsSHA != wantSHA {
			t.Fatalf("case_close by %s verdict %s events_sha256 %s, want %s", actor, gotVerdict, eventsSHA, wantSHA)
		}
	})
	t.Run("events for a run that doesn't exist are not found", func(t *testing.T) {
		_, _, agent := autopilotHarness(t)
		status(t, agent.events(999, event(1, "assistant_text", `{"text":"x"}`)), 404)
	})
}

// price is one row of the price table, in USD per million tokens.
func price(model string, input, output, cacheRead, cacheWrite float64, from time.Time) map[string]any {
	return map[string]any{"provider": "claude", "model": model, "input_usd_per_mtok": input, "output_usd_per_mtok": output,
		"cache_read_usd_per_mtok": cacheRead, "cache_write_usd_per_mtok": cacheWrite, "effective_from": from.UTC().Format(time.RFC3339)}
}

func (c *client) addPrice(p map[string]any) int64 {
	c.h.t.Helper()
	resp := c.do("POST", "/api/autopilot/prices", p)
	if resp.StatusCode != 201 {
		c.h.t.Fatalf("price %d: %s", resp.StatusCode, body(resp))
	}
	return decode[struct{ ID int64 }](c.h.t, resp).ID
}

// costUsage costs exactly $11 at $5 input, $25 output and $0.50 cache read
// per million tokens: 1M input, 200k output, 2M cache read.
var costUsage = usage{Input: 1_000_000, Output: 200_000, CacheRead: 2_000_000}

func TestAutopilotCost(t *testing.T) {
	t.Run("prices are kept by settings.manage and audited", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		h.user("vera", "viewer")
		vera := h.signedIn("vera")
		status(t, vera.do("POST", "/api/autopilot/prices", price("claude-opus-5-5", 5, 25, 0.5, 6.25, h.now())), 403)
		id := pub.addPrice(price("claude-opus-5-5", 5, 25, 0.5, 6.25, h.now()))
		list := decode[[]map[string]any](t, vera.do("GET", "/api/autopilot/prices", nil))
		if len(list) != 1 || list[0]["id"] != float64(id) || list[0]["input_usd_per_mtok"] != float64(5) || list[0]["author"] != "user:pub" {
			t.Fatalf("prices %v", list)
		}
		if !slices.Contains(h.actions(), fmt.Sprintf("settings.autopilot_price price %d", id)) {
			t.Fatalf("audit %v", h.actions())
		}
	})
	for _, tc := range []struct {
		name  string
		price map[string]any
	}{
		{"a negative price", price("claude-opus-5-5", -1, 25, 0.5, 6.25, time.Now())},
		{"a price over $1000 per million tokens", price("claude-opus-5-5", 5, 1001, 0.5, 6.25, time.Now())},
		{"an unknown provider", func() map[string]any {
			p := price("gemini-3", 1, 1, 1, 1, time.Now())
			p["provider"] = "google"
			return p
		}()},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			_, pub, _ := autopilotHarness(t)
			status(t, pub.do("POST", "/api/autopilot/prices", tc.price), 422)
		})
	}
	t.Run("a run is priced at the rate in effect when it started", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		then := pub.addPrice(price("claude-opus-5-5", 5, 25, 0.5, 6.25, h.now().Add(-time.Hour)))
		c := openAndClaim(t, pub, agent)
		h.advance(time.Minute)
		pub.addPrice(price("claude-opus-5-5", 10, 50, 1, 12.5, h.now())) // raised after the run started
		providerCost := 10.5
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", costUsage, &providerCost, 0)), 204)
		var priceID, configured, provider *int64
		if err := h.db.QueryRow(t.Context(), "SELECT price_id, configured_cost_usd_micros, provider_cost_usd_micros FROM autopilot_run_results WHERE run_id = $1", c.RunID).
			Scan(&priceID, &configured, &provider); err != nil {
			t.Fatal(err)
		}
		if priceID == nil || *priceID != then || configured == nil || *configured != 11_000_000 || provider == nil || *provider != 10_500_000 {
			t.Fatalf("price %v, configured %v, provider %v micro-USD", priceID, configured, provider)
		}
	})
	t.Run("a model with no price still runs, and its cost is left unknown", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.addPrice(price("claude-opus-5-5", 5, 25, 0.5, 6.25, h.now().Add(-time.Hour)))
		pub.setAutopilot(map[string]any{"model": "claude-sonnet-5"})
		c := openAndClaim(t, pub, agent)
		if c.Model != "claude-sonnet-5" || c.Provider != "claude" {
			t.Fatalf("claim %+v", c)
		}
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", costUsage, nil, 0)), 204)
		var priceID, configured, provider *int64
		if err := h.db.QueryRow(t.Context(), "SELECT price_id, configured_cost_usd_micros, provider_cost_usd_micros FROM autopilot_run_results WHERE run_id = $1", c.RunID).
			Scan(&priceID, &configured, &provider); err != nil || priceID != nil || configured != nil || provider != nil {
			t.Fatalf("price %v, configured %v, provider %v, err %v", priceID, configured, provider, err)
		}
	})
	t.Run("spend counts runs, unpriced runs and both costs over the last 24 hours and 7 days", func(t *testing.T) {
		type spendWindow struct {
			Runs         int   `json:"runs"`
			UnpricedRuns int   `json:"unpriced_runs"`
			Configured   int64 `json:"configured_usd_micros"`
			Provider     int64 `json:"provider_usd_micros"`
		}
		h, pub, agent := autopilotHarness(t)
		pub.addPrice(price("claude-opus-5-5", 5, 25, 0.5, 6.25, h.now().Add(-time.Hour)))
		providerCost := 10.5
		old := openAndClaim(t, pub, agent)
		status(t, agent.result(old.CaseID, resultBody(old.RunID, "benign", costUsage, &providerCost, 0)), 204)
		h.advance(3 * 24 * time.Hour)
		pub = h.signedIn("pub") // the session lapsed after 48h
		priced := openAndClaim(t, pub, agent)
		status(t, agent.result(priced.CaseID, resultBody(priced.RunID, "benign", costUsage, &providerCost, 0)), 204)
		pub.setAutopilot(map[string]any{"model": "claude-sonnet-5"})
		unpriced := openAndClaim(t, pub, agent)
		status(t, agent.result(unpriced.CaseID, resultBody(unpriced.RunID, "benign", costUsage, nil, 0)), 204)
		got := decode[struct {
			Spend map[string]spendWindow `json:"spend"`
		}](t, pub.do("GET", "/api/autopilot", nil)).Spend
		want := map[string]spendWindow{
			"last_24h": {Runs: 2, UnpricedRuns: 1, Configured: 11_000_000, Provider: 10_500_000},
			"last_7d":  {Runs: 3, UnpricedRuns: 1, Configured: 22_000_000, Provider: 21_000_000},
		}
		if !maps.Equal(got, want) {
			t.Fatalf("spend %+v, want %+v", got, want)
		}
		openAndClaim(t, pub, agent) // still running: no result, so no cost yet
		got = decode[struct {
			Spend map[string]spendWindow `json:"spend"`
		}](t, pub.do("GET", "/api/autopilot", nil)).Spend
		if !maps.Equal(got, want) {
			t.Fatalf("spend with a run still going %+v, want %+v", got, want)
		}
	})
}

// Spend by day is what the Autopilot page's daily table reads: one row per
// UTC day and model over the last 14 days, from finished runs only.
func TestAutopilotSpendByDay(t *testing.T) {
	type spendDay struct {
		Day          string `json:"day"`
		Provider     string `json:"provider"`
		Model        string `json:"model"`
		Runs         int    `json:"runs"`
		Cases        int    `json:"cases"`
		UnpricedRuns int    `json:"unpriced_runs"`
		Configured   int64  `json:"configured_usd_micros"`
		ProviderUSD  int64  `json:"provider_usd_micros"`
	}
	h, pub, agent := autopilotHarness(t)
	pub.addPrice(price("claude-opus-5-5", 5, 25, 0.5, 6.25, h.now().Add(-time.Hour)))
	providerCost := 10.5
	old := openAndClaim(t, pub, agent)
	status(t, agent.result(old.CaseID, resultBody(old.RunID, "benign", costUsage, &providerCost, 0)), 204)

	h.advance(15 * 24 * time.Hour)
	pub = h.signedIn("pub") // the session lapsed after 48h
	day1 := h.now().UTC().Format(time.DateOnly)
	// A run that errors is retried on the same case: two runs, one case.
	first := openAndClaim(t, pub, agent)
	failed := resultBody(first.RunID, "", costUsage, &providerCost, 0)
	failed["status"] = "error"
	status(t, agent.result(first.CaseID, failed), 204)
	again := agent.claimCase()
	if again.CaseID != first.CaseID {
		t.Fatalf("second claim was case %d, want %d", again.CaseID, first.CaseID)
	}
	status(t, agent.result(again.CaseID, resultBody(again.RunID, "benign", costUsage, &providerCost, 0)), 204)

	h.advance(24 * time.Hour)
	day2 := h.now().UTC().Format(time.DateOnly)
	priced := openAndClaim(t, pub, agent)
	status(t, agent.result(priced.CaseID, resultBody(priced.RunID, "benign", costUsage, &providerCost, 0)), 204)
	pub.setAutopilot(map[string]any{"model": "claude-sonnet-5"})
	unpriced := openAndClaim(t, pub, agent)
	status(t, agent.result(unpriced.CaseID, resultBody(unpriced.RunID, "benign", costUsage, nil, 0)), 204)
	openAndClaim(t, pub, agent) // still running: no result, so no cost yet

	got := decode[struct {
		SpendDays *[]spendDay `json:"spend_days"`
	}](t, pub.do("GET", "/api/autopilot", nil)).SpendDays
	if got == nil {
		t.Fatal("GET /api/autopilot has no spend_days")
	}
	// Newest day first, then by model; the run 15 days back is outside.
	want := []spendDay{
		{Day: day2, Provider: "claude", Model: "claude-opus-5-5", Runs: 1, Cases: 1, Configured: 11_000_000, ProviderUSD: 10_500_000},
		{Day: day2, Provider: "claude", Model: "claude-sonnet-5", Runs: 1, Cases: 1, UnpricedRuns: 1},
		{Day: day1, Provider: "claude", Model: "claude-opus-5-5", Runs: 2, Cases: 1, Configured: 22_000_000, ProviderUSD: 21_000_000},
	}
	if !slices.Equal(*got, want) {
		t.Fatalf("spend_days %+v, want %+v", *got, want)
	}
}

// precisionRow is one row of GET /api/autopilot precision.
type precisionRow struct {
	Model        string `json:"model"`
	PromptSHA256 string `json:"prompt_sha256"`
	Correct      int    `json:"correct"`
	Wrong        int    `json:"wrong"`
}

func (c *client) precision() []precisionRow {
	c.h.t.Helper()
	st := decode[struct {
		Precision *[]precisionRow `json:"precision"`
	}](c.h.t, c.do("GET", "/api/autopilot", nil))
	if st.Precision == nil {
		c.h.t.Fatal("GET /api/autopilot has no precision")
	}
	return *st.Precision
}

// tally is rows as "model N correct M wrong", sorted, so a case compares
// them in one line.
func tally(rows []precisionRow) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s %d correct %d wrong", r.Model, r.Correct, r.Wrong))
	}
	slices.Sort(out)
	return out
}

// Precision is how enforce rules ended in the last 7 days, per model and
// prompt: expired after enforcing or adopted is correct, rolled back or
// retired as a false positive is wrong, and other endings say nothing.
func TestAutopilotPrecision(t *testing.T) {
	falsePositive := func(t *testing.T, pub *client, id string) {
		t.Helper()
		status(t, pub.do("POST", "/api/autopilot/rules/"+id+"/retire", map[string]any{"reason": "Blocks our partner's logins", "false_positive": true}), 204)
	}
	t.Run("an enforced rule that expired counts as correct", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(48 * time.Minute)
		ruleMinutes(h, pub, 15, 10_000, 1_000, 0, 0, id, "[]") // limited nothing, so it is not renewed
		h.tick()
		h.advance(13 * time.Minute) // past its expiry
		h.tick()
		if st := ruleState(t, h, id); st != "expired" {
			t.Fatalf("rule %s", st)
		}
		if got := tally(pub.precision()); !slices.Equal(got, []string{"claude-opus-5-5 1 correct 0 wrong"}) {
			t.Fatalf("precision %v", got)
		}
	})
	t.Run("an adopted rule counts as correct", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": id}, "If-Match", pub.revision()), 200)
		status(t, pub.publishDraft("Keep blocking the stuffing"), 201)
		h.tick()
		if st := ruleState(t, h, id); st != "adopted" {
			t.Fatalf("rule %s", st)
		}
		if got := tally(pub.precision()); !slices.Equal(got, []string{"claude-opus-5-5 1 correct 0 wrong"}) {
			t.Fatalf("precision %v", got)
		}
	})
	t.Run("a rule retired as a false positive counts as wrong", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		falsePositive(t, pub, enforcingRule(t, h, pub, agent))
		if got := tally(pub.precision()); !slices.Equal(got, []string{"claude-opus-5-5 0 correct 1 wrong"}) {
			t.Fatalf("precision %v", got)
		}
	})
	t.Run("a rule the guard rolled back counts as wrong", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]") // 40% against a 10% shadow, over 3x
		h.tick()
		if st := ruleState(t, h, id); st != "rolled_back" {
			t.Fatalf("rule %s", st)
		}
		if got := tally(pub.precision()); !slices.Equal(got, []string{"claude-opus-5-5 0 correct 1 wrong"}) {
			t.Fatalf("precision %v", got)
		}
	})
	t.Run("a plain retire is not counted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := enforcingRule(t, h, pub, agent)
		status(t, pub.do("POST", "/api/autopilot/rules/"+id+"/retire", map[string]any{"reason": "The attack moved on"}), 204)
		if got := pub.precision(); len(got) != 0 {
			t.Fatalf("precision %+v", got)
		}
	})
	t.Run("an enforce rule that expired while only logging is not counted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"mode": "observe"})
		id := observed(t, h, pub, agent, 100, "[]")
		h.tick() // nobody approves, so it keeps logging and is not renewed
		h.advance(time.Hour)
		h.tick()
		if st := ruleState(t, h, id); st != "expired" {
			t.Fatalf("rule %s", st)
		}
		if got := pub.precision(); len(got) != 0 {
			t.Fatalf("precision %+v", got)
		}
	})
	t.Run("a sensor that ended is not counted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		falsePositive(t, pub, liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule())))
		if got := pub.precision(); len(got) != 0 {
			t.Fatalf("precision %+v", got)
		}
	})
	t.Run("a second model gets its own row", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		falsePositive(t, pub, enforcingRule(t, h, pub, agent))
		pub.setAutopilot(map[string]any{"model": "claude-sonnet-5"})
		h.advance(time.Minute) // past min_publish_interval, so the next rule goes live
		id := liveRule(t, h, pub, agent, proposal("enforce", "account-stuffing", agentRule(`http.request.uri.path eq "/account"`, "ip")))
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
		falsePositive(t, pub, id)
		if got := tally(pub.precision()); !slices.Equal(got, []string{"claude-opus-5-5 0 correct 1 wrong", "claude-sonnet-5 0 correct 1 wrong"}) {
			t.Fatalf("precision %v", got)
		}
	})
	t.Run("a rule that ended 8 days ago is left out", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		falsePositive(t, pub, enforcingRule(t, h, pub, agent))
		if got := pub.precision(); len(got) != 1 {
			t.Fatalf("precision %+v before the window passed", got)
		}
		h.advance(8 * 24 * time.Hour)
		pub = h.signedIn("pub") // the session lapsed after 48h
		if got := pub.precision(); len(got) != 0 {
			t.Fatalf("precision %+v", got)
		}
	})
	t.Run("a row names the prompt hash the run was given at claim", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c, cs := agentCase(t, h, pub, agent)
		p := propose(t, cs, proposal("enforce", "login-stuffing", loginRule()))
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
		h.tick()
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, p.RuleID, "[]")
		h.tick()
		if st := ruleState(t, h, p.RuleID); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
		falsePositive(t, pub, p.RuleID)
		got := pub.precision()
		if len(got) != 1 || got[0].PromptSHA256 != c.PromptSHA256 || c.PromptSHA256 != hexSHA256([]byte(c.Prompt)) {
			t.Fatalf("precision %+v, claim prompt_sha256 %s", got, c.PromptSHA256)
		}
	})
}

// metricValue is the value of the series line, or false when absent.
func metricValue(m, series string) (string, bool) {
	for line := range strings.Lines(m) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), series+" "); ok {
			return v, true
		}
	}
	return "", false
}

func TestAutopilotMetrics(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	t.Run("every fixed series is exported from zero", func(t *testing.T) {
		lines := []string{
			`admin_autopilot_cases_total{trigger="investigate",verdict="attack"} 0`,
			`admin_autopilot_cases_total{trigger="anomaly",verdict="unsure"} 0`,
			`admin_autopilot_cases_total{trigger="sweep",verdict="benign"} 0`,
			`admin_autopilot_proposals_total{action="add_sensor",result="accepted"} 0`,
			`admin_autopilot_proposals_total{action="enforce",result="rejected"} 0`,
			`admin_autopilot_proposals_total{action="retire",result="accepted"} 0`,
			`admin_background_job_failures_total{job="autopilot"} 0`,
		}
		for _, reason := range []string{"not_overlay_shape", "site_wide", "fail_mode", "key_needs_ip_or_jwt", "constant_or_host_key", "missing_key_rejects",
			"ttl_over_max", "lifetime_over_max", "penalty_past_expiry", "named_subjects", "duplicate", "suppressed", "compile", "budget_enforcing",
			"budget_sensors", "observed_too_short", "block_share", "crawler_subject", "protected_subject", "attack_stopped",
			"note_key", "note_jwt_key", "note_expected_pattern"} {
			lines = append(lines, fmt.Sprintf(`admin_autopilot_policy_rejections_total{reason=%q} 0`, reason))
		}
		lines = append(lines, `admin_autopilot_cases_total{trigger="ablation",verdict="benign"} 0`,
			`admin_autopilot_note_writes_total{result="written"} 0`, `admin_autopilot_note_writes_total{result="refused"} 0`)
		for _, reason := range []string{"off", "ablation", "invalid", "credential", "run_limit", "day_limit", "scope_limit", "total_limit", "hypothesis", "scope", "claim",
			"evidence", "false_claim", "anchor", "merges"} {
			lines = append(lines, fmt.Sprintf(`admin_autopilot_note_refusals_total{reason=%q} 0`, reason))
		}
		for _, to := range []string{"unconfirmed", "confirmed", "dormant", "retracted", "retired"} {
			lines = append(lines, fmt.Sprintf(`admin_autopilot_note_transitions_total{to=%q} 0`, to))
		}
		h.wantMetrics(lines...)
	})
	pub.addPrice(price("claude-opus-5-5", 5, 25, 0.5, 6.25, h.now().Add(-time.Hour)))
	c := openAndClaim(t, pub, agent)
	h.advance(2 * time.Minute)
	providerCost := 10.5
	status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", costUsage, &providerCost, 0)), 204)
	t.Run("a finished run counts its case, tokens, cost and time", func(t *testing.T) {
		h.wantMetrics(
			`admin_autopilot_cases_total{trigger="investigate",verdict="attack"} 1`,
			`admin_autopilot_llm_runs_total{provider="claude",model="claude-opus-5-5",status="ok"} 1`,
			`admin_autopilot_llm_tokens_total{provider="claude",model="claude-opus-5-5",kind="input"} 1000000`,
			`admin_autopilot_llm_tokens_total{provider="claude",model="claude-opus-5-5",kind="output"} 200000`,
			`admin_autopilot_llm_tokens_total{provider="claude",model="claude-opus-5-5",kind="cache_read"} 2000000`,
			`admin_autopilot_llm_tokens_total{provider="claude",model="claude-opus-5-5",kind="cache_write"} 0`,
			`admin_autopilot_llm_cost_usd_total{provider="claude",model="claude-opus-5-5",source="configured"} 11`,
			`admin_autopilot_llm_cost_usd_total{provider="claude",model="claude-opus-5-5",source="provider"} 10.5`,
			`admin_autopilot_llm_run_seconds_count{provider="claude"} 1`,
			`admin_autopilot_llm_run_seconds_bucket{provider="claude",le="+Inf"} 1`,
		)
	})
	t.Run("a model with no price is counted as unpriced", func(t *testing.T) {
		pub.setAutopilot(map[string]any{"model": "claude-sonnet-5"})
		pub.investigate("admin-route", "Scanning the admin pages?")
		c := agent.claimCase()
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 10}, nil, 0)), 204)
		h.wantMetrics(`admin_autopilot_llm_runs_total{provider="claude",model="unpriced",status="ok"} 1`)
		if strings.Contains(h.metrics(), `model="claude-sonnet-5"`) {
			t.Fatal("an unpriced model got its own label")
		}
	})
	t.Run("the leader exports the autopilot gauges", func(t *testing.T) {
		if strings.Contains(h.metrics(), "admin_autopilot_agent_connected") {
			t.Fatal("a replica that isn't leading exports leader gauges")
		}
		pub.investigate("login", "Still guessing passwords?") // one open case
		h.s.met.leader.Store(true)
		h.check()
		h.wantMetrics(`admin_autopilot_agent_connected 1`, `admin_autopilot_cases_open 1`,
			`admin_autopilot_rules{state="observing"} 0`, `admin_autopilot_rules{state="enforcing"} 0`,
			`admin_autopilot_budget_used_ratio{budget="enforcing"} 0`, `admin_autopilot_budget_used_ratio{budget="sensors"} 0`,
			`admin_autopilot_notes{trust="unconfirmed"} 0`, `admin_autopilot_notes{trust="confirmed"} 0`)
		if _, ok := metricValue(h.metrics(), `admin_autopilot_budget_used_ratio{budget="cases_hour"}`); !ok {
			t.Fatal("no cases_hour budget gauge")
		}
		h.advance(3 * time.Minute) // the runner has not been seen for over 2m
		h.check()
		h.wantMetrics(`admin_autopilot_agent_connected 0`)
	})
}

// Settings saved before the renewal minimum existed may sit under it. An
// upgrade must not wedge the autopilot: they are raised to the minimum when
// read, and only a new save below it is refused.
func TestAutopilotSettingsStoredUnderTheRenewalMinimum(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	old := pub.autopilotSettings()
	old["default_ttl"], old["max_ttl"], old["max_lifetime"] = "5m", "5m", "5m" // under 6m: 4 x (30s tick + 1m)
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(t.Context(), `INSERT INTO settings (key, value) VALUES ('autopilot', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, b); err != nil {
		t.Fatal(err)
	}

	t.Run("reading them shows the minimum", func(t *testing.T) {
		s := pub.autopilotSettings()
		for _, f := range []string{"default_ttl", "max_ttl", "max_lifetime"} {
			if got := durationOf(t, s[f]); got != 6*time.Minute {
				t.Errorf("%s %v, want 6m", f, got)
			}
		}
	})
	t.Run("a tick runs and a proposal without a ttl gets the minimum", func(t *testing.T) {
		h.tick()
		in := proposal("add_sensor", "login-watch", loginRule())
		delete(in, "ttl")
		id := liveRule(t, h, pub, agent, in)
		if r, _ := liveRuleIn(pub.active().Config, id); r.ExpiresAt.Sub(h.now().Add(6*time.Minute)).Abs() > time.Second {
			t.Fatalf("rule expiring %v, want 6m from now", r.ExpiresAt)
		}
	})
	t.Run("saving the old value again is refused", func(t *testing.T) {
		resp := pub.do("PUT", "/api/settings/autopilot", old)
		p := decode[problem](t, resp)
		if resp.StatusCode != 422 || len(p.Errors) == 0 || p.Errors[0].Path != "max_ttl" {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
	})
}

// Replay gives an evidence id only to the answers admin's MCP gives one, so
// the contract says which tools those are: stats reads and connector reads.
func TestAutopilotContractMarksEvidence(t *testing.T) {
	_, pub, _ := autopilotHarnessWith(t, map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090"})
	resp := pub.do("GET", "/api/autopilot/contract", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("contract %d: %s", resp.StatusCode, body(resp))
	}
	got := decode[struct {
		Tools []struct {
			Name     string `json:"name"`
			Evidence *bool  `json:"evidence"`
		} `json:"tools"`
	}](t, resp)
	evidence := map[string]*bool{}
	for _, tool := range got.Tools {
		evidence[tool.Name] = tool.Evidence
	}
	for name, want := range map[string]bool{"prom_query": true, "get_rule_stats": true, "propose": false} {
		if e := evidence[name]; e == nil || *e != want {
			t.Errorf("%s evidence %v, want %v", name, e, want)
		}
	}
}
