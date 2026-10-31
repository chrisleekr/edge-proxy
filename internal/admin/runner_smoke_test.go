package admin

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// fakeClaudeCredential makes the runner report the claude provider. No
// model is called: the scripted adapter stands in for one.
const fakeClaudeCredential = "sk-ant-oat01-fake-runner-smoke-credential-0123456789"

// runnerPlan is what the scripted adapter (autopilot/test/scripted.ts,
// read from AUTOPILOT_SCRIPT) does in place of a model. It makes each step
// as one MCP call to admin as the run, in order, reporting tool_use and
// tool_result events for each, and answers with the verdict, the summary
// and the proposal_id of every propose call admin accepted. The runner then
// adds a verdict event and posts an ok result with those proposals, or,
// for an answer without a verdict, an error result with invalid_output.
// With hang set it calls nothing and waits until the run is aborted.
type runnerPlan struct {
	Steps   []planStep `json:"steps,omitempty"`
	Verdict string     `json:"verdict,omitempty"`
	Summary string     `json:"summary,omitempty"`
	Hang    bool       `json:"hang,omitempty"`
}

type planStep struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

// runnerProc is the real runner process with the scripted adapter.
type runnerProc struct {
	cmd  *exec.Cmd
	out  *syncBuffer
	done chan struct{}
	err  error // set when done closes
}

func (p *runnerProc) alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// nodeBinary is the real node, not a version manager's shim: Volta's shim
// neither forwards SIGTERM nor dies with its child, so the runner would
// miss the signal and outlive a kill.
func nodeBinary(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("node", "-p", "process.execPath").Output()
	if err != nil {
		t.Fatalf("find node: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// startRunner starts the runner against h with plan and extra variables.
// Its environment is built from nothing, so a credential on the host can't
// change the providers it reports. Its output must never hold the runner
// token or the credential.
func startRunner(t *testing.T, h *harness, plan runnerPlan, extra ...string) *runnerProc {
	t.Helper()
	dir := t.TempDir()
	token := filepath.Join(dir, "autopilot-token")
	if err := os.WriteFile(token, []byte(agentToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "admin-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(script, b, 0o600); err != nil {
		t.Fatal(err)
	}
	p := &runnerProc{out: &syncBuffer{}, done: make(chan struct{})}
	p.cmd = exec.Command(nodeBinary(t), "test/scripted.ts")
	p.cmd.Dir = "../../autopilot"
	p.cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir,
		"AUTOPILOT_ADMIN_URL=" + h.srv.URL, "AUTOPILOT_TOKEN_FILE=" + token, "NODE_EXTRA_CA_CERTS=" + ca,
		"CLAUDE_CODE_OAUTH_TOKEN=" + fakeClaudeCredential, "AUTOPILOT_SCRIPT=" + script, "AUTOPILOT_SCRIPT_HEARTBEAT=200ms"}, extra...)
	p.cmd.Stdout, p.cmd.Stderr = p.out, p.out
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start the runner: %v", err)
	}
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	// Registered after the harness, so it stops before Postgres does.
	t.Cleanup(func() {
		if p.alive() {
			_ = p.cmd.Process.Kill()
			<-p.done
		}
		out := p.out.String()
		if strings.Contains(out, agentToken) {
			t.Error("the runner's output holds its admin token")
		}
		if strings.Contains(out, fakeClaudeCredential) {
			t.Error("the runner's output holds its model credential")
		}
		if t.Failed() {
			t.Logf("runner output:\n%s", out)
		}
	})
	return p
}

// within waits up to d for cond, checking every 100ms.
func within(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, d)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// connected waits until admin sees the runner, which opening a case needs.
func connected(t *testing.T, pub *client) autopilotState {
	t.Helper()
	var st autopilotState
	within(t, 30*time.Second, "the runner connects", func() bool {
		st = decode[autopilotState](t, pub.do("GET", "/api/autopilot", nil))
		return st.AgentConnected
	})
	return st
}

// runOf is one run of a case and its result, if it posted one.
type runOf struct {
	ID       int64
	Status   string // "" with no result
	Category string
}

func runsOf(t *testing.T, h *harness, caseID int64) []runOf {
	t.Helper()
	rows, err := h.db.Query(t.Context(), `SELECT r.id, coalesce(res.status, ''), coalesce(res.error_category, '') FROM autopilot_runs r
		LEFT JOIN autopilot_run_results res ON res.run_id = r.id WHERE r.case_id = $1 ORDER BY r.id`, caseID)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[runOf])
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

func caseIs(t *testing.T, h *harness, id int64) (state, verdict string) {
	t.Helper()
	if err := h.db.QueryRow(t.Context(), "SELECT state, coalesce(verdict, '') FROM autopilot_cases WHERE id = $1", id).Scan(&state, &verdict); err != nil {
		t.Fatal(err)
	}
	return state, verdict
}

// TestAutopilotRunner runs the real runner process, with a scripted
// adapter in place of a model, against a real admin and Postgres. It needs
// Node and autopilot's dependencies, so it runs only with AUTOPILOT_RUNNER=1
// (scripts/ci/autopilot.sh).
func TestAutopilotRunner(t *testing.T) {
	if os.Getenv("AUTOPILOT_RUNNER") == "" {
		t.Skip("set AUTOPILOT_RUNNER=1 after npm ci in autopilot")
	}
	hang := runnerPlan{Hang: true}

	t.Run("a scripted attack case closes done with the proposal it made", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		plan := runnerPlan{Verdict: "attack", Summary: "Many POSTs to /login from one address", Steps: []planStep{
			{"get_case", map[string]any{}},
			{"validate_rule", map[string]any{"rule": loginRule()}},
			{"propose", proposal("add_sensor", "login-watch", loginRule())},
		}}
		startRunner(t, h, plan)
		st := connected(t, pub)
		if len(st.Runners) != 1 || !slices.Equal(st.Runners[0].Providers, []string{"claude"}) || st.Runners[0].Version == "" || st.Runners[0].SDKVersion == "" {
			t.Fatalf("runners %+v", st.Runners)
		}
		id := pub.investigate("login", "Is someone guessing passwords?")
		within(t, 30*time.Second, "the case closes", func() bool { s, _ := caseIs(t, h, id); return s != "queued" && s != "running" })
		if s, v := caseIs(t, h, id); s != "done" || v != "attack" {
			t.Fatalf("case %s verdict %q", s, v)
		}
		runs := runsOf(t, h, id)
		if len(runs) != 1 || runs[0].Status != "ok" {
			t.Fatalf("runs %+v", runs)
		}
		run := runs[0].ID

		var proposalID int64
		var accepted bool
		var ruleID string
		if err := h.db.QueryRow(t.Context(), "SELECT id, accepted, coalesce(rule_id, '') FROM autopilot_proposals WHERE run_id = $1", run).Scan(&proposalID, &accepted, &ruleID); err != nil || !accepted {
			t.Fatalf("proposal %d accepted %v, err %v", proposalID, accepted, err)
		}
		var closedWith []int64
		if err := h.db.QueryRow(t.Context(), "SELECT details->'proposals' FROM audit_events WHERE action = 'autopilot.case_close' AND target = $1", fmt.Sprintf("case %d", id)).
			Scan(&closedWith); err != nil || !slices.Equal(closedWith, []int64{proposalID}) {
			t.Fatalf("case closed with proposals %v, want [%d], err %v", closedWith, proposalID, err)
		}
		h.tick()
		if r, ok := liveRuleIn(pub.active().Config, ruleID); !ok || r.Action != "log" {
			t.Fatalf("rule %s live %v, action %q", ruleID, ok, r.Action)
		}

		if got := adminEvents(t, h, run); !slices.Equal(got, []string{"get_case", "validate_rule", "propose"}) {
			t.Fatalf("admin recorded calls %v", got)
		}
		rows, err := h.db.Query(t.Context(), "SELECT seq, kind FROM autopilot_run_events WHERE run_id = $1 AND source = 'runner' ORDER BY seq", run)
		if err != nil {
			t.Fatal(err)
		}
		type ev struct {
			Seq  int
			Kind string
		}
		events, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ev])
		if err != nil {
			t.Fatal(err)
		}
		var kinds []string
		for i, e := range events {
			if e.Seq != i+1 {
				t.Fatalf("runner event seqs %+v, want 1 to %d", events, len(events))
			}
			kinds = append(kinds, e.Kind)
		}
		if !slices.Contains(kinds, "tool_use") || !slices.Contains(kinds, "verdict") {
			t.Fatalf("runner event kinds %v", kinds)
		}
		// telemetry_complete holds only when last_seq equals the count and
		// the highest seq of the runner's events.
		var complete bool
		var transcript string
		var toolCalls int
		if err := h.db.QueryRow(t.Context(), "SELECT telemetry_complete, coalesce(encode(transcript_sha256, 'hex'), ''), tool_calls FROM autopilot_run_results WHERE run_id = $1", run).
			Scan(&complete, &transcript, &toolCalls); err != nil || !complete || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(transcript) || toolCalls != len(plan.Steps) {
			t.Fatalf("result telemetry_complete %v transcript_sha256 %q tool_calls %d, err %v", complete, transcript, toolCalls, err)
		}
	})

	t.Run("replay reads a case from admin and never calls its MCP", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		plan := runnerPlan{Verdict: "attack", Summary: "Many POSTs to /login from one address", Steps: []planStep{
			{"get_case", map[string]any{}},
			{"get_rule_stats", map[string]any{"rule": "login"}},
			{"validate_rule", map[string]any{"rule": loginRule()}},
			{"propose", proposal("add_sensor", "login-watch", loginRule())},
		}}
		runner := startRunner(t, h, plan)
		connected(t, pub)
		id := pub.investigate("login", "Is someone guessing passwords?")
		within(t, 30*time.Second, "the case closes", func() bool { s, _ := caseIs(t, h, id); return s == "done" })
		runs := runsOf(t, h, id)
		if len(runs) != 1 || runs[0].Status != "ok" {
			t.Fatalf("runs %+v", runs)
		}
		// Stopped, so nothing but the replay could add a run or an event.
		if err := runner.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		<-runner.done

		dir := t.TempDir()
		token := filepath.Join(dir, "token")
		if err := os.WriteFile(token, []byte(pub.userToken("autopilot.read", "stats.read", "config.read")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Admin behind a server that records every request the replay makes.
		var mu sync.Mutex
		var requests []string
		handler := h.s.Handler()
		front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requests = append(requests, r.Method+" "+r.URL.Path)
			mu.Unlock()
			handler.ServeHTTP(w, r)
		}))
		t.Cleanup(front.Close)
		ca := filepath.Join(dir, "admin-ca.pem")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(dir, "plan.json")
		if err := os.WriteFile(script, b, 0o600); err != nil {
			t.Fatal(err)
		}
		counts := func() (n [4]int64) {
			t.Helper()
			if err := h.db.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM autopilot_runs), (SELECT count(*) FROM autopilot_run_events),
				(SELECT count(*) FROM autopilot_proposals), (SELECT count(*) FROM audit_events)`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := counts()

		cmd := exec.Command(nodeBinary(t), "test/replay-scripted.ts", strconv.FormatInt(id, 10), "--admin", front.URL, "--token-file", token)
		cmd.Dir = "../../autopilot"
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir, "NODE_EXTRA_CA_CERTS=" + ca, "AUTOPILOT_SCRIPT=" + script}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("replay: %v\n%s", err, stderr.String())
		}
		var report struct {
			Case     int64 `json:"case"`
			Run      int64 `json:"run"`
			Recorded struct {
				Verdict string `json:"verdict"`
			} `json:"recorded"`
			Replay struct {
				Verdict   string `json:"verdict"`
				ToolCalls int    `json:"tool_calls"`
			} `json:"replay"`
			Differences struct {
				Verdict              bool              `json:"verdict"`
				PromptChanged        bool              `json:"prompt_changed"`
				ToolsChanged         bool              `json:"tools_changed"`
				UnrecordedCalls      []json.RawMessage `json:"unrecorded_calls"`
				RecordedCallsNotMade []string          `json:"recorded_calls_not_made"`
			} `json:"differences"`
		}
		// stdout is the report alone, so it can be piped.
		if err := json.Unmarshal(out, &report); err != nil {
			t.Fatalf("report %q: %v", out, err)
		}
		d := report.Differences
		if report.Case != id || report.Run != runs[0].ID || report.Recorded.Verdict != "attack" || report.Replay.Verdict != "attack" || report.Replay.ToolCalls != len(plan.Steps) ||
			d.Verdict || d.PromptChanged || d.ToolsChanged || len(d.UnrecordedCalls) != 0 || len(d.RecordedCallsNotMade) != 0 {
			t.Fatalf("report %s", out)
		}
		mu.Lock()
		got := slices.Clone(requests)
		mu.Unlock()
		if want := []string{fmt.Sprintf("GET /api/autopilot/cases/%d", id), "GET /api/autopilot/contract"}; !slices.Equal(got, want) {
			t.Fatalf("the replay asked admin %v, want %v", got, want)
		}
		if after := counts(); after != before {
			t.Fatalf("runs, run events, proposals and audit rows went from %v to %v", before, after)
		}
	})

	t.Run("a case whose model is an openai model gets a 409 and the runner keeps running", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		p := startRunner(t, h, runnerPlan{Verdict: "benign", Summary: "Ordinary logins"})
		connected(t, pub)
		model := pub.autopilotSettings()["model"]
		pub.setAutopilot(map[string]any{"model": "gpt-5"})
		id := pub.investigate("login", "Is someone guessing passwords?")
		within(t, 30*time.Second, "the runner reports admin's refusal", func() bool {
			return strings.Contains(p.out.String(), "has no credential for openai, the provider of model gpt-5")
		})
		if !p.alive() {
			t.Fatalf("the runner exited after the 409: %v", p.err)
		}
		pub.setAutopilot(map[string]any{"model": model})
		within(t, 60*time.Second, "the runner claims the case once the model is claude", func() bool { s, _ := caseIs(t, h, id); return s == "done" })
		if !p.alive() {
			t.Fatalf("the runner exited: %v", p.err)
		}
	})

	t.Run("a run that hangs past AUTOPILOT_CASE_TIMEOUT reports timeout and the case fails after its second attempt", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		startRunner(t, h, hang, "AUTOPILOT_CASE_TIMEOUT=1s")
		connected(t, pub)
		id := pub.investigate("login", "Is someone guessing passwords?")
		within(t, 30*time.Second, "the case fails", func() bool { s, _ := caseIs(t, h, id); return s == "failed" })
		runs := runsOf(t, h, id)
		if len(runs) != 2 || runs[0].Status != "timeout" || runs[1].Status != "timeout" {
			t.Fatalf("runs %+v", runs)
		}
	})

	t.Run("an answer without a verdict reports invalid_output and the case fails after its second attempt", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		startRunner(t, h, runnerPlan{Summary: "No verdict given"})
		connected(t, pub)
		id := pub.investigate("login", "Is someone guessing passwords?")
		within(t, 30*time.Second, "the case fails", func() bool { s, _ := caseIs(t, h, id); return s == "failed" })
		runs := runsOf(t, h, id)
		if len(runs) != 2 || runs[0].Status != "error" || runs[0].Category != "invalid_output" || runs[1].Status != "error" || runs[1].Category != "invalid_output" {
			t.Fatalf("runs %+v", runs)
		}
	})

	t.Run("with AUTOPILOT_CONCURRENCY=2 two cases run at once", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		// Hung runs hold their loops, so one loop could never run both.
		startRunner(t, h, hang, "AUTOPILOT_CONCURRENCY=2")
		connected(t, pub)
		ids := []int64{pub.investigate("login", "Is someone guessing passwords?"), pub.investigate("admin-route", "Scanning the admin pages?")}
		within(t, 30*time.Second, "both cases run", func() bool {
			for _, id := range ids {
				if s, _ := caseIs(t, h, id); s != "running" || len(runsOf(t, h, id)) != 1 {
					return false
				}
			}
			return true
		})
	})

	t.Run("a lapsed lease drops the run and the runner keeps claiming", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		// One run at a time, so the second claim shows the first run ended.
		startRunner(t, h, hang, "AUTOPILOT_CONCURRENCY=1")
		connected(t, pub)
		id := pub.investigate("login", "Is someone guessing passwords?")
		within(t, 30*time.Second, "the runner claims the case", func() bool { return len(runsOf(t, h, id)) == 1 })
		// Past the 10m lease: the next heartbeat gets 409, and the tick requeues the case.
		h.advance(11 * time.Minute)
		h.tick()
		within(t, 30*time.Second, "the runner claims the case again", func() bool { return len(runsOf(t, h, id)) == 2 })
		if runs := runsOf(t, h, id); runs[0].Status != "" {
			t.Fatalf("the dropped run posted a result: %+v", runs[0])
		}
	})

	t.Run("SIGTERM aborts the run, reports it as a shutdown and exits", func(t *testing.T) {
		h, pub, _ := autopilotHarness(t)
		p := startRunner(t, h, hang)
		connected(t, pub)
		id := pub.investigate("login", "Is someone guessing passwords?")
		within(t, 30*time.Second, "the runner claims the case", func() bool { s, _ := caseIs(t, h, id); return s == "running" })
		if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
			t.Fatal("the runner did not exit within 10s of SIGTERM")
		}
		if p.err != nil {
			t.Fatalf("exit: %v", p.err)
		}
		if runs := runsOf(t, h, id); len(runs) != 1 || runs[0].Status != "error" || runs[0].Category != "shutdown" {
			t.Fatalf("runs %+v", runs)
		}
		if s, _ := caseIs(t, h, id); s != "queued" {
			t.Fatalf("case %s, want queued", s)
		}
	})
}
