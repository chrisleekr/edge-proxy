package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// statsAt records one minute of fleet traffic on version 1.
func (h *harness) statsAt(minute time.Time, requests int64, rules, top string) {
	h.t.Helper()
	h.statsSeq++
	if _, err := h.db.Exec(context.Background(), `INSERT INTO edge_stats_minute (minute, version, replica, requests, edge_5xx, upstream_5xx, auth_failures, latency_ms, rate_limit, top_limited)
		VALUES ($1, 1, $2, $3, 0, 0, 0, $4, $5, $6)`, minute.UTC().Truncate(time.Minute), fmt.Sprint("r", h.statsSeq), requests, []int64{requests}, rules, top); err != nil {
		h.t.Fatal(err)
	}
}

// dailyAt is 30 minutes before now, k days back: inside a last_minutes 60
// window now when k is 0, and on each day before.
func dailyAt(h *harness, k int) time.Time {
	return h.now().UTC().Truncate(time.Minute).Add(-30*time.Minute - time.Duration(k)*24*time.Hour)
}

// lastHour is the start of the hour before now's, k days back.
func lastHour(h *harness, k int) time.Time {
	return h.now().UTC().Truncate(time.Hour).Add(-time.Hour - time.Duration(k)*24*time.Hour)
}

// thatHourDaily is a daily_utc window on the hour before now's, so its
// latest occurrence is the hour that just ended.
func thatHourDaily(h *harness) map[string]any {
	from := lastHour(h, 0).Hour()
	return map[string]any{"daily_utc": []int{from, from + 1}}
}

func lastMinutes(n int) map[string]any { return map[string]any{"last_minutes": n} }

func claim(metric, op string, value float64, window map[string]any) map[string]any {
	return map[string]any{"metric": metric, "window": window, "op": op, "value": value}
}

func scopeGlobal() map[string]any        { return map[string]any{"kind": "global"} }
func scopeRule(id string) map[string]any { return map[string]any{"kind": "rule", "rule": id} }
func scopeRoute(host, method, template string) map[string]any {
	return map[string]any{"kind": "route", "host": host, "method": method, "template": template}
}

// learning is a record_learning call for an observed note. The caller adds
// its evidence.
func learning(kind string, scope, claim map[string]any) map[string]any {
	return map[string]any{"kind": kind, "basis": "observed", "scope": scope, "claim": claim, "effect": nil,
		"statement": "Credential stuffing on login comes from addresses that rotate every few minutes",
		"rationale": "The cited stats show the count far above the days before"}
}

// hedged is a record_learning call for a context hypothesis on the fleet.
func hedged(statement string) map[string]any {
	return map[string]any{"kind": "context", "basis": "hypothesis", "scope": scopeGlobal(), "statement": statement,
		"rationale": "No metric admin keeps shows who sends this traffic"}
}

// evidence makes a read and returns the evidence id admin answered it with.
func evidence(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) int64 {
	t.Helper()
	out := mustCall(t, cs, tool, args)
	id, ok := out["evidence_id"].(float64)
	if !ok {
		t.Fatalf("%s answered without an evidence_id", tool)
	}
	return int64(id)
}

func noteID(t *testing.T, out map[string]any) int64 {
	t.Helper()
	id, ok := out["note_id"].(float64)
	if !ok || id < 1 {
		t.Fatalf("record_learning answered %v", out)
	}
	return int64(id)
}

// refused calls record_learning with in, which must be refused, and
// returns why.
func refused(t *testing.T, cs *mcp.ClientSession, in map[string]any) string {
	t.Helper()
	out, why := callTool(t, cs, "record_learning", in)
	if why == "" {
		t.Fatalf("record_learning accepted: %v", out)
	}
	return why
}

// lastSeq is the seq of the run's latest admin event: its latest call.
func (h *harness) lastSeq(run int64) int64 {
	h.t.Helper()
	var seq int64
	if err := h.db.QueryRow(context.Background(), "SELECT max(seq) FROM autopilot_run_events WHERE run_id = $1 AND source = 'admin'", run).Scan(&seq); err != nil {
		h.t.Fatal(err)
	}
	return seq
}

func (h *harness) noteTrust(id int64) string {
	h.t.Helper()
	var trust string
	if err := h.db.QueryRow(context.Background(), "SELECT trust FROM autopilot_notes WHERE id = $1", id).Scan(&trust); err != nil {
		h.t.Fatalf("note %d: %v", id, err)
	}
	return trust
}

// noteChanges is the note's revisions in order, as "change trust".
func (h *harness) noteChanges(id int64) []string {
	h.t.Helper()
	rows, _ := h.db.Query(context.Background(), "SELECT change || ' ' || trust FROM autopilot_note_revisions WHERE note_id = $1 ORDER BY id", id)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

// lastNoteReason is the reason of the note's latest revision.
func (h *harness) lastNoteReason(id int64) string {
	h.t.Helper()
	var reason string
	if err := h.db.QueryRow(context.Background(), "SELECT reason FROM autopilot_note_revisions WHERE note_id = $1 ORDER BY id DESC LIMIT 1", id).Scan(&reason); err != nil {
		h.t.Fatal(err)
	}
	return reason
}

func (h *harness) noteCount() int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(context.Background(), "SELECT count(*) FROM autopilot_notes").Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// confirmNote confirms a note as noteJobs does, with its revision and audit
// row, for a test about what a confirmed note does. TestNoteOneCaseConfirms
// covers when a case confirms one.
func (h *harness) confirmNote(id int64) {
	h.t.Helper()
	ctx := context.Background()
	if err := h.s.noteTx(ctx, func(tx pgx.Tx) error {
		moved, err := h.s.setTrust(ctx, tx, id, []string{"unconfirmed"}, "confirmed", "confirmed", "its case held", "system:autopilot", nil, nil)
		if err == nil && !moved {
			return fmt.Errorf("note %d is not unconfirmed", id)
		}
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
}

// seedNote stores a context hypothesis of the run c claimed on scope, as
// if written at, with trust: unconfirmed, retracted or retired, the ones a
// hypothesis can reach. Writing hundreds through record_learning would
// take a run for every 3.
func (h *harness) seedNote(c claimed, trust string, at time.Time, scope map[string]any, scopeKey string) int64 {
	h.t.Helper()
	var id int64
	if err := h.owner.QueryRow(context.Background(), `WITH n AS (INSERT INTO autopilot_notes (kind, basis, scope, scope_key, statement, rationale, links, evidence,
			trust, trust_since, case_id, run_id, created_at)
		VALUES ('context', 'hypothesis', $1, $2, 'Likely the partner''s nightly sync', '', '{}', '[]', $3, $4, $5, $6, $4) RETURNING id),
		r AS (INSERT INTO autopilot_note_revisions (note_id, change, trust, reason, fields, actor, run_id, case_id, at)
			SELECT id, 'written', 'unconfirmed', '', '{}', 'deployment:autopilot', $6, $5, $4 FROM n)
		SELECT id FROM n`, scope, scopeKey, trust, at, c.CaseID, c.RunID).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

// writeNote has a new case on login record in, citing a get_stats read
// when the note is observed, and closes the case with verdict. It returns
// the note id.
func writeNote(t *testing.T, h *harness, pub, agent *client, in map[string]any, verdict string) int64 {
	t.Helper()
	c, cs := agentCase(t, h, pub, agent)
	if in["basis"] == "observed" {
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
	}
	id := noteID(t, mustCall(t, cs, "record_learning", in))
	status(t, agent.result(c.CaseID, resultBody(c.RunID, verdict, usage{Input: 10}, nil, 0)), 204)
	return id
}

// served is the ids of the notes search_notes serves cs for scope.
func served(t *testing.T, cs *mcp.ClientSession, scope map[string]any) []int64 {
	t.Helper()
	out := mustCall(t, cs, "search_notes", map[string]any{"scope": scope})
	notes, ok := out["notes"].([]any)
	if !ok {
		t.Fatalf("search_notes answered %v", out)
	}
	ids := []int64{}
	for _, n := range notes {
		m, _ := n.(map[string]any)
		id, _ := m["id"].(float64)
		ids = append(ids, int64(id))
	}
	return ids
}

// citedRule has a new case on login served scope's notes, propose in
// citing note, close as an attack and tick, so the rule observes. It
// returns the rule id.
func citedRule(t *testing.T, h *harness, pub, agent *client, scope map[string]any, note int64, in map[string]any) string {
	t.Helper()
	c, cs := agentCase(t, h, pub, agent)
	if ids := served(t, cs, scope); !slices.Contains(ids, note) {
		t.Fatalf("note %d not served: %v", note, ids)
	}
	in["notes"] = []int64{note}
	p := propose(t, cs, in)
	if !p.Accepted {
		t.Fatalf("proposal %+v", p)
	}
	status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
	h.tick()
	if st := ruleState(t, h, p.RuleID); st != "observing" {
		t.Fatalf("rule %s %s, want observing", p.RuleID, st)
	}
	return p.RuleID
}

// claimKind claims cases, closing those of other kinds as benign, until it
// takes one of kind.
func claimKind(t *testing.T, agent *client, kind string) claimed {
	t.Helper()
	for range 5 {
		c := agent.claimCase()
		if c.Kind == kind {
			return c
		}
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
	}
	t.Fatalf("no %s case was queued", kind)
	return claimed{}
}

func (h *harness) observedRoute(host, method, template string) int64 {
	h.t.Helper()
	var id int64
	if err := h.db.QueryRow(context.Background(), "INSERT INTO observed_routes (host, method, template, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		host, method, template, h.now().Add(-30*24*time.Hour), h.now()).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

// routeHour records requests answered 2xx on route in hour.
func (h *harness) routeHour(route int64, hour time.Time, requests int64) {
	h.t.Helper()
	if _, err := h.db.Exec(context.Background(), `INSERT INTO observed_route_hour (route_id, hour, requests, versioned, status, latency_ms, decisions, config_rules, rate_limit_rules, query_shapes)
		VALUES ($1, $2, $3, $3, $4, '{}', '{}', '{}', '{}', '{}')`, route, hour, requests, []int64{0, 0, requests, 0, 0, 0}); err != nil {
		h.t.Fatal(err)
	}
}

// loginStuffing records the last minute of stuffing on login: 400 of 2,000
// logins limited.
func (h *harness) loginStuffing() {
	h.t.Helper()
	h.statsAt(dailyAt(h, 0), 10_000, `[{"id":"login","evaluated":2000,"limited":400,"would_limit":0}]`, "[]")
}

// stuffingNote is an attack_signature on login whose claim the stuffing
// makes true.
func stuffingNote() map[string]any {
	return learning("attack_signature", scopeRule("login"), claim("rule_limited", ">=", 100, lastMinutes(60)))
}

// partnerLimited records login limiting 30 requests from the partner's
// 203.0.113.0/24.
func (h *harness) partnerLimited() {
	h.t.Helper()
	h.statsAt(dailyAt(h, 0), 10_000, `[{"id":"login","evaluated":2000,"limited":30,"would_limit":0}]`,
		`[{"rule":"login","key":"k1","display":"203.0.113.9","limited":30}]`)
}

// partnerNote is a collateral_risk on login anchored by the partner's
// protected network, with effect.
func partnerNote(effect map[string]any) map[string]any {
	c := claim("subject_limited", ">=", 20, lastMinutes(60))
	c["subject"] = "203.0.113.0/24"
	in := learning("collateral_risk", scopeRule("login"), c)
	in["effect"] = effect
	in["statement"] = "Login limits hit the partner's office network, whose staff share one NAT"
	return in
}

// keyNote is a key_preference on login whose claim the stuffing makes
// true.
func keyNote() map[string]any {
	in := learning("key_preference", scopeRule("login"), claim("rule_limited", ">=", 100, lastMinutes(60)))
	in["effect"] = map[string]any{"key": []string{"ip", "jwt_claim:sub"}}
	in["statement"] = "Stuffing on login shares addresses with real users; keying on the account spares them"
	return in
}

// atUTC moves the clock on to the next hour:minute UTC.
func (h *harness) atUTC(hour, minute int) {
	now := h.now().UTC()
	at := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, time.UTC)
	if !at.After(now) {
		at = at.Add(24 * time.Hour)
	}
	h.advance(at.Sub(now))
}

// batchWindow is the nightly batch's hours, from 11:00 to 13:00 UTC.
func batchWindow() map[string]any { return map[string]any{"daily_utc": []int{11, 13}} }

// batchNote moves the clock to 12:30 UTC, inside batchWindow, has the
// fleet take 600,000 requests at 11:10 today and on each of the 15 days
// before, and writes and confirms an expected pattern on it, anchored by
// its history.
func batchNote(t *testing.T, h *harness, pub, agent *client) int64 {
	t.Helper()
	h.atUTC(12, 30)
	for k := range 16 {
		h.statsAt(h.now().Add(-80*time.Minute-time.Duration(k)*24*time.Hour), 600_000, "[]", "[]")
	}
	in := learning("expected_pattern", scopeGlobal(), claim("requests", ">=", 500_000, batchWindow()))
	in["statement"] = "The fleet takes about 600,000 requests from 11:00 to 13:00 UTC every day; the nightly batch sends most of them"
	n := writeNote(t, h, pub, agent, in, "benign")
	h.confirmNote(n)
	return n
}

// benignWith closes a new case on login as benign whose run was served
// note by a search of scope.
func benignWith(t *testing.T, h *harness, pub, agent *client, n int64, scope map[string]any) claimed {
	t.Helper()
	c, cs := agentCase(t, h, pub, agent)
	if ids := served(t, cs, scope); !slices.Contains(ids, n) {
		t.Fatalf("served %v", ids)
	}
	status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
	return c
}

// ablations is the number of ablation cases.
func (h *harness) ablations() int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(context.Background(), "SELECT count(*) FROM autopilot_cases WHERE kind = 'ablation'").Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// waitingOnLocks waits until n transactions wait on a lock in this
// database.
func waitingOnLocks(t *testing.T, h *harness, n int) {
	t.Helper()
	for range 500 {
		var waiting int
		if err := h.db.QueryRow(t.Context(), "SELECT count(DISTINCT pid) FROM pg_locks WHERE NOT granted AND pid IN (SELECT pid FROM pg_stat_activity WHERE datname = current_database())").
			Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fewer than %d transactions wait on a lock", n)
}

// racing has call run while another transaction holds what first takes,
// and once call waits on a lock, has that transaction take what then
// takes. When call takes the two in the other order the transactions
// deadlock, and Postgres aborts one of them.
func racing(t *testing.T, h *harness, first, then func(ctx context.Context, tx pgx.Tx) error, call func() string) {
	t.Helper()
	ctx := t.Context()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := first(ctx, tx); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() { done <- call() }()
	waitingOnLocks(t, h, 1)
	if err := then(ctx, tx); err != nil {
		t.Fatalf("the other transaction: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if why := <-done; why != "" {
		t.Fatalf("the call: %s", why)
	}
}

// caseCloseAudit writes the audit row of a case closing, as a case
// result does after it takes the run's lock.
func caseCloseAudit(h *harness, c claimed) func(ctx context.Context, tx pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		return admindb.Audit(ctx, tx, h.s.cfg.Audit, h.now, admindb.Event{Actor: "deployment:autopilot", Action: "autopilot.case_close", Target: fmt.Sprintf("case %d", c.CaseID)})
	}
}

// notifyingAutopilot is autopilotHarness with notifications that fire and
// resolve on one check.
func notifyingAutopilot(t *testing.T) (*harness, *client, *client) {
	t.Helper()
	am := newFakeAlertmanager(t)
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"ALERTMANAGER_URL": am.srv.URL + "/"})
	n := decode[NotifySettings](t, pub.do("GET", "/api/settings/notifications", nil))
	n.FireAfter, n.ResolveAfter = 1, 1
	status(t, pub.do("PUT", "/api/settings/notifications", n), 204)
	return h, pub, agent
}

// firing is the open anomaly of signal, or nil.
func firing(h *harness, pub *client, signal string) *anomaly {
	h.t.Helper()
	for _, a := range h.anomalies(pub) {
		if a.Signal == signal && a.State != "resolved" {
			return &a
		}
	}
	return nil
}

func TestNoteEvidenceIDs(t *testing.T) {
	t.Run("a runner's stats read carries its evidence id as a second text and in the structured result", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c, cs := agentCase(t, h, pub, agent)
		mustCall(t, cs, "get_case", nil)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_stats", Arguments: map[string]any{"minutes": 60}})
		if err != nil || res.IsError {
			t.Fatalf("get_stats: %v %+v", err, res)
		}
		seq := h.lastSeq(c.RunID)
		if seq != 2 {
			t.Fatalf("get_stats recorded as seq %d, want 2", seq)
		}
		if len(res.Content) != 2 {
			t.Fatalf("%d contents, want the answer and the evidence id", len(res.Content))
		}
		if text, ok := res.Content[1].(*mcp.TextContent); !ok || text.Text != fmt.Sprintf(`{"evidence_id":%d}`, seq) {
			t.Fatalf("second content %+v", res.Content[1])
		}
		b, _ := json.Marshal(res.StructuredContent)
		var structured map[string]any
		if err := json.Unmarshal(b, &structured); err != nil || structured["evidence_id"] != float64(seq) {
			t.Fatalf("structured evidence_id %v, err %v", structured["evidence_id"], err)
		}
	})
	h, pub, agent := autopilotHarness(t)
	_, cs := agentCase(t, h, pub, agent)
	for _, tc := range []struct {
		tool     string
		args     map[string]any
		evidence bool
	}{
		{"get_stats", map[string]any{"minutes": 60}, true},
		{"get_rule_stats", map[string]any{"rule": "login"}, true},
		{"list_anomalies", nil, true},
		{"list_routes", nil, true},
		{"check_subject", map[string]any{"ip": "198.51.100.7"}, true},
		{"list_rules", nil, false},
		{"describe_fields", nil, false},
		{"list_versions", nil, false},
		{"get_autopilot_state", nil, false},
		{"list_cases", nil, false},
		{"get_case", nil, false},
	} {
		name := fmt.Sprintf("a runner's %s has no evidence id", tc.tool)
		if tc.evidence {
			name = fmt.Sprintf("a runner's %s is evidence", tc.tool)
		}
		t.Run(name, func(t *testing.T) {
			_, has := mustCall(t, cs, tc.tool, tc.args)["evidence_id"]
			if has != tc.evidence {
				t.Fatalf("evidence_id present %v, want %v", has, tc.evidence)
			}
		})
	}
	t.Run("a refused stats read has no evidence id", func(t *testing.T) {
		_, why := callTool(t, cs, "get_stats", map[string]any{"minutes": 20161})
		if why == "" || strings.Contains(why, "evidence_id") {
			t.Fatalf("refusal %q", why)
		}
	})
	t.Run("a person's stats read has no evidence id", func(t *testing.T) {
		if _, has := mustCall(t, h.mcpSession(pub.userToken("stats.read"), 0), "get_stats", map[string]any{"minutes": 60})["evidence_id"]; has {
			t.Fatal("a person's read got an evidence id")
		}
	})
}

// Evidence is a successful stats read this run made and admin kept whole,
// so a note can't vouch for itself or cite what the model never saw.
func TestNoteEvidenceMustBeAReadFromThisRun(t *testing.T) {
	stuffing := func() map[string]any {
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 1000, lastMinutes(60)))
		in["statement"] = "Fleet requests stay over 1,000 an hour while the stuffing runs"
		return in
	}
	t.Run("a stats read of this run is accepted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		_, cs := agentCase(t, h, pub, agent)
		in := stuffing()
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		if out := mustCall(t, cs, "record_learning", in); out["trust"] != "unconfirmed" {
			t.Fatalf("record_learning %v", out)
		}
	})
	for _, tc := range []struct {
		name  string
		cite  func(t *testing.T, h *harness, c claimed, cs *mcp.ClientSession) []int64
		want  string
		notes int
	}{
		{"an observed note citing nothing", func(*testing.T, *harness, claimed, *mcp.ClientSession) []int64 { return []int64{} }, "evidence", 0},
		{"an id no call of this run has", func(*testing.T, *harness, claimed, *mcp.ClientSession) []int64 { return []int64{99} }, "no such call", 0},
		{"a refused read", func(t *testing.T, h *harness, c claimed, cs *mcp.ClientSession) []int64 {
			t.Helper()
			callTool(t, cs, "get_stats", map[string]any{"minutes": 20161})
			return []int64{h.lastSeq(c.RunID)}
		}, "it was refused", 0},
		{"a config read", func(t *testing.T, h *harness, c claimed, cs *mcp.ClientSession) []int64 {
			t.Helper()
			mustCall(t, cs, "list_rules", nil)
			return []int64{h.lastSeq(c.RunID)}
		}, "list_rules can't be evidence", 0},
		{"search_notes", func(t *testing.T, h *harness, c claimed, cs *mcp.ClientSession) []int64 {
			t.Helper()
			mustCall(t, cs, "search_notes", map[string]any{"scope": scopeGlobal()})
			return []int64{h.lastSeq(c.RunID)}
		}, "search_notes can't be evidence", 0},
		{"its own earlier record_learning", func(t *testing.T, h *harness, c claimed, cs *mcp.ClientSession) []int64 {
			t.Helper()
			in := stuffing()
			in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
			mustCall(t, cs, "record_learning", in)
			return []int64{h.lastSeq(c.RunID)}
		}, "record_learning can't be evidence", 1},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
			c, cs := agentCase(t, h, pub, agent)
			ids := tc.cite(t, h, c, cs)
			in := stuffing()
			in["evidence"] = ids
			if why := refused(t, cs, in); !strings.Contains(why, tc.want) {
				t.Fatalf("refusal %q, want %q", why, tc.want)
			}
			if n := h.noteCount(); n != tc.notes {
				t.Fatalf("%d notes stored, want %d", n, tc.notes)
			}
			h.wantMetrics(`admin_autopilot_note_refusals_total{reason="evidence"} 1`)
		})
	}
	t.Run("a read of another run is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		o, ocs := agentCase(t, h, pub, agent)
		mustCall(t, ocs, "get_case", nil)
		mustCall(t, ocs, "describe_fields", nil)
		other := evidence(t, ocs, "get_stats", map[string]any{"minutes": 60}) // seq 3 of that run
		status(t, agent.result(o.CaseID, resultBody(o.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
		_, cs := agentCase(t, h, pub, agent)
		mustCall(t, cs, "get_case", nil) // this run's only call, seq 1
		in := stuffing()
		in["evidence"] = []int64{other}
		if why := refused(t, cs, in); !strings.Contains(why, "no such call") {
			t.Fatalf("refusal %q", why)
		}
		if n := h.noteCount(); n != 0 {
			t.Fatalf("%d notes stored", n)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="evidence"} 1`)
	})
	// A read whose record was cut can't be shown later, so it is no
	// evidence. One subject's display sets the answer's size to the byte.
	t.Run("a read too large to keep whole is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		top := func(n int) string {
			return fmt.Sprintf(`[{"rule":"login","key":"k1","display":%q,"limited":1}]`, strings.Repeat("a", n))
		}
		h.statsAt(dailyAt(h, 0), 1000, `[{"id":"login","evaluated":10,"limited":1}]`, top(1000))
		c, cs := agentCase(t, h, pub, agent)
		read := func() (*mcp.CallToolResult, int) {
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_rule_stats", Arguments: map[string]any{"rule": "login", "minutes": 60}})
			if err != nil || res.IsError {
				t.Fatalf("get_rule_stats: %v %+v", err, res)
			}
			text, _ := res.Content[0].(*mcp.TextContent)
			return res, len(text.Text)
		}
		_, size := read()
		// 16 bytes under the result cap: the call is answered, and its record,
		// which adds the tool name and arguments, is over 64 KiB.
		if _, err := h.owner.Exec(t.Context(), "UPDATE edge_stats_minute SET top_limited = $1 WHERE top_limited <> '[]'", top(1000+mcpMaxResult-size-16)); err != nil {
			t.Fatal(err)
		}
		res, size := read()
		seq := h.lastSeq(c.RunID)
		var cut bool
		if err := h.db.QueryRow(t.Context(), "SELECT cut FROM autopilot_run_events WHERE run_id = $1 AND source = 'admin' AND seq = $2", c.RunID, seq).Scan(&cut); err != nil || !cut || size != mcpMaxResult-16 {
			t.Fatalf("record cut %v for an answer of %d bytes, err %v", cut, size, err)
		}
		if len(res.Content) != 1 {
			t.Fatalf("a read kept cut answered with %d contents, want no evidence id", len(res.Content))
		}
		in := stuffing()
		in["evidence"] = []int64{seq}
		if why := refused(t, cs, in); !strings.Contains(why, "it was too large to keep") {
			t.Fatalf("refusal %q", why)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="evidence"} 1`)
	})
}

// A hypothesis is a context note that says it is one. It needs no
// evidence and is never confirmed.
func TestNoteHypothesisMustBeHedged(t *testing.T) {
	withClaim := hedged("Likely the partner's nightly sync")
	withClaim["claim"] = claim("requests", ">=", 1000, lastMinutes(60))
	signature := hedged("Probably a botnet rotating through residential proxies")
	signature["kind"] = "attack_signature"
	for _, tc := range []struct {
		name string
		in   map[string]any
	}{
		{"a statement that reads as a fact", hedged("Traffic from AS64500 at night is the partner's sync job")},
		{"a hedge word only inside another word", hedged("The Mayfair office syncs its catalog every night")},
		{"a hypothesis whose only hedge is the month May", hedged("Traffic from the partner's office spikes every May")},
		{"a hypothesis of another kind", signature},
		{"a hypothesis with a claim", withClaim},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			_, cs := agentCase(t, h, pub, agent)
			if why := refused(t, cs, tc.in); !strings.Contains(why, "hypothesis") {
				t.Fatalf("refusal %q", why)
			}
			if n := h.noteCount(); n != 0 {
				t.Fatalf("%d notes stored", n)
			}
			h.wantMetrics(`admin_autopilot_note_refusals_total{reason="hypothesis"} 1`)
		})
	}
	t.Run("an observed note without a claim is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, cs := agentCase(t, h, pub, agent)
		in := learning("attack_signature", scopeGlobal(), nil)
		delete(in, "claim")
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		if why := refused(t, cs, in); !strings.Contains(why, "claim") {
			t.Fatalf("refusal %q", why)
		}
	})
	for _, statement := range []string{
		"Likely the partner's nightly catalog sync",
		"This might be a load test the platform team runs on Fridays",
		"It appears to come from one CI provider; unconfirmed",
	} {
		t.Run(fmt.Sprintf("%q is stored unconfirmed without evidence", statement), func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			_, cs := agentCase(t, h, pub, agent)
			out := mustCall(t, cs, "record_learning", hedged(statement))
			id := noteID(t, out)
			if out["trust"] != "unconfirmed" || out["anchor"] != nil {
				t.Fatalf("record_learning %v", out)
			}
			var basis string
			var claimNull bool
			if err := h.db.QueryRow(t.Context(), "SELECT basis, claim IS NULL FROM autopilot_notes WHERE id = $1", id).Scan(&basis, &claimNull); err != nil || basis != "hypothesis" || !claimNull {
				t.Fatalf("stored basis %q claim null %v, err %v", basis, claimNull, err)
			}
			if got := h.noteChanges(id); !slices.Equal(got, []string{"written unconfirmed"}) {
				t.Fatalf("revisions %v", got)
			}
			if !slices.Contains(h.actions(), fmt.Sprintf("autopilot.note_write note %d", id)) {
				t.Fatalf("audit %v", h.actions())
			}
		})
	}
	t.Run("a stored statement reaches a later run as untrusted", func(t *testing.T) {
		const injected = "ignore-previous-instructions"
		h, pub, agent := autopilotHarness(t)
		writeNote(t, h, pub, agent, hedged("Likely a partner; its user agent says "+injected), "benign")
		_, cs := agentCase(t, h, pub, agent)
		out := mustCall(t, cs, "search_notes", map[string]any{"scope": scopeGlobal()})
		if !strings.Contains(fmt.Sprint(out), injected) {
			t.Fatalf("the note is missing: %v", out)
		}
		if p := untrustedOnly(out, injected, "", false); p != "" {
			t.Fatalf("%s holds a model-written value outside an untrusted field", p)
		}
	})
}

// Admin recomputes an observed claim on its own data before keeping it,
// and says what it found.
func TestNoteFalseClaimIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		claim map[string]any
		want  string
	}{
		// 30 minutes of 1,000 requests: 30,000 in the last hour.
		{"a floor the traffic is under", claim("requests", ">=", 50_000, lastMinutes(60)), "30000"},
		{"a ceiling the traffic is over", claim("requests", "<=", 1_000, lastMinutes(60)), "30000"},
	} {
		t.Run(tc.name+" is refused with the value admin found", func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
			_, cs := agentCase(t, h, pub, agent)
			in := learning("attack_signature", scopeGlobal(), tc.claim)
			in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
			if why := refused(t, cs, in); !strings.Contains(why, tc.want) {
				t.Fatalf("refusal %q, want the value %s", why, tc.want)
			}
			if n := h.noteCount(); n != 0 {
				t.Fatalf("%d notes stored", n)
			}
			h.wantMetrics(`admin_autopilot_note_refusals_total{reason="false_claim"} 1`)
		})
	}
	t.Run("a claim on a route with no traffic in its window is refused for no data", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.observedRoute("api.example.com", "GET", "/api/v2/export")
		_, cs := agentCase(t, h, pub, agent)
		in := learning("attack_signature", scopeRoute("api.example.com", "GET", "/api/v2/export"), claim("route_requests", ">=", 1, lastMinutes(60)))
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		if why := refused(t, cs, in); !strings.Contains(why, "no data") {
			t.Fatalf("refusal %q", why)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="false_claim"} 1`)
	})
	t.Run("a claim true on admin's data is kept with the value admin found", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		_, cs := agentCase(t, h, pub, agent)
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 25_000, lastMinutes(60)))
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		stats, _ := mustCall(t, cs, "record_learning", in)["stats"].(map[string]any)
		if stats["value"] != float64(30_000) || stats["holds"] != true {
			t.Fatalf("stats %v", stats)
		}
	})
}

// A note that makes the autopilot less likely to act needs evidence an
// attacker can't make: 7 of the 14 days before, or an identity that can't
// be spoofed.
func TestNoteBenignNeedsAnAnchor(t *testing.T) {
	const export = "/api/v2/export"
	// exportDays has export take 2,000 requests in the hour that just ended
	// and on the first held of the 14 days before, and 10 on the others.
	exportDays := func(h *harness, held int) {
		route := h.observedRoute("api.example.com", "GET", export)
		for k := 1; k <= 14; k++ {
			v := int64(10)
			if k <= held {
				v = 2000
			}
			h.routeHour(route, lastHour(h, k), v)
		}
		h.routeHour(route, lastHour(h, 0), 2000)
	}
	exportNote := func(h *harness, kind string) map[string]any {
		in := learning(kind, scopeRoute("api.example.com", "GET", export), claim("route_requests", ">=", 1000, thatHourDaily(h)))
		in["statement"] = "Export takes about 2,000 requests in this hour each day from the partner's catalog sync"
		if kind == "collateral_risk" {
			in["effect"] = map[string]any{"max_block_share": 0.005}
		}
		return in
	}
	for _, tc := range []struct {
		name string
		kind string
		held int
	}{
		{"an expected pattern held on 6 of 14 days", "expected_pattern", 6},
		{"a collateral risk held on 6 of 14 days", "collateral_risk", 6},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			exportDays(h, tc.held)
			_, cs := agentCase(t, h, pub, agent)
			in := exportNote(h, tc.kind)
			in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
			if why := refused(t, cs, in); !strings.Contains(why, "anchor") {
				t.Fatalf("refusal %q", why)
			}
			h.wantMetrics(`admin_autopilot_note_refusals_total{reason="anchor"} 1`)
		})
	}
	t.Run("an expected pattern held on 7 of 14 days is anchored by its history", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exportDays(h, 7)
		_, cs := agentCase(t, h, pub, agent)
		in := exportNote(h, "expected_pattern")
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		out := mustCall(t, cs, "record_learning", in)
		stats, _ := out["stats"].(map[string]any)
		baseline, _ := stats["baseline"].(map[string]any)
		if out["anchor"] != "history" || baseline["held_days"] != float64(7) {
			t.Fatalf("anchor %v, baseline %v", out["anchor"], baseline)
		}
	})
	t.Run("an attack signature on the same 6 days needs no anchor", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exportDays(h, 6)
		_, cs := agentCase(t, h, pub, agent)
		in := exportNote(h, "attack_signature")
		in["statement"] = "Scrapers pull export in this hour, from addresses that change each day"
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		if out := mustCall(t, cs, "record_learning", in); out["anchor"] != nil || out["trust"] != "unconfirmed" {
			t.Fatalf("record_learning %v", out)
		}
	})
	t.Run("a collateral risk naming a protected subject is anchored by it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
		h.partnerLimited()
		_, cs := agentCase(t, h, pub, agent)
		in := partnerNote(map[string]any{"max_block_share": 0.005})
		in["evidence"] = []int64{evidence(t, cs, "get_rule_stats", map[string]any{"rule": "login", "minutes": 60})}
		if out := mustCall(t, cs, "record_learning", in); out["anchor"] != "protected" {
			t.Fatalf("record_learning %v", out)
		}
	})
	t.Run("a collateral risk naming a verified crawler range is anchored by it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		if _, err := h.db.Exec(t.Context(), `INSERT INTO verified_bot_sets (source_url, fetched_at, prefixes) VALUES ('https://bots.example.com/googlebot.json', now(), '["66.249.64.0/19"]')`); err != nil {
			t.Fatal(err)
		}
		h.statsAt(dailyAt(h, 0), 10_000, `[{"id":"login","evaluated":2000,"limited":30,"would_limit":0}]`, `[{"rule":"login","key":"k1","display":"66.249.66.1","limited":30}]`)
		_, cs := agentCase(t, h, pub, agent)
		c := claim("subject_limited", ">=", 20, lastMinutes(60))
		c["subject"] = "66.249.66.0/24"
		in := learning("collateral_risk", scopeRule("login"), c)
		in["effect"] = map[string]any{"max_block_share": 0.005}
		in["statement"] = "Login limits hit Googlebot checking the sign-in page"
		in["evidence"] = []int64{evidence(t, cs, "get_rule_stats", map[string]any{"rule": "login", "minutes": 60})}
		if out := mustCall(t, cs, "record_learning", in); out["anchor"] != "crawler" {
			t.Fatalf("record_learning %v", out)
		}
	})
}

// A claim anchors a note only when it is tight: a floor above 0 and at
// least half what admin found, or a ceiling at most twice it. A loose
// claim holds whatever the traffic does, so neither its history nor its
// subject shows anything.
func TestNoteVacuousClaimsAnchorNothing(t *testing.T) {
	// exportEveryDay has export take 2,000 requests in the hour that just
	// ended and in that hour on each of the 14 days before.
	exportEveryDay := func(h *harness) {
		route := h.observedRoute("api.example.com", "GET", "/api/v2/export")
		for k := range 15 {
			h.routeHour(route, lastHour(h, k), 2000)
		}
	}
	exportNote := func(h *harness, op string, value float64) map[string]any {
		in := learning("expected_pattern", scopeRoute("api.example.com", "GET", "/api/v2/export"), claim("route_requests", op, value, thatHourDaily(h)))
		in["statement"] = "Export takes about 2,000 requests in this hour each day from the partner's catalog sync"
		return in
	}
	t.Run("a floor of 0 on 7 days of stats is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		for k := range 8 {
			h.statsAt(lastHour(h, k).Add(10*time.Minute), 10_000, `[{"id":"login","evaluated":2000,"limited":0,"would_limit":0}]`, "[]")
		}
		_, cs := agentCase(t, h, pub, agent)
		in := learning("expected_pattern", scopeRule("login"), claim("rule_evaluated", ">=", 0, thatHourDaily(h)))
		in["statement"] = "Login is evaluated in this hour every day"
		in["evidence"] = []int64{evidence(t, cs, "get_rule_stats", map[string]any{"rule": "login", "minutes": 60})}
		if why := refused(t, cs, in); !strings.Contains(why, "above 0") {
			t.Fatalf("refusal %q", why)
		}
		if n := h.noteCount(); n != 0 {
			t.Fatalf("%d notes stored", n)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="claim"} 1`)
	})
	t.Run("a ceiling far over what admin found is refused for its anchor", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exportEveryDay(h)
		_, cs := agentCase(t, h, pub, agent)
		in := exportNote(h, "<=", 1e9)
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		if why := refused(t, cs, in); !strings.Contains(why, "anchor") {
			t.Fatalf("refusal %q", why)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="anchor"} 1`)
	})
	t.Run("a ceiling at twice what admin found is anchored by its history", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exportEveryDay(h)
		_, cs := agentCase(t, h, pub, agent)
		in := exportNote(h, "<=", 4000)
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		if out := mustCall(t, cs, "record_learning", in); out["anchor"] != "history" {
			t.Fatalf("record_learning %v", out)
		}
	})
	t.Run("a ceiling at twice a one-day spike is refused for its anchor", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		route := h.observedRoute("api.example.com", "GET", "/api/v2/export")
		for k := 1; k <= 14; k++ {
			h.routeHour(route, lastHour(h, k), 2000+int64(k))
		}
		h.routeHour(route, lastHour(h, 0), 200_000)
		_, cs := agentCase(t, h, pub, agent)
		in := exportNote(h, "<=", 400_000)
		in["kind"], in["effect"] = "collateral_risk", map[string]any{"max_block_share": 0.005}
		in["statement"] = "Export spikes in this hour when the partner reloads its catalog; limiting it blocks the partner"
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		if why := refused(t, cs, in); !strings.Contains(why, "anchor") {
			t.Fatalf("refusal %q", why)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="anchor"} 1`)
	})
	t.Run("a floor under half what admin found is refused for its anchor", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exportEveryDay(h)
		_, cs := agentCase(t, h, pub, agent)
		in := exportNote(h, ">=", 999)
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		if why := refused(t, cs, in); !strings.Contains(why, "anchor") {
			t.Fatalf("refusal %q", why)
		}
	})
	t.Run("a floor far under what a protected subject got is refused for its anchor", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
		h.partnerLimited() // 30 limited
		_, cs := agentCase(t, h, pub, agent)
		in := partnerNote(map[string]any{"max_block_share": 0.005})
		in["claim"].(map[string]any)["value"] = 1
		in["evidence"] = []int64{evidence(t, cs, "get_rule_stats", map[string]any{"rule": "login", "minutes": 60})}
		if why := refused(t, cs, in); !strings.Contains(why, "anchor") {
			t.Fatalf("refusal %q", why)
		}
	})
}

// A rule keyed on a verified JWT claim anchors a note on it: the claim is
// signed by an issuer the deployment trusts.
func TestNoteJWTClaimAnchor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		issuers bool
		anchor  any
	}{
		{"a rule keyed on ip and a JWT claim with an issuer configured anchors a note", true, "jwt_claim"},
		{"the same rule with no issuer configured anchors nothing", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			c := testConfig()
			if tc.issuers {
				c = authConfig("https://auth.example.com/jwks")
			}
			c.RateLimitRules = append(c.RateLimitRules, snapshot.RateLimitRule{ID: "account", Expression: mustParse(`starts_with(http.request.uri.path, "/account")`),
				Algorithm: "sliding_window", Limit: 10, Period: snapshot.Duration(time.Minute), Key: []string{"ip", "jwt_claim:sub"}, OnMissingKey: "fallback_ip",
				Action: "block", FailMode: "open"})
			status(t, pub.save(pub.revision(), c, adminTest), 200)
			status(t, pub.publishDraft("Limit accounts", "override_reason", "IdP is down, publishing anyway"), 201)
			h.statsAt(dailyAt(h, 0), 10_000, `[{"id":"account","evaluated":2000,"limited":30,"would_limit":0}]`, "[]")
			_, cs := agentCase(t, h, pub, agent)
			in := learning("collateral_risk", scopeRule("account"), claim("rule_limited", ">=", 20, lastMinutes(60)))
			in["effect"] = map[string]any{"require_jwt_claim": true}
			in["statement"] = "Account limits hit offices whose staff share one NAT; keying on the account spares them"
			in["evidence"] = []int64{evidence(t, cs, "get_rule_stats", map[string]any{"rule": "account", "minutes": 60})}
			out, why := callTool(t, cs, "record_learning", in)
			if tc.anchor == nil && !strings.Contains(why, "anchor") || tc.anchor != nil && (why != "" || out["anchor"] != tc.anchor) {
				t.Fatalf("record_learning %v, refusal %q", out, why)
			}
		})
	}
}

// A credential anywhere in a note is refused, and the refusal never
// repeats it.
func TestNoteGateRefusesCredentials(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c, cs := agentCase(t, h, pub, agent)
	cases := []struct {
		name, field, secret string
	}{
		{"a bearer token in the statement", "statement", "Bearer abcdefgh12345678"},
		{"a JWT in the rationale", "rationale", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl"},
		{"an AWS access key id in the statement", "statement", "AKIAIOSFODNN7EXAMPLE"},
		{"a private key in the rationale", "rationale", "-----BEGIN RSA PRIVATE KEY-----"},
		{"an API key in the statement", "statement", "sk-proj-abcdefghijklmnopqrstu"},
		{"a GitHub token in the statement", "statement", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"a Slack token in the statement", "statement", "xoxb-1234-5678-abcdef"},
		{"a password in the rationale", "rationale", "password=hunter2hunter2"},
		{"a password with a quote in it", "statement", `password=abc"defgh123`},
		{"a token in a route template", "template", "/api/v2/export/token=abcdef123456"},
		{"a bearer token in a statement over 500 characters", "long", "Bearer abcdefgh12345"},
		{"a bearer token in a field the tool does not take", "unknown", "Bearer abcdefgh12345"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" is refused without repeating it", func(t *testing.T) {
			in := hedged("Likely the partner's sync")
			switch tc.field {
			case "statement":
				in["statement"] = "Likely the partner's sync; its requests carry " + tc.secret
			case "rationale":
				in["rationale"] = "The access log shows " + tc.secret
			case "template":
				in["scope"] = scopeRoute("api.example.com", "GET", tc.secret)
			case "long":
				in["statement"] = "Likely the partner's sync; its requests carry " + tc.secret + " " + strings.Repeat("and more of the same ", 27)
			case "unknown":
				in["authorization"] = tc.secret
			}
			why := refused(t, cs, in)
			if !strings.Contains(why, "credential") || strings.Contains(why, tc.secret) {
				t.Fatalf("refusal %q", why)
			}
			// The run's record keeps the call, with its arguments redacted.
			var events, args string
			if err := h.db.QueryRow(t.Context(), `SELECT string_agg(payload::text, ' '), (array_agg(payload->>'arguments' ORDER BY seq DESC))[1]
				FROM autopilot_run_events WHERE run_id = $1 AND source = 'admin'`, c.RunID).Scan(&events, &args); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(events, tc.secret) || args != `{"redacted": "credential"}` {
				t.Fatalf("recorded arguments %s; the secret is in the record: %v", args, strings.Contains(events, tc.secret))
			}
		})
	}
	t.Run("none of them is stored and each is counted", func(t *testing.T) {
		if n := h.noteCount(); n != 0 {
			t.Fatalf("%d notes stored", n)
		}
		h.wantMetrics(fmt.Sprintf(`admin_autopilot_note_refusals_total{reason="credential"} %d`, len(cases)))
	})
	t.Run("a statement about token buckets is not a credential", func(t *testing.T) {
		mustCall(t, cs, "record_learning", hedged("Likely a client whose token bucket refills every second"))
	})
	t.Run("a statement ending in Bearer tokens is not a credential", func(t *testing.T) {
		mustCall(t, cs, "record_learning", hedged("Likely a client replaying expired Bearer tokens"))
	})
}

// A record_learning call refused before the gate runs is still recorded
// without the secret it carries.
func TestNoteCredentialRefusedInFlightIsRedacted(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c, cs := agentCase(t, h, pub, agent)
	// Holding the anomalies table keeps four list_anomalies calls waiting.
	tx, err := h.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), "LOCK TABLE anomalies IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { _, _ = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_anomalies"}) })
	}
	waitFor(t, func() bool {
		var waiting int
		_ = h.owner.QueryRow(t.Context(), "SELECT count(*) FROM pg_locks WHERE NOT granted").Scan(&waiting)
		return waiting == 4
	})
	secret := "Bearer abcdefgh12345678"
	_, why := callTool(t, cs, "record_learning", hedged("Likely the partner's sync; its requests carry "+secret))
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if !strings.Contains(why, "4 calls") {
		t.Fatalf("refusal %q", why)
	}
	var args string
	if err := h.db.QueryRow(t.Context(), `SELECT payload->>'arguments' FROM autopilot_run_events
		WHERE run_id = $1 AND source = 'admin' AND payload->>'tool' = 'record_learning'`, c.RunID).Scan(&args); err != nil {
		t.Fatal(err)
	}
	if args != `{"redacted": "credential"}` {
		t.Fatalf("recorded arguments %s", args)
	}
}

// A claim names a scope admin has seen and a metric admin can recompute
// over a window it keeps, and its effect is one the kind allows.
func TestNoteClaimCatalog(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	route := h.observedRoute("api.example.com", "GET", "/api/v2/export")
	h.routeHour(route, lastHour(h, 0), 2000)
	h.loginStuffing()
	_, cs := agentCase(t, h, pub, agent)
	ev := evidence(t, cs, "get_stats", map[string]any{"minutes": 60})
	limited := func() map[string]any { return claim("rule_limited", ">=", 100, lastMinutes(60)) }
	withField := func(c map[string]any, k string, v any) map[string]any { c[k] = v; return c }
	withEffect := func(in map[string]any, effect any) map[string]any { in["effect"] = effect; return in }
	scopes := []struct {
		name  string
		scope map[string]any
	}{
		{"a route never observed", scopeRoute("api.example.com", "GET", "/never")},
		{"the host *", map[string]any{"kind": "host", "host": "*"}},
		{"a rule not in the live config", scopeRule("checkout")},
	}
	for _, tc := range scopes {
		t.Run(tc.name+" is refused as a scope", func(t *testing.T) {
			in := learning("attack_signature", tc.scope, claim("requests", ">=", 1, lastMinutes(60)))
			in["evidence"] = []int64{ev}
			if why := refused(t, cs, in); !strings.Contains(why, "scope") {
				t.Fatalf("refusal %q", why)
			}
		})
	}
	claims := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"a metric admin doesn't keep", learning("attack_signature", scopeGlobal(), claim("distinct_paths", ">=", 1, lastMinutes(60))), "metric"},
		{"a route metric on the fleet", learning("attack_signature", scopeGlobal(), claim("route_requests", ">=", 1, lastMinutes(60))), "metric"},
		{"a rule metric on a host", learning("attack_signature", map[string]any{"kind": "host", "host": "api.example.com"}, limited()), "metric"},
		{"two windows", learning("attack_signature", scopeGlobal(), claim("requests", ">=", 1, map[string]any{"last_minutes": 60, "daily_utc": []int{2, 3}})), "window"},
		{"no window", learning("attack_signature", scopeGlobal(), claim("requests", ">=", 1, map[string]any{})), "window"},
		{"a window over 360 minutes", learning("attack_signature", scopeGlobal(), claim("requests", ">=", 1, lastMinutes(361))), "window"},
		{"a top-subjects window over 60 minutes", learning("attack_signature", scopeRule("login"), claim("rule_subjects", ">=", 1, lastMinutes(61))), "window"},
		{"a route window of part of an hour", learning("attack_signature", scopeRoute("api.example.com", "GET", "/api/v2/export"), claim("route_requests", ">=", 1, lastMinutes(90))), "window"},
		{"a daily window ending where it starts", learning("attack_signature", scopeGlobal(), claim("requests", ">=", 1, map[string]any{"daily_utc": []int{3, 3}})), "window"},
		{"a daily window past midnight", learning("attack_signature", scopeGlobal(), claim("requests", ">=", 1, map[string]any{"daily_utc": []int{23, 25}})), "window"},
		{"a daily window of 7 hours", learning("attack_signature", scopeGlobal(), claim("requests", ">=", 1, map[string]any{"daily_utc": []int{0, 7}})), "window"},
		{"an expected pattern over the last minutes", learning("expected_pattern", scopeGlobal(), claim("requests", ">=", 1, lastMinutes(60))), "daily_utc"},
		{"a ceiling on a sampled metric", learning("attack_signature", scopeRule("login"), claim("rule_subjects", "<=", 100, lastMinutes(60))), "op"},
		{"an equality", learning("attack_signature", scopeGlobal(), claim("requests", "==", 1, lastMinutes(60))), "op"},
		{"a subject metric without a subject", learning("attack_signature", scopeRule("login"), claim("subject_limited", ">=", 1, lastMinutes(60))), "subject"},
		{"a subject that is not a CIDR", learning("attack_signature", scopeRule("login"), withField(claim("subject_limited", ">=", 1, lastMinutes(60)), "subject", "partner.example.com")), "subject"},
		{"a key preference without a key", learning("key_preference", scopeRule("login"), limited()), "effect"},
		{"a key preference without ip or a JWT claim", withEffect(learning("key_preference", scopeRule("login"), limited()), map[string]any{"key": []string{"header:x-api-key"}}), "effect"},
		{"a key preference with a header part", withEffect(learning("key_preference", scopeRule("login"), limited()), map[string]any{"key": []string{"ip", "header:x-api-key"}}), "effect"},
		{"a collateral risk with two effects", withEffect(learning("collateral_risk", scopeRule("login"), limited()), map[string]any{"max_block_share": 0.005, "require_jwt_claim": true}), "effect"},
		{"a collateral risk with no effect", withEffect(learning("collateral_risk", scopeRule("login"), limited()), map[string]any{}), "effect"},
		{"a block share not under max_block_share", withEffect(learning("collateral_risk", scopeRule("login"), limited()), map[string]any{"max_block_share": 0.02}), "effect"},
		{"a block share under 0.1%", withEffect(learning("collateral_risk", scopeRule("login"), limited()), map[string]any{"max_block_share": 0.0005}), "effect"},
		{"an expected pattern with an effect", withEffect(learning("expected_pattern", scopeGlobal(), claim("requests", ">=", 1, lastMinutes(60))), map[string]any{"max_block_share": 0.005}), "effect"},
	}
	for _, tc := range claims {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			tc.in["evidence"] = []int64{ev}
			if why := refused(t, cs, tc.in); !strings.Contains(why, tc.want) {
				t.Fatalf("refusal %q, want %q", why, tc.want)
			}
		})
	}
	t.Run("none is stored and each is counted by its reason", func(t *testing.T) {
		if n := h.noteCount(); n != 0 {
			t.Fatalf("%d notes stored", n)
		}
		h.wantMetrics(fmt.Sprintf(`admin_autopilot_note_refusals_total{reason="scope"} %d`, len(scopes)),
			fmt.Sprintf(`admin_autopilot_note_refusals_total{reason="claim"} %d`, len(claims)))
	})
}

// At most 3 notes a run, 20 a day, 5 active in a scope and 200 in all.
func TestNoteLimits(t *testing.T) {
	fleet := func(threshold float64) map[string]any {
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", threshold, lastMinutes(60)))
		in["statement"] = fmt.Sprintf("Fleet requests stay over %v an hour while the stuffing runs", threshold)
		return in
	}
	// setup returns an earlier case, whose run the seeded notes belong to,
	// and the session of the run now writing.
	setup := func(t *testing.T) (*harness, claimed, *mcp.ClientSession, int64) {
		t.Helper()
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		old, _ := agentCase(t, h, pub, agent)
		status(t, agent.result(old.CaseID, resultBody(old.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
		_, cs := agentCase(t, h, pub, agent)
		return h, old, cs, evidence(t, cs, "get_stats", map[string]any{"minutes": 60})
	}
	seedRoutes := func(h *harness, c claimed, n int, trust func(i int) string, at time.Time) {
		for i := range n {
			tmpl := fmt.Sprintf("/api/v2/items/%d", i)
			h.observedRoute("api.example.com", "GET", tmpl)
			h.seedNote(c, trust(i), at, scopeRoute("api.example.com", "GET", tmpl), "route:api.example.com GET "+tmpl)
		}
	}
	unconfirmed := func(int) string { return "unconfirmed" }
	t.Run("a fourth note in one run is refused", func(t *testing.T) {
		h, _, cs, ev := setup(t)
		for _, v := range []float64{1000, 2000, 3000} {
			in := fleet(v)
			in["evidence"] = []int64{ev}
			mustCall(t, cs, "record_learning", in)
		}
		in := fleet(4000)
		in["evidence"] = []int64{ev}
		if why := refused(t, cs, in); !strings.Contains(why, "3") {
			t.Fatalf("refusal %q", why)
		}
		if n := h.noteCount(); n != 3 {
			t.Fatalf("%d notes", n)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="run_limit"} 1`)
	})
	t.Run("two notes at once with room for one store one", func(t *testing.T) {
		h, _, cs, ev := setup(t)
		for _, v := range []float64{1000, 2000} {
			in := fleet(v)
			in["evidence"] = []int64{ev}
			mustCall(t, cs, "record_learning", in)
		}
		ins := []map[string]any{fleet(3000), fleet(4000)}
		accepted := make([]bool, 2)
		var wg sync.WaitGroup
		for i := range 2 {
			ins[i]["evidence"] = []int64{ev}
			wg.Go(func() {
				res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "record_learning", Arguments: ins[i]})
				accepted[i] = err == nil && !res.IsError
			})
		}
		wg.Wait()
		if n := h.noteCount(); n != 3 || accepted[0] == accepted[1] {
			t.Fatalf("%d notes, accepted %v", n, accepted)
		}
	})
	t.Run("a note past 20 in a day is refused", func(t *testing.T) {
		h, c, cs, ev := setup(t)
		seedRoutes(h, c, 20, unconfirmed, h.now().Add(-time.Hour))
		in := fleet(1000)
		in["evidence"] = []int64{ev}
		if why := refused(t, cs, in); !strings.Contains(why, "20") {
			t.Fatalf("refusal %q", why)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="day_limit"} 1`)
	})
	t.Run("a note written over a day ago leaves room in the day", func(t *testing.T) {
		h, c, cs, ev := setup(t)
		seedRoutes(h, c, 19, unconfirmed, h.now().Add(-time.Hour))
		h.observedRoute("api.example.com", "GET", "/api/v2/old")
		h.seedNote(c, "unconfirmed", h.now().Add(-25*time.Hour), scopeRoute("api.example.com", "GET", "/api/v2/old"), "route:api.example.com GET /api/v2/old")
		in := fleet(1000)
		in["evidence"] = []int64{ev}
		mustCall(t, cs, "record_learning", in)
	})
	t.Run("a sixth active note in a scope is refused", func(t *testing.T) {
		h, c, cs, ev := setup(t)
		for range 5 {
			h.seedNote(c, "unconfirmed", h.now().Add(-48*time.Hour), scopeGlobal(), "global")
		}
		in := fleet(1000)
		in["evidence"] = []int64{ev}
		if why := refused(t, cs, in); !strings.Contains(why, "5") {
			t.Fatalf("refusal %q", why)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="scope_limit"} 1`)
	})
	t.Run("a retired note leaves room in its scope", func(t *testing.T) {
		h, c, cs, ev := setup(t)
		for range 4 {
			h.seedNote(c, "unconfirmed", h.now().Add(-48*time.Hour), scopeGlobal(), "global")
		}
		h.seedNote(c, "retired", h.now().Add(-48*time.Hour), scopeGlobal(), "global")
		in := fleet(1000)
		in["evidence"] = []int64{ev}
		mustCall(t, cs, "record_learning", in)
	})
	t.Run("a note past 200 kept is refused", func(t *testing.T) {
		h, c, cs, ev := setup(t)
		seedRoutes(h, c, 200, unconfirmed, h.now().Add(-48*time.Hour))
		in := fleet(1000)
		in["evidence"] = []int64{ev}
		if why := refused(t, cs, in); !strings.Contains(why, "200") {
			t.Fatalf("refusal %q", why)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="total_limit"} 1`)
	})
	t.Run("retracted and retired notes leave room in all", func(t *testing.T) {
		h, c, cs, ev := setup(t)
		seedRoutes(h, c, 200, func(i int) string {
			switch i {
			case 0:
				return "retracted"
			case 1:
				return "retired"
			}
			return "unconfirmed"
		}, h.now().Add(-48*time.Hour))
		in := fleet(1000)
		in["evidence"] = []int64{ev}
		mustCall(t, cs, "record_learning", in)
	})
}

func round3(v any) float64 { f, _ := v.(float64); return math.Round(f*1000) / 1000 }

// Admin attaches the claim's value and its baseline over the 14 days
// before: median, p95, MAD, the ratio to the median and the robust z.
func TestNoteStatistics(t *testing.T) {
	fourteen := func(v int64) []int64 {
		days := make([]int64, 14)
		for i := range days {
			days[i] = v
		}
		return days
	}
	for _, tc := range []struct {
		name                    string
		days                    []int64 // 1 to 14 days back
		value                   int64
		median, p95, mad, ratio float64
		z                       *float64
		held                    float64
	}{
		// sorted 9 10 10 10 11 11 11 12 12 12 12 13 13 50: median 11.5, p95 the 14th; |x - 11.5| has median 1;
		// z = 28.5 / 1.4826; ratio = 40 / 11.5.
		{"the hand-computed fixture", []int64{10, 12, 11, 13, 9, 50, 12, 11, 10, 12, 11, 13, 12, 10}, 40, 11.5, 50, 1, 3.478, new(19.223), 1},
		// MAD 0, mean absolute deviation 14 / 14 = 1: z = 30 / 1.2533.
		{"a MAD of 0 scores by the mean absolute deviation", append(fourteen(10)[:13], 24), 40, 10, 24, 0, 4, new(23.937), 0},
		{"every day the same and the value at the median scores 0", fourteen(100), 100, 100, 100, 0, 1, new(0.0), 14},
		{"every day the same and the value above has no z", fourteen(100), 150, 100, 100, 0, 1.5, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			for k, v := range tc.days {
				h.statsAt(dailyAt(h, k+1), v, "[]", "[]")
			}
			h.statsAt(dailyAt(h, 0), tc.value, "[]", "[]")
			_, cs := agentCase(t, h, pub, agent)
			in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", float64(tc.value), lastMinutes(60)))
			in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
			out := mustCall(t, cs, "record_learning", in)
			stats, _ := out["stats"].(map[string]any)
			b, _ := stats["baseline"].(map[string]any)
			if stats["metric"] != "requests" || stats["precision"] != "exact" || stats["value"] != float64(tc.value) || stats["holds"] != true {
				t.Fatalf("stats %v", stats)
			}
			if b["days"] != float64(14) || b["present"] != float64(14) || b["median"] != tc.median || b["p95"] != tc.p95 || b["mad"] != tc.mad ||
				round3(b["ratio"]) != tc.ratio || b["held_days"] != tc.held {
				t.Fatalf("baseline %v", b)
			}
			if tc.z == nil && b["z"] != nil || tc.z != nil && (b["z"] == nil || round3(b["z"]) != *tc.z) {
				t.Fatalf("z %v, want %v", b["z"], tc.z)
			}
			var stored map[string]any
			if err := h.db.QueryRow(t.Context(), "SELECT stats FROM autopilot_notes WHERE id = $1", noteID(t, out)).Scan(&stored); err != nil || !reflect.DeepEqual(stored, stats) {
				t.Fatalf("stored stats %v, answered %v, err %v", stored, stats, err)
			}
		})
	}
	t.Run("no day of history leaves the baseline empty", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.statsAt(dailyAt(h, 0), 40, "[]", "[]")
		_, cs := agentCase(t, h, pub, agent)
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 40, lastMinutes(60)))
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		stats, _ := mustCall(t, cs, "record_learning", in)["stats"].(map[string]any)
		if b, ok := stats["baseline"]; !ok || b != nil {
			t.Fatalf("baseline %v, want null", stats["baseline"])
		}
	})
	t.Run("days without data are left out of the baseline", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		for k := 1; k <= 10; k++ {
			h.statsAt(dailyAt(h, k), 100, "[]", "[]")
		}
		h.statsAt(dailyAt(h, 0), 100, "[]", "[]")
		_, cs := agentCase(t, h, pub, agent)
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 100, lastMinutes(60)))
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		stats, _ := mustCall(t, cs, "record_learning", in)["stats"].(map[string]any)
		if b, _ := stats["baseline"].(map[string]any); b["days"] != float64(14) || b["present"] != float64(10) || b["median"] != float64(100) || b["held_days"] != float64(10) {
			t.Fatalf("baseline %v", b)
		}
	})
	t.Run("a sampled metric is an estimate", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.statsAt(dailyAt(h, 0), 10_000, `[{"id":"login","evaluated":2000,"limited":40,"would_limit":0}]`,
			`[{"rule":"login","key":"k1","display":"198.51.100.1","limited":20},{"rule":"login","key":"k2","display":"198.51.100.2","limited":20}]`)
		_, cs := agentCase(t, h, pub, agent)
		in := learning("attack_signature", scopeRule("login"), claim("rule_subjects", ">=", 2, lastMinutes(60)))
		in["evidence"] = []int64{evidence(t, cs, "get_rule_stats", map[string]any{"rule": "login", "minutes": 60})}
		stats, _ := mustCall(t, cs, "record_learning", in)["stats"].(map[string]any)
		sample, _ := stats["sample"].(map[string]any)
		if stats["precision"] != "estimate" || stats["value"] != float64(2) || sample["subjects"] != float64(2) || sample["requests"] != float64(2000) {
			t.Fatalf("stats %v", stats)
		}
	})
}

// A day before is 24 hours before, whatever time zone the database session
// runs in: across a daylight saving change, Postgres's '1 day' is 23 or 25
// hours there, and the baseline would read the wrong hour on every day
// before the change.
func TestNoteBaselineDaysAre24Hours(t *testing.T) {
	h, _, agent := autopilotHarness(t)
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	// 3.5 days past the zone's next change: 3 days after it, 11 before.
	change := h.now().Truncate(time.Hour)
	_, offset := change.In(loc).Zone()
	for _, o := change.In(loc).Zone(); o == offset; _, o = change.In(loc).Zone() {
		change = change.Add(time.Hour)
	}
	h.advance(change.Sub(h.now()) + 84*time.Hour)
	pub := h.signedIn("pub") // past the first session's lifetime
	if _, err := h.owner.Exec(t.Context(), "DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET timezone = %L', current_database(), 'America/New_York'); END $$"); err != nil {
		t.Fatal(err)
	}
	h.db.Reset()
	for k := 1; k <= 14; k++ {
		h.statsAt(dailyAt(h, k), 100, "[]", "[]")
	}
	h.statsAt(dailyAt(h, 0), 100, "[]", "[]")
	_, cs := agentCase(t, h, pub, agent)
	in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 100, lastMinutes(60)))
	in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
	stats, _ := mustCall(t, cs, "record_learning", in)["stats"].(map[string]any)
	if b, _ := stats["baseline"].(map[string]any); b["present"] != float64(14) {
		t.Fatalf("baseline %v, want all 14 days present", b)
	}
}

// Policy ignores the effect of a note that is not confirmed.
func TestNoteUnconfirmedEffectIgnored(t *testing.T) {
	t.Run("an unconfirmed key preference does not narrow the key", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, keyNote(), "attack")
		_, cs := agentCase(t, h, pub, agent)
		if ids := served(t, cs, scopeRule("login")); !slices.Contains(ids, n) {
			t.Fatalf("served %v", ids)
		}
		p := proposal("enforce", "login-stuffing", loginRule())
		p["notes"] = []int64{n}
		if got := propose(t, cs, p); !got.Accepted || slices.Contains(got.Reasons, "note_key") {
			t.Fatalf("proposal %+v", got)
		}
	})
	t.Run("an unconfirmed attack signature does not shorten observe_for", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, stuffingNote(), "attack")
		id := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "observing" {
			t.Fatalf("rule %s after 3 of 5 minutes", st)
		}
	})
}

// enforcedNote has a new case record in, citing a get_rule_stats read of
// login, propose p and close as an attack. An enforce rule then observes
// for 6 minutes and enforces. It returns the note and the rule.
func enforcedNote(t *testing.T, h *harness, pub, agent *client, in, p map[string]any) (int64, string) {
	t.Helper()
	c, cs := agentCase(t, h, pub, agent)
	in["evidence"] = []int64{evidence(t, cs, "get_rule_stats", map[string]any{"rule": "login", "minutes": 60})}
	note := noteID(t, mustCall(t, cs, "record_learning", in))
	got := propose(t, cs, p)
	if !got.Accepted {
		t.Fatalf("proposal %+v", got)
	}
	status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
	h.tick()
	if p["action"] == "enforce" {
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, got.RuleID, "[]")
		h.tick()
		if st := ruleState(t, h, got.RuleID); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
	}
	return note, got.RuleID
}

// signatureCase seeds 14 days of 10 limited logins a day and now limited of
// evaluated, and has enforcedNote record an attack_signature on it and
// propose p.
func signatureCase(t *testing.T, h *harness, pub, agent *client, evaluated, limited int64, p map[string]any) (int64, string) {
	t.Helper()
	for k := 1; k <= 14; k++ {
		h.statsAt(dailyAt(h, k), 10_000, `[{"id":"login","evaluated":1000,"limited":10,"would_limit":0}]`, "[]")
	}
	h.statsAt(dailyAt(h, 0), 10_000, fmt.Sprintf(`[{"id":"login","evaluated":%d,"limited":%d,"would_limit":0}]`, evaluated, limited), "[]")
	in := learning("attack_signature", scopeRule("login"), claim("rule_limited", ">=", float64(limited), lastMinutes(60)))
	in["statement"] = "Credential stuffing on login: limited logins far above their daily level, from rotating addresses"
	return enforcedNote(t, h, pub, agent, in, p)
}

// One case confirms an attack signature: a strong deviation on enough
// requests, and the enforce rule it led to passed the guard window.
func TestNoteOneCaseConfirms(t *testing.T) {
	t.Run("before the rule passes the guard window the note stays unconfirmed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		note, _ := signatureCase(t, h, pub, agent, 2000, 400, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(5 * time.Minute)
		h.tick()
		if tr := h.noteTrust(note); tr != "unconfirmed" {
			t.Fatalf("note %s", tr)
		}
	})
	t.Run("a strong deviation on 2,000 requests whose rule held confirms", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		note, _ := signatureCase(t, h, pub, agent, 2000, 400, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(11 * time.Minute)
		h.tick()
		if tr := h.noteTrust(note); tr != "confirmed" {
			t.Fatalf("note %s", tr)
		}
		if got := h.noteChanges(note); !slices.Equal(got, []string{"written unconfirmed", "confirmed confirmed"}) {
			t.Fatalf("revisions %v", got)
		}
		if got := h.actions(); !subsequence(got, []string{fmt.Sprintf("autopilot.note_write note %d", note), fmt.Sprintf("autopilot.note_trust note %d", note)}) {
			t.Fatalf("audit %v", got)
		}
		h.wantMetrics(`admin_autopilot_note_transitions_total{to="confirmed"} 1`)
	})
	t.Run("a false positive mark committed while the job decides leaves the note unconfirmed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		note, id := signatureCase(t, h, pub, agent, 2000, 400, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(11 * time.Minute)
		// Holding the audit lock queues the mark, then the job, which has read
		// the rule as clean by the time it waits.
		tx, err := h.db.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := admindb.LockAudit(t.Context(), tx); err != nil {
			t.Fatal(err)
		}
		marked := make(chan int, 1)
		go func() {
			resp := pub.do("POST", "/api/autopilot/rules/"+id+"/retire", map[string]any{"reason": "It blocked our partner's logins", "false_positive": true})
			_ = resp.Body.Close()
			marked <- resp.StatusCode
		}()
		waitingOnLocks(t, h, 1)
		job := make(chan error, 1)
		go func() { job <- h.s.noteJobs(t.Context()) }()
		waitingOnLocks(t, h, 2)
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if code, err := <-marked, <-job; code != 204 || err != nil {
			t.Fatalf("retire %d, noteJobs %v", code, err)
		}
		if tr := h.noteTrust(note); tr != "unconfirmed" {
			t.Fatalf("note %s", tr)
		}
	})
	for _, tc := range []struct {
		name               string
		evaluated, limited int64
		action             string
		rollBack           bool
	}{
		{"a sample under 1,000 requests", 500, 400, "enforce", false},
		{"a deviation under 3x with no z of 4", 2000, 15, "enforce", false},
		{"a case that only added a sensor", 2000, 400, "add_sensor", false},
		{"a rule the guard rolled back", 2000, 400, "enforce", true},
	} {
		t.Run(tc.name+" leaves the note unconfirmed", func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			note, id := signatureCase(t, h, pub, agent, tc.evaluated, tc.limited, proposal(tc.action, "login-stuffing", loginRule()))
			if tc.rollBack {
				h.advance(3 * time.Minute)
				ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
				h.tick()
				if st := ruleState(t, h, id); st != "rolled_back" {
					t.Fatalf("rule %s", st)
				}
			}
			h.advance(11 * time.Minute)
			h.tick()
			if tr := h.noteTrust(note); tr != "unconfirmed" {
				t.Fatalf("note %s", tr)
			}
		})
	}
	// The guard judges a rule only over its window, so a rule that ended
	// earlier or that no guard watched shows nothing.
	t.Run("a rule that expired a minute after it began enforcing leaves the note unconfirmed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		// Its ttl counts from when it began enforcing, so max_lifetime, from
		// when it went live, is what ends it a minute in.
		pub.setAutopilot(map[string]any{"max_ttl": "7m", "default_ttl": "7m", "max_lifetime": "7m"})
		p := proposal("enforce", "login-stuffing", loginRule())
		p["ttl"] = "7m"
		note, id := signatureCase(t, h, pub, agent, 2000, 400, p)
		h.advance(time.Minute)
		h.tick()
		if st := ruleState(t, h, id); st != "expired" {
			t.Fatalf("rule %s", st)
		}
		h.advance(10 * time.Minute)
		h.tick()
		if tr := h.noteTrust(note); tr != "unconfirmed" {
			t.Fatalf("note %s", tr)
		}
	})
	for _, tc := range []struct {
		name string
		off  func(g *GuardSettings)
	}{
		{"with the guard disabled", func(g *GuardSettings) { g.Enabled = false }},
		{"with the guard's changed rule signal off", func(g *GuardSettings) { g.Signals["changed_rule_limited_ratio"] = Signal{Mode: "off"} }},
	} {
		t.Run(tc.name+" a rule past the window leaves the note unconfirmed", func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			g := decode[GuardSettings](t, pub.do("GET", "/api/settings/guard", nil))
			tc.off(&g)
			status(t, pub.do("PUT", "/api/settings/guard", g), 204)
			note, _ := signatureCase(t, h, pub, agent, 2000, 400, proposal("enforce", "login-stuffing", loginRule()))
			h.advance(11 * time.Minute)
			h.tick()
			if tr := h.noteTrust(note); tr != "unconfirmed" {
				t.Fatalf("note %s", tr)
			}
		})
	}
	// upToGuard has the note's rule pass the guard window, then ticks.
	upToGuard := func(h *harness) { h.advance(11 * time.Minute); h.tick() }
	t.Run("a key preference whose rule held confirms", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		note, _ := enforcedNote(t, h, pub, agent, keyNote(), proposal("enforce", "login-stuffing", loginRule()))
		upToGuard(h)
		if tr := h.noteTrust(note); tr != "confirmed" {
			t.Fatalf("note %s", tr)
		}
	})
	t.Run("an attack signature on 30 subjects of 500 requests whose rule held confirms", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		top := func(n int) string {
			var parts []string
			for i := range n {
				parts = append(parts, fmt.Sprintf(`{"rule":"login","key":"k%d","display":"198.51.100.%d","limited":10}`, i, i+1))
			}
			return "[" + strings.Join(parts, ",") + "]"
		}
		for k := 1; k <= 14; k++ {
			h.statsAt(dailyAt(h, k), 10_000, `[{"id":"login","evaluated":500,"limited":20,"would_limit":0}]`, top(2))
		}
		h.statsAt(dailyAt(h, 0), 10_000, `[{"id":"login","evaluated":500,"limited":300,"would_limit":0}]`, top(30))
		in := learning("attack_signature", scopeRule("login"), claim("rule_subjects", ">=", 30, lastMinutes(60)))
		in["statement"] = "Stuffing on login comes from 30 addresses at once, where 2 are limited on a usual day"
		note, _ := enforcedNote(t, h, pub, agent, in, proposal("enforce", "login-stuffing", loginRule()))
		upToGuard(h)
		if tr := h.noteTrust(note); tr != "confirmed" {
			t.Fatalf("note %s", tr)
		}
	})
	// Days of 98 to 102 limited, a MAD of 1: 150 is a z of 33 at 1.5 times the median.
	t.Run("an attack signature with a z of 4 under 3 times its median confirms", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		for k, v := range []int{100, 101, 99, 100, 102, 98, 100, 101, 99, 100, 100, 101, 99, 100} {
			h.statsAt(dailyAt(h, k+1), 10_000, fmt.Sprintf(`[{"id":"login","evaluated":2000,"limited":%d,"would_limit":0}]`, v), "[]")
		}
		h.statsAt(dailyAt(h, 0), 10_000, `[{"id":"login","evaluated":2000,"limited":150,"would_limit":0}]`, "[]")
		in := learning("attack_signature", scopeRule("login"), claim("rule_limited", ">=", 150, lastMinutes(60)))
		in["statement"] = "Stuffing on login: limited logins well over their steady daily level"
		note, _ := enforcedNote(t, h, pub, agent, in, proposal("enforce", "login-stuffing", loginRule()))
		upToGuard(h)
		if tr := h.noteTrust(note); tr != "confirmed" {
			t.Fatalf("note %s", tr)
		}
		h.s.met.leader.Store(true)
		if err := h.s.refreshLeaderGauges(t.Context()); err != nil {
			t.Fatal(err)
		}
		h.wantMetrics(`admin_autopilot_notes{trust="confirmed"} 1`)
	})
}

// A note that makes the autopilot less likely to act confirms when its
// anchor holds and its case finished, within 30 days of being written.
func TestNoteAnchoredNoteConfirms(t *testing.T) {
	const export = "/api/v2/export"
	// exportDays has export take 2,000 requests in the hour that just ended
	// and on the first held of the 14 days before, and 10 on the others.
	exportDays := func(h *harness, held int) {
		route := h.observedRoute("api.example.com", "GET", export)
		for k := 1; k <= 14; k++ {
			v := int64(10)
			if k <= held {
				v = 2000
			}
			h.routeHour(route, lastHour(h, k), v)
		}
		h.routeHour(route, lastHour(h, 0), 2000)
	}
	exportNote := func(h *harness, kind string) map[string]any {
		in := learning(kind, scopeRoute("api.example.com", "GET", export), claim("route_requests", ">=", 1000, thatHourDaily(h)))
		in["statement"] = "Export takes about 2,000 requests in this hour each day from the partner's catalog sync"
		return in
	}
	for _, tc := range []struct {
		name  string
		kind  string
		held  int
		trust string
	}{
		{"an expected pattern anchored by its history confirms once its case finished", "expected_pattern", 7, "confirmed"},
		{"a context note anchored by its history confirms once its case finished", "context", 7, "confirmed"},
		{"a context note with no anchor stays unconfirmed", "context", 6, "unconfirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			exportDays(h, tc.held)
			n := writeNote(t, h, pub, agent, exportNote(h, tc.kind), "benign")
			h.tick()
			if tr := h.noteTrust(n); tr != tc.trust {
				t.Fatalf("note %s, want %s", tr, tc.trust)
			}
		})
	}
	t.Run("a collateral risk anchored by a protected subject confirms once its case finished", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
		h.partnerLimited()
		in := partnerNote(map[string]any{"max_block_share": 0.005})
		c, cs := agentCase(t, h, pub, agent)
		in["evidence"] = []int64{evidence(t, cs, "get_rule_stats", map[string]any{"rule": "login", "minutes": 60})}
		n := noteID(t, mustCall(t, cs, "record_learning", in))
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 10}, nil, 0)), 204)
		h.tick()
		if tr := h.noteTrust(n); tr != "confirmed" {
			t.Fatalf("note %s", tr)
		}
	})
	t.Run("an anchored note whose case is still running stays unconfirmed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exportDays(h, 7)
		_, cs := agentCase(t, h, pub, agent)
		in := exportNote(h, "expected_pattern")
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		n := noteID(t, mustCall(t, cs, "record_learning", in))
		h.tick()
		if tr := h.noteTrust(n); tr != "unconfirmed" {
			t.Fatalf("note %s", tr)
		}
	})
	// As when the autopilot was off for a month: the leader ran no note jobs.
	t.Run("an anchored note written 31 days ago is never confirmed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		exportDays(h, 7)
		n := writeNote(t, h, pub, agent, exportNote(h, "expected_pattern"), "benign")
		h.advance(31 * 24 * time.Hour)
		h.tick()
		if got := h.noteChanges(n); slices.Contains(got, "confirmed confirmed") {
			t.Fatalf("revisions %v", got)
		}
	})
}

// A confirmed note's effect is bounded and acts only on proposals that
// cite it after search_notes served it to the run.
func TestNoteBoundedEffects(t *testing.T) {
	t.Run("a note not served to the run can't be cited", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, keyNote(), "attack")
		h.confirmNote(n)
		_, cs := agentCase(t, h, pub, agent)
		p := proposal("enforce", "login-stuffing", loginRule())
		p["notes"] = []int64{n}
		if _, why := callTool(t, cs, "propose", p); !strings.Contains(why, fmt.Sprintf("note %d was not served to this run by search_notes", n)) {
			t.Fatalf("refusal %q", why)
		}
	})
	for _, tc := range []struct {
		name   string
		note   func(h *harness, pub *client) map[string]any
		key    []string
		reason string // "" means accepted
	}{
		{"a key preference refuses a key without its parts", func(h *harness, _ *client) map[string]any { h.loginStuffing(); return keyNote() },
			[]string{"ip"}, "note_key"},
		{"a key preference accepts a key with its parts", func(h *harness, _ *client) map[string]any { h.loginStuffing(); return keyNote() },
			[]string{"ip", "jwt_claim:sub"}, ""},
		{"a collateral risk requiring a JWT claim refuses an address key", func(h *harness, pub *client) map[string]any {
			pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
			h.partnerLimited()
			return partnerNote(map[string]any{"require_jwt_claim": true})
		}, []string{"ip"}, "note_jwt_key"},
	} {
		t.Run("confirmed, "+tc.name, func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			n := writeNote(t, h, pub, agent, tc.note(h, pub), "attack")
			h.confirmNote(n)
			_, cs := agentCase(t, h, pub, agent)
			if ids := served(t, cs, scopeRule("login")); !slices.Contains(ids, n) {
				t.Fatalf("served %v", ids)
			}
			p := proposal("enforce", "login-stuffing", agentRule(`http.request.uri.path eq "/login" and http.request.method eq "POST"`, tc.key...))
			p["notes"] = []int64{n}
			got := propose(t, cs, p)
			if tc.reason == "" && !got.Accepted || tc.reason != "" && (got.Accepted || !slices.Contains(got.Reasons, tc.reason)) {
				t.Fatalf("proposal %+v, want refused for %q", got, tc.reason)
			}
			if tc.reason != "" {
				h.wantMetrics(fmt.Sprintf(`admin_autopilot_policy_rejections_total{reason=%q} 1`, tc.reason))
			}
		})
	}
	// 100 of 10,000 fleet requests a minute is 1%: under the 2% setting, over the note's 0.5%.
	t.Run("a confirmed collateral risk lowers the share an enforce rule may block", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
		h.partnerLimited()
		n := writeNote(t, h, pub, agent, partnerNote(map[string]any{"max_block_share": 0.005}), "attack")
		h.confirmNote(n)
		id := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != "block_share" {
			t.Fatalf("rule %s", st)
		}
	})
	// 80 of 10,000 is 0.8%: within 3x its 3% shadow, over the note's 0.5%.
	t.Run("a confirmed collateral risk lowers the share the guard allows", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
		h.partnerLimited()
		n := writeNote(t, h, pub, agent, partnerNote(map[string]any{"max_block_share": 0.005}), "attack")
		h.confirmNote(n)
		id := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 30, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 10_000, 1_000, 80, 0, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "rolled_back" {
			t.Fatalf("rule %s", st)
		}
	})
	// The rule observes from 12:30 and is judged at 12:36, 96 of the
	// window's 120 minutes: the bar is 2 x 600,000 x 96 / 120 = 960,000, and
	// the fleet took 600,000 at 11:10 and 60,000 since.
	for _, tc := range []struct {
		name    string
		observe time.Duration
		surge   int64
		state   string
	}{
		{"a confirmed expected pattern holds an enforce rule back under twice its median over the elapsed part of its window", 6 * time.Minute, 0, "rejected"},
		{"a confirmed expected pattern lets an enforce rule block over twice its median over the elapsed part of its window", 6 * time.Minute, 400_000, "enforcing"},
		{"a confirmed expected pattern lets an enforce rule block far over twice its median", 6 * time.Minute, 700_000, "enforcing"},
		{"a confirmed expected pattern does not hold an enforce rule back outside its window", 35 * time.Minute, 0, "enforcing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			n := batchNote(t, h, pub, agent)
			id := citedRule(t, h, pub, agent, scopeGlobal(), n, proposal("enforce", "login-stuffing", loginRule()))
			h.advance(tc.observe)
			ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, id, "[]")
			if tc.surge > 0 {
				h.statsAt(h.now().Add(-time.Minute), tc.surge, "[]", "[]")
			}
			h.tick()
			if st := ruleState(t, h, id); st != tc.state {
				t.Fatalf("rule %s, want %s", st, tc.state)
			}
			if tc.state == "rejected" && lastReason(t, h, id, "rejected") != "note_expected_pattern" {
				t.Fatalf("rejected for %s", lastReason(t, h, id, "rejected"))
			}
		})
	}
	// Route counts arrive by the hour, so the bar at 12:36 is over 11:00 to
	// 12:00, half the window: 2 x 2,000 x 60 / 120 = 2,000. The hour in
	// progress, 3,000 so far, is left out.
	t.Run("a route's hour in progress does not count against an expected pattern on it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.atUTC(12, 30)
		route := h.observedRoute("api.example.com", "GET", "/api/v2/export")
		today := h.now().Truncate(24 * time.Hour)
		for k := 1; k <= 15; k++ {
			day := today.Add(-time.Duration(k) * 24 * time.Hour)
			h.routeHour(route, day.Add(11*time.Hour), 1000)
			h.routeHour(route, day.Add(12*time.Hour), 1000)
		}
		h.routeHour(route, today.Add(11*time.Hour), 1500)
		h.routeHour(route, today.Add(12*time.Hour), 3000)
		in := learning("expected_pattern", scopeRoute("api.example.com", "GET", "/api/v2/export"), claim("route_requests", ">=", 1500, batchWindow()))
		in["statement"] = "Export takes about 2,000 requests from 11:00 to 13:00 UTC every day from the partner's catalog sync"
		n := writeNote(t, h, pub, agent, in, "benign")
		h.confirmNote(n)
		id := citedRule(t, h, pub, agent, scopeRoute("api.example.com", "GET", "/api/v2/export"), n, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "rejected" || lastReason(t, h, id, "rejected") != "note_expected_pattern" {
			t.Fatalf("rule %s", st)
		}
	})
	t.Run("a confirmed attack signature lets an enforce rule block after half of observe_for", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, stuffingNote(), "attack")
		h.confirmNote(n)
		id := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s after 3 of 5 minutes", st)
		}
	})
	t.Run("a person approves a rule citing a confirmed attack signature after half of observe_for", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"mode": "observe"})
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, stuffingNote(), "attack")
		h.confirmNote(n)
		id := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(3 * time.Minute)
		status(t, pub.do("POST", "/api/autopilot/rules/"+id+"/enforce", nil), 204)
	})
}

// A rule that cited a confirmed note going wrong retracts the note, and
// every other rule still enforcing because of it gets a new case, all in
// the same change.
func TestNoteContradictionRetracts(t *testing.T) {
	for _, tc := range []struct {
		name          string
		confirmed     bool
		falsePositive bool
	}{
		{"a guard rollback of a rule citing a confirmed note", true, false},
		{"a false positive mark on a rule citing a confirmed note", true, true},
		{"a guard rollback of a rule citing an unconfirmed note", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			h.loginStuffing()
			n := writeNote(t, h, pub, agent, stuffingNote(), "attack")
			if tc.confirmed {
				h.confirmNote(n)
			}
			first := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "login-stuffing", loginRule()))
			h.advance(time.Minute) // past min_publish_interval
			second := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "account-stuffing", agentRule(`http.request.uri.path eq "/account"`, "ip")))
			h.advance(6 * time.Minute)
			ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, first, "[]")
			ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, second, "[]")
			h.tick()
			if a, b := ruleState(t, h, first), ruleState(t, h, second); a != "enforcing" || b != "enforcing" {
				t.Fatalf("rules %s %s", a, b)
			}
			ending := "autopilot.rollback rule " + first
			reason := fmt.Sprintf("rule %s, which cited it, was rolled back by the guard", first)
			if tc.falsePositive {
				agent.seen() // a runner is connected, so cases can open
				status(t, pub.do("POST", "/api/autopilot/rules/"+first+"/retire", map[string]any{"reason": "It blocked our partner's logins", "false_positive": true}), 204)
				ending = "autopilot.retire rule " + first
				reason = fmt.Sprintf("rule %s, which cited it, was marked a false positive", first)
			} else {
				h.advance(3 * time.Minute)
				ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, first, "[]")
				agent.seen()
				h.tick()
				if st := ruleState(t, h, first); st != "rolled_back" {
					t.Fatalf("rule %s", st)
				}
			}
			var reopened int
			if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_cases WHERE kind = 'investigate' AND state = 'queued' AND dedupe_key = $1", "rule:"+second).Scan(&reopened); err != nil {
				t.Fatal(err)
			}
			if !tc.confirmed {
				if tr := h.noteTrust(n); tr != "unconfirmed" || reopened != 0 {
					t.Fatalf("note %s, %d cases on %s", tr, reopened, second)
				}
				return
			}
			if tr := h.noteTrust(n); tr != "retracted" || h.lastNoteReason(n) != reason {
				t.Fatalf("note %s for %q", tr, h.lastNoteReason(n))
			}
			if reopened != 1 {
				t.Fatalf("%d cases on %s, want 1", reopened, second)
			}
			if got := h.actions(); !subsequence(got, []string{ending, fmt.Sprintf("autopilot.note_retract note %d", n), "autopilot.case_open case"}) {
				t.Fatalf("audit %v", got)
			}
		})
	}
	// A rule that went wrong shows nothing against a note that held it back.
	t.Run("a collateral risk note cited by a rolled-back rule stays confirmed", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
		h.partnerLimited()
		n := writeNote(t, h, pub, agent, partnerNote(map[string]any{"max_block_share": 0.005}), "attack")
		h.confirmNote(n)
		id := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 30, id, "[]")
		h.tick()
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "rolled_back" {
			t.Fatalf("rule %s", st)
		}
		if tr := h.noteTrust(n); tr != "confirmed" || slices.Contains(h.actions(), fmt.Sprintf("autopilot.note_retract note %d", n)) {
			t.Fatalf("note %s, audit %v", tr, h.actions())
		}
	})
	t.Run("with no runner connected a contradiction retracts the note and opens no case", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, stuffingNote(), "attack")
		h.confirmNote(n)
		first := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(time.Minute)
		second := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "account-stuffing", agentRule(`http.request.uri.path eq "/account"`, "ip")))
		h.advance(6 * time.Minute) // the runner was last seen over 2 minutes ago
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, first, "[]")
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, second, "[]")
		h.tick()
		h.advance(3 * time.Minute)
		ruleMinutes(h, pub, 3, 1_000, 1_000, 400, 0, first, "[]")
		h.tick()
		if st, tr := ruleState(t, h, first), h.noteTrust(n); st != "rolled_back" || tr != "retracted" {
			t.Fatalf("rule %s, note %s", st, tr)
		}
		var cases int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_cases WHERE dedupe_key = $1", "rule:"+second).Scan(&cases); err != nil || cases != 0 {
			t.Fatalf("%d cases on %s, err %v", cases, second, err)
		}
	})
	t.Run("a false positive mark on the rule of the case that confirmed the note", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n, id := signatureCase(t, h, pub, agent, 2000, 400, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(11 * time.Minute)
		h.tick()
		if tr := h.noteTrust(n); tr != "confirmed" {
			t.Fatalf("note %s", tr)
		}
		status(t, pub.do("POST", "/api/autopilot/rules/"+id+"/retire", map[string]any{"reason": "It blocked our partner's logins", "false_positive": true}), 204)
		if reason := h.lastNoteReason(n); h.noteTrust(n) != "retracted" || !strings.Contains(reason, id) || !strings.Contains(reason, "false positive") {
			t.Fatalf("note %s for %q", h.noteTrust(n), reason)
		}
		if got := h.actions(); !subsequence(got, []string{"autopilot.retire rule " + id, fmt.Sprintf("autopilot.note_retract note %d", n)}) {
			t.Fatalf("audit %v", got)
		}
	})
}

// A search checks the 20 newest notes, so a new note is never crowded out
// by old ones.
func TestNoteSearchChecksThe20Newest(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	c, cs := agentCase(t, h, pub, agent)
	var seeded []int64
	for i := range 21 {
		tmpl := fmt.Sprintf("/api/v2/export%d", i)
		h.observedRoute("api.example.com", "GET", tmpl)
		seeded = append(seeded, h.seedNote(c, "unconfirmed", h.now().Add(time.Duration(i-30)*time.Minute), scopeRoute("api.example.com", "GET", tmpl), "route:api.example.com GET "+tmpl))
	}
	out := mustCall(t, cs, "search_notes", map[string]any{})
	notes, _ := out["notes"].([]any)
	got := []int64{}
	for _, n := range notes {
		m, _ := n.(map[string]any)
		id, _ := m["id"].(float64)
		got = append(got, int64(id))
	}
	want := slices.Clone(seeded[1:])
	slices.Reverse(want)
	if !slices.Equal(got, want) {
		t.Fatalf("served %v, want %v", got, want)
	}
	var uses int
	var oldest bool
	if err := h.db.QueryRow(t.Context(), "SELECT count(*), coalesce(bool_or(note_id = $2), false) FROM autopilot_note_uses WHERE run_id = $1", c.RunID, seeded[0]).
		Scan(&uses, &oldest); err != nil || uses != 20 || oldest {
		t.Fatalf("%d uses, the oldest among them %v, err %v", uses, oldest, err)
	}
}

// A search that commits as the call's deadline ends is recorded once, as
// the call that made it, like a proposal.
func TestNoteSearchCommittedAtTheDeadline(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	writeNote(t, h, pub, agent, hedged("Likely the partner's nightly sync"), "benign")
	c, cs := agentCase(t, h, pub, agent)
	proposeDone = func(err error) error {
		if err == nil {
			return context.DeadlineExceeded
		}
		return err
	}
	t.Cleanup(func() { proposeDone = func(err error) error { return err } })
	if _, why := callTool(t, cs, "search_notes", map[string]any{"scope": scopeGlobal()}); why == "" {
		t.Fatal("the call was answered as if it had finished in time")
	}
	var refusals, uses int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_run_events WHERE run_id = $1 AND source = 'admin' AND payload->>'allowed' = 'false'", c.RunID).
		Scan(&refusals); err != nil || refusals != 0 {
		t.Fatalf("%d refusal events, err %v", refusals, err)
	}
	if got := adminEvents(t, h, c.RunID); !slices.Equal(got, []string{"search_notes"}) {
		t.Fatalf("recorded %v", got)
	}
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_note_uses WHERE run_id = $1", c.RunID).Scan(&uses); err != nil || uses != 1 {
		t.Fatalf("%d uses, err %v", uses, err)
	}
}

// A note whose claim fails on 3 uses in a row is no longer served.
func TestNoteClaimStopsHoldingGoesDormant(t *testing.T) {
	// fleetNote holds while the fleet takes over 20,000 requests an hour.
	fleetNote := func(t *testing.T, h *harness, pub, agent *client) int64 {
		t.Helper()
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 20_000, lastMinutes(60)))
		in["statement"] = "During the stuffing the fleet takes over 20,000 requests an hour"
		return writeNote(t, h, pub, agent, in, "attack")
	}
	// searchCase is a case whose run searches the fleet's notes once.
	searchCase := func(t *testing.T, h *harness, pub, agent *client) []int64 {
		t.Helper()
		c, cs := agentCase(t, h, pub, agent)
		ids := served(t, cs, scopeGlobal())
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
		return ids
	}
	t.Run("three searches in a row where the claim fails make the note dormant", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := fleetNote(t, h, pub, agent)
		h.advance(2 * time.Hour) // the stuffing's traffic is out of the window
		for i := range 3 {
			if ids := searchCase(t, h, pub, agent); slices.Contains(ids, n) {
				t.Fatalf("search %d served the note while its claim fails", i+1)
			}
			if want := []string{"unconfirmed", "unconfirmed", "dormant"}[i]; h.noteTrust(n) != want {
				t.Fatalf("after %d failed uses the note is %s, want %s", i+1, h.noteTrust(n), want)
			}
		}
		if got := h.actions(); !slices.Contains(got, fmt.Sprintf("autopilot.note_dormant note %d", n)) {
			t.Fatalf("audit %v", got)
		}
		var uses int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_note_uses WHERE note_id = $1 AND source = 'search' AND NOT matched", n).Scan(&uses); err != nil || uses != 3 {
			t.Fatalf("%d unmatched search uses, err %v", uses, err)
		}
		h.wantMetrics(`admin_autopilot_note_transitions_total{to="dormant"} 1`)
	})
	t.Run("a search where the claim holds again resets the count", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := fleetNote(t, h, pub, agent)
		h.advance(2 * time.Hour)
		searchCase(t, h, pub, agent)
		searchCase(t, h, pub, agent)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]") // the stuffing is back
		if ids := searchCase(t, h, pub, agent); !slices.Contains(ids, n) {
			t.Fatalf("served %v while the claim holds", ids)
		}
		h.advance(2 * time.Hour)
		searchCase(t, h, pub, agent)
		searchCase(t, h, pub, agent)
		var streak int
		if err := h.db.QueryRow(t.Context(), "SELECT fail_streak FROM autopilot_notes WHERE id = $1", n).Scan(&streak); err != nil || h.noteTrust(n) != "unconfirmed" || streak != 2 {
			t.Fatalf("note %s with fail_streak %d, err %v", h.noteTrust(n), streak, err)
		}
	})
	t.Run("a person's search records no use", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := fleetNote(t, h, pub, agent)
		h.advance(2 * time.Hour)
		cs := h.mcpSession(pub.userToken("autopilot.read"), 0)
		for range 3 {
			out := mustCall(t, cs, "search_notes", map[string]any{"scope": scopeGlobal()})
			notes, _ := out["notes"].([]any)
			if len(notes) != 1 || notes[0].(map[string]any)["matches_now"] != false {
				t.Fatalf("search_notes %v", out)
			}
		}
		var uses int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_note_uses WHERE note_id = $1", n).Scan(&uses); err != nil || uses != 0 || h.noteTrust(n) != "unconfirmed" {
			t.Fatalf("%d uses, note %s, err %v", uses, h.noteTrust(n), err)
		}
	})
}

// When cases keep closing as benign with a note, or attack volume on its
// scope keeps rising, admin re-runs the latest case without it. Verdicts
// that differ make the note unconfirmed again.
func TestNoteAblationDemotesContested(t *testing.T) {
	// ablation has three cases close as benign with the note and the next
	// tick open the ablation case, which the runner claims.
	ablation := func(t *testing.T, h *harness, pub, agent *client) (int64, claimed, claimed) {
		t.Helper()
		n := batchNote(t, h, pub, agent)
		var last claimed
		for range 3 {
			last = benignWith(t, h, pub, agent, n, scopeGlobal())
		}
		h.tick()
		return n, last, claimKind(t, agent, "ablation")
	}
	t.Run("three benign cases with a confirmed note open one ablation case that withholds it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n, last, a := ablation(t, h, pub, agent)
		h.tick()
		var count int
		var rule *string
		var of *int64
		var withheld []int64
		if err := h.db.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM autopilot_cases WHERE kind = 'ablation'), rule, ablation_of, withheld_notes FROM autopilot_cases WHERE id = $1", a.CaseID).
			Scan(&count, &rule, &of, &withheld); err != nil {
			t.Fatal(err)
		}
		if count != 1 || rule != nil || of == nil || *of != last.CaseID || !slices.Equal(withheld, []int64{n}) {
			t.Fatalf("%d ablation cases; rule %v, ablation_of %v, withheld %v", count, rule, of, withheld)
		}
		if !strings.Contains(string(a.Brief), "Is someone guessing passwords?") || a.Model != "claude-opus-5-5" {
			t.Fatalf("ablation brief %s on %s", a.Brief, a.Model)
		}
		if ids := served(t, h.mcpSession(agentToken, a.RunID), scopeGlobal()); slices.Contains(ids, n) {
			t.Fatalf("the ablation run was served the withheld note: %v", ids)
		}
	})
	for _, tc := range []struct {
		verdict, trust string
	}{
		{"attack", "unconfirmed"},
		{"unsure", "unconfirmed"},
		{"benign", "confirmed"},
	} {
		t.Run(fmt.Sprintf("an ablation run answering %s leaves the note %s", tc.verdict, tc.trust), func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			n, _, a := ablation(t, h, pub, agent)
			status(t, agent.result(a.CaseID, resultBody(a.RunID, tc.verdict, usage{Input: 10}, nil, 0)), 204)
			if tr := h.noteTrust(n); tr != tc.trust {
				t.Fatalf("note %s", tr)
			}
			if tc.trust == "confirmed" {
				return
			}
			if got := h.noteChanges(n); got[len(got)-1] != "contested unconfirmed" {
				t.Fatalf("revisions %v", got)
			}
			h.wantMetrics(`admin_autopilot_note_transitions_total{to="unconfirmed"} 1`)
			// A contested note never confirms again, though its anchor holds
			// and its case finished.
			h.tick()
			if tr := h.noteTrust(n); tr != "unconfirmed" {
				t.Fatalf("note %s after a tick", tr)
			}
			if got := h.actions(); !slices.Contains(got, fmt.Sprintf("autopilot.case_close case %d", a.CaseID)) || !slices.Contains(got, fmt.Sprintf("autopilot.note_trust note %d", n)) {
				t.Fatalf("audit %v", got)
			}
		})
	}
	t.Run("a contested note notifies for an hour", func(t *testing.T) {
		h, pub, agent := notifyingAutopilot(t)
		n, _, a := ablation(t, h, pub, agent)
		status(t, agent.result(a.CaseID, resultBody(a.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
		h.check()
		if got := firing(h, pub, "autopilot_note_contested"); got == nil || got.State != "firing" || got.Rule != fmt.Sprintf("note %d", n) || got.Severity != "warning" {
			t.Fatalf("autopilot_note_contested %+v", got)
		}
		h.advance(61 * time.Minute)
		h.check()
		if got := firing(h, pub, "autopilot_note_contested"); got != nil {
			t.Fatalf("still %s after an hour", got.State)
		}
	})
	t.Run("attack volume rising over four hours opens an ablation case", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := batchNote(t, h, pub, agent)
		last := benignWith(t, h, pub, agent, n, scopeGlobal())
		hour := h.now().UTC().Truncate(time.Hour)
		for i, v := range []int64{1000, 2000, 3000, 4000} {
			h.statsAt(hour.Add(time.Duration(i-4)*time.Hour+10*time.Minute), v, "[]", "[]")
		}
		h.tick()
		var of int64
		var withheld []int64
		if err := h.db.QueryRow(t.Context(), "SELECT ablation_of, withheld_notes FROM autopilot_cases WHERE kind = 'ablation'").Scan(&of, &withheld); err != nil ||
			of != last.CaseID || !slices.Equal(withheld, []int64{n}) {
			t.Fatalf("ablation_of %d, withheld %v, err %v", of, withheld, err)
		}
	})
	// An ablation run re-answers its case without the note, and does
	// nothing else.
	t.Run("an ablation run can't propose", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, _, a := ablation(t, h, pub, agent)
		_, why := callTool(t, h.mcpSession(agentToken, a.RunID), "propose", proposal("enforce", "login-stuffing", loginRule()))
		if !strings.Contains(why, "ablation") {
			t.Fatalf("refusal %q", why)
		}
		var proposals int
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_proposals WHERE case_id = $1", a.CaseID).Scan(&proposals); err != nil || proposals != 0 {
			t.Fatalf("%d proposals, err %v", proposals, err)
		}
	})
	t.Run("an ablation run can't record a note", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, _, a := ablation(t, h, pub, agent)
		if why := refused(t, h.mcpSession(agentToken, a.RunID), hedged("Likely the partner's nightly sync")); !strings.Contains(why, "ablation") {
			t.Fatalf("refusal %q", why)
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="ablation"} 1`)
	})
	t.Run("an ablation run's case list hides the cases the note was served to and every ablation", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n, _, a := ablation(t, h, pub, agent)
		var writer int64
		if err := h.db.QueryRow(t.Context(), "SELECT case_id FROM autopilot_notes WHERE id = $1", n).Scan(&writer); err != nil {
			t.Fatal(err)
		}
		out := mustCall(t, h.mcpSession(agentToken, a.RunID), "list_cases", map[string]any{"limit": 50})
		var listed []int64
		for _, c := range out["cases"].([]any) {
			id, _ := c.(map[string]any)["id"].(float64)
			listed = append(listed, int64(id))
		}
		rows, _ := h.db.Query(t.Context(), "SELECT DISTINCT case_id FROM autopilot_note_uses WHERE note_id = $1 AND source = 'search' AND matched", n)
		hidden, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil || len(hidden) != 3 {
			t.Fatalf("served to %v, err %v", hidden, err)
		}
		if !slices.Contains(listed, writer) || slices.Contains(listed, a.CaseID) || slices.ContainsFunc(hidden, func(id int64) bool { return slices.Contains(listed, id) }) {
			t.Fatalf("listed %v; writer %d, ablation %d, served %v", listed, writer, a.CaseID, hidden)
		}
	})
	// reviewWith closes the daily review case as benign, its run served n.
	reviewWith := func(t *testing.T, h *harness, agent *client, n int64) claimed {
		t.Helper()
		agent.seen()
		h.tick()
		r := claimKind(t, agent, "review")
		if ids := served(t, h.mcpSession(agentToken, r.RunID), scopeGlobal()); !slices.Contains(ids, n) {
			t.Fatalf("served %v", ids)
		}
		status(t, agent.result(r.CaseID, resultBody(r.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
		return r
	}
	t.Run("only anomaly and investigate cases count toward three benign cases", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := batchNote(t, h, pub, agent)
		benignWith(t, h, pub, agent, n, scopeGlobal())
		benignWith(t, h, pub, agent, n, scopeGlobal())
		reviewWith(t, h, agent, n)
		h.tick()
		if got := h.ablations(); got != 0 {
			t.Fatalf("%d ablation cases", got)
		}
	})
	t.Run("rising volume re-runs the latest investigate case, not a later review", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := batchNote(t, h, pub, agent)
		last := benignWith(t, h, pub, agent, n, scopeGlobal())
		reviewWith(t, h, agent, n)
		hour := h.now().UTC().Truncate(time.Hour)
		for i, v := range []int64{1000, 2000, 3000, 4000} {
			h.statsAt(hour.Add(time.Duration(i-4)*time.Hour+10*time.Minute), v, "[]", "[]")
		}
		h.tick()
		var of int64
		if err := h.db.QueryRow(t.Context(), "SELECT ablation_of FROM autopilot_cases WHERE kind = 'ablation'").Scan(&of); err != nil || of != last.CaseID {
			t.Fatalf("ablation_of %d, want %d, err %v", of, last.CaseID, err)
		}
	})
}

// An ablation opens only on its triggers: 3 benign cases served the note
// within a day, or, for a note that holds the autopilot back, its scope's
// volume rising every hour for 4 hours to twice the first and 1,000.
func TestNoteAblationTriggers(t *testing.T) {
	// confirmedOn writes in in a case closed as benign, confirms it and
	// closes one more case as benign whose run was served it on scope.
	confirmedOn := func(t *testing.T, h *harness, pub, agent *client, in, scope map[string]any) int64 {
		t.Helper()
		n := writeNote(t, h, pub, agent, in, "benign")
		h.confirmNote(n)
		benignWith(t, h, pub, agent, n, scope)
		return n
	}
	partner := func(t *testing.T, h *harness, pub, agent *client) int64 {
		t.Helper()
		pub.setAutopilot(map[string]any{"protected_subjects": []any{"203.0.113.0/24"}})
		h.partnerLimited()
		return confirmedOn(t, h, pub, agent, partnerNote(map[string]any{"max_block_share": 0.005}), scopeRule("login"))
	}
	signature := func(t *testing.T, h *harness, pub, agent *client) int64 {
		t.Helper()
		h.loginStuffing()
		return confirmedOn(t, h, pub, agent, stuffingNote(), scopeRule("login"))
	}
	preference := func(t *testing.T, h *harness, pub, agent *client) int64 {
		t.Helper()
		h.loginStuffing()
		return confirmedOn(t, h, pub, agent, keyNote(), scopeRule("login"))
	}
	// loginHours has login limit each of the 4 hours before this one.
	loginHours := func(h *harness, limited ...int64) {
		hour := h.now().UTC().Truncate(time.Hour)
		for i, v := range limited {
			h.statsAt(hour.Add(time.Duration(i-4)*time.Hour+10*time.Minute), 10_000, fmt.Sprintf(`[{"id":"login","evaluated":%d,"limited":%d,"would_limit":0}]`, 2*v, v), "[]")
		}
	}
	for _, tc := range []struct {
		name    string
		note    func(t *testing.T, h *harness, pub, agent *client) int64
		limited []int64
		want    int
	}{
		{"a collateral risk on a rule limiting more every hour opens one", partner, []int64{1000, 2000, 3000, 4000}, 1},
		{"a collateral risk on a rule whose limiting fell back an hour opens none", partner, []int64{1000, 3000, 2000, 4000}, 0},
		{"a collateral risk on a rule limiting under 1,000 in the last hour opens none", partner, []int64{100, 200, 300, 400}, 0},
		{"a collateral risk on a rule limiting under twice the first hour in the last opens none", partner, []int64{1000, 1100, 1200, 1300}, 0},
		{"an attack signature on a rule limiting more every hour opens none", signature, []int64{1000, 2000, 3000, 4000}, 0},
		{"a key preference on a rule limiting more every hour opens none", preference, []int64{1000, 2000, 3000, 4000}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := autopilotHarness(t)
			tc.note(t, h, pub, agent)
			loginHours(h, tc.limited...)
			h.tick()
			if got := h.ablations(); got != tc.want {
				t.Fatalf("%d ablation cases, want %d", got, tc.want)
			}
		})
	}
	t.Run("an expected pattern on a route taking more requests every hour opens one", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		route := h.observedRoute("api.example.com", "GET", "/api/v2/export")
		for k := 1; k <= 14; k++ {
			h.routeHour(route, lastHour(h, k), 4000)
		}
		for i, v := range []int64{1000, 2000, 3000, 4000} {
			h.routeHour(route, lastHour(h, 0).Add(time.Duration(i-3)*time.Hour), v)
		}
		in := learning("expected_pattern", scopeRoute("api.example.com", "GET", "/api/v2/export"), claim("route_requests", ">=", 2000, thatHourDaily(h)))
		in["statement"] = "Export takes about 4,000 requests in this hour each day from the partner's catalog sync"
		confirmedOn(t, h, pub, agent, in, scopeRoute("api.example.com", "GET", "/api/v2/export"))
		h.tick()
		if got := h.ablations(); got != 1 {
			t.Fatalf("%d ablation cases", got)
		}
	})
	t.Run("two benign cases open none", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := partner(t, h, pub, agent)
		benignWith(t, h, pub, agent, n, scopeRule("login"))
		h.tick()
		if got := h.ablations(); got != 0 {
			t.Fatalf("%d ablation cases", got)
		}
	})
	t.Run("three benign cases over a day ago open none", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := partner(t, h, pub, agent)
		benignWith(t, h, pub, agent, n, scopeRule("login"))
		benignWith(t, h, pub, agent, n, scopeRule("login"))
		h.advance(25 * time.Hour)
		agent.seen()
		h.tick()
		if got := h.ablations(); got != 0 {
			t.Fatalf("%d ablation cases", got)
		}
	})
	t.Run("a second ablation within a day of the first is not opened", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := partner(t, h, pub, agent)
		benignWith(t, h, pub, agent, n, scopeRule("login"))
		benignWith(t, h, pub, agent, n, scopeRule("login"))
		h.tick()
		a := claimKind(t, agent, "ablation")
		status(t, agent.result(a.CaseID, resultBody(a.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
		h.tick()
		if got := h.ablations(); got != 1 {
			t.Fatalf("%d ablation cases", got)
		}
	})
}

// Once a day admin re-checks every active note, retires the ones nothing
// used, and the review case may merge notes on the same topic.
func TestNoteDailyReview(t *testing.T) {
	reviews := func(h *harness, n int64) []bool {
		h.t.Helper()
		rows, _ := h.db.Query(h.t.Context(), "SELECT matched FROM autopilot_note_uses WHERE note_id = $1 AND source = 'review' ORDER BY id", n)
		out, err := pgx.CollectRows(rows, pgx.RowTo[bool])
		if err != nil {
			h.t.Fatal(err)
		}
		return out
	}
	fleetNote := func(t *testing.T, h *harness, pub, agent *client, threshold float64) int64 {
		t.Helper()
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", threshold, lastMinutes(60)))
		in["statement"] = fmt.Sprintf("During the stuffing the fleet takes over %v requests an hour", threshold)
		return writeNote(t, h, pub, agent, in, "attack")
	}
	t.Run("each active note is re-checked once a day", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		h.loginStuffing()
		fleet := fleetNote(t, h, pub, agent, 20_000)
		login := writeNote(t, h, pub, agent, stuffingNote(), "attack")
		h.advance(2 * time.Hour)
		h.statsAt(h.now().Add(-time.Minute), 30_000, "[]", "[]") // the fleet is still busy; login is quiet
		h.tick()
		h.tick()
		if f, l := reviews(h, fleet), reviews(h, login); !slices.Equal(f, []bool{true}) || !slices.Equal(l, []bool{false}) {
			t.Fatalf("review uses: fleet %v, login %v", f, l)
		}
		h.advance(24*time.Hour + time.Minute)
		h.tick()
		if f, l := reviews(h, fleet), reviews(h, login); len(f) != 2 || len(l) != 2 {
			t.Fatalf("review uses a day later: fleet %v, login %v", f, l)
		}
	})
	// dormantNote is a login note whose claim failed three daily re-checks.
	dormantNote := func(t *testing.T, h *harness, pub, agent *client) int64 {
		t.Helper()
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, stuffingNote(), "attack")
		h.advance(2 * time.Hour)
		for i := range 3 {
			if i > 0 {
				h.advance(24*time.Hour + time.Minute)
			}
			h.tick()
		}
		return n
	}
	t.Run("a note whose claim fails three daily re-checks goes dormant", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := dormantNote(t, h, pub, agent)
		if tr := h.noteTrust(n); tr != "dormant" || !slices.Equal(reviews(h, n), []bool{false, false, false}) {
			t.Fatalf("note %s, review uses %v", tr, reviews(h, n))
		}
		if got := h.actions(); !slices.Contains(got, fmt.Sprintf("autopilot.note_dormant note %d", n)) {
			t.Fatalf("audit %v", got)
		}
	})
	t.Run("a note dormant for 30 days retires", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := dormantNote(t, h, pub, agent)
		h.advance(30*24*time.Hour + time.Hour)
		h.tick()
		if got := h.noteChanges(n); h.noteTrust(n) != "retired" || got[len(got)-1] != "retired retired" {
			t.Fatalf("note %s, revisions %v", h.noteTrust(n), got)
		}
	})
	t.Run("a note no run was served for 30 days retires", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		n := fleetNote(t, h, pub, agent, 20_000)
		h.advance(30*24*time.Hour + time.Hour)
		h.tick()
		if h.noteTrust(n) != "retired" || h.lastNoteReason(n) != "no run was served it for 30 days" {
			t.Fatalf("note %s for %q", h.noteTrust(n), h.lastNoteReason(n))
		}
		if got := h.actions(); !slices.Contains(got, fmt.Sprintf("autopilot.note_trust note %d", n)) {
			t.Fatalf("audit %v", got)
		}
	})
	// review has a fleet note written, then the runner claim the daily
	// review case, and returns the note and the review's session.
	review := func(t *testing.T, h *harness, pub, agent *client) (int64, claimed, *mcp.ClientSession) {
		t.Helper()
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		n := fleetNote(t, h, pub, agent, 1000)
		agent.seen()
		h.tick()
		r := claimKind(t, agent, "review")
		return n, r, h.mcpSession(agentToken, r.RunID)
	}
	t.Run("the review case asks the model to re-check and merge notes", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, r, _ := review(t, h, pub, agent)
		if !strings.Contains(string(r.Brief), "search_notes") || !strings.Contains(string(r.Brief), "merges") {
			t.Fatalf("review brief %s", r.Brief)
		}
	})
	t.Run("a merge outside the review case is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		a := fleetNote(t, h, pub, agent, 1000)
		_, cs := agentCase(t, h, pub, agent)
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 2000, lastMinutes(60)))
		in["evidence"], in["merges"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}, []int64{a}
		if why := refused(t, cs, in); !strings.Contains(why, "review") {
			t.Fatalf("refusal %q", why)
		}
		if h.noteTrust(a) != "unconfirmed" {
			t.Fatalf("note %s", h.noteTrust(a))
		}
		h.wantMetrics(`admin_autopilot_note_refusals_total{reason="merges"} 1`)
	})
	t.Run("the review merges a note on the same topic into a new one", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		a, _, cs := review(t, h, pub, agent)
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 2000, lastMinutes(60)))
		in["statement"] = "During stuffing the fleet takes over 2,000 requests an hour, as two earlier notes said"
		in["evidence"], in["merges"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}, []int64{a}
		m := noteID(t, mustCall(t, cs, "record_learning", in))
		if h.noteTrust(a) != "retired" || h.lastNoteReason(a) != fmt.Sprintf("merged into %d", m) {
			t.Fatalf("note %d %s for %q", a, h.noteTrust(a), h.lastNoteReason(a))
		}
		if got := h.actions(); !subsequence(got, []string{fmt.Sprintf("autopilot.note_write note %d", m), fmt.Sprintf("autopilot.note_trust note %d", a)}) {
			t.Fatalf("audit %v", got)
		}
	})
	t.Run("the review can't merge a note on another scope", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		a, _, cs := review(t, h, pub, agent)
		in := stuffingNote()
		in["evidence"], in["merges"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}, []int64{a}
		if why := refused(t, cs, in); !strings.Contains(why, "scope") {
			t.Fatalf("refusal %q", why)
		}
	})
	t.Run("a hypothesis can't merge an observed note", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		a, _, cs := review(t, h, pub, agent)
		in := hedged("Likely the same botnet as before, rotating residential proxies")
		in["merges"] = []int64{a}
		if why := refused(t, cs, in); !strings.Contains(why, "hypothesis") {
			t.Fatalf("refusal %q", why)
		}
		if h.noteTrust(a) != "unconfirmed" {
			t.Fatalf("note %s", h.noteTrust(a))
		}
	})
	// A merge retires the merged note in the new note's transaction, so a
	// write that does not commit retires nothing and counts nothing.
	t.Run("a merge whose call the run has no room to record retires nothing", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		a, r, cs := review(t, h, pub, agent)
		ev := evidence(t, cs, "get_stats", map[string]any{"minutes": 60})
		for batch := range 10 { // 999 runner events beside the read: 1,000, the most a run keeps
			var evs []map[string]any
			for i := range 100 {
				if seq := batch*100 + i + 1; seq < 1000 {
					evs = append(evs, event(seq, "message", `{"text":"a"}`))
				}
			}
			status(t, agent.events(r.RunID, evs...), 204)
		}
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 2000, lastMinutes(60)))
		in["evidence"], in["merges"] = []int64{ev}, []int64{a}
		refused(t, cs, in)
		if h.noteTrust(a) != "unconfirmed" || h.noteCount() != 1 {
			t.Fatalf("note %d %s, %d notes", a, h.noteTrust(a), h.noteCount())
		}
		h.wantMetrics(`admin_autopilot_note_transitions_total{to="retired"} 0`, `admin_autopilot_note_writes_total{result="written"} 1`)
	})
	t.Run("a merge makes room in a full scope", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		old, _ := agentCase(t, h, pub, agent) // the run the seeded notes belong to
		status(t, agent.result(old.CaseID, resultBody(old.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
		var seeded []int64
		for range 5 {
			seeded = append(seeded, h.seedNote(old, "unconfirmed", h.now().Add(-48*time.Hour), scopeGlobal(), "global"))
		}
		agent.seen()
		h.tick()
		r := claimKind(t, agent, "review")
		cs := h.mcpSession(agentToken, r.RunID)
		in := hedged("Likely the partner's nightly sync, as two earlier notes suspected")
		in["merges"] = seeded[:2]
		m := noteID(t, mustCall(t, cs, "record_learning", in))
		for _, id := range seeded[:2] {
			if h.noteTrust(id) != "retired" || h.lastNoteReason(id) != fmt.Sprintf("merged into %d", m) {
				t.Fatalf("note %d %s for %q", id, h.noteTrust(id), h.lastNoteReason(id))
			}
		}
	})
	t.Run("a merge makes room in a store of 200 notes", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		old, _ := agentCase(t, h, pub, agent) // the run the seeded notes belong to
		status(t, agent.result(old.CaseID, resultBody(old.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
		merged := h.seedNote(old, "unconfirmed", h.now().Add(-48*time.Hour), scopeGlobal(), "global")
		for i := range 199 {
			tmpl := fmt.Sprintf("/api/v2/items/%d", i)
			h.observedRoute("api.example.com", "GET", tmpl)
			h.seedNote(old, "unconfirmed", h.now().Add(-48*time.Hour), scopeRoute("api.example.com", "GET", tmpl), "route:api.example.com GET "+tmpl)
		}
		agent.seen()
		h.tick()
		r := claimKind(t, agent, "review")
		in := hedged("Likely the partner's nightly sync, as an earlier note suspected")
		in["merges"] = []int64{merged}
		mustCall(t, h.mcpSession(agentToken, r.RunID), "record_learning", in)
		if n := h.noteCount(); n != 201 || h.noteTrust(merged) != "retired" {
			t.Fatalf("%d notes, merged note %s", n, h.noteTrust(merged))
		}
	})
}

// A person retracts a note at any time; the note page shows what relied
// on it and re-evaluates the rules still enforcing because of it.
func TestNoteRetraction(t *testing.T) {
	// enforcingCited is a confirmed attack signature on login and an enforce
	// rule citing it, now enforcing.
	enforcingCited := func(t *testing.T) (*harness, *client, *client, int64, string) {
		t.Helper()
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, stuffingNote(), "attack")
		h.confirmNote(n)
		id := citedRule(t, h, pub, agent, scopeRule("login"), n, proposal("enforce", "login-stuffing", loginRule()))
		h.advance(6 * time.Minute)
		ruleMinutes(h, pub, 6, 10_000, 1_000, 0, 100, id, "[]")
		h.tick()
		if st := ruleState(t, h, id); st != "enforcing" {
			t.Fatalf("rule %s", st)
		}
		return h, pub, agent, n, id
	}
	retract := func(c *client, n int64, reason string) *http.Response {
		return c.do("POST", fmt.Sprintf("/api/autopilot/notes/%d/retract", n), map[string]any{"reason": reason})
	}
	t.Run("the note page lists the cases, proposals and enforcing rules that relied on it", func(t *testing.T) {
		h, pub, _, n, id := enforcingCited(t)
		var caseID, proposalID int64
		if err := h.db.QueryRow(t.Context(), "SELECT case_id, proposal_id FROM autopilot_rules WHERE id = $1", id).Scan(&caseID, &proposalID); err != nil {
			t.Fatal(err)
		}
		got := decode[struct {
			Note        map[string]any   `json:"note"`
			Revisions   []map[string]any `json:"revisions"`
			BlastRadius struct {
				Cases          []int64  `json:"cases"`
				Proposals      []int64  `json:"proposals"`
				EnforcingRules []string `json:"enforcing_rules"`
			} `json:"blast_radius"`
		}](t, pub.do("GET", fmt.Sprintf("/api/autopilot/notes/%d", n), nil))
		br := got.BlastRadius
		if got.Note["id"] != float64(n) || !slices.Contains(br.Cases, caseID) || !slices.Equal(br.Proposals, []int64{proposalID}) || !slices.Equal(br.EnforcingRules, []string{id}) {
			t.Fatalf("note %v, blast radius %+v", got.Note["id"], br)
		}
	})
	t.Run("a retraction records who and why, and the note is no longer served", func(t *testing.T) {
		h, pub, agent, n, _ := enforcingCited(t)
		status(t, retract(pub, n, "It describes our own load test"), 204)
		if got := h.noteChanges(n); h.noteTrust(n) != "retracted" || got[len(got)-1] != "retracted retracted" || h.lastNoteReason(n) != "It describes our own load test" {
			t.Fatalf("note %s, revisions %v, reason %q", h.noteTrust(n), got, h.lastNoteReason(n))
		}
		h.wantMetrics(`admin_autopilot_note_transitions_total{to="retracted"} 1`)
		var actor string
		if err := h.db.QueryRow(t.Context(), "SELECT actor FROM audit_events WHERE action = 'autopilot.note_retract' AND target = $1", fmt.Sprintf("note %d", n)).Scan(&actor); err != nil || actor != "user:pub" {
			t.Fatalf("retract actor %q, err %v", actor, err)
		}
		_, cs := agentCase(t, h, pub, agent)
		if ids := served(t, cs, scopeRule("login")); slices.Contains(ids, n) {
			t.Fatalf("a retracted note was served: %v", ids)
		}
	})
	t.Run("a retracted note can't be retracted again", func(t *testing.T) {
		_, pub, _, n, _ := enforcingCited(t)
		status(t, retract(pub, n, "It describes our own load test"), 204)
		status(t, retract(pub, n, "Still our load test"), 409)
	})
	for _, tc := range []struct {
		name   string
		reason string
		want   int
	}{
		{"no reason is refused", "", 422},
		{"a reason over 500 characters is refused", strings.Repeat("a", 501), 422},
		{"a 500-character reason in Korean is accepted", strings.Repeat("가", 500), 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pub, _, n, _ := enforcingCited(t)
			status(t, retract(pub, n, tc.reason), tc.want)
		})
	}
	t.Run("re-evaluating opens a case on each rule still enforcing because of it", func(t *testing.T) {
		h, pub, agent, n, id := enforcingCited(t)
		status(t, retract(pub, n, "It describes our own load test"), 204)
		agent.seen()
		resp := pub.do("POST", fmt.Sprintf("/api/autopilot/notes/%d/reevaluate", n), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("reevaluate %d: %s", resp.StatusCode, body(resp))
		}
		got := decode[struct {
			Cases []int64 `json:"cases"`
		}](t, resp)
		if len(got.Cases) != 1 {
			t.Fatalf("cases %v", got.Cases)
		}
		var kind, dedupe, state string
		if err := h.db.QueryRow(t.Context(), "SELECT kind, dedupe_key, state FROM autopilot_cases WHERE id = $1", got.Cases[0]).Scan(&kind, &dedupe, &state); err != nil ||
			kind != "investigate" || dedupe != "rule:"+id || state != "queued" {
			t.Fatalf("case %s %s %s, err %v", kind, dedupe, state, err)
		}
		if !slices.Contains(h.actions(), fmt.Sprintf("autopilot.case_open case %d", got.Cases[0])) {
			t.Fatalf("audit %v", h.actions())
		}
	})
	// As for a case a person opens: none opens that no runner would take.
	for _, tc := range []struct {
		name, want string
		setup      func(pub, agent *client)
	}{
		{"re-evaluating with no runner seen in 2 minutes is refused", "no autopilot runner has been seen in the last 2 minutes", func(*client, *client) {}},
		{"re-evaluating with the autopilot off is refused", "autopilot is off", func(pub, agent *client) {
			agent.seen()
			pub.setAutopilot(map[string]any{"mode": "off"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent, n, id := enforcingCited(t)
			tc.setup(pub, agent)
			resp := pub.do("POST", fmt.Sprintf("/api/autopilot/notes/%d/reevaluate", n), nil)
			if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, tc.want) {
				t.Fatalf("reevaluate %d: %s", resp.StatusCode, b)
			}
			var cases int
			if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM autopilot_cases WHERE dedupe_key = $1", "rule:"+id).Scan(&cases); err != nil || cases != 0 {
				t.Fatalf("%d cases on %s, err %v", cases, id, err)
			}
		})
	}
	t.Run("a retired note can't be retracted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := writeNote(t, h, pub, agent, hedged("Likely the partner's nightly sync"), "benign")
		h.advance(31 * 24 * time.Hour)
		h.tick()
		pub = h.signedIn("pub")
		if tr := h.noteTrust(n); tr != "retired" {
			t.Fatalf("note %s", tr)
		}
		status(t, retract(pub, n, "Our load test"), 409)
	})
	t.Run("two people retract a note at once: one retracts it and the other is told it is now retracted", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := writeNote(t, h, pub, agent, hedged("Likely the partner's nightly sync"), "benign")
		h.user("ann", "admin")
		ann := h.signedIn("ann")
		// Holding the audit lock lines both retractions up after they read
		// the note and before either changes it.
		tx, err := h.db.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := admindb.LockAudit(t.Context(), tx); err != nil {
			t.Fatal(err)
		}
		type answer struct {
			code int
			body string
			err  error
		}
		answers := make(chan answer, 2)
		for _, c := range []*client{pub, ann} {
			go func() {
				req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/autopilot/notes/%d/retract", h.srv.URL, n), strings.NewReader(`{"reason":"It describes our own load test"}`))
				resp, err := c.c.Do(req)
				if err != nil {
					answers <- answer{err: err}
					return
				}
				b, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				answers <- answer{code: resp.StatusCode, body: string(b), err: err}
			}()
		}
		waitingOnLocks(t, h, 2)
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		got := map[int]string{}
		for range 2 {
			a := <-answers
			if a.err != nil {
				t.Fatal(a.err)
			}
			got[a.code] = a.body
		}
		if _, ok := got[204]; !ok || !strings.Contains(got[409], fmt.Sprintf("note %d is retracted", n)) {
			t.Fatalf("answers %v, want one 204 and a 409 naming the note retracted", got)
		}
	})
	t.Run("an unknown note is not found", func(t *testing.T) {
		_, pub, _ := autopilotHarness(t)
		status(t, pub.do("GET", "/api/autopilot/notes/999", nil), 404)
		status(t, retract(pub, 999, "Our load test"), 404)
		status(t, pub.do("POST", "/api/autopilot/notes/999/reevaluate", nil), 404)
	})
	t.Run("re-evaluating a note no enforcing rule cites is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := writeNote(t, h, pub, agent, hedged("Likely the partner's nightly sync"), "benign")
		agent.seen()
		resp := pub.do("POST", fmt.Sprintf("/api/autopilot/notes/%d/reevaluate", n), nil)
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, "no rule enforces") {
			t.Fatalf("reevaluate %d: %s", resp.StatusCode, b)
		}
	})
	t.Run("the list filters by trust and scope", func(t *testing.T) {
		_, pub, _, n, _ := enforcingCited(t)
		ids := func(query string) []int64 {
			out := []int64{}
			for _, note := range decode[[]map[string]any](t, pub.do("GET", "/api/autopilot/notes?"+query, nil)) {
				id, _ := note["id"].(float64)
				out = append(out, int64(id))
			}
			return out
		}
		for _, tc := range []struct {
			query string
			want  []int64
		}{
			{"", []int64{n}},
			{"trust=confirmed", []int64{n}},
			{"trust=retracted", []int64{}},
			{"scope_key=rule:login", []int64{n}},
			{"scope_key=global", []int64{}},
		} {
			if got := ids(tc.query); !slices.Equal(got, tc.want) {
				t.Fatalf("%q lists %v, want %v", tc.query, got, tc.want)
			}
		}
	})
}

func TestNotePermissions(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	h.user("vera", "viewer")
	h.user("ed", "editor")
	h.user("paul", "publisher")
	vera, ed, paul := h.signedIn("vera"), h.signedIn("ed"), h.signedIn("paul")
	h.loginStuffing()
	h.statsAt(dailyAt(h, 0).Add(time.Minute), 987_654, "[]", "[]") // its own minute, a fleet count only the cited get_stats answer holds
	n := writeNote(t, h, pub, agent, stuffingNote(), "attack")
	sessions := map[string]*mcp.ClientSession{
		"a reader's token":   h.mcpSession(pub.userToken("autopilot.read"), 0),
		"a stats-only token": h.mcpSession(pub.userToken("stats.read"), 0),
	}
	for _, tc := range []struct {
		who, tool string
		args      map[string]any
		refusal   string // "" means the call is answered
	}{
		{"a reader's token", "search_notes", map[string]any{"scope": scopeRule("login")}, ""},
		{"a reader's token", "record_learning", hedged("Likely the partner's sync"), "autopilot.agent"},
		{"a stats-only token", "search_notes", map[string]any{"scope": scopeRule("login")}, "autopilot.read"},
	} {
		t.Run(tc.who+" calling "+tc.tool, func(t *testing.T) {
			_, why := callTool(t, sessions[tc.who], tc.tool, tc.args)
			if tc.refusal == "" && why != "" || tc.refusal != "" && !strings.Contains(why, tc.refusal) {
				t.Fatalf("refusal %q, want %q", why, tc.refusal)
			}
		})
	}
	t.Run("a reader's token lists search_notes and not record_learning", func(t *testing.T) {
		names := toolNames(t, sessions["a reader's token"])
		if !slices.Contains(names, "search_notes") || slices.Contains(names, "record_learning") {
			t.Fatalf("tools %v", names)
		}
	})
	notePath := fmt.Sprintf("/api/autopilot/notes/%d", n)
	for _, tc := range []struct {
		name         string
		c            *client
		method, path string
		in           any
		status       int
	}{
		{"a viewer lists notes", vera, "GET", "/api/autopilot/notes", nil, 200},
		{"a viewer reads a note", vera, "GET", notePath, nil, 200},
		{"a viewer can't retract", vera, "POST", notePath + "/retract", map[string]any{"reason": "Our load test"}, 403},
		{"an editor can't retract", ed, "POST", notePath + "/retract", map[string]any{"reason": "Our load test"}, 403},
		{"a viewer can't re-evaluate", vera, "POST", notePath + "/reevaluate", nil, 403},
		{"the runner's token can't list notes", agent, "GET", "/api/autopilot/notes", nil, 403},
		{"the runner's token can't retract", agent, "POST", notePath + "/retract", map[string]any{"reason": "Our load test"}, 403},
		{"a publisher retracts", paul, "POST", notePath + "/retract", map[string]any{"reason": "Our load test"}, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status(t, tc.c.do(tc.method, tc.path, tc.in), tc.status)
		})
	}
	// A cited read's answer holds stats and config, so it needs both.
	for _, tc := range []struct {
		name   string
		scopes []string
		hidden bool
	}{
		{"a token with only autopilot.read gets the cited reads hidden", []string{"autopilot.read"}, true},
		{"a token with autopilot.read and stats.read gets the cited reads hidden", []string{"autopilot.read", "stats.read"}, true},
		{"a token with autopilot.read, stats.read and config.read gets the cited reads", []string{"autopilot.read", "stats.read", "config.read"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := h.client()
			reader.token = pub.userToken(tc.scopes...)
			b := body(reader.do("GET", notePath, nil))
			var got struct {
				Evidence []map[string]any `json:"evidence"`
			}
			if err := json.Unmarshal([]byte(b), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Evidence) != 1 || (got.Evidence[0]["hidden"] == true) != tc.hidden || strings.Contains(b, "987654") == tc.hidden {
				t.Fatalf("evidence %v", got.Evidence)
			}
		})
	}
}

// An attacker who shapes export traffic to look like a nightly sync for
// the 3 days before the case gets no benign note: the history anchor wants
// 7 of 14 days, and a hypothesis is never confirmed.
func TestNotePoisonedSyncJobNeverConfirms(t *testing.T) {
	const export = "/api/v2/export"
	poisoned := func(t *testing.T) (*harness, *client, *client, claimed, *mcp.ClientSession, int64) {
		t.Helper()
		h, pub, agent := autopilotHarness(t)
		route := h.observedRoute("api.example.com", "GET", export)
		for k := 1; k <= 14; k++ {
			v := int64(50) // export's usual hour
			if k <= 3 {
				v = 40_000 // the attacker's shaped hours
			}
			h.routeHour(route, lastHour(h, k), v)
		}
		h.routeHour(route, lastHour(h, 0), 45_000)
		c, cs := agentCase(t, h, pub, agent)
		return h, pub, agent, c, cs, evidence(t, cs, "get_route", map[string]any{"id": route})
	}
	for _, tc := range []struct {
		name   string
		kind   string
		effect any
	}{
		{"an expected pattern", "expected_pattern", nil},
		{"a collateral risk", "collateral_risk", map[string]any{"max_block_share": 0.005}},
	} {
		t.Run(tc.name+" on the shaped hours is refused for its anchor", func(t *testing.T) {
			h, _, _, _, cs, ev := poisoned(t)
			in := learning(tc.kind, scopeRoute("api.example.com", "GET", export), claim("route_requests", ">=", 30_000, thatHourDaily(h)))
			in["effect"], in["evidence"] = tc.effect, []int64{ev}
			in["statement"] = "Export takes over 30,000 requests in this hour from the partner's nightly sync"
			if why := refused(t, cs, in); !strings.Contains(why, "anchor") {
				t.Fatalf("refusal %q", why)
			}
			if n := h.noteCount(); n != 0 {
				t.Fatalf("%d notes stored", n)
			}
		})
	}
	t.Run("the hypothesis the model falls back to stays unconfirmed for days", func(t *testing.T) {
		h, _, agent, c, cs, _ := poisoned(t)
		n := noteID(t, mustCall(t, cs, "record_learning", hedged("Likely the partner's nightly sync on export; unconfirmed")))
		status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 10}, nil, 0)), 204)
		h.tick()
		for range 2 {
			h.advance(25 * time.Hour)
			h.tick()
		}
		if tr := h.noteTrust(n); tr != "unconfirmed" || slices.Contains(h.noteChanges(n), "confirmed confirmed") {
			t.Fatalf("note %s, revisions %v", tr, h.noteChanges(n))
		}
	})
}

// Note writes take the run's lock before any audit row, as a case result
// does, and the audit lock before any note row, as a rule change that
// retracts notes does. Either order the other way round deadlocks with
// those, and Postgres aborts one side.
func TestNoteLockOrder(t *testing.T) {
	// fleetNote holds while the fleet takes over 20,000 requests an hour.
	fleetNote := func(t *testing.T, h *harness, pub, agent *client) int64 {
		t.Helper()
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 20_000, lastMinutes(60)))
		in["statement"] = "During the stuffing the fleet takes over 20,000 requests an hour"
		return writeNote(t, h, pub, agent, in, "attack")
	}
	// failedTwice has the fleet note's claim fail on two searches, so the
	// next unmatched use makes it dormant.
	failedTwice := func(t *testing.T, h *harness, pub, agent *client) int64 {
		t.Helper()
		n := fleetNote(t, h, pub, agent)
		h.advance(2 * time.Hour)
		for range 2 {
			c, cs := agentCase(t, h, pub, agent)
			served(t, cs, scopeGlobal())
			status(t, agent.result(c.CaseID, resultBody(c.RunID, "benign", usage{Input: 1}, nil, 0)), 204)
		}
		return n
	}
	runLock := func(c claimed) func(ctx context.Context, tx pgx.Tx) error {
		return func(ctx context.Context, tx pgx.Tx) error { return lockRun(ctx, tx, c.RunID) }
	}
	callOf := func(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) func() string {
		t.Helper()
		return func() string { _, why := callTool(t, cs, tool, args); return why }
	}
	t.Run("a note written while its run's result holds the run's lock waits for it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		c, cs := agentCase(t, h, pub, agent)
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 20_000, lastMinutes(60)))
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		racing(t, h, runLock(c), caseCloseAudit(h, c), callOf(t, cs, "record_learning", in))
		if n := h.noteCount(); n != 1 {
			t.Fatalf("%d notes", n)
		}
	})
	t.Run("a note written while its case's result waits for the run's lock is kept with the result", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
		c, cs := agentCase(t, h, pub, agent)
		in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 20_000, lastMinutes(60)))
		in["evidence"] = []int64{evidence(t, cs, "get_stats", map[string]any{"minutes": 60})}
		tx, err := h.db.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := lockRun(t.Context(), tx, c.RunID); err != nil {
			t.Fatal(err)
		}
		// The note waits for the run's lock first; the result takes the
		// case's row, then waits behind it.
		learned := make(chan string, 1)
		go func() { _, why := callTool(t, cs, "record_learning", in); learned <- why }()
		waitingOnLocks(t, h, 1)
		result := make(chan int, 1)
		go func() {
			resp := agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0))
			_ = resp.Body.Close()
			result <- resp.StatusCode
		}()
		waitingOnLocks(t, h, 2)
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if why, code := <-learned, <-result; why != "" || code != 204 {
			t.Fatalf("record_learning %q, result %d", why, code)
		}
		if n := h.noteCount(); n != 1 {
			t.Fatalf("%d notes", n)
		}
	})
	t.Run("a search while the lease of its case lapses records its use and requeues the case", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		c, cs := agentCase(t, h, pub, agent)
		n := h.seedNote(c, "unconfirmed", h.now(), scopeGlobal(), "global")
		// Holding the note's row stops the search once it holds the audit
		// lock, before it records its use.
		tx, err := h.db.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if _, err := tx.Exec(t.Context(), "SELECT 1 FROM autopilot_notes WHERE id = $1 FOR NO KEY UPDATE", n); err != nil {
			t.Fatal(err)
		}
		searched := make(chan string, 1)
		go func() {
			_, why := callTool(t, cs, "search_notes", map[string]any{"scope": scopeGlobal()})
			searched <- why
		}()
		waitingOnLocks(t, h, 1)
		// The lapse takes the case's row, then waits for the audit lock.
		h.advance(caseLease + time.Minute)
		expired := make(chan error, 1)
		go func() { expired <- h.s.expireCases(t.Context()) }()
		waitingOnLocks(t, h, 2)
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if why, err := <-searched, <-expired; why != "" || err != nil {
			t.Fatalf("search_notes %q, expireCases %v", why, err)
		}
		var uses int
		var state string
		if err := h.db.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM autopilot_note_uses WHERE note_id = $1), (SELECT state FROM autopilot_cases WHERE id = $2)", n, c.CaseID).
			Scan(&uses, &state); err != nil || uses != 1 || state != "queued" {
			t.Fatalf("%d uses, case %s, err %v", uses, state, err)
		}
	})
	t.Run("a search making a note dormant while its run's result holds the run's lock waits for it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := failedTwice(t, h, pub, agent)
		c, cs := agentCase(t, h, pub, agent)
		racing(t, h, runLock(c), caseCloseAudit(h, c), callOf(t, cs, "search_notes", map[string]any{"scope": scopeGlobal()}))
		if tr := h.noteTrust(n); tr != "dormant" {
			t.Fatalf("note %s", tr)
		}
	})
	t.Run("a retire proposal while its run's result holds the run's lock waits for it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		id := liveRule(t, h, pub, agent, proposal("add_sensor", "login-watch", loginRule()))
		c, cs := agentCase(t, h, pub, agent)
		racing(t, h, runLock(c), caseCloseAudit(h, c), callOf(t, cs, "propose", map[string]any{"action": "retire", "rule_id": id, "rationale": "It never fired"}))
		if st := ruleState(t, h, id); st != "retired" {
			t.Fatalf("rule %s", st)
		}
	})
	// rollbackAudit holds the audit lock as a rule change does once it has
	// written its transition's row; retracting lock then takes the note's
	// row as it retracts it.
	rollbackAudit := func(h *harness) func(ctx context.Context, tx pgx.Tx) error {
		return func(ctx context.Context, tx pgx.Tx) error {
			return admindb.Audit(ctx, tx, h.s.cfg.Audit, h.now, admindb.Event{Actor: "system:guard", Action: "autopilot.rollback", Target: "rule ap-login-stuffing-1"})
		}
	}
	retracting := func(n int64) func(ctx context.Context, tx pgx.Tx) error {
		return func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "SELECT 1 FROM autopilot_notes WHERE id = $1 FOR NO KEY UPDATE", n)
			return err
		}
	}
	t.Run("a search making a note dormant while a rule change retracts notes waits for it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := failedTwice(t, h, pub, agent)
		_, cs := agentCase(t, h, pub, agent)
		racing(t, h, rollbackAudit(h), retracting(n), callOf(t, cs, "search_notes", map[string]any{"scope": scopeGlobal()}))
		if tr := h.noteTrust(n); tr != "dormant" {
			t.Fatalf("note %s", tr)
		}
	})
	t.Run("a daily re-check making a note dormant while a rule change retracts notes waits for it", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		n := failedTwice(t, h, pub, agent)
		racing(t, h, rollbackAudit(h), retracting(n), func() string {
			if err := h.s.runAutopilot(t.Context()); err != nil {
				return err.Error()
			}
			return ""
		})
		if tr := h.noteTrust(n); tr != "dormant" {
			t.Fatalf("note %s", tr)
		}
	})
}

// Two runs searching at once both count: neither overwrites the other's
// unmatched use.
func TestNoteFailStreakCountsEveryUse(t *testing.T) {
	h, pub, agent := autopilotHarness(t)
	h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
	in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 20_000, lastMinutes(60)))
	in["statement"] = "During the stuffing the fleet takes over 20,000 requests an hour"
	n := writeNote(t, h, pub, agent, in, "attack")
	h.advance(2 * time.Hour)
	_, first := agentCase(t, h, pub, agent)
	pub.investigate("", "Who is scraping export?")
	second := h.mcpSession(agentToken, agent.claimCase().RunID)
	// A third transaction holds the note's row, so both searches have read
	// the note before either writes.
	tx, err := h.db.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT 1 FROM autopilot_notes WHERE id = $1 FOR NO KEY UPDATE", n); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	whys := make([]string, 2)
	for i, cs := range []*mcp.ClientSession{first, second} {
		wg.Go(func() { _, whys[i] = callTool(t, cs, "search_notes", map[string]any{"scope": scopeGlobal()}) })
	}
	waitingOnLocks(t, h, 2)
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	var streak int
	if err := h.db.QueryRow(t.Context(), "SELECT fail_streak FROM autopilot_notes WHERE id = $1", n).Scan(&streak); err != nil || streak != 2 || whys[0] != "" || whys[1] != "" {
		t.Fatalf("fail_streak %d, refusals %q, err %v", streak, whys, err)
	}
}

// validate_rule checks the notes a proposal would cite, as propose does.
func TestNoteValidateRuleCitesNotes(t *testing.T) {
	validate := func(rule map[string]any, notes []int64) map[string]any {
		return map[string]any{"action": "enforce", "name": "login-stuffing", "rule": rule, "notes": notes}
	}
	t.Run("a confirmed key preference the rule's key lacks is reported as note_key", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, keyNote(), "attack")
		h.confirmNote(n)
		_, cs := agentCase(t, h, pub, agent)
		served(t, cs, scopeRule("login"))
		out := mustCall(t, cs, "validate_rule", validate(loginRule(), []int64{n}))
		reasons, _ := out["reasons"].([]any)
		if out["ok"] != false || !slices.Contains(reasons, any("note_key")) {
			t.Fatalf("validate_rule %v", out)
		}
	})
	t.Run("a note not served to the run is refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		h.loginStuffing()
		n := writeNote(t, h, pub, agent, keyNote(), "attack")
		_, cs := agentCase(t, h, pub, agent)
		if _, why := callTool(t, cs, "validate_rule", validate(loginRule(), []int64{n})); !strings.Contains(why, fmt.Sprintf("note %d was not served to this run by search_notes", n)) {
			t.Fatalf("refusal %q", why)
		}
	})
	t.Run("its schema takes notes", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, cs := agentCase(t, h, pub, agent)
		res, err := cs.ListTools(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(res.Tools, func(tool *mcp.Tool) bool { return tool.Name == "validate_rule" })
		b, _ := json.Marshal(res.Tools[i].InputSchema)
		var schema struct {
			Properties map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(b, &schema); err != nil || schema.Properties["notes"] == nil {
			t.Fatalf("validate_rule schema %s", b)
		}
	})
	t.Run("six notes are refused", func(t *testing.T) {
		h, pub, agent := autopilotHarness(t)
		_, cs := agentCase(t, h, pub, agent)
		if _, why := callTool(t, cs, "validate_rule", validate(loginRule(), []int64{1, 2, 3, 4, 5, 6})); !strings.Contains(why, "at most 5 notes") {
			t.Fatalf("refusal %q", why)
		}
	})
}
