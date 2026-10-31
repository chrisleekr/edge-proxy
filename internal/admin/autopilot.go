package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// Autopilot bounds that are not settings.
const (
	// agentSeenWithin: a runner seen this recently is connected. Cases open
	// only while one is, so none pile up for a runner that is down.
	agentSeenWithin = 2 * time.Minute
	maxOpenCases    = 100
	caseLease       = 10 * time.Minute
	maxAttempts     = 2
	// queuedMax: a case no runner claimed in this long is cancelled; the
	// question it asked is stale.
	queuedMax = time.Hour
)

// apRule is one autopilot_rules row. Rule is the rate-limit rule as
// published, with its id; its action and expiry come from State and
// ExpiresAt.
type apRule struct {
	ID             string
	ProposalID     int64
	CaseID         int64
	Kind           string // sensor | enforce
	State          string
	Rule           snapshot.RateLimitRule
	Shape          []byte
	TTLSeconds     int
	Cites          *string
	LiveSince      *time.Time
	EnforcingSince *time.Time
	ShadowRatio    *float64
	ExpiresAt      *time.Time
	ApprovedBy     *string
	EndedAt        *time.Time
	Outcome        *string
	GuardAlertedAt *time.Time
	// Exclusions are the ids of the exclusions its expression carries.
	Exclusions []int64
}

const apRuleCols = "id, proposal_id, case_id, kind, state, rule, shape_sha256, ttl_seconds, cites, live_since, enforcing_since, shadow_ratio, expires_at, approved_by, ended_at, outcome, guard_alerted_at, exclusions"

// liveStates are the states whose rule is, or is about to be, published.
var liveStates = []string{"proposed", "observing", "enforcing"}

// published is the rule as the overlay carries it: log-only until it
// enforces.
func (r apRule) published() snapshot.RateLimitRule {
	out := r.Rule
	out.ID, out.Action = r.ID, "log"
	if r.State == "enforcing" {
		out.Action = "block"
	}
	if r.ExpiresAt != nil {
		out.ExpiresAt = r.ExpiresAt.UTC()
	}
	return out
}

func (s *Server) loadRules(ctx context.Context, q querier, where string, args ...any) ([]apRule, error) {
	rows, err := q.Query(ctx, "SELECT "+apRuleCols+" FROM autopilot_rules WHERE "+where+" ORDER BY id", args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[apRule])
}

func (s *Server) loadRule(ctx context.Context, q querier, id string) (*apRule, error) {
	rules, err := s.loadRules(ctx, q, "id = $1", id)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fail(http.StatusNotFound, fmt.Sprintf("no autopilot rule %q", id))
	}
	return &rules[0], nil
}

// ruleChange is one state transition: the row as it becomes, why, who and
// the audit action that records it.
type ruleChange struct {
	from    string
	next    apRule
	reason  string
	actor   string
	action  string
	numbers map[string]any
}

// ended is r moved to a final state.
func ended(r apRule, state, outcome string, now time.Time) apRule {
	r.State, r.Outcome, r.EndedAt = state, &outcome, &now
	return r
}

// applyChanges writes each change, its transition row and its audit row.
// version is the version that published the change, if any.
func (s *Server) applyChanges(ctx context.Context, tx pgx.Tx, changes []ruleChange, version *int64) error {
	now := s.now()
	for _, c := range changes {
		n := c.next
		if _, err := tx.Exec(ctx, `UPDATE autopilot_rules SET state = $2, ttl_seconds = $3, live_since = $4, enforcing_since = $5, shadow_ratio = $6,
			expires_at = $7, approved_by = $8, ended_at = $9, outcome = $10, guard_alerted_at = $11 WHERE id = $1`,
			n.ID, n.State, n.TTLSeconds, n.LiveSince, n.EnforcingSince, n.ShadowRatio, n.ExpiresAt, n.ApprovedBy, n.EndedAt, n.Outcome, n.GuardAlertedAt); err != nil {
			return err
		}
		numbers := c.numbers
		if numbers == nil {
			numbers = map[string]any{}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO autopilot_transitions (rule_id, case_id, proposal_id, from_state, to_state, reason, numbers, version, actor, at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, n.ID, n.CaseID, n.ProposalID, c.from, n.State, c.reason, numbers, version, c.actor, now); err != nil {
			return err
		}
		details := map[string]any{"from": c.from, "to": n.State, "reason": c.reason, "numbers": numbers, "version": version, "case": n.CaseID, "proposal": n.ProposalID}
		if n.ExpiresAt != nil {
			details["expires_at"] = n.ExpiresAt.UTC()
		}
		if err := admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: c.actor, Action: c.action, Target: "rule " + n.ID, Details: details}); err != nil {
			return err
		}
	}
	// After every change is written, so a case is opened only on a rule
	// still enforcing once this transaction commits.
	for _, c := range changes {
		n := c.next
		why := ""
		switch {
		case n.State == "rolled_back":
			why = "was rolled back by the guard"
		case n.Outcome != nil && *n.Outcome == "false_positive":
			why = "was marked a false positive"
		default:
			continue
		}
		if err := s.retractCited(ctx, tx, n, why, c.actor); err != nil {
			return err
		}
	}
	return nil
}

// cancelCases cancels the cases where selects, each with its audit row, and
// returns their kinds for the metrics, counted once the caller commits.
func (s *Server) cancelCases(ctx context.Context, tx pgx.Tx, actor, where, why string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, "UPDATE autopilot_cases SET state = 'cancelled', closed_at = $1, lease_until = NULL, summary = $2 WHERE "+where+" RETURNING id, kind",
		append([]any{s.now(), why}, args...)...)
	if err != nil {
		return nil, err
	}
	type cancelled struct {
		ID   int64
		Kind string
	}
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[cancelled])
	if err != nil {
		return nil, err
	}
	var kinds []string
	for _, c := range got {
		kinds = append(kinds, c.Kind)
		if err := admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: actor, Action: "autopilot.case_close", Target: fmt.Sprintf("case %d", c.ID),
			Details: map[string]any{"state": "cancelled", "reason": why}}); err != nil {
			return nil, err
		}
	}
	return kinds, nil
}

// caseIn is a case to open.
type caseIn struct {
	Kind      string
	DedupeKey string
	Rule      *string
	RouteID   *int64
	AnomalyID *int64
	Question  string
	Brief     map[string]any
	// AblationOf is the case an ablation re-runs with Withheld notes left out.
	AblationOf *int64
	Withheld   []int64
}

// openCaseCount is the number of queued or running cases.
func openCaseCount(ctx context.Context, q querier) (int, error) {
	var n int
	err := q.QueryRow(ctx, "SELECT count(*) FROM autopilot_cases WHERE state IN ('queued', 'running')").Scan(&n)
	return n, err
}

// openCase opens c unless a case on the same key is open or maxOpenCases
// are. It reports whether it opened one.
func (s *Server) openCase(ctx context.Context, tx pgx.Tx, c caseIn, actor string) (int64, bool, error) {
	open, err := openCaseCount(ctx, tx)
	if err != nil {
		return 0, false, err
	}
	if open >= maxOpenCases {
		return 0, false, nil
	}
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO autopilot_cases (kind, dedupe_key, rule, route_id, anomaly_id, question, brief, state, opened_by, created_at, queued_at, ablation_of, withheld_notes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued', $8, $9, $9, $10, $11) ON CONFLICT (dedupe_key) WHERE state IN ('queued', 'running') DO NOTHING RETURNING id`,
		c.Kind, c.DedupeKey, c.Rule, c.RouteID, c.AnomalyID, c.Question, c.Brief, actor, s.now(), c.AblationOf, orEmpty(c.Withheld)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: actor, Action: "autopilot.case_open", Target: fmt.Sprintf("case %d", id),
		Details: map[string]any{"kind": c.Kind, "rule": c.Rule, "route_id": c.RouteID, "anomaly_id": c.AnomalyID, "question": c.Question,
			"ablation_of": c.AblationOf, "withheld_notes": orEmpty(c.Withheld)}})
}

// runnerRow is a runner seen in the last day.
type runnerRow struct {
	ID         string    `json:"id"`
	Version    string    `json:"version"`
	SDKVersion string    `json:"sdk_version"`
	Providers  []string  `json:"providers"`
	LastSeen   time.Time `json:"last_seen"`
}

func (s *Server) runners(ctx context.Context, q querier) ([]runnerRow, error) {
	rows, err := q.Query(ctx, "SELECT id, version, sdk_version, providers, last_seen FROM autopilot_runners WHERE last_seen > $1 ORDER BY id", s.now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[runnerRow])
}

// connected is the runners seen within agentSeenWithin, and the providers
// they hold a credential for.
func (s *Server) connected(rs []runnerRow) ([]runnerRow, map[string]bool) {
	creds := map[string]bool{"claude": false, "openai": false}
	var live []runnerRow
	for _, r := range rs {
		if s.now().Sub(r.LastSeen) <= agentSeenWithin {
			live = append(live, r)
			for _, p := range r.Providers {
				creds[p] = true
			}
		}
	}
	return live, creds
}

// apUsage is what the budgets have used.
type apUsage struct {
	Enforcing, Sensors, CasesHour int
}

func (s *Server) autopilotUsage(ctx context.Context, q querier) (apUsage, error) {
	var u apUsage
	if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind = 'enforce' AND state IN ('proposed', 'observing', 'enforcing')),
		count(*) FILTER (WHERE kind = 'sensor' AND state IN ('proposed', 'observing')) FROM autopilot_rules`).Scan(&u.Enforcing, &u.Sensors); err != nil {
		return u, err
	}
	err := q.QueryRow(ctx, "SELECT count(*) FROM autopilot_runs WHERE started_at > $1", s.now().Add(-time.Hour)).Scan(&u.CasesHour)
	return u, err
}

// budgetView is one budget: used of max.
type budgetView struct {
	Used int `json:"used"`
	Max  int `json:"max"`
}

func ratioOf(used, maximum int) float64 {
	if maximum <= 0 {
		return 0
	}
	return float64(used) / float64(maximum)
}

// ruleView is an autopilot rule as the API shows it.
type ruleView struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	State          string     `json:"state"`
	Expression     string     `json:"expression"`
	Key            []string   `json:"key"`
	Limit          int64      `json:"limit"`
	Period         string     `json:"period"`
	CaseID         int64      `json:"case_id"`
	LiveSince      *time.Time `json:"live_since"`
	EnforcingSince *time.Time `json:"enforcing_since"`
	ExpiresAt      *time.Time `json:"expires_at"`
	ShadowRatio    *float64   `json:"shadow_ratio"`
	Outcome        *string    `json:"outcome"`
	// Host and PathPrefix are what the rule's conditions fix, the scope an
	// exclusion promoted from it defaults to.
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix"`
}

func viewOf(r apRule) ruleView {
	v := ruleView{ID: r.ID, Kind: r.Kind, State: r.State, Expression: expr.Render(r.Rule.Expression), Key: r.Rule.Key, Limit: r.Rule.Limit,
		Period: time.Duration(r.Rule.Period).String(), CaseID: r.CaseID, LiveSince: r.LiveSince, EnforcingSince: r.EnforcingSince,
		ExpiresAt: r.ExpiresAt, ShadowRatio: r.ShadowRatio, Outcome: r.Outcome}
	v.Host, v.PathPrefix = scopeOf(r.Rule.Expression)
	return v
}

// autopilotState is GET /api/autopilot and the get_autopilot_state tool.
type autopilotState struct {
	Mode           string                `json:"mode"`
	AgentConnected bool                  `json:"agent_connected"`
	Runners        []runnerRow           `json:"runners"`
	Credentials    map[string]bool       `json:"credentials"`
	Warnings       []string              `json:"warnings"`
	Budgets        map[string]budgetView `json:"budgets"`
	CasesOpen      int                   `json:"cases_open"`
	Rules          []ruleView            `json:"rules"`
	// Exclusions are the active ones: clients a person found legitimate,
	// which every new autopilot rule leaves out.
	Exclusions []exclusion `json:"exclusions"`
}

func (s *Server) autopilotState(ctx context.Context) (*autopilotState, error) {
	set, err := loadAutopilot(ctx, s.db)
	if err != nil {
		return nil, err
	}
	rs, err := s.runners(ctx, s.db)
	if err != nil {
		return nil, err
	}
	live, creds := s.connected(rs)
	st := &autopilotState{Mode: set.Mode, AgentConnected: len(live) > 0, Runners: orEmpty(rs), Credentials: creds, Warnings: []string{}, Rules: []ruleView{}}
	if st.AgentConnected {
		for _, m := range slices.Compact([]string{set.Model, set.SweepModel}) {
			if p := providerOf(m); !creds[p] {
				st.Warnings = append(st.Warnings, fmt.Sprintf("model %s needs a %s credential, which no connected runner has; cases for it are refused", m, p))
			}
		}
	}
	u, err := s.autopilotUsage(ctx, s.db)
	if err != nil {
		return nil, err
	}
	st.Budgets = map[string]budgetView{"enforcing": {u.Enforcing, set.MaxEnforcing}, "sensors": {u.Sensors, set.MaxSensors}, "cases_hour": {u.CasesHour, set.CasesPerHour}}
	if st.CasesOpen, err = openCaseCount(ctx, s.db); err != nil {
		return nil, err
	}
	rules, err := s.loadRules(ctx, s.db, "state IN ('proposed', 'observing', 'enforcing')")
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		st.Rules = append(st.Rules, viewOf(r))
	}
	ex, err := activeExclusions(ctx, s.db, s.now())
	st.Exclusions = orEmpty(ex)
	return st, err
}

// spendWindow is what runs started in a window cost. Unpriced runs had
// no price for their model, so configured_usd_micros leaves them out.
type spendWindow struct {
	Runs         int64 `json:"runs"`
	UnpricedRuns int64 `json:"unpriced_runs"`
	Configured   int64 `json:"configured_usd_micros"`
	Provider     int64 `json:"provider_usd_micros"`
}

// spendDay is what one model's finished runs cost on one UTC day.
type spendDay struct {
	Day          string `json:"day"`
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	Runs         int64  `json:"runs"`
	Cases        int64  `json:"cases"`
	UnpricedRuns int64  `json:"unpriced_runs"`
	Configured   int64  `json:"configured_usd_micros"`
	ProviderUSD  int64  `json:"provider_usd_micros"`
}

// spendDays is how many UTC days spend_days covers, today included.
const spendDays = 14

// modelPrecision is how enforce rules from one model and prompt ended.
type modelPrecision struct {
	Model        string `json:"model"`
	PromptSHA256 string `json:"prompt_sha256"`
	Correct      int64  `json:"correct"`
	Wrong        int64  `json:"wrong"`
}

// precisionWindow is how far back precision counts rule endings.
const precisionWindow = 7 * 24 * time.Hour

// autopilotPage is GET /api/autopilot: the state the agent also reads, with
// spend and precision, which only people see.
func (s *Server) autopilotPage(w http.ResponseWriter, r *http.Request, _ *principal) error {
	ctx := r.Context()
	st, err := s.autopilotState(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	out := struct {
		*autopilotState
		Spend     map[string]spendWindow `json:"spend"`
		SpendDays []spendDay             `json:"spend_days"`
		Precision []modelPrecision       `json:"precision"`
	}{autopilotState: st, Spend: map[string]spendWindow{}}
	// Only finished runs count: a running one has no cost yet.
	rows, err := s.db.Query(ctx, `SELECT w.name, count(x.run_id), count(x.run_id) FILTER (WHERE x.configured_cost_usd_micros IS NULL),
		coalesce(sum(x.configured_cost_usd_micros), 0)::bigint, coalesce(sum(x.provider_cost_usd_micros), 0)::bigint
		FROM (VALUES ('last_24h', $1::timestamptz), ('last_7d', $2::timestamptz)) w (name, since)
		LEFT JOIN autopilot_runs r ON r.started_at >= w.since LEFT JOIN autopilot_run_results x ON x.run_id = r.id GROUP BY w.name`,
		now.Add(-24*time.Hour), now.Add(-7*24*time.Hour))
	if err != nil {
		return err
	}
	var name string
	var sw spendWindow
	if _, err := pgx.ForEachRow(rows, []any{&name, &sw.Runs, &sw.UnpricedRuns, &sw.Configured, &sw.Provider}, func() error {
		out.Spend[name] = sw
		return nil
	}); err != nil {
		return err
	}
	// A failed run that was retried is a second run of the same case, so
	// cases counts them once.
	since := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, 1-spendDays)
	rows, err = s.db.Query(ctx, `SELECT to_char((r.started_at AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD'), r.provider, r.model, count(*), count(DISTINCT r.case_id),
		count(*) FILTER (WHERE x.configured_cost_usd_micros IS NULL), coalesce(sum(x.configured_cost_usd_micros), 0)::bigint, coalesce(sum(x.provider_cost_usd_micros), 0)::bigint
		FROM autopilot_runs r JOIN autopilot_run_results x ON x.run_id = r.id WHERE r.started_at >= $1 GROUP BY 1, 2, 3 ORDER BY 1 DESC, 3, 2`, since)
	if err != nil {
		return err
	}
	days, err := pgx.CollectRows(rows, pgx.RowToStructByPos[spendDay])
	if err != nil {
		return err
	}
	out.SpendDays = orEmpty(days)
	// Correct: an enforcing rule that expired, or one a person adopted.
	// Wrong: rolled back by the guard, or retired as a false positive.
	// Other endings say nothing about the model.
	rows, err = s.db.Query(ctx, `SELECT r.model, encode(r.prompt_sha256, 'hex'),
		count(*) FILTER (WHERE ar.outcome IN ('adopted', 'expired')), count(*) FILTER (WHERE ar.outcome IN ('rolled_back', 'false_positive'))
		FROM autopilot_rules ar JOIN autopilot_proposals p ON p.id = ar.proposal_id JOIN autopilot_runs r ON r.id = p.run_id
		WHERE ar.kind = 'enforce' AND ar.ended_at >= $1
		AND (ar.outcome IN ('adopted', 'rolled_back', 'false_positive') OR (ar.outcome = 'expired' AND ar.enforcing_since IS NOT NULL))
		GROUP BY 1, 2 ORDER BY 1, 2`, now.Add(-precisionWindow))
	if err != nil {
		return err
	}
	if out.Precision, err = pgx.CollectRows(rows, pgx.RowToStructByPos[modelPrecision]); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// readAutopilotGauges fills the leader's autopilot gauges.
func (s *Server) readAutopilotGauges(ctx context.Context, g *autopilotGauges) error {
	set, err := loadAutopilot(ctx, s.db)
	if err != nil {
		return err
	}
	rs, err := s.runners(ctx, s.db)
	if err != nil {
		return err
	}
	if live, _ := s.connected(rs); len(live) > 0 {
		g.connected = 1
	}
	if err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM autopilot_cases WHERE state IN ('queued', 'running')),
		(SELECT count(*) FROM autopilot_rules WHERE state = 'observing'), (SELECT count(*) FROM autopilot_rules WHERE state = 'enforcing')`).
		Scan(&g.casesOpen, &g.rules[0], &g.rules[1]); err != nil {
		return err
	}
	rows, err := s.db.Query(ctx, "SELECT trust, count(*) FROM autopilot_notes GROUP BY trust")
	if err != nil {
		return err
	}
	var trust string
	var n int64
	if _, err := pgx.ForEachRow(rows, []any{&trust, &n}, func() error {
		if i := slices.Index(noteTrusts[:], trust); i >= 0 {
			g.notes[i] = n
		}
		return nil
	}); err != nil {
		return err
	}
	u, err := s.autopilotUsage(ctx, s.db)
	g.budget = [...]float64{ratioOf(u.Enforcing, set.MaxEnforcing), ratioOf(u.Sensors, set.MaxSensors), ratioOf(u.CasesHour, set.CasesPerHour)}
	return err
}

func (s *Server) autopilotRoutes() {
	s.autopilotSettingsRoutes()
	s.handle("GET /api/autopilot", "autopilot.read", s.autopilotPage)
	s.handle("GET /api/autopilot/contract", "autopilot.read", s.autopilotContract)
	s.handle("GET /api/autopilot/cases", "autopilot.read", s.listCases)
	s.handle("GET /api/autopilot/cases/{id}", "autopilot.read", s.getCase)
	s.handle("POST /api/autopilot/cases", "autopilot.manage", s.investigate)
	s.handle("POST /api/autopilot/rules/{id}/enforce", "autopilot.manage", s.approveRule)
	s.handle("POST /api/autopilot/rules/{id}/retire", "autopilot.manage", s.retireRule)
	s.handle("GET /api/autopilot/exclusions", "autopilot.read", s.listExclusions)
	s.handle("POST /api/autopilot/exclusions", "autopilot.manage", s.addExclusion)
	s.handle("POST /api/autopilot/exclusions/{id}/revoke", "autopilot.manage", s.revokeExclusion)
	s.handle("GET /api/autopilot/prices", "autopilot.read", s.listPrices)
	s.handle("POST /api/autopilot/prices", "settings.manage", s.addPrice)
	s.noteRoutes()
	s.runnerRoutes()
	s.mcpRoutes()
}

// caseRow is one case as the API lists it.
type caseRow struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	Rule       *string         `json:"rule"`
	RouteID    *int64          `json:"route_id"`
	AnomalyID  *int64          `json:"anomaly_id"`
	Question   string          `json:"question"`
	Brief      json.RawMessage `json:"brief"`
	State      string          `json:"state"`
	Attempts   int             `json:"attempts"`
	LeaseUntil *time.Time      `json:"lease_until"`
	RunID      *int64          `json:"run_id"`
	Verdict    *string         `json:"verdict"`
	Summary    string          `json:"summary"`
	OpenedBy   string          `json:"opened_by"`
	CreatedAt  time.Time       `json:"created_at"`
	ClosedAt   *time.Time      `json:"closed_at"`
	AblationOf *int64          `json:"ablation_of"`
}

const caseCols = "id, kind, rule, route_id, anomaly_id, question, brief, state, attempts, lease_until, run_id, verdict, summary, opened_by, created_at, closed_at, ablation_of"

// casesFor lists the latest cases, on one rule when rule is set. For the
// run of ablation, an ablation case, it leaves out every ablation and the
// cases its withheld notes were served to, whose answers lean on them.
func (s *Server) casesFor(ctx context.Context, rule string, limit int, ablation int64) ([]caseRow, error) {
	rows, err := s.db.Query(ctx, "SELECT "+caseCols+` FROM autopilot_cases c WHERE ($1 = '' OR rule = $1) AND ($3 = 0 OR kind <> 'ablation'
		AND NOT EXISTS (SELECT 1 FROM autopilot_note_uses u JOIN autopilot_cases a ON a.id = $3
			WHERE u.case_id = c.id AND u.note_id = ANY(a.withheld_notes) AND u.source = 'search' AND u.matched))
		ORDER BY id DESC LIMIT $2`, rule, limit, ablation)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[caseRow])
}

func (s *Server) listCases(w http.ResponseWriter, r *http.Request, _ *principal) error {
	cases, err := s.casesFor(r.Context(), r.URL.Query().Get("rule"), 100, 0)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, orEmpty(cases))
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		return 0, fail(http.StatusNotFound, "no such id")
	}
	return id, nil
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request, p *principal) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	rows, err := s.db.Query(ctx, "SELECT "+caseCols+" FROM autopilot_cases WHERE id = $1", id)
	if err != nil {
		return err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[caseRow])
	if errors.Is(err, pgx.ErrNoRows) {
		return fail(http.StatusNotFound, fmt.Sprintf("no case %d", id))
	}
	if err != nil {
		return err
	}
	out := map[string]any{"case": c}
	for key, q := range map[string]string{
		"runs": `SELECT r.id, r.attempt, r.runner, r.provider, r.model, encode(r.prompt_sha256, 'hex') AS prompt_sha256,
			encode(r.tools_sha256, 'hex') AS tools_sha256, r.started_at,
			x.finished_at, x.status, x.error_category, x.turns, x.tool_calls, x.input_tokens, x.output_tokens, x.cache_read_tokens, x.cache_write_tokens,
			x.configured_cost_usd_micros, x.provider_cost_usd_micros, x.telemetry_complete
			FROM autopilot_runs r LEFT JOIN autopilot_run_results x ON x.run_id = r.id WHERE r.case_id = $1 ORDER BY r.id`,
		"proposals": `SELECT id, run_id, action, rule_id, rule, ttl_seconds, rationale, evidence, checks, accepted, created_at
			FROM autopilot_proposals WHERE case_id = $1 ORDER BY id`,
		// Every MCP call the runs made, as admin recorded it. A run keeps at
		// most 1000 events and 4 MiB, and a case has at most 2 runs.
		"tool_calls": `SELECT e.run_id, e.seq, e.at, e.payload FROM autopilot_run_events e JOIN autopilot_runs r ON r.id = e.run_id
			WHERE r.case_id = $1 AND e.source = 'admin' ORDER BY e.run_id, e.seq`,
		"transitions": "SELECT rule_id, from_state, to_state, reason, numbers, version, actor, at FROM autopilot_transitions WHERE case_id = $1 ORDER BY id",
	} {
		rows, err := s.db.Query(ctx, q, id)
		if err != nil {
			return err
		}
		got, err := pgx.CollectRows(rows, pgx.RowToMap)
		if err != nil {
			return err
		}
		out[key] = orEmpty(got)
	}
	for _, tc := range out["tool_calls"].([]map[string]any) {
		pl, _ := tc["payload"].(map[string]any)
		tool, _ := pl["tool"].(string)
		why := answerHidden(p, tool)
		if why == "" {
			continue
		}
		// A connector call's query and error text are its answer's too.
		connector := toolConnector[tool] != ""
		if connector {
			delete(pl, "arguments")
			delete(pl, "refusal")
		}
		if pl["result"] != nil || connector {
			delete(pl, "result")
			pl["hidden"], pl["hidden_reason"] = true, why
		}
	}
	rules, err := s.loadRules(ctx, s.db, "case_id = $1", id)
	if err != nil {
		return err
	}
	views := []ruleView{}
	for _, rule := range rules {
		views = append(views, viewOf(rule))
	}
	out["rules"] = views
	return writeJSON(w, http.StatusOK, out)
}

// casesClosed is why no case can open now, as a person asking for one is
// told, or "": the autopilot is off, or no runner was seen lately.
func (s *Server) casesClosed(ctx context.Context, q querier) (string, error) {
	set, err := loadAutopilot(ctx, q)
	if err != nil {
		return "", err
	}
	if set.Mode == "off" {
		return "autopilot is off; turn it on in the autopilot settings first", nil
	}
	rs, err := s.runners(ctx, q)
	if err != nil {
		return "", err
	}
	if live, _ := s.connected(rs); len(live) == 0 {
		return "no autopilot runner has been seen in the last 2 minutes; start the runner, then investigate", nil
	}
	return "", nil
}

// investigate opens a case a person asks for, on a rule, route or anomaly.
func (s *Server) investigate(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Rule      string `json:"rule"`
		RouteID   *int64 `json:"route_id"`
		AnomalyID *int64 `json:"anomaly_id"`
		Question  string `json:"question"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	c := caseIn{Kind: "investigate", Question: strings.TrimSpace(in.Question)}
	targets := 0
	if in.Rule != "" {
		targets++
		c.Rule, c.DedupeKey = &in.Rule, "rule:"+in.Rule
	}
	if in.RouteID != nil {
		targets++
		c.RouteID, c.DedupeKey = in.RouteID, fmt.Sprintf("route:%d", *in.RouteID)
	}
	if in.AnomalyID != nil {
		targets++
		c.AnomalyID, c.DedupeKey = in.AnomalyID, fmt.Sprintf("anomaly:%d", *in.AnomalyID)
	}
	switch {
	case targets > 1:
		return fail(http.StatusUnprocessableEntity, "name one of rule, route_id or anomaly_id")
	case utf8.RuneCountInString(in.Rule) > 200 || utf8.RuneCountInString(c.Question) > 2000:
		return fail(http.StatusUnprocessableEntity, "rule is at most 200 characters and question at most 2000")
	case targets == 0 && c.Question == "":
		return fail(http.StatusUnprocessableEntity, "name a rule, route_id or anomaly_id, or ask a question")
	case targets == 0:
		sum := sha256.Sum256([]byte(c.Question))
		c.DedupeKey = "question:" + hex.EncodeToString(sum[:])
	}
	c.Brief = map[string]any{"kind": "investigate", "rule": c.Rule, "route_id": c.RouteID, "anomaly_id": c.AnomalyID, "question": c.Question}
	ctx := r.Context()
	why, err := s.casesClosed(ctx, s.db)
	if err != nil {
		return err
	}
	if why != "" {
		return fail(http.StatusConflict, why)
	}
	var id int64
	err = dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var opened bool
		var err error
		if id, opened, err = s.openCase(ctx, tx, c, p.actor); err != nil || opened {
			return err
		}
		open, err := openCaseCount(ctx, tx)
		if err != nil {
			return err
		}
		if open >= maxOpenCases {
			return fail(http.StatusConflict, fmt.Sprintf("%d cases are open, the most allowed; wait for some to finish", maxOpenCases))
		}
		return fail(http.StatusConflict, "a case is already open on "+strings.Replace(c.DedupeKey, ":", " ", 1))
	}))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// approveRule lets an enforce rule observed long enough block on the next
// tick, in observe mode where the autopilot waits for a person.
func (s *Server) approveRule(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	id := r.PathValue("id")
	err := s.autopilotTx(ctx, func(tx pgx.Tx) error {
		ar, err := s.loadRule(ctx, tx, id)
		if err != nil {
			return err
		}
		if ar.Kind != "enforce" || ar.State != "observing" {
			return fail(http.StatusConflict, fmt.Sprintf("rule %s is a %s rule %s; only an observing enforce rule can be approved", id, ar.Kind, ar.State))
		}
		set, err := loadAutopilot(ctx, tx)
		if err != nil {
			return err
		}
		observe, err := s.observeFor(ctx, tx, set, *ar)
		if err != nil {
			return err
		}
		if seen := s.now().Sub(*ar.LiveSince); seen < observe {
			s.met.autopilot.rejected("observed_too_short")
			return fail(http.StatusConflict, fmt.Sprintf("observed_too_short: rule %s has observed for %s of the %s it must", id, seen.Truncate(time.Second), observe))
		}
		if _, err := tx.Exec(ctx, "UPDATE autopilot_rules SET approved_by = $2 WHERE id = $1", id, p.actor); err != nil {
			return err
		}
		return admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: p.actor, Action: "autopilot.approve", Target: "rule " + id})
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// retireRule ends a rule a person no longer wants. The next tick publishes
// the overlay without it.
func (s *Server) retireRule(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Reason        string `json:"reason"`
		FalsePositive bool   `json:"false_positive"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	if in.Reason = strings.TrimSpace(in.Reason); in.Reason == "" || len(in.Reason) > 500 {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid retire", Errors: []expr.Issue{{Path: "reason", Msg: "is required, at most 500 characters"}}}
	}
	ctx := r.Context()
	id := r.PathValue("id")
	err := s.autopilotTx(ctx, func(tx pgx.Tx) error {
		ar, err := s.loadRule(ctx, tx, id)
		if err != nil {
			return err
		}
		if !slices.Contains(liveStates, ar.State) {
			return fail(http.StatusConflict, fmt.Sprintf("rule %s is %s already", id, ar.State))
		}
		outcome := "retired"
		if in.FalsePositive {
			outcome = "false_positive"
		}
		return s.applyChanges(ctx, tx, []ruleChange{{from: ar.State, next: ended(*ar, "retired", outcome, s.now()), reason: in.Reason, actor: p.actor,
			action: "autopilot.retire", numbers: map[string]any{"false_positive": in.FalsePositive}}}, nil)
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// priceView is one price row in USD per million tokens.
type priceView struct {
	ID            int64     `json:"id"`
	Provider      string    `json:"provider"`
	Model         string    `json:"model"`
	Input         float64   `json:"input_usd_per_mtok"`
	Output        float64   `json:"output_usd_per_mtok"`
	CacheRead     float64   `json:"cache_read_usd_per_mtok"`
	CacheWrite    float64   `json:"cache_write_usd_per_mtok"`
	EffectiveFrom time.Time `json:"effective_from"`
	Author        string    `json:"author"`
}

func (s *Server) listPrices(w http.ResponseWriter, r *http.Request, _ *principal) error {
	rows, err := s.db.Query(r.Context(), `SELECT id, provider, model, input_usd_micros_per_mtok / 1e6, output_usd_micros_per_mtok / 1e6, cache_read_usd_micros_per_mtok / 1e6,
		cache_write_usd_micros_per_mtok / 1e6, effective_from, author FROM autopilot_model_prices ORDER BY effective_from DESC, id DESC LIMIT 500`)
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[priceView])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, orEmpty(list))
}

// maxPriceUSD per million tokens bounds a typo, and keeps tokens times
// price within int64 micro-USD.
const maxPriceUSD = 1000

// usdMicros is v USD in micro-USD, refusing what is not a finite amount
// from 0 to most.
func usdMicros(v, most float64) (int64, bool) {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > most {
		return 0, false
	}
	return int64(math.Round(v * 1e6)), true
}

func (s *Server) addPrice(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in priceView
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	var errs []expr.Issue
	if in.Provider != "claude" && in.Provider != "openai" {
		errs = append(errs, expr.Issue{Path: "provider", Msg: "must be claude or openai"})
	}
	if !modelID.MatchString(in.Model) {
		errs = append(errs, expr.Issue{Path: "model", Msg: "must be a model id of 1 to 100 letters, digits and ._:/@-"})
	}
	if in.EffectiveFrom.IsZero() {
		errs = append(errs, expr.Issue{Path: "effective_from", Msg: "is required"})
	}
	var micros [4]int64
	for i, f := range []struct {
		path string
		v    float64
	}{{"input_usd_per_mtok", in.Input}, {"output_usd_per_mtok", in.Output}, {"cache_read_usd_per_mtok", in.CacheRead}, {"cache_write_usd_per_mtok", in.CacheWrite}} {
		var ok bool
		if micros[i], ok = usdMicros(f.v, maxPriceUSD); !ok {
			errs = append(errs, expr.Issue{Path: f.path, Msg: fmt.Sprintf("must be 0 to %d USD per million tokens", maxPriceUSD)})
		}
	}
	if errs != nil {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid price", Errors: errs}
	}
	ctx := r.Context()
	var id int64
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		err := tx.QueryRow(ctx, `INSERT INTO autopilot_model_prices (provider, model, input_usd_micros_per_mtok, output_usd_micros_per_mtok, cache_read_usd_micros_per_mtok,
			cache_write_usd_micros_per_mtok, effective_from, author) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
			in.Provider, in.Model, micros[0], micros[1], micros[2], micros[3], in.EffectiveFrom, p.actor).Scan(&id)
		in.ID, in.Author = id, p.actor
		return admindb.Event{Action: "settings.autopilot_price", Target: fmt.Sprintf("price %d", id), Details: map[string]any{"price": in}}, err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// autopilotContract is what a claim gives the runner, minus the case: the
// prompt, this deployment's tools, both hashes and the output schema, so a
// replay can run a recorded case without admin opening a run. Each tool
// also says whether its answer is evidence, as admin's MCP marks it; that
// is outside the hashed tools, so tools_sha256 stays the claim's.
func (s *Server) autopilotContract(w http.ResponseWriter, _ *http.Request, _ *principal) error {
	type contractEntry struct {
		mcpTool
		Evidence bool `json:"evidence"`
	}
	tools := make([]contractEntry, 0, len(s.tools))
	for _, t := range s.tools {
		tools = append(tools, contractEntry{t, citable(t)})
	}
	return writeJSON(w, http.StatusOK, map[string]any{"prompt": autopilotPrompt, "prompt_sha256": hex.EncodeToString(promptSHA256[:]),
		"tools": tools, "tools_sha256": hex.EncodeToString(s.toolsSHA256[:]), "output_schema": verdictSchema})
}
