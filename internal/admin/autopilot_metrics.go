package admin

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Label values of the autopilot's fixed series, exported from zero.
var (
	// The claim filter reads it too: a case kind missing here is never claimed.
	caseTriggers    = [...]string{"anomaly", "sweep", "review", "investigate", "ablation"}
	caseVerdicts    = [...]string{"attack", "benign", "unsure", "failed", "cancelled"}
	proposalActions = [...]string{"add_sensor", "enforce", "retire"}
	proposalResults = [...]string{"accepted", "rejected"}
	policyReasons   = [...]string{"not_overlay_shape", "site_wide", "fail_mode", "key_needs_ip_or_jwt", "constant_or_host_key", "missing_key_rejects",
		"ttl_over_max", "lifetime_over_max", "penalty_past_expiry", "named_subjects", "duplicate", "suppressed", "compile", "budget_enforcing",
		"budget_sensors", "observed_too_short", "block_share", "crawler_subject", "protected_subject", "attack_stopped", "schema", "deployment",
		"note_key", "note_jwt_key", "note_expected_pattern"}
	llmProviders = [...]string{"claude", "openai"}
	runStatuses  = [...]string{"ok", "error", "timeout", "lease_lost"}
	tokenKinds   = [...]string{"input", "output", "cache_read", "cache_write"}
	costSources  = [...]string{"configured", "provider"}
	ruleStates   = [...]string{"observing", "enforcing"}
	budgetNames  = [...]string{"enforcing", "sensors", "cases_hour"}
	noteResults  = [...]string{"written", "refused"}
	noteRefusals = [...]string{"off", "ablation", "invalid", "credential", "run_limit", "day_limit", "scope_limit", "total_limit", "hypothesis", "scope", "claim",
		"evidence", "false_claim", "anchor", "merges"}
	noteTrusts    = [...]string{"unconfirmed", "confirmed", "dormant", "retracted", "retired"}
	runSecondsLes = [...]float64{10, 30, 60, 120, 300, 600, 1200}
)

// maxModelLabels bounds the model label per provider. Models past it are
// counted as "other".
const maxModelLabels = 16

// autopilotMetrics are this replica's autopilot counters. The LLM series
// carry a model label, so they live in a bounded map under a mutex: they
// change once per run, never on the request path.
type autopilotMetrics struct {
	cases      [len(caseTriggers)][len(caseVerdicts)]atomic.Uint64
	proposals  [len(proposalActions)][len(proposalResults)]atomic.Uint64
	rejections [len(policyReasons)]atomic.Uint64
	// runSeconds counts runs per provider and duration bucket; the last
	// bucket is above every bound.
	runSeconds [len(llmProviders)][len(runSecondsLes) + 1]atomic.Uint64
	notes      [len(noteResults)]atomic.Uint64
	refusals   [len(noteRefusals)]atomic.Uint64
	moved      [len(noteTrusts)]atomic.Uint64
	mu         sync.Mutex
	llm        map[llmKey]*llmCounts
}

type llmKey struct{ provider, model string }

type llmCounts struct {
	runs   [len(runStatuses)]uint64
	tokens [len(tokenKinds)]uint64
	cost   [len(costSources)]uint64 // micro-USD
}

func (m *autopilotMetrics) caseClosed(kind, verdict string) {
	t, v := slices.Index(caseTriggers[:], kind), slices.Index(caseVerdicts[:], verdict)
	if t >= 0 && v >= 0 {
		m.cases[t][v].Add(1)
	}
}

func (m *autopilotMetrics) proposed(action string, accepted bool, reasons []string) {
	r := 1
	if accepted {
		r = 0
	}
	if a := slices.Index(proposalActions[:], action); a >= 0 {
		m.proposals[a][r].Add(1)
	}
	for _, reason := range reasons {
		m.rejected(reason)
	}
}

func (m *autopilotMetrics) rejected(reason string) {
	if i := slices.Index(policyReasons[:], reason); i >= 0 {
		m.rejections[i].Add(1)
	}
}

func (m *autopilotMetrics) noteWritten() { m.notes[0].Add(1) }

func (m *autopilotMetrics) noteRefused(reason string) {
	m.notes[1].Add(1)
	if i := slices.Index(noteRefusals[:], reason); i >= 0 {
		m.refusals[i].Add(1)
	}
}

func (m *autopilotMetrics) noteMoved(to string) {
	if i := slices.Index(noteTrusts[:], to); i >= 0 {
		m.moved[i].Add(1)
	}
}

// runFinished counts one run. model is the priced model, or "" when the
// run had no price.
func (m *autopilotMetrics) runFinished(provider, model, status string, tokens [4]int64, costs [2]*int64, took time.Duration) {
	p := slices.Index(llmProviders[:], provider)
	st := slices.Index(runStatuses[:], status)
	if p < 0 || st < 0 {
		return
	}
	b := len(runSecondsLes)
	for i, le := range runSecondsLes {
		if took.Seconds() <= le {
			b = i
			break
		}
	}
	m.runSeconds[p][b].Add(1)
	if model == "" {
		model = "unpriced"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.llm == nil {
		m.llm = map[llmKey]*llmCounts{}
	}
	k := llmKey{provider, model}
	if m.llm[k] == nil {
		n := 0
		for o := range m.llm {
			if o.provider == provider {
				n++
			}
		}
		if n >= maxModelLabels {
			k.model = "other"
		}
		if m.llm[k] == nil {
			m.llm[k] = &llmCounts{}
		}
	}
	c := m.llm[k]
	c.runs[st]++
	for i, t := range tokens {
		c.tokens[i] += uint64(max(t, 0))
	}
	for i, v := range costs {
		if v != nil {
			c.cost[i] += uint64(max(*v, 0))
		}
	}
}

// autopilotGauges are what the leader last read for the autopilot.
type autopilotGauges struct {
	connected int64
	casesOpen int64
	rules     [len(ruleStates)]int64
	budget    [len(budgetNames)]float64
	notes     [len(noteTrusts)]int64
}

func fmtFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func (m *autopilotMetrics) write(w io.Writer) {
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	p("# TYPE admin_autopilot_cases_total counter\n")
	for t := range caseTriggers {
		for v := range caseVerdicts {
			p("admin_autopilot_cases_total{trigger=%q,verdict=%q} %d\n", caseTriggers[t], caseVerdicts[v], m.cases[t][v].Load())
		}
	}
	p("# TYPE admin_autopilot_proposals_total counter\n")
	for a := range proposalActions {
		for r := range proposalResults {
			p("admin_autopilot_proposals_total{action=%q,result=%q} %d\n", proposalActions[a], proposalResults[r], m.proposals[a][r].Load())
		}
	}
	p("# TYPE admin_autopilot_policy_rejections_total counter\n")
	for i := range policyReasons {
		p("admin_autopilot_policy_rejections_total{reason=%q} %d\n", policyReasons[i], m.rejections[i].Load())
	}
	p("# TYPE admin_autopilot_note_writes_total counter\n")
	for i := range noteResults {
		p("admin_autopilot_note_writes_total{result=%q} %d\n", noteResults[i], m.notes[i].Load())
	}
	p("# TYPE admin_autopilot_note_refusals_total counter\n")
	for i := range noteRefusals {
		p("admin_autopilot_note_refusals_total{reason=%q} %d\n", noteRefusals[i], m.refusals[i].Load())
	}
	p("# TYPE admin_autopilot_note_transitions_total counter\n")
	for i := range noteTrusts {
		p("admin_autopilot_note_transitions_total{to=%q} %d\n", noteTrusts[i], m.moved[i].Load())
	}
	m.mu.Lock()
	keys := make([]llmKey, 0, len(m.llm))
	counts := make([]llmCounts, 0, len(m.llm))
	for k := range m.llm {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b llmKey) int {
		return cmp.Or(cmp.Compare(a.provider, b.provider), cmp.Compare(a.model, b.model))
	})
	for _, k := range keys {
		counts = append(counts, *m.llm[k])
	}
	m.mu.Unlock()
	p("# TYPE admin_autopilot_llm_runs_total counter\n")
	for i, k := range keys {
		for st := range runStatuses {
			p("admin_autopilot_llm_runs_total{provider=%q,model=%q,status=%q} %d\n", k.provider, k.model, runStatuses[st], counts[i].runs[st])
		}
	}
	p("# TYPE admin_autopilot_llm_tokens_total counter\n")
	for i, k := range keys {
		for t := range tokenKinds {
			p("admin_autopilot_llm_tokens_total{provider=%q,model=%q,kind=%q} %d\n", k.provider, k.model, tokenKinds[t], counts[i].tokens[t])
		}
	}
	p("# TYPE admin_autopilot_llm_cost_usd_total counter\n")
	for i, k := range keys {
		for c := range costSources {
			p("admin_autopilot_llm_cost_usd_total{provider=%q,model=%q,source=%q} %s\n", k.provider, k.model, costSources[c], fmtFloat(float64(counts[i].cost[c])/1e6))
		}
	}
	p("# TYPE admin_autopilot_llm_run_seconds histogram\n")
	for pi := range llmProviders {
		var cum uint64
		for b := range m.runSeconds[pi] {
			cum += m.runSeconds[pi][b].Load()
			le := "+Inf"
			if b < len(runSecondsLes) {
				le = fmtFloat(runSecondsLes[b])
			}
			p("admin_autopilot_llm_run_seconds_bucket{provider=%q,le=%q} %d\n", llmProviders[pi], le, cum)
		}
		p("admin_autopilot_llm_run_seconds_count{provider=%q} %d\n", llmProviders[pi], cum)
	}
}

func (g *autopilotGauges) write(w io.Writer) {
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	p("# TYPE admin_autopilot_agent_connected gauge\nadmin_autopilot_agent_connected %d\n", g.connected)
	p("# TYPE admin_autopilot_cases_open gauge\nadmin_autopilot_cases_open %d\n", g.casesOpen)
	p("# TYPE admin_autopilot_rules gauge\n")
	for i := range ruleStates {
		p("admin_autopilot_rules{state=%q} %d\n", ruleStates[i], g.rules[i])
	}
	p("# TYPE admin_autopilot_budget_used_ratio gauge\n")
	for i := range budgetNames {
		p("admin_autopilot_budget_used_ratio{budget=%q} %s\n", budgetNames[i], fmtFloat(g.budget[i]))
	}
	p("# TYPE admin_autopilot_notes gauge\n")
	for i := range noteTrusts {
		p("admin_autopilot_notes{trust=%q} %d\n", noteTrusts[i], g.notes[i])
	}
}
