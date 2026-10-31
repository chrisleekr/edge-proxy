package admin

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// autopilotPrompt is the system prompt every runner gets with its claim,
// so Claude and OpenAI get the same instructions and a prompt change ships
// with the admin release that changes the tools.
//
//go:embed autopilot_prompt.md
var autopilotPrompt string

var promptSHA256 = sha256.Sum256([]byte(autopilotPrompt))

// verdictSchema is the output schema the runner asks the model for.
var verdictSchema = json.RawMessage(`{"type":"object","required":["verdict","summary","proposals"],"additionalProperties":false,"properties":{` +
	`"verdict":{"type":"string","enum":["attack","benign","unsure"]},"summary":{"type":"string","maxLength":4000},` +
	`"proposals":{"type":"array","items":{"type":"integer"},"maxItems":50}}}`)

// Run record bounds. An event over maxEventBytes is stored as a marker with
// its size and hash; a run holds at most maxRunEvents events and
// maxRunEventBytes of payload; one batch is at most maxEventBatch.
const (
	maxEventBytes    = 64 << 10
	maxRunEvents     = 1000
	maxRunEventBytes = 4 << 20
	maxEventBatch    = 1 << 20
	maxClaimWait     = 30 * time.Second
	maxTokens        = 1_000_000_000
)

func (s *Server) runnerRoutes() {
	s.handle("POST /v1/autopilot/claim", permAutopilot, s.claim)
	s.handle("POST /v1/autopilot/cases/{id}/heartbeat", permAutopilot, s.heartbeat)
	s.handle("POST /v1/autopilot/cases/{id}/result", permAutopilot, s.caseResult)
	s.handle("POST /v1/autopilot/runs/{id}/events", permAutopilot, s.runEvents)
}

// readJSONLimit is readJSON with a smaller body limit.
func readJSONLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	return decodeOne(dec, v, "invalid JSON body")
}

func validProviders(ps []string) bool {
	return len(ps) <= len(llmProviders) && !slices.ContainsFunc(ps, func(p string) bool { return !slices.Contains(llmProviders[:], p) })
}

type claimIn struct {
	Runner     string             `json:"runner"`
	Version    string             `json:"version"`
	SDKVersion string             `json:"sdk_version"`
	Providers  []string           `json:"providers"`
	Wait       *snapshot.Duration `json:"wait"`
}

// claim long-polls for a queued case. It answers 204 when none comes, the
// autopilot is off or cases_per_hour is spent, and 409 when the runner
// holds no credential for the model the case needs.
func (s *Server) claim(w http.ResponseWriter, r *http.Request, _ *principal) error {
	var in claimIn
	if err := readJSONLimit(w, r, &in, 16<<10); err != nil {
		return err
	}
	if in.Providers == nil {
		in.Providers = []string{}
	}
	wait := maxClaimWait
	if in.Wait != nil {
		wait = time.Duration(*in.Wait)
	}
	switch {
	case len(in.Runner) < 1 || len(in.Runner) > 100 || len(in.Version) > 100 || len(in.SDKVersion) > 200:
		return fail(http.StatusUnprocessableEntity, "runner is 1 to 100 characters, version at most 100 and sdk_version at most 200")
	case !validProviders(in.Providers):
		return fail(http.StatusUnprocessableEntity, "providers lists claude and openai only")
	case wait < 0 || wait > maxClaimWait:
		return fail(http.StatusUnprocessableEntity, "wait is 0s to 30s")
	}
	ctx := r.Context()
	if _, err := s.db.Exec(ctx, `INSERT INTO autopilot_runners (id, version, sdk_version, providers, last_seen) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET version = $2, sdk_version = $3, providers = $4, last_seen = $5`, in.Runner, in.Version, in.SDKVersion, in.Providers, s.now()); err != nil {
		return err
	}
	deadline := time.Now().Add(wait)
	for {
		got, err := s.tryClaim(ctx, in)
		if err != nil {
			return err
		}
		if got != nil {
			return writeJSON(w, http.StatusOK, got)
		}
		left := time.Until(deadline)
		if left <= 0 {
			w.WriteHeader(http.StatusNoContent)
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(min(left, time.Second)):
		}
	}
}

// claimOut is a claimed case: the run admin recorded for it and what the
// runner needs to run it.
type claimOut struct {
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

func (s *Server) tryClaim(ctx context.Context, in claimIn) (*claimOut, error) {
	var out *claimOut
	err := dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		set, err := loadAutopilot(ctx, tx)
		if err != nil || set.Mode == "off" {
			return err
		}
		// Claims count and insert runs under one lock, so concurrent claims
		// can't pass cases_per_hour together.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('autopilot-claim', 0))"); err != nil {
			return err
		}
		now := s.now()
		var used int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM autopilot_runs WHERE started_at > $1", now.Add(-time.Hour)).Scan(&used); err != nil || used >= set.CasesPerHour {
			return err
		}
		// The runner takes the oldest case whose model it holds a credential for.
		kinds := []string{} // never NULL, which would match no case
		for _, k := range caseTriggers {
			if slices.Contains(in.Providers, providerOf(caseModel(set, k))) {
				kinds = append(kinds, k)
			}
		}
		var c claimOut
		var attempts int
		// FOR NO KEY UPDATE, as the UPDATE below takes: a transaction holding
		// the audit lock may insert a row that references the case.
		err = tx.QueryRow(ctx, "SELECT id, kind, brief, attempts FROM autopilot_cases WHERE state = 'queued' AND kind = ANY($1) ORDER BY created_at, id LIMIT 1 FOR NO KEY UPDATE SKIP LOCKED", kinds).
			Scan(&c.CaseID, &c.Kind, &c.Brief, &attempts)
		if errors.Is(err, pgx.ErrNoRows) {
			var other string
			err := tx.QueryRow(ctx, "SELECT kind FROM autopilot_cases WHERE state = 'queued' AND NOT kind = ANY($1) ORDER BY created_at, id LIMIT 1", kinds).Scan(&other)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			model := caseModel(set, other)
			return fail(http.StatusConflict, fmt.Sprintf("runner %s has no credential for %s, the provider of model %s; give the runner one or change the model in the autopilot settings",
				in.Runner, providerOf(model), model))
		}
		if err != nil {
			return err
		}
		c.Model = caseModel(set, c.Kind)
		c.Provider = providerOf(c.Model)
		c.Attempt, c.LeaseUntil = attempts+1, now.Add(caseLease)
		c.Prompt, c.PromptSHA256, c.ToolsSHA256, c.OutputSchema = autopilotPrompt, hex.EncodeToString(promptSHA256[:]), hex.EncodeToString(s.toolsSHA256[:]), verdictSchema
		if err := tx.QueryRow(ctx, `INSERT INTO autopilot_runs (case_id, attempt, runner, runner_version, sdk_version, provider, model, prompt_sha256, tools_sha256, started_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`, c.CaseID, c.Attempt, in.Runner, in.Version, in.SDKVersion, c.Provider, c.Model,
			promptSHA256[:], s.toolsSHA256[:], now).Scan(&c.RunID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE autopilot_cases SET state = 'running', attempts = $2, lease_until = $3, run_id = $4 WHERE id = $1",
			c.CaseID, c.Attempt, c.LeaseUntil, c.RunID); err != nil {
			return err
		}
		out = &c
		return admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: "deployment:autopilot", Action: "autopilot.case_claim", Target: fmt.Sprintf("case %d", c.CaseID),
			Details: map[string]any{"run_id": c.RunID, "attempt": c.Attempt, "runner": in.Runner, "provider": c.Provider, "model": c.Model, "prompt_sha256": c.PromptSHA256}})
	}))
	return out, err
}

// caseModel is the model a case of kind runs on.
func caseModel(set AutopilotSettings, kind string) string {
	if kind == "sweep" || kind == "review" {
		return set.SweepModel
	}
	return set.Model
}

var errLeaseLost = fail(http.StatusConflict, "the lease on this case lapsed; drop the run")

// heartbeat extends a running case's lease and records which providers
// the runner holds a credential for.
func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request, _ *principal) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	var in struct {
		RunID     int64    `json:"run_id"`
		Providers []string `json:"providers"`
	}
	if err := readJSONLimit(w, r, &in, 16<<10); err != nil {
		return err
	}
	if !validProviders(in.Providers) {
		return fail(http.StatusUnprocessableEntity, "providers lists claude and openai only")
	}
	ctx := r.Context()
	now := s.now()
	lease := now.Add(caseLease)
	err = dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE autopilot_cases SET lease_until = $3 WHERE id = $1 AND state = 'running' AND run_id = $2 AND lease_until >= $4", id, in.RunID, lease, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errLeaseLost
		}
		if in.Providers == nil {
			_, err = tx.Exec(ctx, "UPDATE autopilot_runners SET last_seen = $2 WHERE id = (SELECT runner FROM autopilot_runs WHERE id = $1)", in.RunID, now)
		} else {
			_, err = tx.Exec(ctx, "UPDATE autopilot_runners SET last_seen = $2, providers = $3 WHERE id = (SELECT runner FROM autopilot_runs WHERE id = $1)", in.RunID, now, in.Providers)
		}
		return err
	}))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]time.Time{"lease_until": lease})
}

// runEvent is one event of a run, as the runner sends it.
type runEvent struct {
	Seq     int             `json:"seq"`
	Kind    string          `json:"kind"`
	At      time.Time       `json:"at"`
	Payload json.RawMessage `json:"payload"`
}

var errEventCap = fail(http.StatusConflict, fmt.Sprintf("the run has reached its record limit of %d events or %d MiB", maxRunEvents, maxRunEventBytes>>20))

// lockRun takes the transaction lock that orders writes to one run's events.
func lockRun(ctx context.Context, tx pgx.Tx, runID int64) error {
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('autopilot-run:' || $1::bigint, 0))", runID)
	return err
}

// addEvents records events of a run under a lock on the run, refusing a
// batch that would pass the run's limits. An event over maxEventBytes is
// stored as a marker with its full size and hash. A batch sent again is
// stored once.
func (s *Server) addEvents(ctx context.Context, tx pgx.Tx, runID int64, source string, evs []runEvent) error {
	if err := lockRun(ctx, tx, runID); err != nil {
		return err
	}
	var n, total int64
	if err := tx.QueryRow(ctx, "SELECT count(*), coalesce(sum(bytes), 0) FROM autopilot_run_events WHERE run_id = $1", runID).Scan(&n, &total); err != nil {
		return err
	}
	// Only events not stored yet count: a batch sent again after a lost
	// answer must not be refused for events it already stored.
	seqs := make([]int, len(evs))
	for i, e := range evs {
		seqs[i] = e.Seq
	}
	rows, err := tx.Query(ctx, "SELECT seq FROM autopilot_run_events WHERE run_id = $1 AND source = $2 AND seq = ANY($3)", runID, source, seqs)
	if err != nil {
		return err
	}
	stored, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		return err
	}
	for _, e := range evs {
		if !slices.Contains(stored, e.Seq) {
			stored = append(stored, e.Seq)
			n++
			total += int64(len(e.Payload))
		}
	}
	if n > maxRunEvents || total > maxRunEventBytes {
		return errEventCap
	}
	for _, e := range evs {
		sum := sha256.Sum256(e.Payload)
		payload, cut := e.Payload, len(e.Payload) > maxEventBytes
		if cut {
			payload, _ = json.Marshal(map[string]any{"cut": true, "bytes": len(e.Payload), "sha256": hex.EncodeToString(sum[:])})
		}
		if _, err := tx.Exec(ctx, `INSERT INTO autopilot_run_events (run_id, source, seq, kind, at, payload, bytes, payload_sha256, cut)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (run_id, source, seq) DO NOTHING`,
			runID, source, e.Seq, e.Kind, e.At, string(payload), len(e.Payload), sum[:], cut); err != nil {
			return err
		}
	}
	return nil
}

// runEvents records what the model wrote, as the runner reports it.
func (s *Server) runEvents(w http.ResponseWriter, r *http.Request, _ *principal) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	var in struct {
		Events []runEvent `json:"events"`
	}
	if err := readJSONLimit(w, r, &in, maxEventBatch); err != nil {
		return err
	}
	for i, e := range in.Events {
		if e.Seq < 1 || len(e.Kind) < 1 || len(e.Kind) > 64 || e.At.IsZero() || len(e.Payload) == 0 {
			return fail(http.StatusUnprocessableEntity, fmt.Sprintf("events[%d] needs a seq of at least 1, a kind of 1 to 64 characters, at and payload", i))
		}
	}
	ctx := r.Context()
	err = dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// Locked before the check: the result hashes the run's events under
		// this lock, so a batch checked first could land after it.
		if err := lockRun(ctx, tx, id); err != nil {
			return err
		}
		var finished bool
		err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_run_results WHERE run_id = $1) FROM autopilot_runs WHERE id = $1", id).Scan(&finished)
		if errors.Is(err, pgx.ErrNoRows) {
			return fail(http.StatusNotFound, fmt.Sprintf("no run %d", id))
		}
		if err != nil {
			return err
		}
		if finished {
			return fail(http.StatusConflict, fmt.Sprintf("run %d has reported its result", id))
		}
		return s.addEvents(ctx, tx, id, "runner", in.Events)
	}))
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type resultIn struct {
	RunID            int64    `json:"run_id"`
	Status           string   `json:"status"`
	ErrorCategory    string   `json:"error_category"`
	Verdict          string   `json:"verdict"`
	Summary          string   `json:"summary"`
	Proposals        []int64  `json:"proposals"`
	Turns            int      `json:"turns"`
	ToolCalls        int      `json:"tool_calls"`
	Usage            tokenUse `json:"usage"`
	ProviderCostUSD  *float64 `json:"provider_cost_usd"`
	TranscriptBytes  int64    `json:"transcript_bytes"`
	TranscriptSHA256 string   `json:"transcript_sha256"`
	LastSeq          int      `json:"last_seq"`
}

type tokenUse struct {
	Input      int64 `json:"input_tokens"`
	Output     int64 `json:"output_tokens"`
	CacheRead  int64 `json:"cache_read_tokens"`
	CacheWrite int64 `json:"cache_write_tokens"`
}

func (u tokenUse) all() [4]int64 { return [...]int64{u.Input, u.Output, u.CacheRead, u.CacheWrite} }

func (u tokenUse) list() []int64 { a := u.all(); return a[:] }

func (in resultIn) problems() string {
	switch {
	case in.Status != "ok" && in.Status != "error" && in.Status != "timeout":
		return "status must be ok, error or timeout"
	case in.Status == "ok" && in.Verdict != "attack" && in.Verdict != "benign" && in.Verdict != "unsure":
		return "verdict must be attack, benign or unsure"
	// Characters, as the output schema's maxLength counts them.
	case utf8.RuneCountInString(in.Summary) > 4000 || len(in.ErrorCategory) > 64 || len(in.Proposals) > 50:
		return "summary is at most 4000 characters, error_category at most 64 and proposals at most 50"
	case in.Turns < 0 || in.ToolCalls < 0 || in.TranscriptBytes < 0 || in.LastSeq < 0:
		return "counts can't be negative"
	case slices.ContainsFunc(in.Usage.list(), func(t int64) bool { return t < 0 || t > maxTokens }):
		return "token counts are 0 to 1000000000"
	}
	if in.TranscriptSHA256 != "" {
		if b, err := hex.DecodeString(in.TranscriptSHA256); err != nil || len(b) != 32 {
			return "transcript_sha256 must be 64 hex characters"
		}
	}
	return ""
}

// caseResult records a run's verdict and telemetry and closes its case,
// with the audit row, in one transaction. A result from a run whose lease
// lapsed is kept as lease_lost and closes nothing.
func (s *Server) caseResult(w http.ResponseWriter, r *http.Request, _ *principal) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	var in resultIn
	if err := readJSONLimit(w, r, &in, 64<<10); err != nil {
		return err
	}
	if msg := in.problems(); msg != "" {
		return fail(http.StatusUnprocessableEntity, msg)
	}
	var providerCost *int64
	if in.ProviderCostUSD != nil {
		v, ok := usdMicros(*in.ProviderCostUSD, 1e6)
		if !ok {
			return fail(http.StatusUnprocessableEntity, "provider_cost_usd must be 0 to 1000000")
		}
		providerCost = &v
	}
	var transcript []byte
	if in.TranscriptSHA256 != "" {
		transcript, _ = hex.DecodeString(in.TranscriptSHA256)
	}
	ctx := r.Context()
	now := s.now()
	var kind, provider, model, pricedModel, closedAs string
	var started time.Time
	var configured *int64
	stale := false
	// An ablation's result can contest notes, counted once this commits.
	err = s.noteTx(ctx, func(tx pgx.Tx) error {
		var state string
		var runID *int64
		var lease *time.Time
		var attempts int
		// FOR NO KEY UPDATE, as the UPDATE below takes: a tool call holding the
		// run's lock still inserts rows that reference the case.
		err := tx.QueryRow(ctx, "SELECT state, run_id, lease_until, kind, attempts FROM autopilot_cases WHERE id = $1 FOR NO KEY UPDATE", id).Scan(&state, &runID, &lease, &kind, &attempts)
		if errors.Is(err, pgx.ErrNoRows) {
			return fail(http.StatusNotFound, fmt.Sprintf("no case %d", id))
		}
		if err != nil {
			return err
		}
		// Events and the result of one run are written in order: none
		// lands between the count and hash below and the result.
		if err := lockRun(ctx, tx, in.RunID); err != nil {
			return err
		}
		var caseOf int64
		var finished bool
		err = tx.QueryRow(ctx, "SELECT case_id, provider, model, started_at, EXISTS (SELECT 1 FROM autopilot_run_results WHERE run_id = $1) FROM autopilot_runs WHERE id = $1", in.RunID).
			Scan(&caseOf, &provider, &model, &started, &finished)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && caseOf != id {
			return fail(http.StatusNotFound, fmt.Sprintf("no run %d of case %d", in.RunID, id))
		}
		if err != nil {
			return err
		}
		if finished {
			return fail(http.StatusConflict, fmt.Sprintf("run %d has reported its result", in.RunID))
		}
		stale = state != "running" || runID == nil || *runID != in.RunID || lease == nil || lease.Before(now)
		var count, maxSeq int
		if err := tx.QueryRow(ctx, "SELECT count(*), coalesce(max(seq), 0) FROM autopilot_run_events WHERE run_id = $1 AND source = 'runner'", in.RunID).Scan(&count, &maxSeq); err != nil {
			return err
		}
		complete := count == in.LastSeq && maxSeq == in.LastSeq
		var priceID *int64
		var prices [4]int64
		err = tx.QueryRow(ctx, `SELECT id, input_usd_micros_per_mtok, output_usd_micros_per_mtok, cache_read_usd_micros_per_mtok, cache_write_usd_micros_per_mtok
			FROM autopilot_model_prices WHERE provider = $1 AND model = $2 AND effective_from <= $3 ORDER BY effective_from DESC, id DESC LIMIT 1`, provider, model, started).
			Scan(&priceID, &prices[0], &prices[1], &prices[2], &prices[3])
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		default:
			// Tokens and prices are bounded, so the sum stays within int64.
			var sum int64
			for i, t := range in.Usage.all() {
				sum += t * prices[i]
			}
			cost := (sum + 500_000) / 1_000_000
			configured, pricedModel = &cost, model
		}
		var eventsSHA []byte
		if err := tx.QueryRow(ctx, "SELECT sha256(string_agg(payload_sha256, ''::bytea ORDER BY id)) FROM autopilot_run_events WHERE run_id = $1", in.RunID).Scan(&eventsSHA); err != nil {
			return err
		}
		status := in.Status
		if stale {
			status = "lease_lost"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO autopilot_run_results (run_id, finished_at, status, error_category, turns, tool_calls, input_tokens, output_tokens,
			cache_read_tokens, cache_write_tokens, price_id, configured_cost_usd_micros, provider_cost_usd_micros, transcript_bytes, transcript_sha256, events_sha256, telemetry_complete)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
			in.RunID, now, status, in.ErrorCategory, in.Turns, in.ToolCalls, in.Usage.Input, in.Usage.Output, in.Usage.CacheRead, in.Usage.CacheWrite,
			priceID, configured, providerCost, in.TranscriptBytes, transcript, eventsSHA, complete); err != nil {
			return err
		}
		in.Status = status
		if stale {
			return nil
		}
		details := map[string]any{"run_id": in.RunID, "status": status, "events_sha256": hex.EncodeToString(eventsSHA), "transcript_sha256": in.TranscriptSHA256,
			"telemetry_complete": complete, "proposals": orEmpty(in.Proposals)}
		action := "autopilot.case_close"
		switch {
		case in.Status == "ok":
			closedAs = in.Verdict
			details["verdict"], details["summary"] = in.Verdict, in.Summary
			_, err = tx.Exec(ctx, "UPDATE autopilot_cases SET state = 'done', verdict = $2, summary = $3, closed_at = $4, lease_until = NULL WHERE id = $1", id, in.Verdict, in.Summary, now)
			if err == nil && kind == "ablation" {
				err = s.ablationDone(ctx, tx, id, in.RunID, in.Verdict)
			}
		case attempts < maxAttempts:
			action, details["state"] = "autopilot.case_release", "queued"
			_, err = tx.Exec(ctx, "UPDATE autopilot_cases SET state = 'queued', lease_until = NULL, queued_at = $2 WHERE id = $1", id, now)
		default:
			closedAs, details["state"] = "failed", "failed"
			_, err = tx.Exec(ctx, "UPDATE autopilot_cases SET state = 'failed', summary = $2, closed_at = $3, lease_until = NULL WHERE id = $1",
				id, fmt.Sprintf("the run ended with %s after %d attempts; a person needs to look", in.Status, attempts), now)
		}
		if err != nil {
			return err
		}
		return admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: "deployment:autopilot", Action: action, Target: fmt.Sprintf("case %d", id), Details: details})
	})
	if err != nil {
		return err
	}
	s.met.autopilot.runFinished(provider, pricedModel, in.Status, in.Usage.all(), [2]*int64{configured, providerCost}, now.Sub(started))
	if closedAs != "" {
		s.met.autopilot.caseClosed(kind, closedAs)
	}
	if stale {
		return fail(http.StatusConflict, fmt.Sprintf("the lease on case %d lapsed before this result; it is kept as lease_lost and does not close the case", id))
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
