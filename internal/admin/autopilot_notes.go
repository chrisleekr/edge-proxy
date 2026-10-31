package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// Memory bounds. A note is written by the case run that learned it and
// goes live without a person; these and the gate keep it from being
// poisoned or growing without end.
const (
	notesPerRun   = 3
	notesPerDay   = 20
	notesPerScope = 5
	notesKept     = 200
	// anchorDays of the baselineDays before is the history anchor.
	anchorDays = 7
	// dormantAfter unmatched uses in a row, a note is no longer served.
	dormantAfter = 3
	noteIdle     = 30 * 24 * time.Hour
	// searchBytes keeps a search answer under the result cap.
	searchBytes = mcpMaxResult - 8<<10
	maxSearched = 20
)

// keptTrust is a note that still counts against the limits.
var keptTrust = []string{"unconfirmed", "confirmed", "dormant"}

var noteKinds = []string{"context", "expected_pattern", "attack_signature", "collateral_risk", "key_preference"}

// apNote is one autopilot_notes row.
type apNote struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	Basis      string          `json:"basis"`
	Scope      noteScope       `json:"scope"`
	ScopeKey   string          `json:"scope_key"`
	Claim      *noteClaim      `json:"claim"`
	Effect     *noteEffect     `json:"effect"`
	Statement  string          `json:"statement"`
	Rationale  string          `json:"rationale"`
	Stats      *noteStats      `json:"stats"`
	Links      json.RawMessage `json:"links"`
	Evidence   json.RawMessage `json:"evidence"`
	Anchor     *string         `json:"anchor"`
	Trust      string          `json:"trust"`
	TrustSince time.Time       `json:"trust_since"`
	FailStreak int             `json:"fail_streak"`
	ServedAt   *time.Time      `json:"served_at"`
	CaseID     int64           `json:"case_id"`
	RunID      int64           `json:"run_id"`
	CreatedAt  time.Time       `json:"created_at"`
}

const noteCols = "id, kind, basis, scope, scope_key, claim, effect, statement, rationale, stats, links, evidence, anchor, trust, trust_since, fail_streak, served_at, case_id, run_id, created_at"

func loadNotes(ctx context.Context, q querier, where string, args ...any) ([]apNote, error) {
	rows, err := q.Query(ctx, "SELECT "+noteCols+" FROM autopilot_notes WHERE "+where+" ORDER BY id", args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[apNote])
}

// evidenceRef is a cited read: the run event that recorded it, which is
// never pruned, and the hash of what it answered.
type evidenceRef struct {
	RunID  int64  `json:"run_id"`
	Seq    int64  `json:"seq"`
	Tool   string `json:"tool"`
	SHA256 string `json:"sha256"`
}

type learningIn struct {
	Kind      string      `json:"kind"`
	Basis     string      `json:"basis"`
	Scope     noteScope   `json:"scope"`
	Claim     *noteClaim  `json:"claim"`
	Effect    *noteEffect `json:"effect"`
	Evidence  []int64     `json:"evidence"`
	Statement string      `json:"statement"`
	Rationale string      `json:"rationale"`
	Merges    []int64     `json:"merges"`
}

// credential matches what looks like a secret in a decoded string: bearer
// tokens, JWTs, cloud and SaaS keys, private keys and key=value assignments.
var credential = regexp.MustCompile(`Bearer\s+\S{8,}|eyJ[\w-]+\.[\w-]+\.[\w-]+|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|sk-[\w-]{20,}|` +
	`gh[pousr]_\w{30,}|xox[abposr]-|(?i:(api[_-]?key|secret|password|token)\s*[:=]\s*\S{6,})`)

// rawCredential is credential for raw JSON. Its runs stop at a quote, so a
// match stays inside one string value instead of reaching the next field.
var rawCredential = regexp.MustCompile(strings.ReplaceAll(credential.String(), `\S`, `[^\s"]`))

// looksLikeCredential reports whether a call's arguments hold what looks
// like a secret. The raw bytes cover a call that does not decode and keys
// strict decoding drops as duplicates; the decoded values cover escapes.
func looksLikeCredential(args json.RawMessage) bool {
	var raw any
	return rawCredential.Match(args) || json.Unmarshal(args, &raw) == nil && holdsCredential(raw)
}

// holdsCredential reports whether any key or string value in v looks like
// a secret.
func holdsCredential(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if credential.MatchString(k) || holdsCredential(e) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(x, holdsCredential)
	case string:
		return credential.MatchString(x)
	}
	return false
}

// hedge is a word that marks a statement as a hypothesis. "may" counts in
// lower case only, so the month is no hedge.
var hedge = regexp.MustCompile(`(?i:\b(likely|unlikely|possibly|perhaps|probably|might|unconfirmed|suspect(ed)?|appears?|seems?|hypothesis)\b)|\bmay\b`)

// noteRefused is a record_learning refusal: the reason it is counted by
// and what the model is told.
type noteRefused struct{ reason, msg string }

func (e *noteRefused) Error() string { return e.msg }

func refuse(reason, format string, args ...any) error {
	return &noteRefused{reason: reason, msg: fmt.Sprintf(format, args...)}
}

// recordLearning is the record_learning tool: the gate, then the note, its
// revision, its audit row and the call event in one transaction.
func (s *Server) recordLearning(ctx context.Context, call *mcpCall, args json.RawMessage) (any, error) {
	out, err := s.learn(ctx, call, args)
	if r, ok := errors.AsType[*noteRefused](err); ok {
		s.met.autopilot.noteRefused(r.reason)
		return nil, fail(http.StatusUnprocessableEntity, r.msg)
	}
	return out, err
}

func (s *Server) learn(ctx context.Context, call *mcpCall, args json.RawMessage) (any, error) {
	// First, so a refusal, which reaches the model, never repeats a secret.
	// mcpHandler has already redacted the run's record of the call.
	if looksLikeCredential(args) {
		return nil, refuse("credential", "a field holds what looks like a credential; leave secrets and tokens out of notes")
	}
	set, err := loadAutopilot(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if set.Mode == "off" {
		return nil, refuse("off", "autopilot is off")
	}
	if call.kind == "ablation" {
		return nil, refuse("ablation", "an ablation run re-answers its case without some notes, so it records no notes")
	}
	var in learningIn
	if err := strict(args, &in); err != nil {
		return nil, refuse("invalid", "%s", errText(err))
	}
	in.Statement, in.Rationale = strings.TrimSpace(in.Statement), strings.TrimSpace(in.Rationale)
	switch n := utf8.RuneCountInString(in.Statement); {
	case !slices.Contains(noteKinds, in.Kind):
		return nil, refuse("invalid", "kind is one of %s", strings.Join(noteKinds, ", "))
	case in.Basis != "observed" && in.Basis != "hypothesis":
		return nil, refuse("invalid", "basis is observed or hypothesis")
	case n < 1 || n > 500 || utf8.RuneCountInString(in.Rationale) > 1000:
		return nil, refuse("invalid", "statement is 1 to 500 characters and rationale at most 1000")
	case len(in.Evidence) > 20 || len(in.Merges) > 5:
		return nil, refuse("invalid", "evidence has at most 20 ids and merges at most 5")
	}
	key := in.Scope.key()
	if len(key) > 700 {
		return nil, refuse("scope", "the scope is too long")
	}
	var out map[string]any
	var newID int64
	moves, err := s.notesTx(ctx, call.run, func(tx pgx.Tx) error {
		now := s.now()
		var run, day, scope, kept int
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE run_id = $1), count(*) FILTER (WHERE created_at > $2),
			count(*) FILTER (WHERE scope_key = $3 AND trust = ANY($4) AND NOT id = ANY($5)), count(*) FILTER (WHERE trust = ANY($4) AND NOT id = ANY($5)) FROM autopilot_notes`,
			call.run, now.Add(-24*time.Hour), key, keptTrust, orEmpty(in.Merges)).Scan(&run, &day, &scope, &kept); err != nil {
			return err
		}
		switch {
		case run >= notesPerRun:
			return refuse("run_limit", "a run records at most %d notes", notesPerRun)
		case day >= notesPerDay:
			return refuse("day_limit", "at most %d notes are written a day", notesPerDay)
		case scope >= notesPerScope:
			return refuse("scope_limit", "scope %s has %d notes already; merge them in the daily review", key, notesPerScope)
		case kept >= notesKept:
			return refuse("total_limit", "admin keeps at most %d notes", notesKept)
		}
		switch {
		case in.Basis == "hypothesis" && (in.Kind != "context" || in.Claim != nil || !hedge.MatchString(in.Statement)):
			return refuse("hypothesis", "a hypothesis is a context note with no claim whose statement says it is one, with a word such as likely or unconfirmed")
		case in.Basis == "observed" && in.Claim == nil:
			return refuse("hypothesis", "an observed note needs a claim admin can check; without one, write a context hypothesis")
		}
		if err := s.scopeExists(ctx, tx, in.Scope); err != nil {
			return err
		}
		if in.Claim != nil {
			if msg := claimProblem(in.Kind, in.Scope, *in.Claim, in.Effect, set.MaxBlockShare); msg != "" {
				return refuse("claim", "%s", msg)
			}
		} else if in.Effect != nil {
			return refuse("claim", "a hypothesis has no effect")
		}
		evidence, err := s.citedReads(ctx, tx, call.run, in.Basis, in.Evidence)
		if err != nil {
			return err
		}
		var st *noteStats
		links := map[string]any{}
		if in.Claim != nil {
			c := *in.Claim
			from, to := c.span(now)
			days, err := s.evalClaim(ctx, tx, in.Scope, c, from, to, baselineDays)
			if err != nil {
				return err
			}
			if !days[0].present {
				return refuse("false_claim", "claim: admin has no data in its window, so it can't check it")
			}
			stats := statsOf(c, from, to, days)
			if !stats.Holds {
				return refuse("false_claim", "claim is false on admin's data: %s from %s to %s is %s, not %s %s", c.Metric,
					from.Format(time.RFC3339), to.Format(time.RFC3339), fmtFloat(stats.Value), c.Op, fmtFloat(c.Value))
			}
			st, links = &stats, noteLinks(in.Scope, c, from, to)
		}
		var anchor *string
		if in.Kind == "expected_pattern" || in.Kind == "collateral_risk" || in.Kind == "context" {
			if anchor, err = s.anchorOf(ctx, tx, set, in.Scope, in.Claim, st); err != nil {
				return err
			}
			if anchor == nil && in.Kind != "context" {
				held := 0
				if st != nil && st.Baseline != nil {
					held = st.Baseline.HeldDays
				}
				return refuse("anchor", "a note that makes the autopilot less likely to act needs an anchor: a tight claim (a floor of at least half "+
					"what admin found, or a ceiling of at most twice it) that names a verified crawler range or protected subject, or that is also "+
					"tight against the median of the %d days before and held on %d of them, or a rule keyed on a verified JWT claim; its claim held on %d", baselineDays, anchorDays, held)
			}
		}
		if err := s.checkMerges(ctx, tx, call.caseID, in, key); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT nextval('autopilot_notes_id_seq')").Scan(&newID); err != nil {
			return err
		}
		fields := map[string]any{"kind": in.Kind, "basis": in.Basis, "scope": in.Scope, "claim": in.Claim, "effect": in.Effect, "statement": in.Statement,
			"rationale": in.Rationale, "stats": st, "links": links, "evidence": evidence, "anchor": anchor, "merges": orEmpty(in.Merges)}
		fb, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO autopilot_notes (id, kind, basis, scope, scope_key, claim, effect, statement, rationale, stats, links, evidence, anchor,
			trust, trust_since, case_id, run_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'unconfirmed', $14, $15, $16, $14)`,
			newID, in.Kind, in.Basis, in.Scope, key, in.Claim, in.Effect, in.Statement, in.Rationale, st, links, evidence, anchor, now, call.caseID, call.run); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO autopilot_note_revisions (note_id, change, trust, fields, actor, run_id, case_id, at)
			VALUES ($1, 'written', 'unconfirmed', $2, 'deployment:autopilot', $3, $4, $5)`, newID, string(fb), call.run, call.caseID, now); err != nil {
			return err
		}
		sum := sha256.Sum256(fb)
		if err := admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: "deployment:autopilot", Action: "autopilot.note_write", Target: fmt.Sprintf("note %d", newID),
			Details: map[string]any{"case": call.caseID, "run": call.run, "kind": in.Kind, "basis": in.Basis, "scope_key": key, "anchor": anchor,
				"merges": orEmpty(in.Merges), "fields_sha256": hex.EncodeToString(sum[:])}}); err != nil {
			return err
		}
		for _, m := range in.Merges {
			if _, err := s.setTrust(ctx, tx, m, keptTrust, "retired", "retired", fmt.Sprintf("merged into %d", newID), "deployment:autopilot", &call.run, &call.caseID); err != nil {
				return err
			}
		}
		out = map[string]any{"note_id": newID, "trust": "unconfirmed", "anchor": anchor, "stats": st}
		b, err := json.Marshal(out)
		if err != nil {
			return err
		}
		_, _, err = s.callEvent(ctx, tx, call.run, "record_learning", call.args, b, "", time.Since(call.start))
		return err
	})
	if err = proposeDone(err); err != nil {
		// As for a proposal: a note committed as the deadline ended has its
		// call event, so no refusal is recorded beside it.
		if newID != 0 && s.committed(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_notes WHERE id = $1)", newID) {
			call.recorded = true
			s.met.autopilot.noteWritten()
			s.countMoves(moves)
		}
		return nil, err
	}
	call.recorded = true
	s.met.autopilot.noteWritten()
	s.countMoves(moves)
	return out, nil
}

// movesTx is a transaction that keeps the note trust moves made in it, so
// they are counted only once it commits.
type movesTx struct {
	pgx.Tx
	moves *[]string
}

// txMoves runs fn in a transaction and returns the note trust moves it
// made. The caller counts them once it knows the transaction committed.
func (s *Server) txMoves(ctx context.Context, fn func(tx pgx.Tx) error) ([]string, error) {
	var moves []string
	err := dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error { return fn(movesTx{Tx: tx, moves: &moves}) }))
	return moves, err
}

// noteTx is txMoves that counts the moves when the transaction committed.
func (s *Server) noteTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	moves, err := s.txMoves(ctx, fn)
	if err == nil {
		s.countMoves(moves)
	}
	return err
}

func (s *Server) countMoves(moves []string) {
	for _, to := range moves {
		s.met.autopilot.noteMoved(to)
	}
}

// notesTx runs fn under run's lock, taken before any audit row as a case
// result takes it, then the lock that serializes note writes, so the
// limits hold against concurrent calls.
func (s *Server) notesTx(ctx context.Context, run int64, fn func(tx pgx.Tx) error) ([]string, error) {
	return s.txMoves(ctx, func(tx pgx.Tx) error {
		if err := lockRun(ctx, tx, run); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('autopilot-notes', 0))"); err != nil {
			return err
		}
		return fn(tx)
	})
}

// committed reports whether the EXISTS query finds what a call wrote, after
// its deadline may have ended it past its commit.
func (s *Server) committed(ctx context.Context, exists string, args ...any) bool {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mcpCallTimeout)
	defer cancel()
	var ok bool
	return s.db.QueryRow(cctx, exists, args...).Scan(&ok) == nil && ok
}

// scopeExists checks the scope names what admin has seen: a host or route
// in the observed routes, short of the overflow route, or a live rule.
func (s *Server) scopeExists(ctx context.Context, q querier, sc noteScope) error {
	named := func(v string) bool { return v != "" && v != "*" }
	var ok bool
	var err error
	switch sc.Kind {
	case "global":
		ok = sc.Host == "" && sc.Method == "" && sc.Template == "" && sc.Rule == ""
	case "host":
		ok = named(sc.Host) && sc.Method == "" && sc.Template == "" && sc.Rule == ""
		if ok {
			err = q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM observed_routes WHERE host = $1)", sc.Host).Scan(&ok)
		}
	case "route":
		ok = sc.Rule == "" && named(sc.Host) && named(sc.Method) && named(sc.Template)
		if ok {
			err = q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM observed_routes WHERE host = $1 AND method = $2 AND template = $3)", sc.Host, sc.Method, sc.Template).Scan(&ok)
		}
	case "rule":
		active, aerr := s.activeConfig(ctx, q)
		err = aerr
		ok = active != nil && sc.Host == "" && sc.Method == "" && sc.Template == "" &&
			slices.ContainsFunc(active.RateLimitRules, func(r snapshot.RateLimitRule) bool { return r.ID == sc.Rule })
	}
	if err != nil {
		return err
	}
	if !ok {
		return refuse("scope", "scope %s doesn't exist: name global, an observed host or route, or a live rate-limit rule", sc.key())
	}
	return nil
}

// citedReads checks each evidence id is a successful stats read of this
// run that admin kept whole, and returns them as references.
func (s *Server) citedReads(ctx context.Context, q querier, run int64, basis string, ids []int64) ([]evidenceRef, error) {
	if basis == "observed" && len(ids) == 0 {
		return nil, refuse("evidence", "an observed note cites at least one evidence id, a stats read of this run")
	}
	refs := []evidenceRef{}
	for _, id := range ids {
		var tool *string
		var allowed, cut bool
		var sum []byte
		err := q.QueryRow(ctx, `SELECT payload->>'tool', coalesce(payload->>'allowed' = 'true', false), cut, payload_sha256 FROM autopilot_run_events
			WHERE run_id = $1 AND source = 'admin' AND seq = $2`, run, id).Scan(&tool, &allowed, &cut, &sum)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return nil, refuse("evidence", "evidence %d: no such call in this run", id)
		case err != nil:
			return nil, err
		case cut:
			return nil, refuse("evidence", "evidence %d: it was too large to keep", id)
		case !allowed:
			return nil, refuse("evidence", "evidence %d: it was refused", id)
		}
		if i := slices.IndexFunc(mcpTools, func(t mcpTool) bool { return t.Name == *tool }); i < 0 || !citable(mcpTools[i]) {
			return nil, refuse("evidence", "evidence %d: %s can't be evidence; cite a stats read", id, *tool)
		}
		refs = append(refs, evidenceRef{RunID: run, Seq: id, Tool: *tool, SHA256: hex.EncodeToString(sum)})
	}
	return refs, nil
}

// anchorOf is what the attacker can't create behind a note: a verified
// crawler range or protected subject its tight claim names, a rule keyed
// on a verified JWT claim, or a claim tight against both now and the
// median of the days before that held on anchorDays of them.
func (s *Server) anchorOf(ctx context.Context, q querier, set AutopilotSettings, sc noteScope, c *noteClaim, st *noteStats) (*string, error) {
	pick := func(a string) (*string, error) { return &a, nil }
	// A loose claim holds whatever the traffic does, so it anchors nothing.
	claimed := c != nil && st != nil && tight(*c, st.Value)
	if claimed {
		if sub, ok := claimSubject(*c); ok {
			if slices.ContainsFunc(protectedPrefixes(set), func(p netip.Prefix) bool { return inside(p, sub) }) {
				return pick("protected")
			}
			crawlers, err := s.crawlerPrefixes(ctx, q)
			if err != nil {
				return nil, err
			}
			if slices.ContainsFunc(crawlers, func(p netip.Prefix) bool { return inside(p, sub) }) {
				return pick("crawler")
			}
		}
	}
	if sc.Kind == "rule" {
		active, err := s.activeConfig(ctx, q)
		if err != nil {
			return nil, err
		}
		if active != nil && len(active.Auth.Issuers) > 0 && slices.ContainsFunc(active.RateLimitRules, func(r snapshot.RateLimitRule) bool {
			return r.ID == sc.Rule && slices.ContainsFunc(r.Key, func(k string) bool { return strings.HasPrefix(k, "jwt_claim:") })
		}) {
			return pick("jwt_claim")
		}
	}
	// Tight against the median too: a ceiling twice a one-day spike holds on
	// every normal day before.
	if claimed && st.Baseline != nil && st.Baseline.HeldDays >= anchorDays && tight(*c, st.Baseline.Median) {
		return pick("history")
	}
	return nil, nil
}

// checkMerges allows merges in the daily review case only, of kept notes of
// the same kind and scope; a hypothesis never replaces an observed note.
func (s *Server) checkMerges(ctx context.Context, q querier, caseID int64, in learningIn, key string) error {
	if len(in.Merges) == 0 {
		return nil
	}
	var kind string
	if err := q.QueryRow(ctx, "SELECT kind FROM autopilot_cases WHERE id = $1", caseID).Scan(&kind); err != nil {
		return err
	}
	if kind != "review" {
		return refuse("merges", "merges are only for the daily review case")
	}
	notes, err := loadNotes(ctx, q, "id = ANY($1) AND trust = ANY($2)", in.Merges, keptTrust)
	if err != nil {
		return err
	}
	for _, m := range in.Merges {
		i := slices.IndexFunc(notes, func(n apNote) bool { return n.ID == m })
		switch {
		case i < 0:
			return refuse("merges", "note %d is not a kept note, so it can't be merged", m)
		case in.Basis == "hypothesis" && notes[i].Basis == "observed":
			return refuse("merges", "a hypothesis can't merge an observed note")
		case notes[i].Kind != in.Kind || notes[i].ScopeKey != key:
			return refuse("merges", "note %d is not a %s note on scope %s, so it can't be merged", m, in.Kind, key)
		}
	}
	return nil
}

// setTrust moves note id from one of from to to, with its revision and
// audit row. It reports whether the note moved. It takes the audit lock
// before the note's row, the order lockNotes gives every note write.
func (s *Server) setTrust(ctx context.Context, tx pgx.Tx, id int64, from []string, to, change, reason, actor string, run, caseID *int64) (bool, error) {
	if err := admindb.LockAudit(ctx, tx); err != nil {
		return false, err
	}
	now := s.now()
	var was string
	err := tx.QueryRow(ctx, `UPDATE autopilot_notes n SET trust = $2, trust_since = $3 FROM (SELECT id, trust FROM autopilot_notes WHERE id = $1 FOR NO KEY UPDATE) o
		WHERE n.id = o.id AND o.trust = ANY($4) RETURNING o.trust`, id, to, now, from).Scan(&was)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO autopilot_note_revisions (note_id, change, trust, reason, actor, run_id, case_id, at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, change, to, reason, actor, run, caseID, now); err != nil {
		return false, err
	}
	action := map[string]string{"dormant": "autopilot.note_dormant", "retracted": "autopilot.note_retract"}[change]
	if action == "" {
		action = "autopilot.note_trust"
	}
	if m, ok := tx.(movesTx); ok {
		*m.moves = append(*m.moves, to)
	}
	return true, admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: actor, Action: action, Target: fmt.Sprintf("note %d", id),
		Details: map[string]any{"from": was, "to": to, "change": change, "reason": reason, "run": run, "case": caseID}})
}

// noteUse records one use of a note against its latest revision.
func noteUse(ctx context.Context, tx pgx.Tx, note int64, source string, run, caseID, proposal *int64, matched bool, value *float64, at time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO autopilot_note_uses (note_id, revision_id, source, run_id, case_id, proposal_id, matched, cited, value, at)
		SELECT $1, max(id), $2, $3, $4, $5, $6, $2 = 'propose', $7, $8 FROM autopilot_note_revisions WHERE note_id = $1`, note, source, run, caseID, proposal, matched, value, at)
	return err
}

// checked records a search or review use of note id and keeps its streak:
// a matched use resets it, and the dormantAfter unmatched one in a row
// makes the note dormant.
func (s *Server) checked(ctx context.Context, tx pgx.Tx, id int64, source string, run, caseID *int64, matched bool, value *float64) error {
	now := s.now()
	if err := noteUse(ctx, tx, id, source, run, caseID, nil, matched, value, now); err != nil {
		return err
	}
	var streak int
	if err := tx.QueryRow(ctx, `UPDATE autopilot_notes SET fail_streak = CASE WHEN $2 THEN 0 ELSE fail_streak + 1 END,
		served_at = CASE WHEN $3 THEN $4 ELSE served_at END WHERE id = $1 RETURNING fail_streak`, id, matched, source == "search" && matched, now).Scan(&streak); err != nil {
		return err
	}
	if streak < dormantAfter {
		return nil
	}
	_, err := s.setTrust(ctx, tx, id, []string{"unconfirmed", "confirmed"}, "dormant", "dormant", fmt.Sprintf("its claim failed on %d uses in a row", streak),
		"system:autopilot", run, caseID)
	return err
}

// servedNote is a note as search_notes answers it. What the model wrote
// reaches a later run as untrusted.
type servedNote struct {
	ID         int64          `json:"id"`
	Kind       string         `json:"kind"`
	Basis      string         `json:"basis"`
	Trust      string         `json:"trust"`
	Anchor     *string        `json:"anchor"`
	Scope      map[string]any `json:"scope"`
	Claim      *noteClaim     `json:"claim"`
	Effect     *noteEffect    `json:"effect"`
	Statement  map[string]any `json:"statement"`
	Rationale  map[string]any `json:"rationale"`
	Stats      *noteStats     `json:"stats"`
	Value      *float64       `json:"value"`
	MatchesNow *bool          `json:"matches_now,omitempty"`
}

// searchNotes is the search_notes tool. A run is served the newest notes
// whose claim matches its data now, and hypotheses, and each check is
// recorded as a use. A person reads every note not ended, with whether it
// matches now, and records nothing.
func (s *Server) searchNotes(ctx context.Context, call *mcpCall, args json.RawMessage) (any, error) {
	var in struct {
		Scope *noteScope `json:"scope"`
		Kind  string     `json:"kind"`
	}
	if err := strict(args, &in); err != nil {
		return nil, err
	}
	key := ""
	if in.Scope != nil {
		key = in.Scope.key()
	}
	// A person calls with no run.
	person := call.run == 0
	trusts := keptTrust
	var withheld []int64
	if !person {
		trusts = []string{"unconfirmed", "confirmed"}
		if err := s.db.QueryRow(ctx, "SELECT withheld_notes FROM autopilot_cases WHERE id = $1", call.caseID).Scan(&withheld); err != nil {
			return nil, err
		}
	}
	rows, err := s.db.Query(ctx, "SELECT "+noteCols+` FROM autopilot_notes WHERE trust = ANY($1) AND ($2 = '' OR scope_key = $2) AND ($3 = '' OR kind = $3)
		AND NOT id = ANY($4) ORDER BY id DESC LIMIT $5`, trusts, key, in.Kind, orEmpty(withheld), maxSearched)
	if err != nil {
		return nil, err
	}
	notes, err := pgx.CollectRows(rows, pgx.RowToStructByPos[apNote])
	if err != nil {
		return nil, err
	}
	// Claims are evaluated before any lock is taken: each is a query over
	// days of stats.
	type check struct {
		view    servedNote
		matched bool
	}
	var checks []check
	var ids []int64
	for _, n := range notes {
		matched, v, err := s.matchNow(ctx, s.db, n)
		if err != nil {
			return nil, err
		}
		view := servedNote{ID: n.ID, Kind: n.Kind, Basis: n.Basis, Trust: n.Trust, Anchor: n.Anchor, Scope: untrusted(n.Scope), Claim: n.Claim, Effect: n.Effect,
			Statement: untrusted(n.Statement), Rationale: untrusted(n.Rationale), Stats: n.Stats, Value: v}
		if person {
			view.MatchesNow = &matched
		}
		checks = append(checks, check{view, matched})
		ids = append(ids, n.ID)
	}
	// serve answers the checks of the notes live allows, up to the answer's
	// size, calling use on each it reaches.
	serve := func(live []int64, use func(c check) error) ([]servedNote, error) {
		out := []servedNote{}
		size := 0
		for _, c := range checks {
			if !slices.Contains(live, c.view.ID) {
				continue // moved since it was read
			}
			if c.matched || person {
				b, _ := json.Marshal(c.view) // plain values
				if size += len(b); size > searchBytes {
					break // the rest are left for a narrower search
				}
				out = append(out, c.view)
			}
			if err := use(c); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	if person {
		out, err := serve(ids, func(check) error { return nil })
		return map[string]any{"notes": out}, err
	}
	var out []servedNote
	seq := 0
	moves, err := s.txMoves(ctx, func(tx pgx.Tx) error {
		if err := lockRun(ctx, tx, call.run); err != nil {
			return err
		}
		live, err := lockNotes(ctx, tx, ids, trusts)
		if err != nil {
			return err
		}
		if out, err = serve(live, func(c check) error {
			return s.checked(ctx, tx, c.view.ID, "search", &call.run, &call.caseID, c.matched, c.view.Value)
		}); err != nil {
			return err
		}
		b, err := json.Marshal(map[string]any{"notes": out})
		if err != nil {
			return err
		}
		seq, _, err = s.callEvent(ctx, tx, call.run, "search_notes", call.args, b, "", time.Since(call.start))
		return err
	})
	if err = proposeDone(err); err != nil {
		// As for a proposal: a search committed as the deadline ended has its
		// call event and uses, so no refusal is recorded beside them.
		if seq != 0 && s.committed(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_run_events WHERE run_id = $1 AND source = 'admin' AND seq = $2)", call.run, seq) {
			call.recorded = true
			s.countMoves(moves)
		}
		return nil, err
	}
	call.recorded = true
	s.countMoves(moves)
	return map[string]any{"notes": out}, nil
}

// lockNotes takes the audit lock, then the rows of the notes ids still in
// one of trusts, in id order, and returns their ids. Every note write takes
// the two in this order, since a rule change that retracts notes holds the
// audit lock already. FOR NO KEY UPDATE is what an UPDATE of a non-key
// column takes, so a proposal recording a use of a note does not wait.
func lockNotes(ctx context.Context, tx pgx.Tx, ids []int64, trusts []string) ([]int64, error) {
	if err := admindb.LockAudit(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, "SELECT id FROM autopilot_notes WHERE id = ANY($1) AND trust = ANY($2) ORDER BY id FOR NO KEY UPDATE", orEmpty(ids), trusts)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// servedTo loads the notes a proposal cites, each of which search_notes
// must have served to this run.
func (s *Server) servedTo(ctx context.Context, q querier, call *mcpCall, ids []int64) ([]apNote, error) {
	for _, id := range ids {
		var ok bool
		if err := q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_note_uses WHERE note_id = $1 AND run_id = $2 AND source = 'search' AND matched)", id, call.run).
			Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, fail(http.StatusUnprocessableEntity, fmt.Sprintf("note %d was not served to this run by search_notes", id))
		}
	}
	return loadNotes(ctx, q, "id = ANY($1)", ids)
}

// citedNotes are the confirmed notes a proposal cites: only they have an
// effect.
func citedNotes(ctx context.Context, q querier, proposal int64) ([]apNote, error) {
	return loadNotes(ctx, q, "trust = 'confirmed' AND id IN (SELECT note_id FROM autopilot_note_uses WHERE proposal_id = $1 AND cited)", proposal)
}

// observeFor is how long an enforce rule observes before it may block: half
// of observe_for, at least a minute, when it cites a confirmed attack
// signature.
func (s *Server) observeFor(ctx context.Context, q querier, set AutopilotSettings, r apRule) (time.Duration, error) {
	d := time.Duration(set.ObserveFor)
	notes, err := citedNotes(ctx, q, r.ProposalID)
	if err != nil || !slices.ContainsFunc(notes, func(n apNote) bool { return n.Kind == "attack_signature" }) {
		return d, err
	}
	return max(time.Minute, d/2), nil
}

// blockShare is the share of the fleet a rule may block: max_block_share,
// or less when it cites a confirmed collateral risk.
func blockShare(set AutopilotSettings, notes []apNote) float64 {
	share := set.MaxBlockShare
	for _, n := range notes {
		if n.Kind == "collateral_risk" && n.Effect != nil && n.Effect.MaxBlockShare > 0 {
			share = min(share, n.Effect.MaxBlockShare)
		}
	}
	return share
}

// expectedBar is the first confirmed expected pattern a rule cites that
// holds it back: now is inside the pattern's daily window, and its metric
// over the part of today's window gone by is under twice its baseline
// median scaled to that part. It returns the numbers, or nil.
// ponytail: the scaling assumes the pattern's traffic spreads evenly over
// its window, so one that peaks late holds a rule back early in it. A
// per-hour baseline would fix that.
func (s *Server) expectedBar(ctx context.Context, q querier, notes []apNote) (map[string]any, error) {
	now := s.now().UTC()
	for _, n := range notes {
		if n.Kind != "expected_pattern" || n.Claim == nil || n.Claim.Window.DailyUTC == nil || n.Stats == nil || n.Stats.Baseline == nil {
			continue
		}
		c, d, day := *n.Claim, n.Claim.Window.DailyUTC, now.Truncate(24*time.Hour)
		from, end := day.Add(time.Duration(d[0])*time.Hour), day.Add(time.Duration(d[1])*time.Hour)
		// Route counts come by the hour, so the part gone by ends on one.
		at := now.Truncate(time.Minute)
		if claimMetrics[c.Metric].source == fromRoute {
			at = now.Truncate(time.Hour)
		}
		if now.Before(from) || !now.Before(end) || !at.After(from) {
			continue
		}
		days, err := s.evalClaim(ctx, q, n.Scope, c, from, at, 0)
		if err != nil {
			return nil, err
		}
		if bar := 2 * n.Stats.Baseline.Median * float64(at.Sub(from)) / float64(end.Sub(from)); days[0].value < bar {
			return map[string]any{"note": n.ID, "metric": c.Metric, "from": from, "to": at, "value": days[0].value, "bar": bar}, nil
		}
	}
	return nil, nil
}

// noteMove is a trust change noteJobs decided on. A confirmation keeps its
// note, to be checked again under the locks.
type noteMove struct {
	id              int64
	from            []string
	to, change, why string
	caseID          *int64
	note            *apNote
}

// noteJobs is the leader's note upkeep: confirming notes whose case held,
// retiring notes dormant or unused for 30 days, and once a day re-checking
// every active note's claim. It decides on what it read, then makes the
// changes in one short transaction.
func (s *Server) noteJobs(ctx context.Context) error {
	now := s.now()
	g, err := loadGuard(ctx, s.db)
	if err != nil {
		return err
	}
	// A note that was ever confirmed or contested is not confirmed again.
	fresh, err := loadNotes(ctx, s.db, `trust = 'unconfirmed' AND basis = 'observed' AND created_at > $1 AND NOT EXISTS (SELECT 1 FROM autopilot_note_revisions v
		WHERE v.note_id = autopilot_notes.id AND v.change IN ('confirmed', 'contested'))`, now.Add(-noteIdle))
	if err != nil {
		return err
	}
	var moves []noteMove
	for _, n := range fresh {
		why, err := s.confirmable(ctx, s.db, n, g)
		if err != nil {
			return err
		}
		if why != "" {
			moves = append(moves, noteMove{n.ID, []string{"unconfirmed"}, "confirmed", "confirmed", why, &n.CaseID, &n})
		}
	}
	var retired []int64
	for _, r := range []struct{ where, why string }{
		{"trust = 'dormant' AND trust_since < $1", "it was dormant for 30 days"},
		{"trust IN ('unconfirmed', 'confirmed') AND coalesce(served_at, created_at) < $1", "no run was served it for 30 days"},
	} {
		idle, err := loadNotes(ctx, s.db, r.where, now.Add(-noteIdle))
		if err != nil {
			return err
		}
		for _, n := range idle {
			moves = append(moves, noteMove{n.ID, keptTrust, "retired", "retired", r.why, nil, nil})
			retired = append(retired, n.ID)
		}
	}
	type check struct {
		id      int64
		matched bool
		value   *float64
	}
	var checks []check
	var recent bool
	if err := s.db.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_note_uses WHERE source = 'review' AND at > $1)", now.Add(-24*time.Hour)).Scan(&recent); err != nil {
		return err
	}
	if !recent {
		active, err := loadNotes(ctx, s.db, "trust IN ('unconfirmed', 'confirmed')")
		if err != nil {
			return err
		}
		for _, n := range active {
			if slices.Contains(retired, n.ID) {
				continue
			}
			matched, v, err := s.matchNow(ctx, s.db, n)
			if err != nil {
				return err
			}
			checks = append(checks, check{n.ID, matched, v})
		}
	}
	if len(moves) == 0 && len(checks) == 0 {
		return nil
	}
	var ids []int64
	for _, m := range moves {
		ids = append(ids, m.id)
	}
	for _, c := range checks {
		ids = append(ids, c.id)
	}
	return s.noteTx(ctx, func(tx pgx.Tx) error {
		live, err := lockNotes(ctx, tx, ids, keptTrust)
		if err != nil {
			return err
		}
		for _, m := range moves {
			if m.note != nil {
				// A false positive mark or rollback committed since the read
				// held the audit lock, so this read sees it.
				if m.why, err = s.confirmable(ctx, tx, *m.note, g); err != nil {
					return err
				}
				if m.why == "" {
					continue
				}
			}
			if _, err := s.setTrust(ctx, tx, m.id, m.from, m.to, m.change, m.why, "system:autopilot", nil, m.caseID); err != nil {
				return err
			}
		}
		for _, c := range checks {
			if !slices.Contains(live, c.id) {
				continue
			}
			if err := s.checked(ctx, tx, c.id, "review", nil, nil, c.matched, c.value); err != nil {
				return err
			}
		}
		return nil
	})
}

// confirmable is why one case confirms n, or "". Its statistics must clear
// the bar, and its case's outcome must hold: for an attack signature or key
// preference, an enforce rule of its case the guard watched for its whole
// window and never alerted on; for the others, an anchor and a finished
// case.
func (s *Server) confirmable(ctx context.Context, q querier, n apNote, g GuardSettings) (string, error) {
	st := n.Stats
	if st == nil || st.Sample.Requests < 1000 && st.Sample.Subjects < 30 {
		return "", nil
	}
	var ok bool
	switch n.Kind {
	case "attack_signature", "key_preference":
		if b := st.Baseline; n.Kind == "attack_signature" && (b == nil || !(b.Z != nil && *b.Z >= 4 || b.Ratio >= 3)) {
			return "", nil
		}
		if !g.Enabled || g.Signals["changed_rule_limited_ratio"].Mode == "off" {
			return "", nil // nothing judged the rule
		}
		// ponytail: a rule whose window saw fewer than the guard's
		// min_requests was never judged, yet passes here as clean. Recording
		// the guard's verdicts per rule would tell the two apart.
		window := time.Duration(g.Window).Seconds()
		err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM autopilot_rules WHERE case_id = $1 AND kind = 'enforce'
			AND enforcing_since <= $2::timestamptz - $3 * interval '1 second' AND coalesce(ended_at, $2) >= enforcing_since + $3 * interval '1 second'
			AND guard_alerted_at IS NULL AND coalesce(outcome, '') NOT IN ('rolled_back', 'false_positive'))`, n.CaseID, s.now(), window).Scan(&ok)
		if err != nil || !ok {
			return "", err
		}
		return "the enforce rule of its case passed the guard window", nil
	default:
		if n.Anchor == nil {
			return "", nil
		}
		err := q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM autopilot_cases WHERE id = $1 AND state = 'done')", n.CaseID).Scan(&ok)
		if err != nil || !ok {
			return "", err
		}
		return "it is anchored by " + *n.Anchor + " and its case finished", nil
	}
}

// retractCited retracts the confirmed notes that pushed a rule that went
// wrong: the attack signatures and key preferences its proposal cited or
// its own case wrote. A note that held the rule back, a collateral risk or
// expected pattern, is not shown wrong by it. Every other rule still
// enforcing because of a retracted note gets a case, when cases can open.
func (s *Server) retractCited(ctx context.Context, tx pgx.Tx, r apRule, why, actor string) error {
	rows, err := tx.Query(ctx, `SELECT id, id IN (SELECT note_id FROM autopilot_note_uses WHERE proposal_id = $1 AND cited) FROM autopilot_notes
		WHERE trust = 'confirmed' AND kind IN ('attack_signature', 'key_preference')
			AND (id IN (SELECT note_id FROM autopilot_note_uses WHERE proposal_id = $1 AND cited) OR case_id = $2) ORDER BY id`, r.ProposalID, r.CaseID)
	if err != nil {
		return err
	}
	type hit struct {
		ID    int64
		Cited bool
	}
	hits, err := pgx.CollectRows(rows, pgx.RowToStructByPos[hit])
	if err != nil || len(hits) == 0 {
		return err
	}
	closed, err := s.casesClosed(ctx, tx)
	if err != nil {
		return err
	}
	for _, h := range hits {
		how := "cited it"
		if !h.Cited {
			how = "its case enforced"
		}
		reason := fmt.Sprintf("rule %s, which %s, %s", r.ID, how, why)
		moved, err := s.setTrust(ctx, tx, h.ID, []string{"confirmed"}, "retracted", "retracted", reason, actor, nil, &r.CaseID)
		if err != nil {
			return err
		}
		if moved && closed == "" {
			if _, _, err := s.reevaluate(ctx, tx, h.ID, fmt.Sprintf("was retracted because %s", reason), "system:autopilot"); err != nil {
				return err
			}
		}
	}
	return nil
}

// reevaluate opens a case on every rule still enforcing because it cites
// note. It returns the cases it opened and how many rules there were.
func (s *Server) reevaluate(ctx context.Context, tx pgx.Tx, note int64, what, actor string) ([]int64, int, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT r.id FROM autopilot_rules r JOIN autopilot_note_uses u ON u.proposal_id = r.proposal_id AND u.cited
		WHERE u.note_id = $1 AND r.state = 'enforcing' ORDER BY r.id`, note)
	if err != nil {
		return nil, 0, err
	}
	rules, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, 0, err
	}
	opened := []int64{}
	for _, id := range rules {
		q := fmt.Sprintf("Rule %s enforces citing note %d, which %s. Check whether the rule is still right.", id, note, what)
		c, ok, err := s.openCase(ctx, tx, caseIn{Kind: "investigate", DedupeKey: "rule:" + id, Rule: &id, Question: q,
			Brief: map[string]any{"kind": "investigate", "rule": id, "question": q}}, actor)
		if err != nil {
			return nil, 0, err
		}
		if ok {
			opened = append(opened, c)
		}
	}
	return opened, len(rules), nil
}

// openAblations opens a case that re-runs a confirmed note's latest case
// without it, at most once a day per note, when 3 cases served it closed
// as benign in a day, or when a benign note's scope keeps getting busier.
// Only anomaly and investigate cases count and are re-run: they answer a
// question about traffic the note may have bent.
func (s *Server) openAblations(ctx context.Context, tx pgx.Tx) error {
	now := s.now()
	notes, err := loadNotes(ctx, tx, `trust = 'confirmed' AND NOT EXISTS (SELECT 1 FROM autopilot_cases c WHERE c.kind = 'ablation'
		AND autopilot_notes.id = ANY(c.withheld_notes) AND c.created_at > $1)`, now.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	for _, n := range notes {
		rows, err := tx.Query(ctx, `SELECT c.id FROM autopilot_cases c WHERE c.kind IN ('anomaly', 'investigate') AND c.state = 'done' AND c.closed_at > $2 AND c.verdict = 'benign'
			AND EXISTS (SELECT 1 FROM autopilot_note_uses u WHERE u.note_id = $1 AND u.case_id = c.id AND u.source = 'search' AND u.matched)
			ORDER BY c.closed_at DESC, c.id DESC LIMIT 3`, n.ID, now.Add(-24*time.Hour))
		if err != nil {
			return err
		}
		benign, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		var of int64
		switch {
		case len(benign) == 3:
			of = benign[0]
		case n.Kind != "attack_signature" && n.Kind != "key_preference" && n.ServedAt != nil && n.ServedAt.After(now.Add(-24*time.Hour)):
			rising, err := s.rising(ctx, tx, n.Scope, now.UTC().Truncate(time.Hour))
			if err != nil {
				return err
			}
			if !rising {
				continue
			}
			err = tx.QueryRow(ctx, `SELECT c.id FROM autopilot_cases c WHERE c.kind IN ('anomaly', 'investigate') AND c.state = 'done' AND EXISTS (SELECT 1 FROM autopilot_note_uses u
				WHERE u.note_id = $1 AND u.case_id = c.id AND u.source = 'search' AND u.matched) ORDER BY c.closed_at DESC, c.id DESC LIMIT 1`, n.ID).Scan(&of)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
		default:
			continue
		}
		var c caseIn
		var brief json.RawMessage
		if err := tx.QueryRow(ctx, "SELECT route_id, anomaly_id, question, brief FROM autopilot_cases WHERE id = $1", of).Scan(&c.RouteID, &c.AnomalyID, &c.Question, &brief); err != nil {
			return err
		}
		if err := json.Unmarshal(brief, &c.Brief); err != nil {
			return err
		}
		c.Kind, c.DedupeKey, c.AblationOf, c.Withheld = "ablation", fmt.Sprintf("ablation:note:%d", n.ID), &of, []int64{n.ID}
		if _, _, err := s.openCase(ctx, tx, c, "system:autopilot"); err != nil {
			return err
		}
	}
	return nil
}

// rising reports whether a scope's volume over the 4 hours before hour
// rose every hour, to at least twice the first and 1,000: requests for the
// fleet and routes, limited and would-limit requests for a rule.
func (s *Server) rising(ctx context.Context, q querier, sc noteScope, hour time.Time) (bool, error) {
	var rows pgx.Rows
	var err error
	if sc.Kind == "route" || sc.Kind == "host" {
		rows, err = q.Query(ctx, `SELECT coalesce(sum(h.requests), 0)::bigint FROM generate_series(1, 4) i
			LEFT JOIN (observed_route_hour h JOIN observed_routes r ON r.id = h.route_id AND r.host = $2 AND ($3 = '' OR r.method = $3 AND r.template = $4))
				ON h.hour >= $1::timestamptz - i * interval '1 hour' AND h.hour < $1::timestamptz - (i - 1) * interval '1 hour'
			GROUP BY i ORDER BY i DESC`, hour, sc.Host, sc.Method, sc.Template)
	} else {
		rows, err = q.Query(ctx, `SELECT coalesce(sum(CASE WHEN $2 = '' THEN m.requests
				ELSE coalesce((e->>'limited')::bigint, 0) + coalesce((e->>'would_limit')::bigint, 0) END), 0)::bigint
			FROM generate_series(1, 4) i
			LEFT JOIN edge_stats_minute m ON m.minute >= $1::timestamptz - i * interval '1 hour' AND m.minute < $1::timestamptz - (i - 1) * interval '1 hour'
			LEFT JOIN LATERAL (SELECT x FROM jsonb_array_elements(m.rate_limit) x WHERE x->>'id' = $2 LIMIT 1) r(e) ON true
			GROUP BY i ORDER BY i DESC`, hour, sc.Rule)
	}
	if err != nil {
		return false, err
	}
	v, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil || len(v) != 4 {
		return false, err
	}
	return v[0] < v[1] && v[1] < v[2] && v[2] < v[3] && v[3] >= 2*v[0] && v[3] >= 1000, nil
}

// ablationDone compares an ablation case's verdict with the case it
// re-ran. Any difference, unsure included, means the withheld notes
// changed the answer, so they go back to unconfirmed for good.
func (s *Server) ablationDone(ctx context.Context, tx pgx.Tx, id, run int64, verdict string) error {
	var of int64
	var withheld []int64
	var was *string
	if err := tx.QueryRow(ctx, "SELECT c.ablation_of, c.withheld_notes, o.verdict FROM autopilot_cases c JOIN autopilot_cases o ON o.id = c.ablation_of WHERE c.id = $1", id).
		Scan(&of, &withheld, &was); err != nil {
		return err
	}
	if was != nil && *was == verdict {
		return nil
	}
	before := "no verdict"
	if was != nil {
		before = *was
	}
	for _, n := range withheld {
		reason := fmt.Sprintf("case %d, re-run without it, answered %s where case %d answered %s", id, verdict, of, before)
		if _, err := s.setTrust(ctx, tx, n, []string{"confirmed"}, "unconfirmed", "contested", reason, "system:autopilot", &run, &id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) noteRoutes() {
	s.handle("GET /api/autopilot/notes", "autopilot.read", s.listNotes)
	s.handle("GET /api/autopilot/notes/{id}", "autopilot.read", s.getNote)
	s.handle("POST /api/autopilot/notes/{id}/retract", "autopilot.manage", s.retractNote)
	s.handle("POST /api/autopilot/notes/{id}/reevaluate", "autopilot.manage", s.reevaluateNote)
}

func (s *Server) listNotes(w http.ResponseWriter, r *http.Request, _ *principal) error {
	q := r.URL.Query()
	rows, err := s.db.Query(r.Context(), "SELECT "+noteCols+" FROM autopilot_notes WHERE ($1 = '' OR trust = $1) AND ($2 = '' OR scope_key = $2) ORDER BY id DESC LIMIT 500",
		q.Get("trust"), q.Get("scope_key"))
	if err != nil {
		return err
	}
	notes, err := pgx.CollectRows(rows, pgx.RowToStructByPos[apNote])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, notes)
}

func (s *Server) noteByID(ctx context.Context, r *http.Request) (*apNote, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	notes, err := loadNotes(ctx, s.db, "id = $1", id)
	if err != nil {
		return nil, err
	}
	if len(notes) == 0 {
		return nil, fail(http.StatusNotFound, fmt.Sprintf("no note %d", id))
	}
	return &notes[0], nil
}

// getNote is a note with its revisions, its last 200 uses, its cited reads
// and its blast radius: the cases served it, the proposals that cited it
// and the rules still enforcing because of it.
func (s *Server) getNote(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	n, err := s.noteByID(ctx, r)
	if err != nil {
		return err
	}
	out := map[string]any{"note": n}
	for key, q := range map[string]string{
		"revisions": "SELECT id, change, trust, reason, fields, actor, run_id, case_id, at FROM autopilot_note_revisions WHERE note_id = $1 ORDER BY id",
		"uses":      "SELECT id, revision_id, source, run_id, case_id, proposal_id, matched, cited, value, at FROM autopilot_note_uses WHERE note_id = $1 ORDER BY id DESC LIMIT 200",
	} {
		rows, err := s.db.Query(ctx, q, n.ID)
		if err != nil {
			return err
		}
		got, err := pgx.CollectRows(rows, pgx.RowToMap)
		if err != nil {
			return err
		}
		out[key] = got
	}
	var refs []evidenceRef
	if err := json.Unmarshal(n.Evidence, &refs); err != nil {
		return err
	}
	evidence := []map[string]any{}
	for _, e := range refs {
		item := map[string]any{"run_id": e.RunID, "seq": e.Seq, "tool": e.Tool, "sha256": e.SHA256}
		if why := answerHidden(p, e.Tool); why != "" {
			item["hidden"], item["hidden_reason"] = true, why
		} else {
			var payload json.RawMessage
			if err := s.db.QueryRow(ctx, "SELECT payload FROM autopilot_run_events WHERE run_id = $1 AND source = 'admin' AND seq = $2", e.RunID, e.Seq).Scan(&payload); err != nil {
				return err
			}
			item["payload"] = payload
		}
		evidence = append(evidence, item)
	}
	out["evidence"] = evidence
	blast := struct {
		Cases          []int64  `json:"cases"`
		Proposals      []int64  `json:"proposals"`
		EnforcingRules []string `json:"enforcing_rules"`
	}{}
	for _, f := range []struct {
		q    string
		into *[]int64
	}{
		{"SELECT DISTINCT case_id FROM autopilot_note_uses WHERE note_id = $1 AND case_id IS NOT NULL ORDER BY 1", &blast.Cases},
		{"SELECT DISTINCT proposal_id FROM autopilot_note_uses WHERE note_id = $1 AND cited ORDER BY 1", &blast.Proposals},
	} {
		rows, err := s.db.Query(ctx, f.q, n.ID)
		if err != nil {
			return err
		}
		if *f.into, err = pgx.CollectRows(rows, pgx.RowTo[int64]); err != nil {
			return err
		}
	}
	rows, err := s.db.Query(ctx, "SELECT id FROM autopilot_rules WHERE state = 'enforcing' AND proposal_id = ANY($1) ORDER BY id", blast.Proposals)
	if err != nil {
		return err
	}
	if blast.EnforcingRules, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return err
	}
	out["blast_radius"] = blast
	return writeJSON(w, http.StatusOK, out)
}

// retractNote retracts a note at a person's word. Nothing is deleted: the
// retraction is a new revision.
func (s *Server) retractNote(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	if in.Reason = strings.TrimSpace(in.Reason); in.Reason == "" || utf8.RuneCountInString(in.Reason) > 500 {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid retraction", Errors: []expr.Issue{{Path: "reason", Msg: "is required, at most 500 characters"}}}
	}
	ctx := r.Context()
	n, err := s.noteByID(ctx, r)
	if err != nil {
		return err
	}
	err = s.noteTx(ctx, func(tx pgx.Tx) error {
		moved, err := s.setTrust(ctx, tx, n.ID, keptTrust, "retracted", "retracted", in.Reason, p.actor, nil, nil)
		if err != nil || moved {
			return err
		}
		// Read again under the lock setTrust took: another change may have
		// committed since the read above.
		var trust string
		if err := tx.QueryRow(ctx, "SELECT trust FROM autopilot_notes WHERE id = $1", n.ID).Scan(&trust); err != nil {
			return err
		}
		return fail(http.StatusConflict, fmt.Sprintf("note %d is %s, so it can't be retracted", n.ID, trust))
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// reevaluateNote opens a case on every rule still enforcing because it
// cites the note.
func (s *Server) reevaluateNote(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	n, err := s.noteByID(ctx, r)
	if err != nil {
		return err
	}
	// As for a case a person opens: none opens that no runner would take.
	why, err := s.casesClosed(ctx, s.db)
	if err != nil {
		return err
	}
	if why != "" {
		return fail(http.StatusConflict, why)
	}
	var opened []int64
	err = dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var rules int
		var err error
		opened, rules, err = s.reevaluate(ctx, tx, n.ID, "a person asked to re-evaluate", p.actor)
		if err == nil && rules == 0 {
			return fail(http.StatusConflict, fmt.Sprintf("no rule enforces citing note %d", n.ID))
		}
		return err
	}))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string][]int64{"cases": opened})
}
