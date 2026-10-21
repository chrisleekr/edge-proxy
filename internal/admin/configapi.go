package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/jwks"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// publishLock serializes publishes, reverts and imports.
const publishLock = 0x7075626c // "publ"

func (s *Server) configRoutes() {
	s.handle("GET /api/expr/schema", "config.read", s.exprSchema)
	s.handle("POST /api/expr/parse", "config.read", s.exprParse)
	s.handle("POST /api/expr/render", "config.read", s.exprRender)
	s.handle("POST /api/expr/validate", "config.read", s.exprValidate)
	s.handle("GET /api/draft", "config.read", s.getDraft)
	s.handle("PUT /api/draft", "config.write", s.putDraft)
	s.handle("POST /api/draft/check", "config.read", s.checkDraft)
	s.handle("GET /api/draft/rebase", "config.read", s.previewRebase)
	s.handle("POST /api/draft/rebase", "config.write", s.applyRebase)
	s.handle("POST /api/simulate", "config.test", s.simulate)
	s.handle("POST /api/tests/run", "config.test", s.runDraftTests)
	s.handle("POST /api/publish", "config.publish", s.publish)
	s.handle("GET /api/versions", "config.read", s.listVersions)
	s.handle("GET /api/versions/{v}", "config.read", s.getVersion)
	s.handle("POST /api/versions/{v}/revert", "config.rollback", s.revert)
	s.handle("POST /api/versions/{v}/copy-to-draft", "config.write", s.copyToDraft)
	s.handle("GET /api/diff/{a}/{b}", "config.read", s.diff)
	s.handle("GET /api/rules/{id}/history", "config.read", s.ruleHistory)
	s.handle("GET /api/export", "config.read", s.export)
	s.handle("POST /api/import", "config.publish", s.importConfig)
}

// --- Expression helpers: the UI never parses or validates. ---

var phases = []expr.Phase{expr.PhaseConfig, expr.PhaseRateLimit, expr.PhaseRequestHeaders}

func (s *Server) exprSchema(w http.ResponseWriter, _ *http.Request, _ *principal) error {
	type field struct {
		Name      string       `json:"name"`
		Label     string       `json:"label"`
		Type      expr.Type    `json:"type"`
		Keyed     bool         `json:"keyed"`
		Phases    []expr.Phase `json:"phases"`
		Available bool         `json:"available"`
	}
	viewer := map[string]bool{}
	for _, f := range s.cfg.Deployment.ViewerFields {
		viewer[f] = true
	}
	var fields []field
	for _, f := range expr.Fields {
		fd := field{Name: f.Name, Label: f.Label, Type: f.Type, Keyed: f.Keyed, Phases: []expr.Phase{},
			Available: f.Source != expr.SourceViewer || viewer[f.Name]}
		for _, p := range phases {
			if f.InPhase(p) {
				fd.Phases = append(fd.Phases, p)
			}
		}
		fields = append(fields, fd)
	}
	var ops []expr.OpDef
	for _, o := range expr.Operators {
		if o.Name != "matches" || s.cfg.Deployment.AllowRegex {
			ops = append(ops, o)
		}
	}
	type keyKind struct {
		Name  string `json:"name"`
		Named bool   `json:"named"`
	}
	var kinds []keyKind
	for _, k := range snapshot.KeyKinds {
		kinds = append(kinds, keyKind{k, slices.Contains(snapshot.NamedKeyKinds, k)})
	}
	// Each kind with the status its template must use, so the editor offers
	// only templates that fit.
	type kindStatus struct {
		Name   string `json:"name"`
		Status int    `json:"status"`
	}
	statuses := snapshot.ResponseStatuses()
	var kindStatuses []kindStatus
	for _, k := range slices.Sorted(maps.Keys(statuses)) {
		kindStatuses = append(kindStatuses, kindStatus{k, statuses[k]})
	}
	// The rule editor offers these as choices, so none can be misspelled.
	rules := map[string]any{
		"algorithms":      snapshot.Algorithms,
		"key_kinds":       kinds,
		"max_key_parts":   snapshot.MaxKeyParts,
		"on_missing_keys": snapshot.OnMissingKeys,
		"actions":         snapshot.Actions,
		"fail_modes":      snapshot.FailModes,
		"auth_modes":      snapshot.AuthModes,
		"forward_modes":   snapshot.ForwardModes,
		"header_ops":      snapshot.HeaderOps,
		"response_kinds":  kindStatuses,
		"content_types":   snapshot.ContentTypes,
		"jwt_algorithms":  snapshot.JWTAlgorithms,
		// RFC 9110 §9 methods and PATCH (RFC 5789), for CORS and Simulate.
		// Validation takes any uppercase token; these are what a form offers.
		"methods": []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
	}
	return writeJSON(w, http.StatusOK, map[string]any{"fields": fields, "operators": ops, "rules": rules})
}

func (s *Server) exprParse(w http.ResponseWriter, r *http.Request, _ *principal) error {
	var in struct{ Text string }
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	n, err := expr.Parse(in.Text)
	if err != nil {
		return fail(http.StatusUnprocessableEntity, err.Error()) // "position N: message"
	}
	return writeJSON(w, http.StatusOK, map[string]any{"ast": n})
}

type exprIn struct {
	AST   expr.Node  `json:"ast"`
	Phase expr.Phase `json:"phase"`
}

// check validates an expression against the draft (or an empty config) as
// a save would.
func (s *Server) check(ctx context.Context, in exprIn) (errs, warns []expr.Issue, err error) {
	if !slices.Contains(phases, in.Phase) {
		return nil, nil, fail(http.StatusBadRequest, "phase must be config, rate_limit or request_headers")
	}
	c := &snapshot.Config{}
	if d, err := s.loadDraft(ctx, s.db, false); err != nil {
		return nil, nil, err
	} else if d != nil {
		c = &d.Config
	}
	errs, warns = snapshot.CheckExpression(in.AST, in.Phase, c, s.cfg.Deployment)
	return errs, warns, nil
}

func (s *Server) exprRender(w http.ResponseWriter, r *http.Request, _ *principal) error {
	var in exprIn
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	errs, warns, err := s.check(r.Context(), in)
	if err != nil {
		return err
	}
	text := expr.Render(in.AST)
	return writeJSON(w, http.StatusOK, map[string]any{"text": text, "length": len(text), "errors": orEmpty(errs), "warnings": orEmpty(warns)})
}

func (s *Server) exprValidate(w http.ResponseWriter, r *http.Request, _ *principal) error {
	var in exprIn
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	errs, warns, err := s.check(r.Context(), in)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"errors": orEmpty(errs), "warnings": orEmpty(warns)})
}

// --- Draft ---

type draftRow struct {
	Config      snapshot.Config
	Tests       []ConfigTest
	BaseVersion *int64
	Revision    int64
	UpdatedBy   string
	UpdatedAt   time.Time
}

func (s *Server) loadDraft(ctx context.Context, q querier, lock bool) (*draftRow, error) {
	sql := "SELECT config, tests, base_version, revision, updated_by, updated_at FROM config_draft"
	if lock {
		sql += " FOR UPDATE"
	}
	var d draftRow
	err := q.QueryRow(ctx, sql).Scan(&d.Config, &d.Tests, &d.BaseVersion, &d.Revision, &d.UpdatedBy, &d.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &d, err
}

// querier is what loaders need: pools and transactions satisfy it.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ifMatch reads the draft revision the client edited. A write without it
// could overwrite someone else's edit.
func ifMatch(r *http.Request) (int64, error) {
	v := r.Header.Get("If-Match")
	if v == "" {
		return 0, fail(http.StatusPreconditionRequired, "send If-Match with the draft revision")
	}
	n, err := strconv.ParseInt(strings.Trim(v, `"`), 10, 64)
	if err != nil {
		return 0, fail(http.StatusBadRequest, "If-Match must be a draft revision")
	}
	return n, nil
}

func etag(rev int64) string { return `"` + strconv.FormatInt(rev, 10) + `"` }

func (s *Server) getDraft(w http.ResponseWriter, r *http.Request, _ *principal) error {
	d, err := s.loadDraft(r.Context(), s.db, false)
	if err != nil {
		return err
	}
	if d == nil {
		// Revision 0: the first save creates the draft from here.
		if d, err = s.startDraft(r.Context()); err != nil {
			return err
		}
	}
	w.Header().Set("ETag", etag(d.Revision))
	return writeJSON(w, http.StatusOK, map[string]any{"config": d.Config, "tests": d.Tests, "base_version": d.BaseVersion,
		"revision": d.Revision, "updated_by": d.UpdatedBy, "updated_at": d.UpdatedAt})
}

// startDraft is what editing starts from: the active version, or the
// starter config when nothing is published.
func (s *Server) startDraft(ctx context.Context) (*draftRow, error) {
	av, err := activeVersion(ctx, s.db)
	if err != nil || av == nil {
		return &draftRow{Config: *snapshot.Starter(), Tests: []ConfigTest{}}, err
	}
	v, err := s.loadVersion(ctx, s.db, *av)
	if err != nil {
		return nil, err
	}
	return &draftRow{Config: v.Config, Tests: v.Tests, BaseVersion: av}, nil
}

type draftIn struct {
	Config *snapshot.Config `json:"config"`
	Tests  []ConfigTest     `json:"tests"`
}

// validate compiles c as the next version and checks the tests. Nothing
// invalid is saved.
func (s *Server) validate(ctx context.Context, q querier, c *snapshot.Config, tests []ConfigTest) (*snapshot.Compiled, []expr.Issue, error) {
	var next int64
	if err := q.QueryRow(ctx, "SELECT coalesce(max(version), 0) + 1 FROM config_versions").Scan(&next); err != nil {
		return nil, nil, err
	}
	c.Version = next
	compiled, warns, errs := snapshot.Compile(c, s.cfg.Deployment)
	for i := range errs {
		errs[i].Path = joinPath("config", errs[i].Path)
	}
	errs = append(errs, checkTests(tests)...)
	if errs != nil {
		return nil, warns, &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid config", Errors: errs}
	}
	return compiled, warns, nil
}

func joinPath(prefix, p string) string {
	if p == "" {
		return prefix
	}
	return prefix + "." + p
}

// saveDraft replaces the draft if rev is still current. base picks the
// draft's base version; action and extra go to the audit row, which also
// records the change against the old draft.
func (s *Server) saveDraft(ctx context.Context, p *principal, rev int64, in draftIn, base func(tx pgx.Tx, old *draftRow) (*int64, error), action string, extra map[string]any) (int64, []expr.Issue, []TestResult, error) {
	if in.Config == nil {
		return 0, nil, nil, fail(http.StatusUnprocessableEntity, "config is required")
	}
	if in.Tests == nil {
		in.Tests = []ConfigTest{}
	}
	var warns []expr.Issue
	var results []TestResult
	var saved int64
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		old, err := s.loadDraft(ctx, tx, true)
		if err != nil {
			return admindb.Event{}, err
		}
		var cur int64
		if old != nil {
			cur = old.Revision
		}
		if cur != rev {
			return admindb.Event{}, fail(http.StatusPreconditionFailed, fmt.Sprintf("the draft is at revision %d; reload and reapply your change", cur))
		}
		compiled, w, err := s.validate(ctx, tx, in.Config, in.Tests)
		if err != nil {
			return admindb.Event{}, err
		}
		warns, results = w, runTests(compiled, in.Tests)
		bv, err := base(tx, old)
		if err != nil {
			return admindb.Event{}, err
		}
		saved = cur + 1
		_, err = tx.Exec(ctx, `INSERT INTO config_draft (id, config, tests, base_version, revision, updated_by, updated_at)
			VALUES (true, $1, $2, $3, $4, $5, $6)
			ON CONFLICT (id) DO UPDATE SET config = $1, tests = $2, base_version = $3, revision = $4, updated_by = $5, updated_at = $6`,
			in.Config, in.Tests, bv, saved, p.actor, s.now())
		details := map[string]any{"revision": saved}
		if old != nil {
			// Field-level before and after.
			details["changes"] = semanticDiff(&old.Config, in.Config)
			details["tests_changed"] = !jsonEqual(old.Tests, in.Tests)
		}
		maps.Copy(details, extra)
		return admindb.Event{Action: action, Target: "draft", Details: details}, err
	})
	return saved, warns, results, err
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// keepBase keeps the draft's base version; a new draft starts from active.
func (s *Server) keepBase(ctx context.Context) func(pgx.Tx, *draftRow) (*int64, error) {
	return func(tx pgx.Tx, old *draftRow) (*int64, error) {
		if old != nil {
			return old.BaseVersion, nil
		}
		return activeVersion(ctx, tx)
	}
}

func activeVersion(ctx context.Context, q querier) (*int64, error) {
	var v int64
	err := q.QueryRow(ctx, "SELECT version FROM config_versions WHERE status = 'active'").Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &v, err
}

func (s *Server) putDraft(w http.ResponseWriter, r *http.Request, p *principal) error {
	rev, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in draftIn
	if err := readDraft(w, r, &in); err != nil {
		return err
	}
	saved, warns, results, err := s.saveDraft(r.Context(), p, rev, in, s.keepBase(r.Context()), "config.save", nil)
	if err != nil {
		return err
	}
	return s.draftSaved(w, r.Context(), in.Config, saved, warns, results)
}

// checkDraft validates a config as a save would, without saving it, so the
// rule editor can show each problem by its field before the rule is applied.
func (s *Server) checkDraft(w http.ResponseWriter, r *http.Request, _ *principal) error {
	var in draftIn
	err := readDraft(w, r, &in)
	if err == nil && in.Config == nil {
		err = fail(http.StatusUnprocessableEntity, "config is required")
	}
	var warns []expr.Issue
	if err == nil {
		_, warns, err = s.validate(r.Context(), s.db, in.Config, nil)
	}
	// Problems with a path are the answer; anything else is a failed request.
	if p, ok := errors.AsType[*problem](err); ok && p.Errors != nil {
		return writeJSON(w, http.StatusOK, map[string]any{"errors": p.Errors, "warnings": orEmpty(warns)})
	}
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"errors": []expr.Issue{}, "warnings": orEmpty(warns)})
}

// readDraft decodes a draft like readJSON. A body that does not decode also
// gets the path of the config section or rule at fault, so the editor can
// link to it: the decoder's own message names neither.
func readDraft(w http.ResponseWriter, r *http.Request, in *draftIn) error {
	const msg = "invalid JSON body"
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		return fail(http.StatusRequestEntityTooLarge, msg+": body is too large")
	}
	if err != nil {
		return fail(http.StatusBadRequest, msg+": "+err.Error())
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	err = decodeOne(dec, in, msg)
	// The issue repeats the decoder's message, so the detail need not.
	if p, ok := errors.AsType[*problem](err); ok {
		if p.Errors = configIssue(body); p.Errors != nil {
			p.Detail = msg
		}
	}
	return err
}

// configIssue decodes each config section, and each rule of a rule list,
// on its own and reports the first that fails.
func configIssue(body []byte) []expr.Issue {
	var in struct {
		Config map[string]json.RawMessage `json:"config"`
	}
	if json.Unmarshal(body, &in) != nil {
		return nil
	}
	for _, k := range slices.Sorted(maps.Keys(in.Config)) {
		err := decodeSection(k, in.Config[k])
		if err == nil {
			continue
		}
		var items []json.RawMessage
		if json.Unmarshal(in.Config[k], &items) == nil {
			for i, item := range items {
				if err := decodeSection(k, append(append([]byte("["), item...), ']')); err != nil {
					return []expr.Issue{{Path: fmt.Sprintf("config.%s[%d]", k, i), Msg: strings.TrimPrefix(err.Error(), "json: ")}}
				}
			}
		}
		return []expr.Issue{{Path: "config." + k, Msg: strings.TrimPrefix(err.Error(), "json: ")}}
	}
	return nil
}

func decodeSection(key string, v json.RawMessage) error {
	b, err := json.Marshal(map[string]json.RawMessage{key: v})
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(new(snapshot.Config))
}

// draftSaved answers every draft save. It fetches keys for issuers that
// have none, whichever way the config reached the draft.
func (s *Server) draftSaved(w http.ResponseWriter, ctx context.Context, c *snapshot.Config, saved int64, warns []expr.Issue, results []TestResult) error {
	warns = append(warns, s.fetchNewKeys(ctx, c)...)
	w.Header().Set("ETag", etag(saved))
	return writeJSON(w, http.StatusOK, map[string]any{"revision": saved, "warnings": orEmpty(warns), "test_results": results})
}

// --- Simulate and tests ---

func (s *Server) simulate(w http.ResponseWriter, r *http.Request, _ *principal) error {
	var in struct {
		Version *int64      `json:"version"` // default: the draft
		Request TestRequest `json:"request"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	c, _, err := s.compiledFor(r.Context(), in.Version)
	if err != nil {
		return err
	}
	res, err := simulate(c, in.Request)
	if err != nil {
		// The simulator names the field first, as "ip: ...". The form shows an
		// IP problem under its field, in words rather than the parser's.
		if strings.HasPrefix(err.Error(), "ip: ") {
			return &problem{Status: http.StatusUnprocessableEntity, Title: "Request can't be simulated",
				Errors: []expr.Issue{{Path: "request.ip", Msg: "must be an IP address, such as 203.0.113.7 or 2001:db8::1"}}}
		}
		return fail(http.StatusUnprocessableEntity, err.Error())
	}
	return writeJSON(w, http.StatusOK, res)
}

// compiledFor compiles a version, or the draft when v is nil, against
// today's deployment.
func (s *Server) compiledFor(ctx context.Context, v *int64) (*snapshot.Compiled, []ConfigTest, error) {
	var c *snapshot.Config
	var tests []ConfigTest
	if v == nil {
		d, err := s.loadDraft(ctx, s.db, false)
		if err != nil {
			return nil, nil, err
		}
		if d == nil {
			return nil, nil, fail(http.StatusNotFound, "no draft yet")
		}
		c, tests = &d.Config, d.Tests
	} else {
		vr, err := s.loadVersion(ctx, s.db, *v)
		if err != nil {
			return nil, nil, err
		}
		c, tests = &vr.Config, vr.Tests
	}
	compiled, _, errs := snapshot.Compile(c, s.cfg.Deployment)
	if errs != nil {
		return nil, nil, &problem{Status: http.StatusUnprocessableEntity, Title: "Config no longer valid in this deployment", Errors: errs}
	}
	return compiled, tests, nil
}

func (s *Server) runDraftTests(w http.ResponseWriter, r *http.Request, _ *principal) error {
	c, tests, err := s.compiledFor(r.Context(), nil)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, runTests(c, tests))
}

// --- Versions and publishing ---

type versionRow struct {
	Version        int64           `json:"version"`
	Author         string          `json:"author"`
	PublishedAt    time.Time       `json:"published_at"`
	Message        string          `json:"message"`
	Source         string          `json:"source"`
	BasedOn        *int64          `json:"based_on"`
	Status         string          `json:"status"`
	ChangeSummary  string          `json:"change_summary"`
	OverrideReason *string         `json:"override_reason"`
	Config         snapshot.Config `json:"config"`
	Tests          []ConfigTest    `json:"tests"`
	TestResults    []TestResult    `json:"test_results"`
	GuardOutcome   json.RawMessage `json:"guard_outcome"`
	// GuardOverride replaces the guard settings while this version is judged.
	GuardOverride       *GuardSettings `json:"guard_override"`
	GuardOverrideReason *string        `json:"guard_override_reason"`
	AbortReason         *string        `json:"abort_reason"`
}

const versionCols = "version, author, published_at, message, source, based_on, status, change_summary, override_reason, config, tests, test_results, guard_outcome, guard_override, guard_override_reason, abort_reason"

func scanVersion(row pgx.Row) (*versionRow, error) {
	var v versionRow
	err := row.Scan(&v.Version, &v.Author, &v.PublishedAt, &v.Message, &v.Source, &v.BasedOn, &v.Status, &v.ChangeSummary,
		&v.OverrideReason, &v.Config, &v.Tests, &v.TestResults, &v.GuardOutcome, &v.GuardOverride, &v.GuardOverrideReason, &v.AbortReason)
	return &v, err
}

func (s *Server) loadVersion(ctx context.Context, q querier, v int64) (*versionRow, error) {
	vr, err := scanVersion(q.QueryRow(ctx, "SELECT "+versionCols+" FROM config_versions WHERE version = $1", v))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fail(http.StatusNotFound, fmt.Sprintf("no version %d", v))
	}
	return vr, err
}

// publishActions is the audit action for each publish source. The sources
// are the ones config_versions.source allows.
var publishActions = map[string]string{
	"manual": "config.publish", "revert": "config.revert", "guard_rollback": "config.rollback", "import": "config.import",
}

// publishReq is one new version from any source.
type publishReq struct {
	config   *snapshot.Config
	tests    []ConfigTest
	message  string
	source   string // manual | revert | guard_rollback | import
	basedOn  *int64
	override string  // reason to publish despite issuers without keys
	canary   float64 // percent of clients; 0 publishes to everyone
	guard    *GuardSettings
	guardWhy string // required with guard
}

// guardIn is the optional per-publish guard override in a request body.
type guardIn struct {
	Guard       *GuardSettings `json:"guard_override"`
	GuardReason string         `json:"guard_override_reason"`
}

// publishTx validates, tests and records a new active version in tx.
func (s *Server) publishTx(ctx context.Context, tx pgx.Tx, p *principal, req publishReq) (int64, error) {
	if strings.TrimSpace(req.message) == "" {
		return 0, &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid publish", Errors: []expr.Issue{{Path: "message", Msg: "is required"}}}
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", publishLock); err != nil {
		return 0, err
	}
	if c, err := loadCanary(ctx, tx); err != nil {
		return 0, err
	} else if c != nil {
		return 0, fail(http.StatusConflict, fmt.Sprintf("version %d is in canary; promote or abort it first", c.Version))
	}
	if req.canary != 0 && !p.can("canary.manage") {
		return 0, errForbidden
	}
	if req.canary != 0 && !validPercent(req.canary) {
		return 0, fail(http.StatusUnprocessableEntity, "canary_percent must be a number from 0.01 to 99.99, or left out for all traffic")
	}
	if req.guard != nil {
		errs := req.guard.problems()
		if strings.TrimSpace(req.guardWhy) == "" {
			errs = append(errs, expr.Issue{Path: "guard_override_reason", Msg: "is required with guard_override"})
		}
		if errs != nil {
			return 0, &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid guard override", Errors: errs}
		}
	}
	if err := s.checkSchema(ctx, tx, req.config.Schema); err != nil {
		return 0, err
	}
	// Reverts and rollbacks restore content edges already served, and must
	// never wait on an edge that reports a different (or bogus) deployment.
	if req.source != "revert" && req.source != "guard_rollback" {
		if err := s.checkDeployment(ctx, tx); err != nil {
			return 0, err
		}
	}
	compiled, _, err := s.validate(ctx, tx, req.config, req.tests)
	if err != nil {
		return 0, err
	}
	results := runTests(compiled, req.tests)
	for _, res := range results {
		if !res.Pass {
			return 0, &problem{Status: http.StatusUnprocessableEntity, Title: "Config tests failed", Detail: "fix the config or the tests before publishing", Tests: results}
		}
	}
	missing, err := issuersWithoutKeys(ctx, tx, req.config)
	if err != nil {
		return 0, err
	}
	if len(missing) > 0 && strings.TrimSpace(req.override) == "" {
		return 0, &problem{Status: http.StatusUnprocessableEntity, Title: "Issuer keys never fetched",
			Detail: "rules require auth from " + strings.Join(missing, ", ") + ", whose JWKS has never been fetched; check the JWKS URL, or publish with override_reason"}
	}
	var override *string
	if len(missing) > 0 {
		override = &req.override
	}
	summary := "first version"
	if av, err := activeVersion(ctx, tx); err != nil {
		return 0, err
	} else if av != nil {
		prev, err := s.loadVersion(ctx, tx, *av)
		if err != nil {
			return 0, err
		}
		summary = semanticDiff(&prev.Config, req.config).summary()
	}
	status := "active"
	if req.canary > 0 {
		status = "canary" // active keeps serving everyone else
	} else if _, err := tx.Exec(ctx, "UPDATE config_versions SET status = 'superseded' WHERE status = 'active'"); err != nil {
		return 0, err
	}
	v := req.config.Version
	now := s.now()
	var guardWhy *string
	if req.guard != nil {
		guardWhy = &req.guardWhy
	}
	_, err = tx.Exec(ctx, `INSERT INTO config_versions (version, author, published_at, message, source, based_on, status, config, tests, test_results, change_summary, override_reason, guard_override, guard_override_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		v, p.actor, now, req.message, req.source, req.basedOn, status, req.config, req.tests, results, summary, override, req.guard, guardWhy)
	if err != nil {
		return 0, err
	}
	details := map[string]any{"version": v, "message": req.message, "change_summary": summary}
	if req.canary > 0 {
		if _, err := tx.Exec(ctx, "INSERT INTO canary (version, percent, started_at, step_started_at, expires_at) VALUES ($1, $2, $3, $3, $4)",
			v, req.canary, now, now.Add(canaryLease)); err != nil {
			return 0, err
		}
		details["canary_percent"] = req.canary
	}
	if req.basedOn != nil {
		details["based_on"] = *req.basedOn
	}
	if req.guard != nil {
		// The saved settings beside the override, so the log can say what
		// this publish changed rather than repeat every setting.
		saved, err := loadGuard(ctx, tx)
		if err != nil {
			return 0, err
		}
		details["guard_settings"], details["guard_override"], details["guard_override_reason"] = saved, req.guard, req.guardWhy
	}
	if override != nil {
		details["override_reason"] = *override
		details["issuers_without_keys"] = missing
	}
	return v, admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: p.actor, Action: publishActions[req.source], Target: fmt.Sprintf("version %d", v), Details: details})
}

// issuersWithoutKeys lists issuers that a required-auth rule accepts and
// whose JWKS URL has never been fetched.
func issuersWithoutKeys(ctx context.Context, q querier, c *snapshot.Config) ([]string, error) {
	needed := map[string]bool{}
	for _, r := range c.ConfigRules {
		if a := r.Settings.Auth; a != nil && a.Mode == "required" {
			ids := a.Accepted
			if len(ids) == 0 {
				ids = c.Auth.DefaultAccepted
			}
			for _, id := range ids {
				needed[id] = true
			}
		}
	}
	var missing []string
	for _, is := range c.Auth.Issuers {
		if !needed[is.ID] {
			continue
		}
		ok, err := hasKeys(ctx, q, is)
		if err != nil {
			return nil, err
		}
		if !ok {
			missing = append(missing, is.ID)
		}
	}
	return missing, nil
}

// canaryPercent is a request's canary_percent. Left out, it is 0 (all
// traffic). An explicit null is NaN, which validPercent refuses: a client
// that sends null meant a canary, such as a UI encoding NaN from "5%", and
// must not publish to all traffic instead.
type canaryPercent float64

func (c *canaryPercent) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*c = canaryPercent(math.NaN())
		return nil
	}
	return json.Unmarshal(b, (*float64)(c))
}

func (s *Server) publish(w http.ResponseWriter, r *http.Request, p *principal) error {
	rev, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in struct {
		Message        string        `json:"message"`
		OverrideReason string        `json:"override_reason"`
		CanaryPercent  canaryPercent `json:"canary_percent"`
		guardIn
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	ctx := r.Context()
	var v int64
	err = dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		d, err := s.loadDraft(ctx, tx, true)
		if err != nil {
			return err
		}
		if d == nil || d.Revision != rev {
			return fail(http.StatusPreconditionFailed, "the draft changed since you loaded it; reload before publishing")
		}
		av, err := activeVersion(ctx, tx)
		if err != nil {
			return err
		}
		// A revert or rollback since the draft started can't be undone by
		// publishing an older draft.
		if !samePtr(av, d.BaseVersion) {
			return fail(http.StatusConflict, "the active version changed since this draft started; rebase the draft first")
		}
		v, err = s.publishTx(ctx, tx, p, publishReq{config: &d.Config, tests: d.Tests, message: in.Message, source: "manual", override: in.OverrideReason, canary: float64(in.CanaryPercent),
			guard: in.Guard, guardWhy: in.GuardReason})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE config_draft SET base_version = $1, config = $2, revision = revision + 1", v, &d.Config)
		return err
	}))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]int64{"version": v})
}

func samePtr(a, b *int64) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

func pathVersion(r *http.Request, name string) (int64, error) {
	v, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil {
		return 0, fail(http.StatusBadRequest, name+" must be a version number")
	}
	return v, nil
}

func (s *Server) listVersions(w http.ResponseWriter, r *http.Request, _ *principal) error {
	rows, err := s.db.Query(r.Context(), `SELECT version, author, published_at, message, source, based_on, status, change_summary, override_reason, guard_outcome, abort_reason
		FROM config_versions ORDER BY version DESC`)
	if err != nil {
		return err
	}
	type item struct {
		Version        int64           `json:"version"`
		Author         string          `json:"author"`
		PublishedAt    time.Time       `json:"published_at"`
		Message        string          `json:"message"`
		Source         string          `json:"source"`
		BasedOn        *int64          `json:"based_on"`
		Status         string          `json:"status"`
		ChangeSummary  string          `json:"change_summary"`
		OverrideReason *string         `json:"override_reason"`
		GuardOutcome   json.RawMessage `json:"guard_outcome"`
		AbortReason    *string         `json:"abort_reason"`
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[item])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, list)
}

func (s *Server) getVersion(w http.ResponseWriter, r *http.Request, _ *principal) error {
	v, err := pathVersion(r, "v")
	if err != nil {
		return err
	}
	vr, err := s.loadVersion(r.Context(), s.db, v)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, vr)
}

// revert publishes version K's content as a new version, validated and
// tested against today's deployment. Keys are never reverted: they live
// apart from config.
func (s *Server) revert(w http.ResponseWriter, r *http.Request, p *principal) error {
	k, err := pathVersion(r, "v")
	if err != nil {
		return err
	}
	var in struct {
		Reason         string `json:"reason"`
		OverrideReason string `json:"override_reason"`
		// Revert with canary, for an old version you'd rather stage.
		// The default skips the canary.
		CanaryPercent canaryPercent `json:"canary_percent"`
		guardIn
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	ctx := r.Context()
	var v int64
	err = dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		old, err := s.loadVersion(ctx, tx, k)
		if err != nil {
			return err
		}
		v, err = s.publishTx(ctx, tx, p, publishReq{config: &old.Config, tests: old.Tests, message: in.Reason, source: "revert", basedOn: &k, override: in.OverrideReason,
			canary: float64(in.CanaryPercent), guard: in.Guard, guardWhy: in.GuardReason})
		return err
	}))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]int64{"version": v})
}

func (s *Server) copyToDraft(w http.ResponseWriter, r *http.Request, p *principal) error {
	k, err := pathVersion(r, "v")
	if err != nil {
		return err
	}
	rev, err := ifMatch(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	old, err := s.loadVersion(ctx, s.db, k)
	if err != nil {
		return err
	}
	saved, warns, results, err := s.saveDraft(ctx, p, rev, draftIn{Config: &old.Config, Tests: old.Tests},
		func(tx pgx.Tx, _ *draftRow) (*int64, error) { return activeVersion(ctx, tx) }, "config.copy_to_draft", map[string]any{"from_version": k})
	if err != nil {
		return err
	}
	return s.draftSaved(w, ctx, &old.Config, saved, warns, results)
}

// rebasePlan is the three-way view of a draft on top of the active version.
type rebasePlan struct {
	draft  *draftRow
	active int64
	// view is what the API shows: both sides' changes, the result and any
	// conflicts.
	view   map[string]any
	result *snapshot.Config
}

// rebaseView computes the three-way view: what the draft changed, what
// active changed, and the draft applied on top of active.
func (s *Server) rebaseView(ctx context.Context) (*rebasePlan, error) {
	d, err := s.loadDraft(ctx, s.db, false)
	if err != nil {
		return nil, err
	}
	av, err := activeVersion(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if d == nil || d.BaseVersion == nil || av == nil || *av == *d.BaseVersion {
		return nil, fail(http.StatusConflict, "nothing to rebase: the draft is based on the active version")
	}
	// A draft based on the running canary already has the newest changes;
	// rebasing onto active would strip them.
	c, err := loadCanary(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if c != nil && c.Version == *d.BaseVersion {
		return nil, fail(http.StatusConflict, "nothing to rebase: the draft is based on the canary version")
	}
	base, err := s.loadVersion(ctx, s.db, *d.BaseVersion)
	if err != nil {
		return nil, err
	}
	active, err := s.loadVersion(ctx, s.db, *av)
	if err != nil {
		return nil, err
	}
	result, conflicts := rebase(&base.Config, &d.Config, &active.Config)
	view := map[string]any{
		"base_version": base.Version, "active_version": active.Version,
		"draft_changes": semanticDiff(&base.Config, &d.Config), "active_changes": semanticDiff(&base.Config, &active.Config),
		"result": result, "conflicts": orEmpty(conflicts),
	}
	return &rebasePlan{draft: d, active: *av, view: view, result: result}, nil
}

func (s *Server) previewRebase(w http.ResponseWriter, r *http.Request, _ *principal) error {
	plan, err := s.rebaseView(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, plan.view)
}

func (s *Server) applyRebase(w http.ResponseWriter, r *http.Request, p *principal) error {
	rev, err := ifMatch(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	plan, err := s.rebaseView(ctx)
	if err != nil {
		return err
	}
	saved, warns, results, err := s.saveDraft(ctx, p, rev, draftIn{Config: plan.result, Tests: plan.draft.Tests},
		func(pgx.Tx, *draftRow) (*int64, error) { return &plan.active, nil }, "config.rebase", map[string]any{"onto_version": plan.active})
	if err != nil {
		return err
	}
	return s.draftSaved(w, ctx, plan.result, saved, warns, results)
}

// configOf loads a version's config, or the draft's for "draft".
func (s *Server) configOf(ctx context.Context, ref string) (*snapshot.Config, error) {
	if ref == "draft" {
		d, err := s.loadDraft(ctx, s.db, false)
		if err != nil {
			return nil, err
		}
		if d == nil {
			return nil, fail(http.StatusNotFound, "no draft yet")
		}
		return &d.Config, nil
	}
	v, err := strconv.ParseInt(ref, 10, 64)
	if err != nil {
		return nil, fail(http.StatusBadRequest, "compare a version number or draft")
	}
	vr, err := s.loadVersion(ctx, s.db, v)
	if err != nil {
		return nil, err
	}
	return &vr.Config, nil
}

func (s *Server) diff(w http.ResponseWriter, r *http.Request, _ *principal) error {
	ctx := r.Context()
	a, err := s.configOf(ctx, r.PathValue("a"))
	if err != nil {
		return err
	}
	b, err := s.configOf(ctx, r.PathValue("b"))
	if err != nil {
		return err
	}
	switch r.URL.Query().Get("view") {
	case "", "semantic":
		d := semanticDiff(a, b)
		return writeJSON(w, http.StatusOK, map[string]any{"diff": d, "summary": d.summary()})
	case "raw":
		// The UI renders the side-by-side view; JSON keeps it to the
		// stdlib.
		ja, _ := json.MarshalIndent(a, "", "  ")
		jb, _ := json.MarshalIndent(b, "", "  ")
		return writeJSON(w, http.StatusOK, map[string]string{"a": string(ja), "b": string(jb)})
	}
	return fail(http.StatusBadRequest, "view must be semantic or raw")
}

// ruleHistory lists the versions where a rule appeared, changed or went
// away.
func (s *Server) ruleHistory(w http.ResponseWriter, r *http.Request, _ *principal) error {
	id := r.PathValue("id")
	rows, err := s.db.Query(r.Context(), "SELECT version, author, published_at, config FROM config_versions ORDER BY version")
	if err != nil {
		return err
	}
	type entry struct {
		Version     int64          `json:"version"`
		Author      string         `json:"author"`
		PublishedAt time.Time      `json:"published_at"`
		Phase       string         `json:"phase,omitempty"`
		Rule        map[string]any `json:"rule"` // null when removed
	}
	out := []entry{}
	var last map[string]any
	var e entry
	var c snapshot.Config
	_, err = pgx.ForEachRow(rows, []any{&e.Version, &e.Author, &e.PublishedAt, &c}, func() error {
		cur := entry{Version: e.Version, Author: e.Author, PublishedAt: e.PublishedAt}
		for ph, rs := range rulesOf(&c) {
			for _, rr := range rs {
				if rr.id == id {
					cur.Phase, cur.Rule = ph, rr.body
				}
			}
		}
		if !jsonEqual(cur.Rule, last) {
			out = append(out, cur)
			last = cur.Rule
		}
		c = snapshot.Config{}
		return nil
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// --- Portability ---

// export is the bootstrap file: the active config and its keys, in the
// snapshot envelope format the edge reads.
func (s *Server) export(w http.ResponseWriter, r *http.Request, p *principal) error {
	ctx := r.Context()
	av, err := activeVersion(ctx, s.db)
	if err != nil {
		return err
	}
	if av == nil {
		return fail(http.StatusNotFound, "nothing published yet")
	}
	vr, err := s.loadVersion(ctx, s.db, *av)
	if err != nil {
		return err
	}
	keys, err := issuerKeys(ctx, s.db, &vr.Config)
	if err != nil {
		return err
	}
	env := snapshot.Envelope{ExportedAt: s.now().UTC(), Active: &vr.Config, Keys: keys}
	err = s.change(ctx, p.actor, func(pgx.Tx) (admindb.Event, error) {
		return admindb.Event{Action: "config.export", Target: fmt.Sprintf("version %d", vr.Version)}, nil
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"envelope": env, "tests": vr.Tests})
}

// issuerKeys returns the latest good keys for c's issuers at their URLs,
// once per issuer and URL.
func issuerKeys(ctx context.Context, q querier, configs ...*snapshot.Config) ([]snapshot.IssuerKeys, error) {
	var out []snapshot.IssuerKeys
	seen := map[snapshot.KeySource]bool{}
	for _, c := range configs {
		for _, is := range c.Auth.Issuers {
			src := snapshot.KeySource{IssuerID: is.ID, JWKSURL: is.JWKSURL}
			if seen[src] {
				continue
			}
			seen[src] = true
			k := snapshot.IssuerKeys{IssuerID: is.ID, JWKSURL: is.JWKSURL}
			err := q.QueryRow(ctx, "SELECT fetched_at, jwks FROM jwks_keys WHERE issuer_id = $1 AND jwks_url = $2", is.ID, is.JWKSURL).Scan(&k.FetchedAt, &k.JWKS)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, k)
		}
	}
	return out, nil
}

// importConfig publishes a config exported elsewhere (staging promotion),
// through every check a publish runs.
func (s *Server) importConfig(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Config         *snapshot.Config `json:"config"`
		Tests          []ConfigTest     `json:"tests"`
		Message        string           `json:"message"`
		OverrideReason string           `json:"override_reason"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	if in.Config == nil {
		return fail(http.StatusUnprocessableEntity, "config is required")
	}
	ctx := r.Context()
	var v int64
	err := dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var err error
		v, err = s.publishTx(ctx, tx, p, publishReq{config: in.Config, tests: in.Tests, message: in.Message, source: "import", override: in.OverrideReason})
		return err
	}))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]int64{"version": v})
}

// fetchNewKeys fetches keys for issuers that have none yet, so a mistyped
// JWKS URL shows at save. Reachability is a warning, not an error: it is
// environmental.
func (s *Server) fetchNewKeys(ctx context.Context, c *snapshot.Config) []expr.Issue {
	var warns []expr.Issue
	for i, is := range c.Auth.Issuers {
		path := fmt.Sprintf("config.auth.issuers[%d].jwks_url", i)
		ok, err := hasKeys(ctx, s.db, is)
		if err != nil {
			// The draft is already saved; say so rather than fail the save.
			warns = append(warns, expr.Issue{Path: path, Msg: "keys could not be checked: " + err.Error()})
			continue
		}
		if ok {
			continue
		}
		if err := s.refreshIssuer(ctx, is); err != nil {
			msg := "keys could not be fetched: " + err.Error()
			if errors.Is(err, jwks.ErrNonPublic) {
				msg = "keys could not be fetched: the keys URL is a private address, and admin fetches from those only for hosts in its JWKS_ALLOWED_HOSTS"
			}
			warns = append(warns, expr.Issue{Path: path, Msg: msg})
		}
	}
	return warns
}

// hasKeys reports whether admin holds keys for the issuer at its JWKS URL.
func hasKeys(ctx context.Context, q querier, is snapshot.Issuer) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM jwks_keys WHERE issuer_id = $1 AND jwks_url = $2)", is.ID, is.JWKSURL).Scan(&ok)
	return ok, err
}
