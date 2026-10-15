package admin

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

func TestDraftLifecycle(t *testing.T) {
	h := newHarness(t)
	h.user("ed", "editor")
	h.user("vera", "viewer")
	ed := h.signedIn("ed")
	// Before anything is saved or published, the draft is the starter.
	first := decode[struct {
		Config   snapshot.Config
		Revision int64
	}](t, ed.do("GET", "/api/draft", nil))
	if first.Revision != 0 || len(first.Config.Global.Responses) != 9 || first.Config.RateLimitRules != nil {
		t.Fatalf("first draft %+v", first)
	}
	status(t, ed.save("", testConfig()), 428)
	resp := ed.save(`"0"`, testConfig(), adminTest)
	if resp.Header.Get("ETag") != `"1"` {
		t.Fatalf("etag %q", resp.Header.Get("ETag"))
	}
	saved := decode[struct {
		Revision    int64
		TestResults []TestResult `json:"test_results"`
	}](t, resp)
	if saved.Revision != 1 || len(saved.TestResults) != 1 || !saved.TestResults[0].Pass {
		t.Fatalf("saved %+v", saved)
	}

	t.Run("a stale revision is refused", func(t *testing.T) {
		status(t, ed.save(`"0"`, testConfig()), 412)
	})
	t.Run("an invalid config is never saved", func(t *testing.T) {
		bad := testConfig()
		bad.RateLimitRules[0].Limit = 0
		bad.ConfigRules[0].Settings.Upstream = new("billing")
		resp := ed.save(`"1"`, bad)
		p := decode[problem](t, resp)
		paths := []string{}
		for _, e := range p.Errors {
			paths = append(paths, e.Path)
		}
		if resp.StatusCode != 422 || !slices.Contains(paths, "config.rate_limit_rules[0].limit") || !slices.Contains(paths, "config.config_rules[0].settings.upstream") {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
		if ed.revision() != `"1"` {
			t.Fatal("invalid config changed the draft")
		}
	})
	t.Run("a failing test is saved but reported", func(t *testing.T) {
		wrong := adminTest
		wrong.Expect.Settings = map[string]any{"upstream": "app"}
		res := decode[struct {
			TestResults []TestResult `json:"test_results"`
		}](t, ed.save(`"1"`, testConfig(), wrong))
		if res.TestResults[0].Pass || !strings.Contains(res.TestResults[0].Failures[0], `settings.upstream: want app, got admin`) {
			t.Fatalf("results %+v", res.TestResults)
		}
	})
	t.Run("viewers can't edit", func(t *testing.T) {
		status(t, h.signedIn("vera").save(`"2"`, testConfig()), 403)
	})
	t.Run("saves are audited with field changes", func(t *testing.T) {
		c := testConfig()
		c.RateLimitRules[0].Limit = 5
		status(t, ed.save(`"2"`, c, adminTest), 200)
		var details string
		if err := h.db.QueryRow(t.Context(), "SELECT details::text FROM audit_events WHERE action = 'config.save' ORDER BY seq DESC LIMIT 1").Scan(&details); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(details, `"path":"limit","before":10,"after":5`) {
			t.Fatalf("details %s", details)
		}
	})
}

func TestPublish(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "publisher")
	h.user("ed", "editor")
	pub := h.signedIn("pub")
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)

	status(t, h.signedIn("ed").publishDraft("not allowed"), 403)
	status(t, pub.publishDraft(""), 422)
	status(t, pub.do("POST", "/api/publish", map[string]string{"message": "stale"}, "If-Match", `"0"`), 412)
	resp := pub.publishDraft("Initial policy")
	if v := decode[map[string]int64](t, resp)["version"]; v != 1 {
		t.Fatalf("version %d", v)
	}

	t.Run("failing tests block publish", func(t *testing.T) {
		wrong := adminTest
		wrong.Expect.ConfigRules = &[]string{}
		status(t, pub.save(pub.revision(), testConfig(), wrong), 200)
		resp := pub.publishDraft("broken")
		if p := decode[problem](t, resp); resp.StatusCode != 422 || len(p.Tests) != 1 || p.Tests[0].Pass {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
	})
	t.Run("a second publish supersedes the first", func(t *testing.T) {
		c := testConfig()
		c.RateLimitRules[0].Limit = 5
		status(t, pub.save(pub.revision(), c, adminTest), 200)
		status(t, pub.publishDraft("Tighten login"), 201)
		list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil))
		if len(list) != 2 || list[0].Status != "active" || list[1].Status != "superseded" || list[0].ChangeSummary != "+0 rules, ~1 changed, -0" || list[0].Author != "user:pub" {
			t.Fatalf("versions %+v", list)
		}
		v2 := decode[versionRow](t, pub.do("GET", "/api/versions/2", nil))
		if v2.Config.Version != 2 || v2.Config.RateLimitRules[0].Limit != 5 || len(v2.TestResults) != 1 {
			t.Fatalf("version 2 %+v", v2)
		}
	})
	if got := h.actions(); !slices.Contains(got, "config.publish version 1") || !slices.Contains(got, "config.publish version 2") {
		t.Fatalf("audit %v", got)
	}
}

// An issuer whose keys were never fetched blocks publish, unless a reason
// is given. Usually it's a mistyped JWKS URL.
func TestPublishWithoutIssuerKeys(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "publisher")
	pub := h.signedIn("pub")
	c := testConfig()
	c.Auth = snapshot.Auth{Issuers: []snapshot.Issuer{{ID: "corp", Issuer: "https://auth.example.com/", Audiences: []string{"api"}, JWKSURL: "https://auth.example.com/jwks", Algorithm: "RS256"}}, DefaultAccepted: []string{"corp"}}
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "orders", Expression: mustParse(`starts_with(http.request.uri.path, "/orders")`), Settings: snapshot.Settings{Auth: &snapshot.AuthSetting{Mode: "required"}}})
	status(t, pub.save(`"0"`, c), 200)
	resp := pub.publishDraft("Protect orders")
	if b := body(resp); resp.StatusCode != 422 || !strings.Contains(b, "corp, whose JWKS has never been fetched") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	status(t, pub.publishDraft("Protect orders", "override_reason", "IdP is down, publishing anyway"), 201)
	if v := decode[versionRow](t, pub.do("GET", "/api/versions/1", nil)); v.OverrideReason == nil || *v.OverrideReason != "IdP is down, publishing anyway" {
		t.Fatalf("override %v", v.OverrideReason)
	}
	// Every draft save tries to fetch missing keys, a copy of an old version
	// as much as an edit.
	if b := body(pub.do("POST", "/api/versions/1/copy-to-draft", nil, "If-Match", pub.revision())); !strings.Contains(b, "keys could not be fetched") {
		t.Fatalf("copy to draft: %s", b)
	}
	// Once keys exist, no override is needed.
	if _, err := h.db.Exec(t.Context(), "INSERT INTO jwks_keys VALUES ('corp', 'https://auth.example.com/jwks', now(), '{}')"); err != nil {
		t.Fatal(err)
	}
	status(t, pub.publishDraft("Again"), 201)
}

func TestRevert(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "publisher")
	h.user("ed", "editor")
	pub := h.signedIn("pub")
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v1"), 201)
	c := testConfig()
	c.RateLimitRules[0].Limit = 1
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("v2 too tight"), 201)

	status(t, h.signedIn("ed").do("POST", "/api/versions/1/revert", map[string]string{"reason": "x"}), 403)
	status(t, pub.do("POST", "/api/versions/1/revert", map[string]string{}), 422)
	resp := pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "Login limit locked users out"})
	if v := decode[map[string]int64](t, resp)["version"]; v != 3 {
		t.Fatalf("version %d", v)
	}
	v3 := decode[versionRow](t, pub.do("GET", "/api/versions/3", nil))
	if v3.Source != "revert" || *v3.BasedOn != 1 || v3.Config.RateLimitRules[0].Limit != 10 || v3.Status != "active" || v3.Message != "Login limit locked users out" {
		t.Fatalf("v3 %+v", v3)
	}

	t.Run("the draft can't silently undo the revert", func(t *testing.T) {
		resp := pub.publishDraft("publish the old draft")
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, "rebase") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("rebase applies the draft on top of the revert", func(t *testing.T) {
		view := decode[struct {
			Conflicts []string
			Result    snapshot.Config
		}](t, pub.do("GET", "/api/draft/rebase", nil))
		// The draft didn't change the login rule since v2, so the revert's
		// version is kept.
		if len(view.Conflicts) != 0 || view.Result.RateLimitRules[0].Limit != 10 {
			t.Fatalf("view %+v", view)
		}
		status(t, pub.do("POST", "/api/draft/rebase", nil, "If-Match", pub.revision()), 200)
		status(t, pub.do("GET", "/api/draft/rebase", nil), 409)
		status(t, pub.publishDraft("after the revert"), 201)
	})
	t.Run("a version that no longer fits the deployment can't be restored", func(t *testing.T) {
		// The admin upstream was removed from the deployment since v1.
		e := baseEnv("unused")
		e["UPSTREAMS"] = "app=http://app:8080"
		cfg, err := LoadConfig(env(e))
		if err != nil {
			t.Fatal(err)
		}
		h.s.cfg.Deployment = cfg.Deployment
		resp := pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "go back"})
		if b := body(resp); resp.StatusCode != 422 || !strings.Contains(b, "config.config_rules[0].settings.upstream") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	})
}

func TestCopyToDraftAndHistory(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "publisher")
	pub := h.signedIn("pub")
	status(t, pub.save(`"0"`, testConfig()), 200)
	status(t, pub.publishDraft("v1"), 201)
	c := testConfig()
	c.RateLimitRules[0].Limit = 3
	status(t, pub.save(pub.revision(), c), 200)
	status(t, pub.publishDraft("v2"), 201)
	c.RateLimitRules = nil
	status(t, pub.save(pub.revision(), c), 200)
	status(t, pub.publishDraft("v3 drop login limit"), 201)

	hist := decode[[]struct {
		Version int64
		Rule    map[string]any
	}](t, pub.do("GET", "/api/rules/login/history", nil))
	if len(hist) != 3 || hist[0].Rule["limit"] != 10.0 || hist[1].Rule["limit"] != 3.0 || hist[2].Rule != nil || hist[0].Rule["expression"] != `http.request.uri.path eq "/login"` {
		t.Fatalf("history %+v", hist)
	}
	status(t, pub.do("POST", "/api/versions/1/copy-to-draft", nil, "If-Match", `"9"`), 412)
	status(t, pub.do("POST", "/api/versions/1/copy-to-draft", nil, "If-Match", pub.revision()), 200)
	d := decode[struct {
		Config      snapshot.Config
		BaseVersion int64 `json:"base_version"`
	}](t, pub.do("GET", "/api/draft", nil))
	if len(d.Config.RateLimitRules) != 1 || d.BaseVersion != 3 {
		t.Fatalf("draft %+v", d)
	}
	diff := decode[struct {
		Diff    Diff
		Summary string
	}](t, pub.do("GET", "/api/diff/3/draft", nil))
	if diff.Summary != "+1 rules, ~0 changed, -0" || !slices.Equal(diff.Diff.Phases["rate_limit_rules"].Added, []string{"login"}) {
		t.Fatalf("diff %+v", diff)
	}
	raw := decode[map[string]string](t, pub.do("GET", "/api/diff/1/2?view=raw", nil))
	if !strings.Contains(raw["a"], `"limit": 10`) || !strings.Contains(raw["b"], `"limit": 3`) {
		t.Fatalf("raw %v", raw)
	}
	for _, path := range []string{"/api/diff/1/9", "/api/diff/x/1", "/api/diff/1/2?view=yaml", "/api/versions/x"} {
		if resp := pub.do("GET", path, nil); resp.StatusCode < 400 {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
}

func TestSimulateAndExpressionHelpers(t *testing.T) {
	h := newHarness(t)
	h.user("ed", "editor")
	ed := h.signedIn("ed")
	status(t, ed.do("POST", "/api/tests/run", nil), 404)
	status(t, ed.save(`"0"`, testConfig(), adminTest), 200)

	sim := decode[SimView](t, ed.do("POST", "/api/simulate", map[string]any{"request": TestRequest{Method: "POST", Host: "api.example.com", Path: "/login"}}))
	if !slices.Equal(sim.RateLimitRules, []string{"login"}) || sim.Settings.Upstream != "" {
		t.Fatalf("simulate %+v", sim)
	}
	if res := decode[[]TestResult](t, ed.do("POST", "/api/tests/run", nil)); len(res) != 1 || !res[0].Pass {
		t.Fatalf("tests %+v", res)
	}
	status(t, ed.do("POST", "/api/simulate", map[string]any{"request": TestRequest{Host: "api.example.com", Path: "/", IP: "not-an-ip"}}), 422)

	type op struct {
		Name  string
		Types []string
	}
	schema := decode[struct {
		Fields []struct {
			Name      string
			Available bool
			Phases    []string
		}
		Operators []op
	}](t, ed.do("GET", "/api/expr/schema", nil))
	avail := map[string]bool{}
	for _, f := range schema.Fields {
		avail[f.Name] = f.Available
	}
	// The cloudfront preset has country but not continent.
	if !avail["ip.src.country"] || avail["ip.src.continent"] || slices.ContainsFunc(schema.Operators, func(o op) bool { return o.Name == "matches" }) {
		t.Fatalf("schema availability %v", avail)
	}
	// The UI picks operators by these type names.
	if gt := schema.Operators[slices.IndexFunc(schema.Operators, func(o op) bool { return o.Name == "gt" })]; !slices.Equal(gt.Types, []string{"int"}) {
		t.Fatalf("gt types %v", gt.Types)
	}

	parsed := decode[struct{ AST expr.Node }](t, ed.do("POST", "/api/expr/parse", map[string]string{"text": `http.host eq "api.example.com"`}))
	// A syntax error is an RFC 9457 problem like every other API error.
	resp := ed.do("POST", "/api/expr/parse", map[string]string{"text": `http.host eq`})
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
	if syntax := decode[problem](t, resp); syntax.Status != 422 || syntax.Title == "" || !strings.HasPrefix(syntax.Detail, "position 12:") {
		t.Fatalf("syntax error %+v", syntax)
	}
	rendered := decode[struct {
		Text   string
		Length int
		Errors []expr.Issue
	}](t, ed.do("POST", "/api/expr/render", map[string]any{"ast": parsed.AST, "phase": "config"}))
	if rendered.Text != `http.host eq "api.example.com"` || rendered.Length != len(rendered.Text) || len(rendered.Errors) != 0 {
		t.Fatalf("render %+v", rendered)
	}
	claim := mustParse(`http.request.jwt.claims["sub"] eq "x"`)
	v := decode[struct{ Errors []expr.Issue }](t, ed.do("POST", "/api/expr/validate", map[string]any{"ast": claim, "phase": "config"}))
	if len(v.Errors) == 0 {
		t.Fatal("claims accepted in the config phase")
	}
	status(t, ed.do("POST", "/api/expr/validate", map[string]any{"ast": claim, "phase": "edge"}), 400)
}

// The export is the bootstrap file: an edge decodes and compiles it.
func TestExportLoadsOnAnEdgeAndImports(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "publisher")
	pub := h.signedIn("pub")
	status(t, pub.do("GET", "/api/export", nil), 404)
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v1"), 201)
	out := decode[struct {
		Envelope json.RawMessage
		Tests    []ConfigTest
	}](t, pub.do("GET", "/api/export", nil))
	exported, err := snapshot.Decode(bytes.NewReader(out.Envelope))
	if err != nil {
		t.Fatal(err)
	}
	dep, _ := edge.LoadDeployment(env(baseEnv("")))
	if _, errs := snapshot.CompileEnvelope(exported, dep); errs != nil {
		t.Fatalf("edge rejects the export: %v", errs)
	}

	// Staging promotion: import into another admin, through every check.
	prod := newHarness(t)
	prod.user("pub", "publisher")
	p := prod.signedIn("pub")
	status(t, p.do("POST", "/api/import", map[string]any{"config": exported.Active, "tests": out.Tests}), 422) // no message
	resp := p.do("POST", "/api/import", map[string]any{"config": exported.Active, "tests": out.Tests, "message": "Promote from staging"})
	if v := decode[map[string]int64](t, resp)["version"]; v != 1 {
		t.Fatalf("import version %d", v)
	}
	if v := decode[versionRow](t, p.do("GET", "/api/versions/1", nil)); v.Source != "import" {
		t.Fatalf("source %s", v.Source)
	}
	// With no draft yet, editing starts from what is active.
	d := decode[struct {
		Config      snapshot.Config
		Tests       []ConfigTest
		Revision    int64
		BaseVersion int64 `json:"base_version"`
	}](t, p.do("GET", "/api/draft", nil))
	if d.Revision != 0 || d.BaseVersion != 1 || len(d.Config.RateLimitRules) != 1 || len(d.Tests) != 1 {
		t.Fatalf("draft %+v", d)
	}
	if !slices.Contains(h.actions(), "config.export version 1") {
		t.Fatal("export not audited")
	}
}

func TestRebaseMerge(t *testing.T) {
	base := testConfig()
	base.RateLimitRules = append(base.RateLimitRules,
		snapshot.RateLimitRule{ID: "search", Expression: mustParse(`http.request.uri.path eq "/search"`), Algorithm: "sliding_window", Limit: 50, Period: snapshot.Duration(time.Minute), Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"})
	draft, active := clone(base), clone(base)
	// The draft adds a rule and edits search; active edits login, adds a
	// config rule and changes the kill switch.
	draft.RateLimitRules = append(draft.RateLimitRules, snapshot.RateLimitRule{ID: "signup", Expression: mustParse(`http.request.uri.path eq "/signup"`), Algorithm: "sliding_window", Limit: 5, Period: snapshot.Duration(time.Minute), Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"})
	draft.RateLimitRules[1].Limit = 40
	active.RateLimitRules[0].Limit = 2
	active.ConfigRules = append([]snapshot.ConfigRule{{ID: "maintenance", Expression: mustParse(`true`), Settings: snapshot.Settings{Locale: new(false)}}}, active.ConfigRules...)
	active.KillSwitch.RateLimit = true
	got, conflicts := rebase(base, draft, active)
	ids := func(rs []snapshot.RateLimitRule) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	if len(conflicts) != 0 || !slices.Equal(ids(got.RateLimitRules), []string{"login", "search", "signup"}) || got.RateLimitRules[0].Limit != 2 ||
		got.RateLimitRules[1].Limit != 40 || got.ConfigRules[0].ID != "maintenance" || !got.KillSwitch.RateLimit {
		t.Fatalf("rebase = %+v, conflicts %v", got, conflicts)
	}
	// Active removed search, which the draft left alone: it stays removed.
	active2 := clone(base)
	active2.RateLimitRules = active2.RateLimitRules[:1]
	got, _ = rebase(base, clone(base), active2)
	if !slices.Equal(ids(got.RateLimitRules), []string{"login"}) {
		t.Fatalf("removed rule came back: %v", ids(got.RateLimitRules))
	}
	// The draft removed login, which active edited: a conflict, the draft wins.
	draft3 := clone(base)
	draft3.RateLimitRules = draft3.RateLimitRules[1:]
	got, conflicts = rebase(base, draft3, active)
	if !slices.Equal(conflicts, []string{"rate_limit_rules.login"}) || !slices.Equal(ids(got.RateLimitRules), []string{"search"}) {
		t.Fatalf("got %v, conflicts %v", ids(got.RateLimitRules), conflicts)
	}
	// Both changed global: conflict, the draft wins.
	d4, a4 := clone(base), clone(base)
	d4.Global.Defaults.BodyLimit, a4.Global.Defaults.BodyLimit = 2048, 4096
	got, conflicts = rebase(base, d4, a4)
	if !slices.Equal(conflicts, []string{"global"}) || got.Global.Defaults.BodyLimit != 2048 {
		t.Fatalf("global conflict %v", conflicts)
	}
}
