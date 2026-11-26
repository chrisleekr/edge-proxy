package admin

import (
	"bytes"
	"context"
	"encoding"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// docRows returns the cells of every Markdown table row in a docs page, or
// only under the "## section" heading when section is set.
func docRows(t *testing.T, page, section string) [][]string {
	t.Helper()
	b, err := os.ReadFile("../../docs/" + page)
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]string
	in := section == ""
	for line := range strings.Lines(string(b)) {
		line = strings.TrimSpace(line)
		if section != "" && strings.HasPrefix(line, "## ") {
			in = line == "## "+section
		}
		if in && strings.HasPrefix(line, "|") && !strings.HasPrefix(line, "|---") {
			rows = append(rows, strings.Split(strings.Trim(line, "|"), "|"))
		}
	}
	return rows
}

var codeSpan = regexp.MustCompile("`([^`]+)`")

// spans lists the code spans in s that match keep.
func spans(s string, keep *regexp.Regexp) []string {
	var out []string
	for _, m := range codeSpan.FindAllStringSubmatch(s, -1) {
		if keep.MatchString(m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

// diff reports what one side has and the other lacks.
func diff(t *testing.T, what string, code, docs []string) {
	t.Helper()
	for _, c := range code {
		if !slices.Contains(docs, c) {
			t.Errorf("%s %s is in the code but not documented", what, c)
		}
	}
	for _, d := range docs {
		if !slices.Contains(code, d) {
			t.Errorf("%s %s is documented but not in the code", what, d)
		}
	}
}

func uniq(s []string) []string { slices.Sort(s); return slices.Compact(s) }

// Every variable the edge and admin read is in the settings tables, and
// every variable there is still read.
func TestDocsListEveryVariable(t *testing.T) {
	envName := regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,}$`)
	for _, c := range []struct {
		page string
		load func(ctx context.Context, getenv func(string) string)
	}{
		{"deploy/edge.md", func(_ context.Context, getenv func(string) string) {
			_, _ = edge.LoadConfig(getenv)
			_, _ = edge.LoadDeployment(getenv)
		}},
		{"deploy/admin.md", func(ctx context.Context, getenv func(string) string) {
			_, _ = LoadConfig(getenv)
			Main(ctx, nil, []string{"migrate"}, getenv, strings.NewReader(""), io.Discard)
		}},
	} {
		t.Run(c.page, func(t *testing.T) {
			var read []string
			// A valid source, so the parsers read past it to the variables it enables.
			c.load(t.Context(), func(k string) string {
				read = append(read, k)
				if k == "CLIENT_IP_SOURCE" {
					return "cloudfront"
				}
				return ""
			})
			var documented []string
			for _, row := range docRows(t, c.page, "") {
				documented = append(documented, spans(row[0], envName)...)
			}
			diff(t, "variable", uniq(read), uniq(documented))
		})
	}
}

// Every variable the autopilot runner reads is in its settings table, and
// every variable there is still read. The runner reads them as env['NAME'].
func TestDocsListEveryRunnerVariable(t *testing.T) {
	files, err := filepath.Glob("../../autopilot/src/*.ts")
	if err != nil || len(files) == 0 {
		t.Fatalf("no runner sources in autopilot/src, err %v", err)
	}
	read := regexp.MustCompile(`env\[['"]([A-Z][A-Z0-9_]{2,})['"]\]`)
	var code []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range read.FindAllStringSubmatch(string(b), -1) {
			code = append(code, m[1])
		}
	}
	envName := regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,}$`)
	var documented []string
	for _, row := range docRows(t, "deploy/autopilot.md", "Variables") {
		documented = append(documented, spans(row[0], envName)...)
	}
	diff(t, "variable", uniq(code), uniq(documented))
}

// The API reference lists every route with the permission it needs.
func TestDocsListEveryRoute(t *testing.T) {
	s := NewServer(&Config{}, nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	route := regexp.MustCompile(`^(GET|POST|PUT|DELETE|PATCH) /`)
	need := map[string]string{} // route -> permission as the docs write it
	var code []string
	for _, r := range s.registered {
		i := strings.LastIndexByte(r, ' ')
		pattern, perm := r[:i], r[i+1:]
		switch perm {
		case "":
			perm = "signed in"
		case "public":
		case permEdge:
			perm = "edge token"
		default:
			perm = "`" + perm + "`"
		}
		need[pattern] = perm
		code = append(code, pattern)
	}
	var documented []string
	for _, row := range docRows(t, "reference/api.md", "Endpoints") {
		for _, r := range spans(row[0], route) {
			documented = append(documented, r)
			if p, ok := need[r]; ok && len(row) > 1 && !strings.HasPrefix(strings.TrimSpace(row[1]), p) {
				t.Errorf("%s needs %s, but the docs say %q", r, p, strings.TrimSpace(row[1]))
			}
		}
	}
	diff(t, "route", uniq(code), uniq(documented))
}

// The expression reference lists every field.
func TestDocsListEveryField(t *testing.T) {
	var code []string
	for _, f := range expr.Fields {
		code = append(code, f.Name)
	}
	field := regexp.MustCompile(`^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*(\[.*\])?$`)
	var documented []string
	for _, row := range docRows(t, "reference/expressions.md", "Fields") {
		for _, f := range spans(row[0], field) {
			documented = append(documented, strings.SplitN(f, "[", 2)[0])
		}
	}
	diff(t, "field", uniq(code), uniq(documented))
}

// Every screenshot in the docs is rendered by the screenshot check, and
// every image it renders is shown, so no image can go stale unchecked.
func TestDocsShowEveryScreenshot(t *testing.T) {
	spec, err := os.ReadFile("../../web/admin/docs-shots/screenshots.spec.ts")
	if err != nil {
		t.Fatal(err)
	}
	var rendered []string
	for _, m := range regexp.MustCompile(`\['([a-z-]+)', '/|shot\(page, '([a-z-]+)'|toHaveScreenshot\('([a-z-]+)\.png'`).FindAllStringSubmatch(string(spec), -1) {
		rendered = append(rendered, m[1]+m[2]+m[3]+".png")
	}
	files, err := os.ReadDir("../../docs/assets/screenshots")
	if err != nil {
		t.Fatal(err)
	}
	var stored []string
	for _, f := range files {
		stored = append(stored, f.Name())
	}
	var shown []string
	link := regexp.MustCompile(`assets/screenshots/([a-z-]+\.png)`)
	err = filepath.WalkDir("../../docs", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
			return err
		}
		b, err := os.ReadFile(p)
		for _, m := range link.FindAllStringSubmatch(string(b), -1) {
			shown = append(shown, m[1])
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	diff(t, "screenshot", uniq(rendered), uniq(stored))
	diff(t, "screenshot", uniq(rendered), uniq(shown))
}

// The monitoring page lists every admin metric, including the leader-only
// gauges, and nothing admin no longer exports.
func TestDocsListEveryAdminMetric(t *testing.T) {
	s := &Server{}
	s.met.leader.Store(true)
	s.met.gauges.Store(&leaderGauges{})
	var b bytes.Buffer
	s.writeMetrics(&b)
	var code []string
	for line := range strings.Lines(b.String()) {
		if f := strings.Fields(line); len(f) == 4 && f[1] == "TYPE" {
			code = append(code, f[2])
		}
	}
	metric := regexp.MustCompile(`^admin_[a-z_]+(\{[a-z_,]+\})?$`)
	var documented []string
	for _, row := range docRows(t, "operate/monitoring.md", "Admin metrics") {
		for _, m := range spans(row[0], metric) {
			documented = append(documented, strings.SplitN(m, "{", 2)[0])
		}
	}
	diff(t, "metric", uniq(code), uniq(documented))
}

// The Default IP lists table has every list the migration seeds, with its
// address and whether it allows wide ranges, and nothing else.
func TestDocsListEveryDefaultIPList(t *testing.T) {
	b, err := os.ReadFile("../admindb/migrations/0022_ip_list_names.sql")
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for _, m := range regexp.MustCompile(`\('([a-z0-9-]+)', '([^']+)', (true|false)\)[,;]`).FindAllStringSubmatch(string(b), -1) {
		code = append(code, m[1]+" "+m[2]+" wide="+m[3])
	}
	if len(code) != 73 {
		t.Fatalf("the migration seeds %d lists, want 73", len(code))
	}
	var docs []string
	for _, row := range docRows(t, "use/ip-lists.md", "Default IP lists") {
		if len(row) != 4 || strings.TrimSpace(row[0]) == "Name" || strings.TrimSpace(row[0]) == "---" {
			continue
		}
		name, url := strings.Trim(strings.TrimSpace(row[0]), "`"), strings.Trim(strings.TrimSpace(row[2]), "`")
		docs = append(docs, name+" "+url+" wide="+map[string]string{"yes": "true", "no": "false"}[strings.TrimSpace(row[3])])
	}
	diff(t, "default IP list", uniq(code), uniq(docs))
}

// leaf reports a type the docs treat as one value: it has its own JSON or
// text form, so its Go fields are not settings.
func leaf(t reflect.Type) bool {
	if t == reflect.TypeFor[expr.Node]() {
		return true
	}
	for _, i := range []reflect.Type{reflect.TypeFor[json.Marshaler](), reflect.TypeFor[encoding.TextMarshaler]()} {
		if t.Implements(i) || reflect.PointerTo(t).Implements(i) {
			return true
		}
	}
	return false
}

// mapKeyNames name the key of a map by where it sits; any other map key is <name>.
var mapKeyNames = map[string]string{"notifications.rules": "<rule>", "notifications.rules.<rule>": "<signal>"}

// settingPaths appends the dotted JSON path of every leaf setting under t.
// Map keys read <name> and slice elements [], so a path names a setting once
// however many entries a policy holds.
func settingPaths(t *testing.T, out *[]string, typ reflect.Type, path string) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	join := func(name string) string {
		if path == "" {
			return name
		}
		return path + "." + name
	}
	nested := func(e reflect.Type) bool {
		for e.Kind() == reflect.Pointer {
			e = e.Elem()
		}
		return (e.Kind() == reflect.Struct || e.Kind() == reflect.Map) && !leaf(e)
	}
	switch {
	case leaf(typ):
		*out = append(*out, path)
	case typ.Kind() == reflect.Struct:
		for f := range typ.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if !f.IsExported() || name == "-" {
				continue
			}
			// An untagged or embedded field gets a path this walk cannot name, so it would escape the docs check.
			if name == "" || f.Anonymous {
				t.Fatalf("%s.%s has no json name: tag it so the policy fields reference can list it", typ, f.Name)
			}
			settingPaths(t, out, f.Type, join(name))
		}
	case typ.Kind() == reflect.Map && nested(typ.Elem()):
		key := mapKeyNames[path]
		if key == "" {
			key = "<name>"
		}
		settingPaths(t, out, typ.Elem(), join(key))
	case typ.Kind() == reflect.Slice && nested(typ.Elem()):
		settingPaths(t, out, typ.Elem(), path+"[]")
	default:
		*out = append(*out, path)
	}
}

// The policy fields reference lists every policy and admin setting, so a
// field added or removed without its docs fails here.
func TestDocsListEveryPolicyField(t *testing.T) {
	var policy, adminSettings []string
	settingPaths(t, &policy, reflect.TypeFor[snapshot.Config](), "")
	for prefix, typ := range map[string]reflect.Type{
		"guard":         reflect.TypeFor[GuardSettings](),
		"notifications": reflect.TypeFor[NotifySettings](),
		"autopilot":     reflect.TypeFor[AutopilotSettings](),
		"traffic_map":   reflect.TypeFor[TrafficMapSettings](),
	} {
		settingPaths(t, &adminSettings, typ, prefix)
	}
	anySpan := regexp.MustCompile(`.`)
	for section, code := range map[string][]string{"Policy": policy, "Admin settings": adminSettings} {
		var documented []string
		for _, row := range docRows(t, "reference/policy-fields.md", section) {
			documented = append(documented, spans(row[0], anySpan)...)
		}
		diff(t, section+" field", uniq(code), uniq(documented))
	}
}

// Every admin page has a section in the tour page of its sidebar group.
func TestDocsTourEveryPage(t *testing.T) {
	b, err := os.ReadFile("../../web/admin/src/nav.ts")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	matches := regexp.MustCompile(`group: '([^']+)'|label: '([^']+)'`).FindAllStringSubmatch(src, -1)
	// A quoting change in nav.ts would make the pattern match nothing and the test pass silently.
	labels, links := 0, len(regexp.MustCompile(`to:\s*['"]`).FindAllString(src, -1))
	for _, m := range matches {
		if m[2] != "" {
			labels++
		}
	}
	if labels == 0 || labels != links {
		t.Fatalf("read %d page labels from nav.ts but it has %d links: update the pattern to match its quoting", labels, links)
	}
	var group string
	for _, m := range matches {
		if m[1] != "" {
			group = strings.ToLower(m[1])
			continue
		}
		label := m[2]
		tour, err := os.ReadFile("../../docs/tour/" + group + ".md")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains("\n"+string(tour), "\n## "+label+"\n") {
			t.Errorf("page %s has no \"## %s\" section in tour/%s.md", label, label, group)
		}
	}
}

// recipe is one "## " section of a use-case page: the rules and settings it
// tells the reader to enter, and the policy tests that prove them.
type recipe struct {
	heading string
	rules   []map[string]any
	phases  []string    // config key of each rule's phase list
	sets    [][2]string // settings path and its JSON
	tests   []string
	text    string // the section's Markdown, to find a promised warning
}

var (
	rulePhases = map[string]string{"Access rule": "config_rules", "Rate limit rule": "rate_limit_rules", "Request header rule": "request_header_rules"}
	// Paths an "Also set" may name, and whether its JSON adds keys to a map.
	setPaths    = map[string]bool{"auth": false, "global.cors_policies": true, "global.responses": true, "global.lists": true, "global.locale": false, "global.client_allowlist": false}
	ruleMarker  = regexp.MustCompile("^\\*\\*Rule\\*\\* · (.+?), ID `([^`]+)`")
	setMarker   = regexp.MustCompile("^\\*\\*Also set\\*\\*.*?\\(`([^`]+)`\\)[.:]")
	jsonFence   = regexp.MustCompile("(?s)```json\n(.*?)\n```")
	proveMarker = regexp.MustCompile(`(?m)^\*\*Prove it\*\*`)
	ruleCount   = regexp.MustCompile(`(?m)^\*\*Rule\*\*`)
)

// strictDecode reads src as admin reads a draft: unknown fields and data after the value are errors.
func strictDecode(src string, v any) error {
	dec := json.NewDecoder(strings.NewReader(src))
	dec.DisallowUnknownFields()
	return decodeOne(dec, v, "invalid JSON")
}

// parseRecipes reads the recipes of a cookbook page. It returns the number
// of Rule and Prove it fences it found, for the caller to compare with the
// markers in the text.
func parseRecipes(t *testing.T, src string) (recipes []*recipe, rules, proofs int) {
	t.Helper()
	var cur *recipe
	var pending, when, phase, id string // what the next fence is for
	start := 0
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if cur != nil {
			cur.text = strings.Join(lines[start:min(i+1, len(lines))], "\n")
		}
		if h, ok := strings.CutPrefix(line, "## "); ok {
			cur = &recipe{heading: h}
			start = i
			recipes = append(recipes, cur)
			pending = ""
		} else if m := ruleMarker.FindStringSubmatch(line); m != nil {
			pending, phase, id = "when", m[1], m[2]
		} else if m := setMarker.FindStringSubmatch(line); m != nil {
			pending = "set " + m[1]
		} else if strings.HasPrefix(line, "**Also set**") {
			// IP lists and monitors have no JSON, the policy test supplies them.
			pending = "also"
		} else if strings.HasPrefix(line, "**Prove it**") {
			pending = "prove"
		} else if lang, ok := strings.CutPrefix(line, "```"); ok && lang != "" {
			j := i + 1
			for ; j < len(lines) && lines[j] != "```"; j++ {
			}
			if j == len(lines) {
				t.Fatalf("%s: code fence on line %d is never closed", cur.heading, i+1)
			}
			body := strings.Join(lines[i+1:j], "\n")
			i = j
			switch {
			case pending == "also" && lang == "json":
				t.Fatalf("%s: JSON after an Also set line that names no settings path: write the path in backticks and end the sentence with . or :", cur.heading)
			case pending == "when" && lang == "text":
				when, pending = body, "then"
			case pending == "then" && lang == "json":
				var rule map[string]any
				if err := strictDecode(body, &rule); err != nil {
					t.Fatalf("%s: Then is not a JSON object: %v", cur.heading, err)
				}
				rule["when"] = when
				rule["id"] = id
				cur.rules, cur.phases = append(cur.rules, rule), append(cur.phases, phase)
				rules++
				pending = ""
			case strings.HasPrefix(pending, "set ") && lang == "json":
				cur.sets = append(cur.sets, [2]string{strings.TrimPrefix(pending, "set "), body})
				pending = ""
			case pending == "prove" && lang == "json":
				cur.tests = append(cur.tests, body)
				proofs++
				pending = ""
			}
		}
	}
	return recipes, rules, proofs
}

// build applies the recipe to the starter policy the way the admin UI does,
// then decodes it as admin reads a draft.
func (r *recipe) build(t *testing.T) snapshot.Config {
	t.Helper()
	raw, _ := json.Marshal(snapshot.Starter())
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	for i, rule := range r.rules {
		key, ok := rulePhases[r.phases[i]]
		if !ok {
			t.Fatalf("unknown phase label %q", r.phases[i])
		}
		node, err := expr.Parse(rule["when"].(string))
		if err != nil {
			t.Fatalf("rule %s: When does not parse: %v", rule["id"], err)
		}
		delete(rule, "when")
		rule["expression"] = node
		list, _ := root[key].([]any)
		root[key] = append(list, rule)
	}
	for _, s := range r.sets {
		merge, ok := setPaths[s[0]]
		if !ok {
			t.Fatalf("Also set path %q is not handled by the docs test: add it to setPaths", s[0])
		}
		var val any
		if err := json.Unmarshal([]byte(s[1]), &val); err != nil {
			t.Fatalf("Also set %s: %v", s[0], err)
		}
		m := root
		keys := strings.Split(s[0], ".")
		for _, k := range keys[:len(keys)-1] {
			m = m[k].(map[string]any)
		}
		last := keys[len(keys)-1]
		add, isMap := val.(map[string]any)
		if dst, ok := m[last].(map[string]any); ok && merge && isMap {
			maps.Copy(dst, add)
			val = dst
		}
		m[last] = val
	}
	raw, _ = json.Marshal(root)
	var cfg snapshot.Config
	if err := strictDecode(string(raw), &cfg); err != nil {
		t.Fatalf("policy does not decode: %v", err)
	}
	return cfg
}

// Every recipe in the use docs (the cookbook and the feature pages that show
// one) compiles, and its policy tests pass, against the same validator and
// test runner admin uses.
func TestDocsCookbookRecipes(t *testing.T) {
	// Every viewer field is available and verified bots are on, so a recipe
	// is not rejected for a deployment detail the reader sets up themselves.
	dep := snapshot.Deployment{VerifiedBots: true}
	for _, f := range expr.Fields {
		if f.Source == expr.SourceViewer {
			dep.ViewerFields = append(dep.ViewerFields, f.Name)
		}
	}
	var pages []string
	err := filepath.WalkDir("../../docs/use", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".md") {
			pages = append(pages, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, p := range pages {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		page := strings.TrimPrefix(p, "../../docs/")
		recipes, rules, proofs := parseRecipes(t, string(b))
		// A parser regression would otherwise test nothing and pass.
		if want := len(ruleCount.FindAllString(string(b), -1)); rules != want {
			t.Errorf("%s: parsed %d rules but the page has %d Rule markers", page, rules, want)
		}
		if want := len(proveMarker.FindAllString(string(b), -1)); proofs != want {
			t.Errorf("%s: parsed %d policy tests but the page has %d Prove it markers", page, proofs, want)
		}
		for _, r := range recipes {
			if len(r.rules)+len(r.sets)+len(r.tests) == 0 {
				continue
			}
			ran++
			t.Run(page+"/"+r.heading, func(t *testing.T) {
				cfg := r.build(t)
				cfg.Version = 1 // admin assigns the next version on save
				compiled, warns, errs := snapshot.Compile(&cfg, dep)
				if compiled == nil {
					t.Fatalf("does not compile: %v", errs)
				}
				if len(warns) > 0 && !strings.Contains(r.text, "expect the warning") {
					t.Fatalf("saves with warnings the recipe does not mention: %v", expr.Issues(warns))
				}
				var tests []ConfigTest
				for _, body := range r.tests {
					var more []ConfigTest
					if err := strictDecode(body, &more); err != nil {
						t.Fatalf("policy tests do not decode: %v", err)
					}
					tests = append(tests, more...)
				}
				if issues := checkTests(tests); len(issues) > 0 {
					t.Fatalf("policy tests are invalid: %v", issues)
				}
				for _, res := range runTests(compiled, tests) {
					for _, f := range res.Failures {
						t.Errorf("test %q failed: %s", res.Name, f)
					}
				}
			})
		}
	}
	if ran == 0 {
		t.Fatal("found no recipes under docs/use")
	}
}

// Every policy test array shown anywhere in the use docs is valid, including
// those on pages whose policy is not built here.
func TestDocsPolicyTestsAreValid(t *testing.T) {
	err := filepath.WalkDir("../../docs/use", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range jsonFence.FindAllStringSubmatch(string(b), -1) {
			if !strings.Contains(m[1], `"expect"`) {
				continue
			}
			body := m[1]
			// One test on its own, as docs/use/policy.md shows it.
			if strings.HasPrefix(strings.TrimSpace(body), "{") {
				body = "[" + body + "]"
			}
			var tests []ConfigTest
			if err := strictDecode(body, &tests); err != nil {
				t.Errorf("%s: policy tests do not decode: %v", p, err)
			} else if issues := checkTests(tests); len(issues) > 0 {
				t.Errorf("%s: policy tests are invalid: %v", p, issues)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
