package admin

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
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
	for _, m := range regexp.MustCompile(`\['([a-z-]+)', '/|shot\(page, '([a-z-]+)'`).FindAllStringSubmatch(string(spec), -1) {
		rendered = append(rendered, m[1]+m[2]+".png")
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
