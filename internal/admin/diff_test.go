package admin

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

func TestSemanticDiff(t *testing.T) {
	a, b := testConfig(), testConfig()
	b.RateLimitRules[0].Expression = mustParse(`http.request.uri.path eq "/v2/login"`)
	b.ConfigRules = append(b.ConfigRules, snapshot.ConfigRule{ID: "uploads", Expression: mustParse(`true`), Settings: snapshot.Settings{BodyLimit: new(int64(1 << 20))}})
	b.ConfigRules[0], b.ConfigRules[1] = b.ConfigRules[1], b.ConfigRules[0]
	b.Global.Defaults.BodyLimit = 2048
	d := semanticDiff(a, b)
	rl := d.Phases["rate_limit_rules"]
	if len(rl.Changed) != 1 || rl.Changed[0].Fields[0] != (FieldChange{Path: "expression", Before: `http.request.uri.path eq "/login"`, After: `http.request.uri.path eq "/v2/login"`}) {
		t.Fatalf("rate limit diff %+v", rl)
	}
	if cr := d.Phases["config_rules"]; !slices.Equal(cr.Added, []string{"uploads"}) || cr.Reordered {
		t.Fatalf("config diff %+v", cr)
	}
	if len(d.Sections) != 1 || d.Sections[0].Path != "global.defaults.body_limit" || d.summary() != "1 rule added, 1 rule changed, 1 setting changed" {
		t.Fatalf("sections %+v, %s", d.Sections, d.summary())
	}
	c := testConfig()
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "z", Expression: mustParse(`true`)})
	e := clone(c)
	e.ConfigRules[0], e.ConfigRules[1] = e.ConfigRules[1], e.ConfigRules[0]
	if !semanticDiff(c, e).Phases["config_rules"].Reordered {
		t.Fatal("reorder not reported")
	}
}

// The version list shows the summary, so each kind of change reads as it
// is, in the same words as the UI's draft status.
func TestVersionSummary(t *testing.T) {
	base := testConfig()
	base.ConfigRules = append(base.ConfigRules, snapshot.ConfigRule{ID: "z", Expression: mustParse(`true`)})
	cases := []struct {
		name   string
		change func(c *snapshot.Config)
		want   string
	}{
		{"republishing the same config says no changes", func(*snapshot.Config) {}, "no changes"},
		{"a reorder alone is a change", func(c *snapshot.Config) { c.ConfigRules[0], c.ConfigRules[1] = c.ConfigRules[1], c.ConfigRules[0] }, "rules reordered"},
		{"two removed rules read in the plural", func(c *snapshot.Config) { c.ConfigRules = c.ConfigRules[:len(c.ConfigRules)-2] }, "2 rules removed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := clone(base)
			tc.change(next)
			if got := semanticDiff(base, next).summary(); got != tc.want {
				t.Fatalf("summary %q, want %q", got, tc.want)
			}
		})
	}
}

// A new top-level config field must show in the audit diff and survive a
// rebase, so it has to be a section or a phase.
func TestDiffCoversEveryConfigField(t *testing.T) {
	known := map[string]bool{"schema": true, "version": true}
	for _, sec := range configSections {
		known[sec.name] = true
	}
	for _, ph := range phaseNames {
		known[ph] = true
	}
	for f := range reflect.TypeFor[snapshot.Config]().Fields() {
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); !known[name] {
			t.Errorf("config field %s is neither a diff section nor a phase", name)
		}
	}
}
