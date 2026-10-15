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
	if len(d.Sections) != 1 || d.Sections[0].Path != "global.defaults.body_limit" || d.summary() != "+1 rules, ~1 changed, -0, 1 settings changed" {
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
