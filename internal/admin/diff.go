package admin

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// Diff is the semantic diff of two configs: rules added,
// removed, changed and reordered per phase, and field-level changes.
type Diff struct {
	Sections []FieldChange         `json:"sections"`
	Phases   map[string]*PhaseDiff `json:"phases"`
}

// PhaseDiff is one rule list's changes.
type PhaseDiff struct {
	Added     []string     `json:"added"`
	Removed   []string     `json:"removed"`
	Changed   []RuleChange `json:"changed"`
	Reordered bool         `json:"reordered"`
}

// RuleChange is one rule's field-level differences.
type RuleChange struct {
	ID     string        `json:"id"`
	Fields []FieldChange `json:"fields"`
}

// FieldChange is one value before and after. Expressions are shown as
// rendered text, which is what people read.
type FieldChange struct {
	Path   string `json:"path"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

var phaseNames = []string{"config_rules", "rate_limit_rules", "request_header_rules"}

// rule is one rule of any phase, in generic form.
type rule struct {
	id   string
	body map[string]any
}

// rulesOf returns each phase's rules in order, with expressions rendered.
func rulesOf(c *snapshot.Config) map[string][]rule {
	out := map[string][]rule{}
	add := func(phase, id string, r any, n expr.Node) {
		m := generic(r).(map[string]any)
		m["expression"] = expr.Render(n)
		out[phase] = append(out[phase], rule{id: id, body: m})
	}
	for _, r := range c.ConfigRules {
		add("config_rules", r.ID, r, r.Expression)
	}
	for _, r := range c.RateLimitRules {
		add("rate_limit_rules", r.ID, r, r.Expression)
	}
	for _, r := range c.RequestHeaderRules {
		add("request_header_rules", r.ID, r, r.Expression)
	}
	return out
}

// configSections are the non-rule parts of a config, for diff and rebase.
// schema and version are left out: version changes on every publish, and
// schema with the build. A test checks every Config field is a section, a
// phase or one of these two.
var configSections = []struct {
	name string
	get  func(*snapshot.Config) any
	set  func(dst, src *snapshot.Config)
}{
	{"kill_switch", func(c *snapshot.Config) any { return c.KillSwitch }, func(d, s *snapshot.Config) { d.KillSwitch = s.KillSwitch }},
	{"global", func(c *snapshot.Config) any { return c.Global }, func(d, s *snapshot.Config) { d.Global = s.Global }},
	{"auth", func(c *snapshot.Config) any { return c.Auth }, func(d, s *snapshot.Config) { d.Auth = s.Auth }},
}

func sections(c *snapshot.Config) map[string]any {
	out := map[string]any{}
	for _, sec := range configSections {
		out[sec.name] = generic(sec.get(c))
	}
	return out
}

func generic(v any) any {
	b, _ := json.Marshal(v) // config types and decoded JSON always marshal
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// semanticDiff compares a and b.
func semanticDiff(a, b *snapshot.Config) Diff {
	d := Diff{Sections: []FieldChange{}, Phases: map[string]*PhaseDiff{}}
	compare("", sections(a), sections(b), &d.Sections)
	ra, rb := rulesOf(a), rulesOf(b)
	for _, ph := range phaseNames {
		pd := &PhaseDiff{Added: []string{}, Removed: []string{}, Changed: []RuleChange{}}
		before := byID(ra[ph])
		after := byID(rb[ph])
		var keptA, keptB []string
		for _, r := range ra[ph] {
			if _, ok := after[r.id]; !ok {
				pd.Removed = append(pd.Removed, r.id)
			} else {
				keptA = append(keptA, r.id)
			}
		}
		for _, r := range rb[ph] {
			old, ok := before[r.id]
			if !ok {
				pd.Added = append(pd.Added, r.id)
				continue
			}
			keptB = append(keptB, r.id)
			var fields []FieldChange
			compare("", old, r.body, &fields)
			if len(fields) > 0 {
				pd.Changed = append(pd.Changed, RuleChange{ID: r.id, Fields: fields})
			}
		}
		pd.Reordered = !slices.Equal(keptA, keptB)
		d.Phases[ph] = pd
	}
	return d
}

func byID(rs []rule) map[string]map[string]any {
	m := make(map[string]map[string]any, len(rs))
	for _, r := range rs {
		m[r.id] = r.body
	}
	return m
}

// compare appends the leaf differences between a and b. Lists that differ
// are reported whole: their elements have no stable identity.
func compare(path string, a, b any, out *[]FieldChange) {
	ma, okA := a.(map[string]any)
	mb, okB := b.(map[string]any)
	if okA && okB {
		keys := slices.Sorted(maps.Keys(ma))
		for k := range mb {
			if _, ok := ma[k]; !ok {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		keys = slices.Compact(keys)
		for _, k := range keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			compare(p, ma[k], mb[k], out)
		}
		return
	}
	if !reflect.DeepEqual(a, b) {
		*out = append(*out, FieldChange{Path: path, Before: a, After: b})
	}
}

// summary is the change count shown on a version, in words, such as
// "2 rules added, 1 rule changed".
func (d Diff) summary() string {
	var add, chg, rm int
	var reordered bool
	for _, pd := range d.Phases {
		add, chg, rm = add+len(pd.Added), chg+len(pd.Changed), rm+len(pd.Removed)
		reordered = reordered || pd.Reordered
	}
	var parts []string
	count := func(n int, what, done string) {
		if n == 1 {
			parts = append(parts, "1 "+what+" "+done)
		} else if n > 1 {
			parts = append(parts, fmt.Sprintf("%d %ss %s", n, what, done))
		}
	}
	// The same order and words as the UI's describe, so the version list and
	// the draft status agree. Order decides which rules run, so a reorder alone
	// is a change.
	count(add, "rule", "added")
	count(rm, "rule", "removed")
	count(chg, "rule", "changed")
	if reordered {
		parts = append(parts, "rules reordered")
	}
	count(len(d.Sections), "setting", "changed")
	if len(parts) == 0 {
		return "no changes"
	}
	return strings.Join(parts, ", ")
}

// rebase applies the draft's changes since base on top of active,
// so a revert or rollback published meanwhile is kept unless the
// draft itself changed the same thing. conflicts lists what both changed;
// the draft's version wins there.
func rebase(base, draft, active *snapshot.Config) (*snapshot.Config, []string) {
	var conflicts []string
	out := *draft
	// Sections: the draft's edit wins; otherwise take active's.
	for _, sec := range configSections {
		d, b, a := generic(sec.get(draft)), generic(sec.get(base)), generic(sec.get(active))
		if reflect.DeepEqual(d, b) {
			sec.set(&out, active)
		} else if !reflect.DeepEqual(a, b) && !reflect.DeepEqual(a, d) {
			conflicts = append(conflicts, sec.name)
		}
	}
	out.ConfigRules = mergeRules("config_rules", base.ConfigRules, draft.ConfigRules, active.ConfigRules, func(r snapshot.ConfigRule) string { return r.ID }, &conflicts)
	out.RateLimitRules = mergeRules("rate_limit_rules", base.RateLimitRules, draft.RateLimitRules, active.RateLimitRules, func(r snapshot.RateLimitRule) string { return r.ID }, &conflicts)
	out.RequestHeaderRules = mergeRules("request_header_rules", base.RequestHeaderRules, draft.RequestHeaderRules, active.RequestHeaderRules, func(r snapshot.HeaderRule) string { return r.ID }, &conflicts)
	return &out, conflicts
}

// mergeRules starts from the draft's list and brings in what active changed
// since base where the draft left the rule alone: added rules at active's
// position, removed rules dropped, edited rules replaced.
func mergeRules[R any](phase string, base, draft, active []R, id func(R) string, conflicts *[]string) []R {
	index := func(rs []R) map[string]R {
		m := map[string]R{}
		for _, r := range rs {
			m[id(r)] = r
		}
		return m
	}
	b, d, a := index(base), index(draft), index(active)
	same := func(x, y R) bool { return reflect.DeepEqual(generic(x), generic(y)) }
	out := []R{}
	for _, r := range draft {
		k := id(r)
		br, inBase := b[k]
		ar, inActive := a[k]
		switch {
		case !inBase:
			out = append(out, r) // added by the draft
		case same(r, br) && !inActive:
			// removed by active, untouched by the draft
		case same(r, br):
			out = append(out, ar) // active's version of an untouched rule
		default:
			if inActive && !same(ar, br) && !same(ar, r) {
				*conflicts = append(*conflicts, phase+"."+k)
			}
			out = append(out, r)
		}
	}
	for i, r := range active {
		k := id(r)
		br, inBase := b[k]
		_, inDraft := d[k]
		if inBase && !inDraft && !same(r, br) {
			*conflicts = append(*conflicts, phase+"."+k) // the draft removed what active edited
		}
		if inBase || inDraft {
			continue
		}
		// Added by active: keep it at its position in active.
		out = slices.Insert(out, min(i, len(out)), r)
	}
	return out
}
