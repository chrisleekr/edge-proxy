package snapshot

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// ints returns n distinct AS numbers as text.
func ints(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprint(64000 + i)
	}
	return out
}

// pathValues returns n distinct URL paths.
func pathValues(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("/p%d", i)
	}
	return out
}

// useValueList appends a log-only rule whose expression is src.
func useValueList(c *Config, id, src string) {
	c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: id, Expression: mustParse(src), Settings: Settings{Block: new("log")}})
}

func withValueList(c *Config, name string, g expr.ValueList) {
	if c.Global.Lists == nil {
		c.Global.Lists = map[string]expr.ValueList{}
	}
	c.Global.Lists[name] = g
}

func TestCompileRejectsValueLists(t *testing.T) {
	agents := expr.ValueList{Field: "http.user_agent", Values: []string{"curl/", "python-requests/"}}
	runRejects(t, []rejectCase{
		{"value list on an IP field", func(c *Config) {
			withValueList(c, "ips", expr.ValueList{Field: "ip.src", Values: []string{"10.0.0.1"}})
		}, nil, `global.lists["ips"].field`, "IP addresses go in an IP list"},
		{"value list on an edge-computed field", func(c *Config) {
			withValueList(c, "sig", expr.ValueList{Field: "client.signals", Values: []string{"ua_tool"}})
		}, nil, `global.lists["sig"].field`, "can't have a value list"},
		{"value list on a field that doesn't exist", func(c *Config) {
			withValueList(c, "x", expr.ValueList{Field: "http.nope", Values: []string{"a"}})
		}, nil, `global.lists["x"].field`, "can't have a value list"},
		{"value list with no values", func(c *Config) { withValueList(c, "empty", expr.ValueList{Field: "http.user_agent"}) }, nil, `global.lists["empty"].values`, "must hold 1 to 10,000 values"},
		{"value list over 10,000 values", func(c *Config) {
			withValueList(c, "huge", expr.ValueList{Field: "ip.src.asnum", Values: ints(MaxListValues + 1)})
		}, nil, `global.lists["huge"].values`, "must hold 1 to 10,000 values"},
		{"value list with a repeated value", func(c *Config) {
			withValueList(c, "dup", expr.ValueList{Field: "http.user_agent", Values: []string{"a", "b", "a"}})
		}, nil, `global.lists["dup"].values[2]`, "repeats line 1"},
		{"value list with an empty value", func(c *Config) {
			withValueList(c, "blank", expr.ValueList{Field: "http.user_agent", Values: []string{""}})
		}, nil, `global.lists["blank"].values[0]`, "is blank; delete the line"},
		{"hostname value list with capitals", func(c *Config) {
			withValueList(c, "hosts", expr.ValueList{Field: "http.host", Values: []string{"A.com"}})
		}, nil, `global.lists["hosts"].values[0]`, `use "a.com"`},
		{"AS number value list with a word", func(c *Config) {
			withValueList(c, "asns", expr.ValueList{Field: "ip.src.asnum", Values: []string{"abc"}})
		}, nil, `global.lists["asns"].values[0]`, "is not an integer"},
		{"value list name with capitals", func(c *Config) { withValueList(c, "Bad Name", agents) }, nil, `global.lists["Bad Name"]`, "lowercase letters"},
		{"more value lists than the limit", func(c *Config) {
			for i := range MaxListLen + 1 {
				withValueList(c, fmt.Sprintf("g%d", i), agents)
			}
		}, nil, "global.lists", "at most 100"},
		{"rule naming a value list that was removed", func(c *Config) {
			useValueList(c, "ua", `http.user_agent contains $gone`)
		}, nil, "config_rules[3].expression.rules[0]", `value list "gone" doesn't exist`},
		{"value list used on another field", func(c *Config) {
			withValueList(c, "agents", agents)
			useValueList(c, "ref", `http.referer contains $agents`)
		}, nil, "config_rules[3].expression.rules[0]", "holds values for http.user_agent, not http.referer"},
		{"countries used with contains", func(c *Config) {
			withValueList(c, "eu", expr.ValueList{Field: "ip.src.country", Values: []string{"DE", "FR"}})
			useValueList(c, "geo", `ip.src.country contains $eu`)
		}, nil, "config_rules[3].expression.rules[0]", `can't take a value list of countries; use "is in" or "is not in"`},
		{"a path value list of extensions used with in", func(c *Config) {
			withValueList(c, "exts", expr.ValueList{Field: "http.request.uri.path", Values: []string{".php"}})
			useValueList(c, "ext", `http.request.uri.path in $exts`)
		}, nil, "config_rules[3].expression.rules[0]", `paths start with "/"`},
		{"32 values and one other condition", func(c *Config) {
			withValueList(c, "p32", expr.ValueList{Field: "http.request.uri.path", Values: pathValues(32)})
			useValueList(c, "many", `starts_with(http.request.uri.path, $p32) and ssl`)
		}, nil, "config_rules[3].expression", "33 conditions; at most 32"},
		{"more than 200,000 value list values in use", func(c *Config) {
			withValueList(c, "asns", expr.ValueList{Field: "ip.src.asnum", Values: ints(MaxListValues)})
			for i := range MaxListUses/MaxListValues + 1 {
				useValueList(c, fmt.Sprintf("use%d", i), `ip.src.asnum in $asns`)
			}
		}, nil, "global.lists", "holding 210,000 values in all; at most 200,000"},
	})
}

func TestCompileAcceptsValueLists(t *testing.T) {
	t.Run("31 values and one other condition are 32 conditions", func(t *testing.T) {
		c := validConfig()
		withValueList(c, "p31", expr.ValueList{Field: "http.request.uri.path", Values: pathValues(31)})
		useValueList(c, "many", `starts_with(http.request.uri.path, $p31) and ssl`)
		if _, _, errs := Compile(c, testDeployment); errs != nil {
			t.Fatal(expr.Issues(errs))
		}
	})
	t.Run("200,000 value list values in use are allowed", func(t *testing.T) {
		c := validConfig()
		withValueList(c, "asns", expr.ValueList{Field: "ip.src.asnum", Values: ints(MaxListValues)})
		for i := range MaxListUses / MaxListValues {
			useValueList(c, fmt.Sprintf("use%d", i), `ip.src.asnum in $asns`)
		}
		if _, _, errs := Compile(c, testDeployment); errs != nil {
			t.Fatal(expr.Issues(errs))
		}
	})
	t.Run("a path value list of extensions is allowed with ends with", func(t *testing.T) {
		c := validConfig()
		withValueList(c, "exts", expr.ValueList{Field: "http.request.uri.path", Values: []string{".php", ".asp"}})
		useValueList(c, "ext", `ends_with(http.request.uri.path, $exts)`)
		if _, _, errs := Compile(c, testDeployment); errs != nil {
			t.Fatal(expr.Issues(errs))
		}
	})
}

func TestValueListWarnings(t *testing.T) {
	c := validConfig()
	withValueList(c, "unused", expr.ValueList{Field: "http.user_agent", Values: []string{"a"}})
	withValueList(c, "used", expr.ValueList{Field: "http.user_agent", Values: []string{"b"}})
	c.RateLimitRules[2].Expression = mustParse(`http.user_agent contains $used`)
	_, warns, errs := Compile(c, testDeployment)
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	var got []string
	for _, w := range warns {
		if strings.HasPrefix(w.Path, "global.lists") {
			got = append(got, w.Path+": "+w.Msg)
		}
	}
	if want := []string{`global.lists["unused"]: no rule uses it as $unused, so it has no effect`}; !slices.Equal(got, want) {
		t.Fatalf("value list warnings = %q, want %q", got, want)
	}
}

// Value lists and $name need schema 13. A policy of any schema may use them
// and then needs edges that read schema 13.
func TestValueListsNeedSchema13Edges(t *testing.T) {
	older := validConfig()
	older.Schema = 9
	cases := []struct {
		name  string
		lists bool
		want  int
	}{
		{"schema 9 policy without value lists", false, 9},
		{"schema 9 policy with a value list", true, ValueListsSchema},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := *older
			c.ConfigRules = slices.Clone(c.ConfigRules)
			if tc.lists {
				c.Global.Lists = map[string]expr.ValueList{"agents": {Field: "http.user_agent", Values: []string{"curl/"}}}
				useValueList(&c, "ua", `http.user_agent contains $agents`)
			}
			got, _, errs := Compile(&c, testDeployment)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got.NeedsSchema != tc.want {
				t.Fatalf("needs schema %d, want %d", got.NeedsSchema, tc.want)
			}
		})
	}
}
