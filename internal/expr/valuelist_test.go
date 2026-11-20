package expr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func valueListRule(field, op, name string) Node {
	return Node{Field: field, Operator: op, Value: Value{ListName: name}}
}

// values returns n distinct path-shaped values.
func values(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("/p%d", i)
	}
	return out
}

var testLists = map[string]ValueList{
	"agents":  {Field: "http.user_agent", Values: []string{"curl/", "python-requests/"}},
	"eu":      {Field: "ip.src.country", Values: []string{"DE", "FR"}},
	"asns":    {Field: "ip.src.asnum", Values: []string{"64500", "64501"}},
	"paths":   {Field: "http.request.uri.path", Values: []string{"/admin", "/login"}},
	"exts":    {Field: "http.request.uri.path", Values: []string{".php", ".asp"}},
	"tokens":  {Field: "http.request.headers", Values: []string{"bad", "worse"}},
	"hosts":   {Field: "http.host", Values: []string{"a.example.com"}},
	"mixed":   {Field: "http.request.uri.path", Values: []string{"/a", "b"}},
	"limit31": {Field: "http.request.uri.path", Values: values(31)},
	"limit32": {Field: "http.request.uri.path", Values: values(32)},
}

var valueListEnv = Env{Phase: PhaseRateLimit, ViewerAvailable: allViewer, AllowRegex: true, Lists: testLists}

func TestValueJSONValueListForm(t *testing.T) {
	t.Run("a value list reference survives storage", func(t *testing.T) {
		n := valueListRule("http.user_agent", "contains", "agents")
		b, err := json.Marshal(n)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"value":{"list":"agents"}`) {
			t.Fatalf("stored %s", b)
		}
		var back Node
		if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, n) {
			t.Fatalf("loaded %#v, %v", back, err)
		}
	})
	for _, tc := range []struct{ name, in string }{
		{"unknown key beside the value list", `{"list":"a","extra":1}`},
		{"unknown key instead of the value list", `{"grp":"a"}`},
		{"the earlier group key", `{"group":"a"}`},
		{"empty object", `{}`},
		{"empty value list name", `{"list":""}`},
		{"value list name that is not a string", `{"list":1}`},
		{"number", `1`},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			var v Value
			if err := json.Unmarshal([]byte(tc.in), &v); err == nil {
				t.Fatalf("Unmarshal(%s) = %#v, want an error", tc.in, v)
			}
		})
	}
}

func TestParseValueListReferences(t *testing.T) {
	t.Run("a bare $name is a value list and a quoted one is a literal", func(t *testing.T) {
		bare, err := Parse(`http.user_agent contains $agents`)
		if err != nil {
			t.Fatal(err)
		}
		quoted, err := Parse(`http.user_agent contains "$agents"`)
		if err != nil {
			t.Fatal(err)
		}
		if got := bare.Rules[0].Value; got.ListName != "agents" || got.One != "" {
			t.Fatalf("bare value = %#v", got)
		}
		if got := quoted.Rules[0].Value; got.ListName != "" || got.One != "$agents" {
			t.Fatalf("quoted value = %#v", got)
		}
		if Render(quoted) != `http.user_agent contains "$agents"` {
			t.Fatalf("render = %s", Render(quoted))
		}
	})
	for _, tc := range []struct{ name, in, msg string }{
		{"a lone $ in a comparison", `http.user_agent contains $`, "expected a value list name after $"},
		{"a lone $ in a function", `starts_with(http.request.uri.path, $)`, "expected a value list name after $"},
	} {
		t.Run(tc.name+" is a syntax error", func(t *testing.T) {
			_, err := Parse(tc.in)
			var se *SyntaxError
			if !errors.As(err, &se) || !strings.Contains(se.Error(), tc.msg) {
				t.Fatalf("Parse(%q) = %v, want %q", tc.in, err, tc.msg)
			}
		})
	}
	t.Run("an AS number value starting with $ is quoted on render", func(t *testing.T) {
		n := Node{Field: "ip.src.asnum", Operator: "eq", Value: Value{One: "$1"}}
		if got := Render(n); got != `ip.src.asnum eq "$1"` {
			t.Fatalf("Render = %s", got)
		}
	})
}

func TestCheckValueListReferences(t *testing.T) {
	cases := []struct {
		name string
		n    Node
		msg  string // "" means accepted
	}{
		{"user agents with contains", valueListRule("http.user_agent", "contains", "agents"), ""},
		{"user agents not contains", valueListRule("http.user_agent", "not_contains", "agents"), ""},
		{"countries with in", valueListRule("ip.src.country", "in", "eu"), ""},
		{"AS numbers with not in", valueListRule("ip.src.asnum", "not_in", "asns"), ""},
		{"a path value list ending with .php", valueListRule("http.request.uri.path", "ends_with", "exts"), ""},
		{"a keyed header value list", Node{Field: "http.request.headers", Key: "x-a", Operator: "contains", Value: Value{ListName: "tokens"}}, ""},
		{"31 values and one other condition are 32 conditions", and(valueListRule("http.request.uri.path", "starts_with", "limit31"), rule("ssl", "is_true", "")), ""},
		{"32 values and one other condition are over the limit", and(valueListRule("http.request.uri.path", "starts_with", "limit32"), Node{Field: "ssl", Operator: "is_true"}), "33 conditions; at most 32"},
		{"a path value list of .php with in", valueListRule("http.request.uri.path", "in", "exts"), `".php" can never match: paths start with "/"`},
		{"a path value list with one value that can never start a path", valueListRule("http.request.uri.path", "starts_with", "mixed"), `"b" can never match: paths start with "/"`},
		{"a value list that doesn't exist", valueListRule("http.user_agent", "contains", "nope"), `value list "nope" doesn't exist`},
		{"a value list on another field", valueListRule("http.referer", "contains", "agents"), "holds values for http.user_agent, not http.referer"},
		{"a country value list with contains", valueListRule("ip.src.country", "contains", "eu"), `operator "contains" can't take a value list of countries; use "is in" or "is not in"`},
		{"equals with a value list", valueListRule("http.user_agent", "eq", "agents"), `operator "eq" can't take a value list of user agents`},
		{"an IP field", valueListRule("ip.src", "in", "agents"), "addresses go in an IP list"},
		{"a field that has no value lists", valueListRule("client.signals", "in", "agents"), "takes values written in the condition, not a value list"},
		{"a hostname value list with contains", valueListRule("http.host", "contains", "hosts"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := Issues(Check(tc.n, valueListEnv))
			switch {
			case tc.msg == "" && len(is) > 0:
				t.Fatalf("Check = %v, want none", is)
			case tc.msg != "" && !strings.Contains(is.Error(), tc.msg):
				t.Fatalf("Check = %q, want %q", is.Error(), tc.msg)
			}
		})
	}
	t.Run("a pattern value list over the limit reports the count without checking each value", func(t *testing.T) {
		env := valueListEnv
		env.Lists = map[string]ValueList{"big": {Field: "http.request.uri.path", Values: values(100)}}
		is := Issues(Check(valueListRule("http.request.uri.path", "starts_with", "big"), env))
		if !strings.Contains(is.Error(), "100 conditions; at most 32") {
			t.Fatalf("Check = %q", is.Error())
		}
	})
}

func TestExpandAndMatchValueLists(t *testing.T) {
	req := &fakeReq{
		str: map[string]string{
			"http.user_agent":       "python-requests/2.31",
			"ip.src.country":        "FR",
			"http.request.uri.path": "/index.php",
		},
		lists: map[string][]string{"http.request.headers|X-A": {"fine", "very bad"}},
		ints:  map[string]int64{"ip.src.asnum": 64501},
		ip:    netip.MustParseAddr("192.0.2.1"),
	}
	hdr := func(op string) Node {
		return Node{Field: "http.request.headers", Key: "x-a", Operator: op, Value: Value{ListName: "tokens"}}
	}
	cases := []struct {
		name string
		n    Node
		want bool
	}{
		{"contains any value of the value list", valueListRule("http.user_agent", "contains", "agents"), true},
		{"does not contain any value of the value list", valueListRule("http.user_agent", "not_contains", "agents"), false},
		{"a header with a value containing a value list value", hdr("contains"), true},
		{"no header value contains any value list value", hdr("not_contains"), false},
		{"in a value list of countries", valueListRule("ip.src.country", "in", "eu"), true},
		{"not in a value list of countries", valueListRule("ip.src.country", "not_in", "eu"), false},
		{"in a value list of AS numbers", valueListRule("ip.src.asnum", "in", "asns"), true},
		{"a path ends with a value list value", valueListRule("http.request.uri.path", "ends_with", "exts"), true},
		{"a path starts with no value list value", valueListRule("http.request.uri.path", "starts_with", "paths"), false},
		{"a wildcard over a value list", valueListRule("http.user_agent", "wildcard", "agents"), false},
		{"a regex over a value list", valueListRule("http.user_agent", "matches", "agents"), true},
		{"a value list inside a negated group", Node{Combinator: "and", Not: true, Rules: []Node{valueListRule("ip.src.country", "in", "eu"), rule("ssl", "is_true", "")}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, is := Compile(tc.n, valueListEnv)
			if is != nil {
				t.Fatalf("Compile: %v", Issues(is))
			}
			if got := m(req); got != tc.want {
				t.Fatalf("match = %v, want %v for %s", got, tc.want, Render(tc.n))
			}
		})
	}
	t.Run("expansion leaves a rule without a value list as it was", func(t *testing.T) {
		n := rule("http.host", "eq", "a")
		if got := Expand(n, testLists); !reflect.DeepEqual(got, n) {
			t.Fatalf("Expand = %#v", got)
		}
	})
}

// A value list is expanded into the existing closures at compile time, so matching
// still allocates nothing.
func TestValueListMatchingDoesNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items under -race; scripts/ci/bench.sh runs this without -race")
	}
	req := &fakeReq{
		str:  map[string]string{"http.user_agent": "Mozilla/5.0 (X11; Linux x86_64)", "ip.src.country": "AU"},
		ints: map[string]int64{"ip.src.asnum": 64500},
	}
	for _, n := range []Node{
		valueListRule("http.user_agent", "contains", "agents"),
		valueListRule("http.user_agent", "not_contains", "agents"),
		valueListRule("ip.src.country", "in", "eu"),
		valueListRule("ip.src.asnum", "in", "asns"),
	} {
		m, is := Compile(n, valueListEnv)
		if is != nil {
			t.Fatalf("Compile: %v", Issues(is))
		}
		if allocs := testing.AllocsPerRun(100, func() { m(req) }); allocs != 0 {
			t.Errorf("%s: %v allocations per match", Render(n), allocs)
		}
	}
}

func TestListValueProblem(t *testing.T) {
	path, _ := LookupField("http.request.uri.path")
	country, _ := LookupField("ip.src.country")
	asn, _ := LookupField("ip.src.asnum")
	host, _ := LookupField("http.host")
	cases := []struct {
		name  string
		f     FieldDef
		value string
		msg   string
	}{
		{"an extension in a path value list", path, ".php", ""},
		{"an empty value", path, "", "is blank; delete the line"},
		{"a lowercase country", country, "au", "uppercase"},
		{"an uppercase hostname", host, "A.com", "lowercase"},
		{"a word for an AS number", asn, "abc", "is not an integer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ListValueProblem(tc.f, tc.value); !strings.Contains(got, tc.msg) || (tc.msg == "") != (got == "") {
				t.Fatalf("ListValueProblem = %q, want %q", got, tc.msg)
			}
		})
	}
}

func TestListOps(t *testing.T) {
	ua, _ := LookupField("http.user_agent")
	country, _ := LookupField("ip.src.country")
	ip, _ := LookupField("ip.src")
	if got := ListOps(ip); got != nil {
		t.Errorf("IP field takes %v, want none", got)
	}
	if got := ListOps(country); !reflect.DeepEqual(got, []string{"in", "not_in"}) {
		t.Errorf("country takes %v", got)
	}
	if got := ListOps(ua); len(got) != len(listPatternOps) {
		t.Errorf("user agent takes %v", got)
	}
}
