package expr

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func rule(field, op, v string) Node {
	return Node{Field: field, Operator: op, Value: Value{One: v}}
}

func listRule(field, op string, items ...string) Node {
	return Node{Field: field, Operator: op, Value: Value{List: items, IsList: true}}
}

func and(rules ...Node) Node { return Node{Combinator: "and", Rules: rules} }

var allViewer = func(string) bool { return true }

// Valid rules from the builder pass without issues.
func TestCheckAcceptsValidRules(t *testing.T) {
	env := Env{Phase: PhaseRateLimit, ViewerAvailable: allViewer, AllowRegex: true}
	valid := []Node{
		True(),
		rule("http.host", "eq", "example.com"),
		{Field: "http.request.headers", Key: "x-api-key", Operator: "contains", Value: Value{One: "k"}},
		listRule("ip.src", "in", "10.0.0.0/8", "192.0.2.1", "2001:db8::/32"),
		rule("ip.src", "eq", "192.0.2.1"),
		listRule("ip.src.asnum", "not_in", "64500", "64501"),
		rule("ip.src.asnum", "lt", "100"),
		{Field: "ssl", Operator: "is_false"},
		rule("http.user_agent", "matches", "(?i)^curl/"),
		rule("http.host", "wildcard", `*.example.com\*`),
		rule("edge.locale", "eq", "ko"),
		// Case-insensitive operators and regex may use any case.
		rule("http.host", "wildcard", "*.Example.com"),
		rule("ip.src.country", "matches", "^(?i)au$"),
		rule("http.request.method", "strict_wildcard", "P*"),
		listRule("http.request.method", "in", "GET", "M-SEARCH"),
		{Field: "http.request.cookies", Key: "__Host-sid", Operator: "eq", Value: Value{One: "s"}},
		{Field: "http.request.uri.args", Key: "a b", Operator: "eq", Value: Value{One: "x"}},
		{Field: "http.request.jwt.claims", Key: "sub", Operator: "eq", Value: Value{One: "u1"}},
	}
	for _, n := range valid {
		if err := Check(n, env); err != nil {
			t.Errorf("Check(%s) = %v, want nil", Render(n), err)
		}
	}
}

// Each mistake an operator can make in the builder is reported against the
// rule it belongs to, and nothing invalid passes.
func TestCheckRejectsInvalidRules(t *testing.T) {
	env := Env{Phase: PhaseRateLimit, ViewerAvailable: allViewer}
	// About 300 IPv4 ranges: the text limit, not an item count, bounds a set.
	big := make([]string, 300)
	for i := range big {
		big[i] = fmt.Sprintf("10.0.%d.0/24", i%256)
	}
	cases := []struct {
		name string
		n    Node
		env  *Env
		msg  string
	}{
		{"unknown field", rule("http.nope", "eq", "a"), nil, `unknown field "http.nope"`},
		// Group fields on a condition would be stored but never run: a stored
		// "not" that the edge ignores is a rule that does the opposite.
		{"negated condition", Node{Field: "http.host", Operator: "eq", Value: Value{One: "a"}, Not: true}, nil, "group fields"},
		{"condition with child rules", Node{Field: "http.host", Operator: "eq", Value: Value{One: "a"}, Rules: []Node{}}, nil, "group fields"},
		{"condition with a combinator", Node{Field: "http.host", Operator: "eq", Value: Value{One: "a"}, Combinator: "or"}, nil, "group fields"},
		{"viewer field with no source configured", rule("ip.src.country", "eq", "AU"), &Env{Phase: PhaseConfig}, "no trusted source configured"},
		{"viewer field the deployment lacks", rule("ip.src.asnum", "eq", "1"), &Env{Phase: PhaseConfig, ViewerAvailable: func(f string) bool { return f == "ip.src.country" }}, "no trusted source configured"},
		{"jwt claim in config phase", Node{Field: "http.request.jwt.claims", Key: "sub", Operator: "eq", Value: Value{One: "a"}}, &Env{Phase: PhaseConfig}, "not available in the config phase"},
		{"locale in config phase", rule("edge.locale", "eq", "ko"), &Env{Phase: PhaseConfig}, "not available in the config phase"},
		{"keyed field without a name", rule("http.request.headers", "eq", "a"), nil, "needs a name"},
		{"plain field with a name", Node{Field: "http.host", Key: "x", Operator: "eq", Value: Value{One: "a"}}, nil, "doesn't take a name"},
		{"name too long", Node{Field: "http.request.cookies", Key: strings.Repeat("k", MaxKeyLen+1), Operator: "eq", Value: Value{One: "a"}}, nil, "name is longer"},
		{"name with control characters", Node{Field: "http.request.cookies", Key: "a\nb", Operator: "eq", Value: Value{One: "a"}}, nil, "name contains control"},
		{"unknown operator", rule("http.host", "like", "a"), nil, `unknown operator "like"`},
		{"operator wrong for type", rule("ip.src", "contains", "1"), nil, `can't be used with field "ip.src"`},
		{"bool operator with a value", Node{Field: "ssl", Operator: "is_true", Value: Value{One: "x"}}, nil, "takes no value"},
		{"in without a list", rule("http.host", "in", "a"), nil, "needs a list"},
		{"in with an empty list", listRule("http.host", "in"), nil, "at least 1 value"},
		{"ip list too long as text", listRule("ip.src", "in", big...), nil, "characters as text"},
		{"bad item in an ip list", listRule("ip.src", "in", "10.0.0.0/8", "nope"), nil, `"nope" is not an IP address or CIDR range`},
		{"single operator given a list", listRule("http.host", "eq", "a"), nil, "takes a single value"},
		{"cidr where one ip is expected", rule("ip.src", "eq", "10.0.0.0/8"), nil, "is not an IP address"},
		{"non-integer asn", rule("ip.src.asnum", "gt", "1.5"), nil, "is not an integer"},
		{"value too long", rule("http.host", "eq", strings.Repeat("a", MaxValueLen+1)), nil, "value is longer"},
		{"value with control characters", rule("http.host", "eq", "a\x00"), nil, "value contains control"},
		{"regex disabled", rule("http.user_agent", "matches", "a"), nil, "matches operator is disabled"},
		{"regex too long", rule("http.user_agent", "matches", strings.Repeat("a", MaxRegexLen+1)), &Env{Phase: PhaseRateLimit, AllowRegex: true}, "regex is longer"},
		{"invalid regex", rule("http.user_agent", "matches", "("), &Env{Phase: PhaseRateLimit, AllowRegex: true}, "invalid regex"},
		{"bad wildcard escape", rule("http.host", "wildcard", `a\b`), nil, `only \* and \\ may follow`},
		{"uppercase hostname", rule("http.host", "eq", "API.example.com"), nil, `values are lowercase, use "api.example.com"`},
		{"uppercase hostname in a list", listRule("http.host", "in", "a.com", "B.com"), nil, "values are lowercase"},
		{"uppercase hostname with strict wildcard", rule("http.host", "strict_wildcard", "*.Example.com"), nil, "values are lowercase"},
		{"lowercase country", rule("ip.src.country", "eq", "au"), nil, `values are uppercase, use "AU"`},
		{"lowercase continent in a list", listRule("ip.src.continent", "not_in", "EU", "na"), nil, "values are uppercase"},
		{"method with a space", rule("http.request.method", "eq", "GET POST"), nil, "http.request.method values contain only"},
		{"lowercase method", listRule("http.request.method", "in", "GET", "post"), nil, `values are uppercase, use "POST"`},
		{"empty method", rule("http.request.method", "ne", ""), nil, "http.request.method values contain only"},
		{"header name with a space", Node{Field: "http.request.headers", Key: "x api", Operator: "eq", Value: Value{One: "a"}}, nil, "header and cookie names contain only"},
		{"cookie name with a semicolon", Node{Field: "http.request.cookies", Key: "a;b", Operator: "eq", Value: Value{One: "a"}}, nil, "header and cookie names contain only"},
		{"name with invalid UTF-8", Node{Field: "http.request.uri.args", Key: "a\xff", Operator: "eq", Value: Value{One: "a"}}, nil, "name is not valid UTF-8"},
		{"value with invalid UTF-8", rule("http.user_agent", "eq", "a\xff"), nil, "value is not valid UTF-8"},
		{"zoned ip", rule("ip.src", "eq", "fe80::1%eth0"), nil, "client IPs have no zone"},
		{"zoned ip in a list", listRule("ip.src", "in", "fe80::1%eth0"), nil, "client IPs have no zone"},
		{"double star wildcard", rule("http.request.uri.path", "wildcard", "/a/**"), nil, `can't contain "**"`},
		{"bad combinator", Node{Combinator: "xor", Rules: []Node{rule("http.host", "eq", "a"), rule("http.host", "eq", "b")}}, nil, `combinator must be`},
		{"too many conditions", and(repeatRule(MaxConditions + 1)...), nil, "conditions; at most 32"},
		{"too long as text", rule("http.host", "eq", strings.Repeat("a", MaxValueLen)), nil, "characters as text"},
		{"too deep", deepAST(MaxDepth + 1), nil, "nesting deeper"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := env
			if tc.env != nil {
				e = *tc.env
			}
			is := Issues(Check(tc.n, e))
			if !strings.Contains(is.Error(), tc.msg) {
				t.Fatalf("issues %q do not mention %q", is.Error(), tc.msg)
			}
			if _, err := Compile(tc.n, e); err == nil {
				t.Fatal("Compile accepted an expression Check rejected")
			}
		})
	}
}

// Every issue carries the path of its rule, so the UI can highlight the row.
func TestCheckIssuePaths(t *testing.T) {
	n := and(rule("http.host", "eq", "ok"), Node{Combinator: "or", Rules: []Node{rule("http.nope", "eq", "a"), rule("ip.src", "eq", "x")}})
	is := Check(n, Env{Phase: PhaseConfig})
	if len(is) != 2 {
		t.Fatalf("Check = %v, want 2 issues", is)
	}
	if is[0].Path != "expression.rules[1].rules[0]" || is[1].Path != "expression.rules[1].rules[1]" {
		t.Fatalf("paths = %q, %q", is[0].Path, is[1].Path)
	}
}

func repeatRule(n int) []Node {
	out := make([]Node, n)
	for i := range out {
		out[i] = rule("http.host", "eq", "a")
	}
	return out
}

// deepAST nests groups with two children each, so Normalize can't collapse them.
func deepAST(depth int) Node {
	n := and(rule("http.host", "eq", "a"), rule("http.host", "eq", "b"))
	for i := 1; i < depth; i++ {
		n = Node{Combinator: "or", Rules: []Node{n, rule("http.host", "eq", "c")}}
	}
	return n
}

// The AST JSON is the react-querybuilder tree shape the admin UI edits
// directly: combinator / not / rules, and field / operator / value.
func TestJSONShapeMatchesBuilder(t *testing.T) {
	in := `{"combinator":"or","not":true,"rules":[` +
		`{"field":"http.request.headers","key":"x-api-key","operator":"eq","value":"k"},` +
		`{"field":"ip.src","operator":"in","value":["10.0.0.0/8"]},` +
		`{"field":"ssl","operator":"is_true"}]}`
	var n Node
	if err := json.Unmarshal([]byte(in), &n); err != nil {
		t.Fatal(err)
	}
	if got := Render(n); got != `not (http.request.headers["x-api-key"] eq "k" or ip.src in {10.0.0.0/8} or ssl)` {
		t.Fatalf("Render = %q", got)
	}
	out, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Fatalf("JSON round trip:\n got %s\nwant %s", out, in)
	}
	if err := json.Unmarshal([]byte(`{"field":"ssl","operator":"eq","value":5}`), &n); err == nil {
		t.Fatal("a numeric value was accepted")
	}
}

// "All incoming requests" is the empty group, and only that.
func TestTrueExpression(t *testing.T) {
	tr := True()
	if !tr.IsTrue() || Render(tr) != "true" {
		t.Fatal("True() is not the match-everything expression")
	}
	neg := Node{Combinator: "and", Not: true}
	if neg.IsTrue() {
		t.Fatal("not (true) reported as true")
	}
	r := rule("http.host", "eq", "a")
	if r.IsTrue() {
		t.Fatal("a rule reported as true")
	}
}

// The schema tables the UI loads are complete and consistent.
func TestSchemaLookups(t *testing.T) {
	if _, ok := LookupField("http.host"); !ok {
		t.Fatal("http.host missing")
	}
	if _, ok := LookupOp("strict_wildcard"); !ok {
		t.Fatal("strict_wildcard missing")
	}
	for _, f := range Fields {
		ok := false
		for _, o := range Operators {
			ok = ok || o.accepts(f.Type)
		}
		if !ok {
			t.Errorf("field %s has no usable operator", f.Name)
		}
	}
}

// The admin schema API sends operators with type names the UI matches
// against field types.
func TestOperatorSchemaJSON(t *testing.T) {
	b, _ := json.Marshal([]OpDef{Operators[0], Operators[len(Operators)-1]})
	want := `[{"name":"eq","label":"equals","list":false,"no_value":false,"types":["string","string_list","ip","int"]},` +
		`{"name":"is_false","label":"is false","negates":"is_true","list":false,"no_value":true,"types":["bool"]}]`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}
