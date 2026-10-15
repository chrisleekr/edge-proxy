package expr

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Typing an expression in "Edit expression" and switching back must show the
// same canonical text the builder would render.
func TestParseRendersCanonicalText(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"all incoming requests", "true", "true"},
		{"hostname equals", `http.host eq "example.com"`, `http.host eq "example.com"`},
		{"bare string value is quoted on render", `http.host eq example.com`, `http.host eq "example.com"`},
		{"does not equal keeps its keyword", `http.host ne "a"`, `http.host ne "a"`},
		{"not equals becomes ne", `not http.host eq "a"`, `http.host ne "a"`},
		{"path starts with", `starts_with(http.request.uri.path, "/api/")`, `starts_with(http.request.uri.path, "/api/")`},
		{"path does not end with", `not ends_with(http.request.uri.path, ".js")`, `not ends_with(http.request.uri.path, ".js")`},
		{"user agent does not contain", `not http.user_agent contains "bot"`, `not http.user_agent contains "bot"`},
		{"header key is lowercased", `http.request.headers["X-Api-Key"] eq "k"`, `http.request.headers["x-api-key"] eq "k"`},
		{"cookie key keeps case", `http.request.cookies["SessionID"] eq "s"`, `http.request.cookies["SessionID"] eq "s"`},
		{"wildcard", `http.host wildcard "*.example.com"`, `http.host wildcard "*.example.com"`},
		{"strict wildcard", `http.request.uri.path strict wildcard "/Admin/*"`, `http.request.uri.path strict wildcard "/Admin/*"`},
		{"ip in ranges renders bare", `ip.src in {"10.0.0.0/8" 2001:db8::/32}`, `ip.src in {10.0.0.0/8 2001:db8::/32}`},
		{"ip not in", `not ip.src in {192.0.2.1}`, `not ip.src in {192.0.2.1}`},
		{"empty list", `http.host in {}`, `http.host in {}`},
		{"asn comparison renders bare", `ip.src.asnum ge "64500"`, `ip.src.asnum ge 64500`},
		{"bool field is true", `ssl`, `ssl`},
		{"bool field is false", `not ssl`, `not ssl`},
		{"regex", `http.user_agent matches "^curl/"`, `http.user_agent matches "^curl/"`},
		{"quotes and backslashes are escaped", `http.user_agent eq "a\"b\\c"`, `http.user_agent eq "a\"b\\c"`},
		{"and binds tighter than or", `ssl and http.host eq "a" or http.host eq "b"`, `(ssl and http.host eq "a") or http.host eq "b"`},
		{"parentheses keep a nested group", `ssl and (http.host eq "a" or http.host eq "b")`, `ssl and (http.host eq "a" or http.host eq "b")`},
		{"redundant parentheses collapse", `((http.host eq "a" or ssl))`, `http.host eq "a" or ssl`},
		{"negated group", `not (http.host eq "a" or ssl)`, `not (http.host eq "a" or ssl)`},
		{"double negation of a group cancels", `not not (http.host eq "a" or ssl)`, `http.host eq "a" or ssl`},
		{"operator without a negated form is wrapped", `not http.host wildcard "*.a"`, `not (http.host wildcard "*.a")`},
		{"negating ne wraps it", `not http.host ne "a"`, `not (http.host ne "a")`},
		{"true inside a chain", `ssl and true`, `ssl and (true)`},
		{"negated true", `not true`, `not (true)`},
		{"whitespace is free", "ssl\tand\n\r ssl", `ssl and ssl`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if got := Render(n); got != tc.want {
				t.Fatalf("Render = %q, want %q", got, tc.want)
			}
			again, err := Parse(Render(n))
			if err != nil {
				t.Fatalf("reparse: %v", err)
			}
			if !reflect.DeepEqual(again, n) {
				t.Fatalf("round trip changed the AST:\n got %#v\nwant %#v", again, n)
			}
		})
	}
}

// A malformed expression typed in text mode is reported with the position of
// the problem, so the UI can point at it.
func TestParseReportsSyntaxErrors(t *testing.T) {
	cases := []struct {
		name, in, msg string
	}{
		{"empty input", ``, `expected a field`},
		{"dangling and", `ssl and`, `expected a field`},
		{"dangling or", `ssl or`, `expected a field`},
		{"dangling not", `not`, `expected a field`},
		{"missing close paren", `(ssl`, `expected ")"`},
		{"error inside parens", `(and)`, `expected a field`},
		{"trailing tokens", `ssl ssl`, `unexpected "ssl"`},
		{"unterminated string", `http.host eq "abc`, `unterminated string`},
		{"bad escape", `http.host eq "a\nb"`, `only \" and \\ escapes`},
		{"escape at end of input", `http.host eq "a\`, `only \" and \\ escapes`},
		{"control character in string", "http.host eq \"a\tb\"", `control characters`},
		{"invalid UTF-8 in a string", "http.host eq \"a\xffb\"", `position 15: text is not valid UTF-8`},
		{"control character in a bare word", "http.host eq a\x10", `control characters`},
		{"keyword as value", `http.host eq and`, `expected a value`},
		{"missing value", `http.host eq`, `expected a value`},
		{"strict without wildcard", `http.host strict "a"`, `expected "wildcard"`},
		{"in without braces", `http.host in "a"`, `expected "{"`},
		{"bad list item", `http.host in {"a" (}`, `expected a value`},
		{"key must be quoted", `http.request.headers[x] eq "a"`, `expected a quoted key`},
		{"key missing close bracket", `http.request.headers["x" eq "a"`, `expected "]"`},
		{"function missing paren", `starts_with http.host`, `expected "("`},
		{"function with keyword field", `starts_with(and, "a")`, `expected a field name`},
		{"function missing comma", `starts_with(http.host "a")`, `expected ","`},
		{"function missing value", `starts_with(http.host, )`, `expected a value`},
		{"function missing close", `starts_with(http.host, "a"`, `expected ")"`},
		{"closing brace where a field belongs", `}`, `expected a field`},
		{"too deep", strings.Repeat("(", MaxDepth+1) + "ssl" + strings.Repeat(")", MaxDepth+1), `nesting deeper`},
		{"too long", strings.Repeat(" ", MaxTextLen+1), `longer than`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.in)
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("Parse(%q) error = %v, want SyntaxError", tc.in, err)
			}
			if !strings.Contains(se.Error(), tc.msg) {
				t.Fatalf("error %q does not mention %q", se.Error(), tc.msg)
			}
		})
	}
}

// Rendering an AST saved by the builder works for every operator, and values
// that aren't safe bare words are quoted even for IP and int fields.
func TestRenderBuilderAST(t *testing.T) {
	cases := []struct {
		name string
		n    Node
		want string
	}{
		{"single rule at the top level", Node{Field: "http.host", Operator: "eq", Value: Value{One: "a"}}, `http.host eq "a"`},
		{"or group of one rule renders as the rule", Node{Combinator: "or", Rules: []Node{{Field: "ssl", Operator: "is_true"}}}, `ssl`},
		{"ip value with a space is quoted", Node{Field: "ip.src", Operator: "eq", Value: Value{One: "1 2"}}, `ip.src eq "1 2"`},
		{"empty int value is quoted", Node{Field: "ip.src.asnum", Operator: "eq"}, `ip.src.asnum eq ""`},
		{"keyword int value is quoted", Node{Field: "ip.src.asnum", Operator: "eq", Value: Value{One: "or"}}, `ip.src.asnum eq "or"`},
		{"unknown field values are quoted", Node{Field: "nope", Operator: "eq", Value: Value{One: "1"}}, `nope eq "1"`},
		{"negated wrapper of a group negates that group", Node{Combinator: "and", Not: true, Rules: []Node{
			{Combinator: "or", Rules: []Node{{Field: "ssl", Operator: "is_true"}, {Field: "ssl", Operator: "is_false"}}},
		}}, `not (ssl or not ssl)`},
		{"nested negated group", Node{Combinator: "and", Rules: []Node{
			{Field: "ssl", Operator: "is_true"},
			{Combinator: "or", Not: true, Rules: []Node{{Field: "ssl", Operator: "is_true"}, {Field: "ssl", Operator: "is_false"}}},
		}}, `ssl and not (ssl or not ssl)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Render(tc.n); got != tc.want {
				t.Fatalf("Render = %q, want %q", got, tc.want)
			}
		})
	}
}
