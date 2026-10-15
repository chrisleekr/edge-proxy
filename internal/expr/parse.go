package expr

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// SyntaxError reports a parse failure at a byte offset in the expression text.
type SyntaxError struct {
	Pos int
	Msg string
}

func (e *SyntaxError) Error() string { return fmt.Sprintf("position %d: %s", e.Pos, e.Msg) }

var keywords = map[string]bool{
	"and": true, "or": true, "not": true, "true": true,
	"eq": true, "ne": true, "contains": true, "wildcard": true, "strict": true,
	"matches": true, "in": true, "gt": true, "ge": true, "lt": true, "le": true,
	"starts_with": true, "ends_with": true,
}

// binaryOps are operators written between a field and a value.
var binaryOps = map[string]bool{
	"eq": true, "ne": true, "contains": true, "wildcard": true, "strict": true,
	"matches": true, "in": true, "gt": true, "ge": true, "lt": true, "le": true,
}

type tokKind int

const (
	tokEOF tokKind = iota
	tokWord
	tokString
	tokPunct
)

type token struct {
	kind tokKind
	text string
	pos  int
}

func isDelim(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '(', ')', '{', '}', '[', ']', ',', '"':
		return true
	}
	// Ends the word so lex reports the control character.
	return c < 0x20 || c == 0x7f
}

func lex(src string) ([]token, error) {
	var toks []token
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c < 0x20 || c == 0x7f:
			return nil, &SyntaxError{i, "control characters are not allowed"}
		case strings.IndexByte("(){}[],", c) >= 0:
			toks = append(toks, token{tokPunct, string(c), i})
			i++
		case c == '"':
			s, n, err := lexString(src, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tokString, s, i})
			i += n
		default:
			start := i
			for i < len(src) && !isDelim(src[i]) {
				i++
			}
			toks = append(toks, token{tokWord, src[start:i], start})
		}
	}
	return append(toks, token{kind: tokEOF, pos: len(src)}), nil
}

// lexString reads a quoted string starting at src[start] == '"'. Only \" and
// \\ are escapes; control characters are rejected so values are header-safe.
func lexString(src string, start int) (string, int, error) {
	var b strings.Builder
	for i := start + 1; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '"':
			return b.String(), i - start + 1, nil
		case c == '\\':
			if i+1 >= len(src) || (src[i+1] != '"' && src[i+1] != '\\') {
				return "", 0, &SyntaxError{i, `only \" and \\ escapes are allowed`}
			}
			i++
			b.WriteByte(src[i])
		case c < 0x20 || c == 0x7f:
			return "", 0, &SyntaxError{i, "control characters are not allowed in strings"}
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, &SyntaxError{start, "unterminated string"}
}

type parser struct {
	toks  []token
	i     int
	depth int
}

// Parse converts expression text into a normalized AST. It checks syntax
// only; Check validates fields, operators and values.
func Parse(src string) (Node, error) {
	if len(src) > MaxTextLen {
		return Node{}, &SyntaxError{MaxTextLen, fmt.Sprintf("expression longer than %d characters", MaxTextLen)}
	}
	// JSON storage would replace invalid bytes with U+FFFD, so the saved rule
	// would differ from the one validated.
	for i, r := range src {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(src[i:]); size == 1 {
				return Node{}, &SyntaxError{i, "text is not valid UTF-8"}
			}
		}
	}
	toks, err := lex(src)
	if err != nil {
		return Node{}, err
	}
	p := &parser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return Node{}, err
	}
	if t := p.peek(); t.kind != tokEOF {
		return Node{}, &SyntaxError{t.pos, fmt.Sprintf("unexpected %q", t.text)}
	}
	return asGroup(n), nil
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

func (p *parser) isWord(text string) bool {
	t := p.peek()
	return t.kind == tokWord && t.text == text
}

func (p *parser) expectPunct(text string) error {
	t := p.next()
	if t.kind != tokPunct || t.text != text {
		return &SyntaxError{t.pos, fmt.Sprintf("expected %q", text)}
	}
	return nil
}

func (p *parser) parseOr() (Node, error) { return p.parseChain("or", p.parseAnd) }

func (p *parser) parseAnd() (Node, error) { return p.parseChain("and", p.parseUnary) }

// parseChain parses item (sep item)*. A single item is returned as is; more
// become a group with that combinator.
func (p *parser) parseChain(sep string, item func() (Node, error)) (Node, error) {
	first, err := item()
	if err != nil {
		return Node{}, err
	}
	if !p.isWord(sep) {
		return first, nil
	}
	g := Node{Combinator: sep, Rules: []Node{first}}
	for p.isWord(sep) {
		p.next()
		n, err := item()
		if err != nil {
			return Node{}, err
		}
		g.Rules = append(g.Rules, n)
	}
	return g, nil
}

func (p *parser) parseUnary() (Node, error) {
	if !p.isWord("not") {
		return p.parsePrimary()
	}
	p.next()
	inner, err := p.parseUnary()
	if err != nil {
		return Node{}, err
	}
	return negate(inner), nil
}

// negate applies "not" the same way Normalize would see it: a rule with a
// negated operator form takes it, a group toggles its Not flag, and anything
// else is wrapped in a negated group.
func negate(n Node) Node {
	if n.IsGroup() {
		n.Not = !n.Not
		return n
	}
	if neg, ok := negatedOf[n.Operator]; ok {
		n.Operator = neg
		return n
	}
	return Node{Combinator: "and", Not: true, Rules: []Node{n}}
}

func (p *parser) parsePrimary() (Node, error) {
	t := p.peek()
	switch {
	case t.kind == tokPunct && t.text == "(":
		p.depth++
		if p.depth > MaxDepth {
			return Node{}, &SyntaxError{t.pos, fmt.Sprintf("nesting deeper than %d", MaxDepth)}
		}
		p.next()
		n, err := p.parseOr()
		if err != nil {
			return Node{}, err
		}
		if err := p.expectPunct(")"); err != nil {
			return Node{}, err
		}
		p.depth--
		return asGroup(n), nil
	case t.kind == tokWord && t.text == "true":
		p.next()
		return True(), nil
	case t.kind == tokWord && (t.text == "starts_with" || t.text == "ends_with"):
		return p.parseFunc()
	case t.kind == tokWord && !keywords[t.text]:
		return p.parseComparison()
	}
	return Node{}, &SyntaxError{t.pos, fmt.Sprintf("expected a field, %q or \"(\"", "true")}
}

// asGroup wraps a single rule as a one-rule group; groups pass through.
func asGroup(n Node) Node {
	if n.IsGroup() {
		return n
	}
	return Node{Combinator: "and", Rules: []Node{n}}
}

func (p *parser) parseFunc() (Node, error) {
	name := p.next().text
	if err := p.expectPunct("("); err != nil {
		return Node{}, err
	}
	r, err := p.parseFieldRef()
	if err != nil {
		return Node{}, err
	}
	if err := p.expectPunct(","); err != nil {
		return Node{}, err
	}
	v, err := p.parseScalar()
	if err != nil {
		return Node{}, err
	}
	if err := p.expectPunct(")"); err != nil {
		return Node{}, err
	}
	r.Operator = name
	r.Value = Value{One: v}
	return r, nil
}

func (p *parser) parseComparison() (Node, error) {
	r, err := p.parseFieldRef()
	if err != nil {
		return Node{}, err
	}
	t := p.peek()
	if t.kind != tokWord || !binaryOps[t.text] {
		r.Operator = "is_true"
		return r, nil
	}
	p.next()
	op := t.text
	if op == "strict" {
		if !p.isWord("wildcard") {
			return Node{}, &SyntaxError{p.peek().pos, `expected "wildcard" after "strict"`}
		}
		p.next()
		op = "strict_wildcard"
	}
	r.Operator = op
	if op == "in" {
		list, err := p.parseList()
		if err != nil {
			return Node{}, err
		}
		r.Value = Value{List: list, IsList: true}
		return r, nil
	}
	v, err := p.parseScalar()
	if err != nil {
		return Node{}, err
	}
	r.Value = Value{One: v}
	return r, nil
}

func (p *parser) parseFieldRef() (Node, error) {
	t := p.next()
	if t.kind != tokWord || keywords[t.text] {
		return Node{}, &SyntaxError{t.pos, "expected a field name"}
	}
	r := Node{Field: t.text}
	if pt := p.peek(); pt.kind == tokPunct && pt.text == "[" {
		p.next()
		k := p.next()
		if k.kind != tokString {
			return Node{}, &SyntaxError{k.pos, "expected a quoted key"}
		}
		if err := p.expectPunct("]"); err != nil {
			return Node{}, err
		}
		r.Key = canonKey(r.Field, k.text)
	}
	return r, nil
}

func (p *parser) parseScalar() (string, error) {
	t := p.next()
	if t.kind == tokString || (t.kind == tokWord && !keywords[t.text]) {
		return t.text, nil
	}
	return "", &SyntaxError{t.pos, "expected a value"}
}

func (p *parser) parseList() ([]string, error) {
	if err := p.expectPunct("{"); err != nil {
		return nil, err
	}
	list := []string{}
	for {
		if t := p.peek(); t.kind == tokPunct && t.text == "}" {
			p.next()
			return list, nil
		}
		v, err := p.parseScalar()
		if err != nil {
			return nil, err
		}
		list = append(list, v)
	}
}

// canonKey lowercases keys of case-insensitive fields (header names).
func canonKey(field, key string) string {
	if f, ok := LookupField(field); ok && f.LowerKey {
		return strings.ToLower(key)
	}
	return key
}
