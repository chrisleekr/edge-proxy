package expr

import "strings"

// Render returns the canonical text form of n, used for the admin UI preview.
// Parse(Render(n)) equals Normalize(n) for every AST that Check accepts.
func Render(n Node) string {
	var b strings.Builder
	// Normalize always returns a group.
	renderGroupBody(&b, Normalize(n), true)
	return b.String()
}

func renderGroupBody(b *strings.Builder, g Node, top bool) {
	if g.Not {
		b.WriteString("not (")
		renderChildren(b, g)
		b.WriteString(")")
		return
	}
	if !top {
		b.WriteString("(")
		renderChildren(b, g)
		b.WriteString(")")
		return
	}
	renderChildren(b, g)
}

func renderChildren(b *strings.Builder, g Node) {
	if len(g.Rules) == 0 {
		b.WriteString("true")
		return
	}
	sep := " and "
	if g.Combinator == "or" {
		sep = " or "
	}
	for i, c := range g.Rules {
		if i > 0 {
			b.WriteString(sep)
		}
		if c.IsGroup() {
			renderGroupBody(b, c, false)
		} else {
			renderRule(b, c)
		}
	}
}

func renderRule(b *strings.Builder, r Node) {
	op, _ := LookupOp(r.Operator)
	positive := r.Operator
	// "ne" has its own keyword; other negated operators render as "not <positive>".
	if op.Negates != "" && r.Operator != "ne" {
		b.WriteString("not ")
		positive = op.Negates
	}
	f := fieldRef(r)
	v := func() { renderValue(b, r.Field, r.Value.One) }
	switch positive {
	case "starts_with", "ends_with":
		b.WriteString(positive + "(" + f + ", ")
		v()
		b.WriteString(")")
	case "is_true":
		b.WriteString(f)
	case "in":
		b.WriteString(f + " in {")
		for i, item := range r.Value.List {
			if i > 0 {
				b.WriteString(" ")
			}
			renderValue(b, r.Field, item)
		}
		b.WriteString("}")
	case "strict_wildcard":
		b.WriteString(f + " strict wildcard ")
		v()
	default:
		b.WriteString(f + " " + positive + " ")
		v()
	}
}

func fieldRef(r Node) string {
	if r.Key == "" {
		return r.Field
	}
	return r.Field + "[" + quote(r.Key) + "]"
}

// renderValue writes IP and int literals bare and everything else quoted.
// A value that isn't safe as a bare word is quoted regardless; the parser
// accepts both forms, so the round trip holds either way.
func renderValue(b *strings.Builder, field, v string) {
	if f, ok := LookupField(field); ok && (f.Type == TypeIP || f.Type == TypeInt) && isBareWord(v) {
		b.WriteString(v)
		return
	}
	b.WriteString(quote(v))
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}

func isBareWord(s string) bool {
	if s == "" || keywords[s] {
		return false
	}
	for i := 0; i < len(s); i++ {
		if isDelim(s[i]) {
			return false
		}
	}
	return true
}
