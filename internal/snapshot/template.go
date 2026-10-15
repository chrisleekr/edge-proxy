package snapshot

import (
	"fmt"
	"strings"
)

// Template is text with {{name}} or {{name:arg}} placeholders, split once at
// compile time so rendering is a single pass of appends.
type Template struct {
	parts []part
}

type part struct {
	lit string
	// name and arg are set for a placeholder; lit is empty then.
	name, arg string
}

// Placeholder is one placeholder found in a template.
type Placeholder struct{ Name, Arg string }

// parseTemplate splits s. Every "{{" must open a well-formed placeholder, so
// a typo is an error instead of literal braces in a live response.
func parseTemplate(s string) (Template, error) {
	var t Template
	for s != "" {
		i := strings.Index(s, "{{")
		if i < 0 {
			t.parts = append(t.parts, part{lit: s})
			break
		}
		if i > 0 {
			t.parts = append(t.parts, part{lit: s[:i]})
		}
		end := strings.Index(s[i:], "}}")
		if end < 0 {
			return Template{}, fmt.Errorf(`"{{" at offset %d has no closing "}}"`, i)
		}
		inner := s[i+2 : i+end]
		name, arg, _ := strings.Cut(inner, ":")
		if !isName(name) {
			return Template{}, fmt.Errorf("invalid placeholder {{%s}}", inner)
		}
		t.parts = append(t.parts, part{name: name, arg: arg})
		s = s[i+end+2:]
	}
	return t, nil
}

// Placeholders lists the placeholders in t, in order.
func (t Template) Placeholders() []Placeholder {
	var ps []Placeholder
	for _, p := range t.parts {
		if p.name != "" {
			ps = append(ps, Placeholder{p.name, p.arg})
		}
	}
	return ps
}

// Render appends t to dst, asking value for each placeholder. The caller
// guarantees values are safe for the output.
func (t Template) Render(dst []byte, value func(Placeholder) string) []byte {
	for _, p := range t.parts {
		if p.name == "" {
			dst = append(dst, p.lit...)
		} else {
			dst = append(dst, value(Placeholder{p.name, p.arg})...)
		}
	}
	return dst
}
