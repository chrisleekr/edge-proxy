// Package expr implements the rule expression language: a JSON AST shaped like
// react-querybuilder's rule-group tree, a text syntax, a type
// checker and a compiler to closures. Admin and edge share this package so the
// UI preview, validation and enforcement can never disagree.
package expr

import (
	"encoding/json"
	"errors"
)

// Node is either a group (Combinator set) or a rule (Field set).
// The JSON shape matches react-querybuilder's RuleGroupType/RuleType so the
// admin UI needs no conversion layer.
type Node struct {
	Combinator string `json:"combinator,omitempty"` // "and" | "or"; set only on groups
	Not        bool   `json:"not,omitempty"`        // groups only
	Rules      []Node `json:"rules,omitempty"`

	Field    string `json:"field,omitempty"`
	Key      string `json:"key,omitempty"` // header, cookie, query arg or claim name for keyed fields
	Operator string `json:"operator,omitempty"`
	Value    Value  `json:"value,omitzero"`
}

// IsGroup reports whether n is a group rather than a single comparison.
func (n Node) IsGroup() bool { return n.Field == "" }

// True returns the expression that matches every request ("All incoming requests").
func True() Node { return Node{Combinator: "and"} }

// IsTrue reports whether n is the match-everything expression.
func (n Node) IsTrue() bool { return n.IsGroup() && !n.Not && len(n.Rules) == 0 }

// Value is a rule's right-hand side: one literal, or a list for "in"/"not_in".
// Literals are kept as text; the checker converts them by field type.
type Value struct {
	One  string
	List []string
	// IsList distinguishes an empty list from an absent value.
	IsList bool
}

// IsZero lets `omitzero` drop the value for operators that take none.
func (v Value) IsZero() bool { return !v.IsList && v.One == "" }

// MarshalJSON writes a list as a JSON array and a literal as a string.
func (v Value) MarshalJSON() ([]byte, error) {
	if v.IsList {
		return json.Marshal(v.List)
	}
	return json.Marshal(v.One)
}

// UnmarshalJSON accepts a string or an array of strings.
func (v *Value) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*v = Value{One: one}
		return nil
	}
	// "null" never reaches here: it decodes as the empty string above.
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*v = Value{List: list, IsList: true}
		return nil
	}
	return errors.New("value must be a string or an array of strings")
}

// Normalize returns the canonical form of n, which is always a group.
// Parse(Render(n)) equals Normalize(n), so the AST saved from the UI builder
// and the AST parsed from text agree.
func Normalize(n Node) Node {
	if !n.IsGroup() {
		n = Node{Combinator: "and", Rules: []Node{n}}
	}
	return normalize(n)
}

func normalize(n Node) Node {
	if !n.IsGroup() {
		n.Key = canonKey(n.Field, n.Key)
		return n
	}
	out := Node{Combinator: n.Combinator, Not: n.Not}
	for _, c := range n.Rules {
		out.Rules = append(out.Rules, normalize(c))
	}
	// A group with one child carries no combinator meaning.
	if len(out.Rules) <= 1 {
		out.Combinator = "and"
	}
	// A group wrapping exactly one group is that group, negated if the
	// wrapper was: "not ((a or b))" and "not (a or b)" are the same tree.
	if len(out.Rules) == 1 && out.Rules[0].IsGroup() {
		inner := out.Rules[0]
		inner.Not = inner.Not != out.Not
		return inner
	}
	return out
}
