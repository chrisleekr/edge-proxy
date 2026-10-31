package expr

import (
	"net/netip"
	"net/textproto"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Request gives compiled matchers access to request fields. The edge
// implements it with lazily extracted, memoized values; a field is only
// computed if some rule reads it.
type Request interface {
	String(field string) string
	// List returns every value of a keyed field (all headers with that name,
	// all query args, ...). Empty means absent.
	List(field, key string) []string
	// IP returns the field's address; the zero Addr means absent.
	IP(field string) netip.Addr
	// Int returns the field's value and whether it is present.
	Int(field string) (int64, bool)
	Bool(field string) bool
}

// Matcher reports whether a request matches a compiled expression.
type Matcher func(Request) bool

// Compile checks n and builds a Matcher. All parsing and allocation happens
// here, once per snapshot, so matching does none of it per request.
func Compile(n Node, env Env) (Matcher, []Issue) {
	if is := Check(n, env); is != nil {
		return nil, is
	}
	return compileGroup(Normalize(n)), nil
}

func compileGroup(g Node) Matcher {
	children := make([]Matcher, len(g.Rules))
	for i, r := range g.Rules {
		if r.IsGroup() {
			children[i] = compileGroup(r)
		} else {
			children[i] = compileRule(r)
		}
	}
	var m Matcher
	if g.Combinator == "or" {
		m = func(req Request) bool {
			for _, c := range children {
				if c(req) {
					return true
				}
			}
			return false
		}
	} else {
		// "and"; an empty group matches everything.
		m = func(req Request) bool {
			for _, c := range children {
				if !c(req) {
					return false
				}
			}
			return true
		}
	}
	if g.Not {
		inner := m
		m = func(req Request) bool { return !inner(req) }
	}
	return m
}

// compileRule builds the matcher for one checked rule. Negated operators are
// compiled as the negation of their positive form, so "does not contain" on a
// list means "no value contains".
func compileRule(r Node) Matcher {
	op, _ := LookupOp(r.Operator)
	if op.Negates != "" {
		pos := r
		pos.Operator = op.Negates
		inner := compileRule(pos)
		return func(req Request) bool { return !inner(req) }
	}
	f, _ := LookupField(r.Field)
	// Only whole values map; a pattern keeps its literal.
	if f.Name == "http.request.version" && (op.Name == "eq" || op.Name == "in") {
		r.Value = versionLiterals(r.Value)
	}
	switch f.Type {
	case TypeIP:
		return compileIP(f.Name, op.Name, r.Value)
	case TypeInt:
		return compileInt(f.Name, op.Name, r.Value)
	case TypeBool:
		name := f.Name
		return func(req Request) bool { return req.Bool(name) }
	}
	pred := stringPred(op.Name, r.Value)
	if f.Type == TypeStringList {
		name, key := f.Name, r.Key
		// Rules store header names lowercased; Go keys http.Header by the
		// canonical form, so canonicalize once here instead of per request.
		if f.LowerKey {
			key = textproto.CanonicalMIMEHeaderKey(key)
		}
		return func(req Request) bool {
			return slices.ContainsFunc(req.List(name, key), pred)
		}
	}
	name := f.Name
	return func(req Request) bool { return pred(req.String(name)) }
}

// versionLiterals maps literals in a form the edge normalises, such as
// "HTTP/2", to that form, so rules saved before the edge normalised the
// version keep matching what they matched. Other literals are kept as is.
func versionLiterals(v Value) Value {
	if n := HTTPVersion(v.One); n != "" {
		v.One = n
	}
	// A new slice: v.List is shared with the stored rule.
	list := make([]string, len(v.List))
	for i, s := range v.List {
		if n := HTTPVersion(s); n != "" {
			s = n
		}
		list[i] = s
	}
	v.List = list
	return v
}

func stringPred(op string, v Value) func(string) bool {
	c := v.One
	switch op {
	case "contains":
		return func(s string) bool { return strings.Contains(s, c) }
	case "starts_with":
		return func(s string) bool { return strings.HasPrefix(s, c) }
	case "ends_with":
		return func(s string) bool { return strings.HasSuffix(s, c) }
	case "wildcard":
		w, _ := compileWildcard(c, true)
		return w.match
	case "strict_wildcard":
		w, _ := compileWildcard(c, false)
		return w.match
	case "matches":
		re := regexp.MustCompile(c) // validated by Check
		return re.MatchString
	case "in":
		set := make(map[string]struct{}, len(v.List))
		for _, item := range v.List {
			set[item] = struct{}{}
		}
		return func(s string) bool { _, ok := set[s]; return ok }
	}
	// eq
	return func(s string) bool { return s == c }
}

func compileIP(name, op string, v Value) Matcher {
	if op == "in" {
		set := newIPSet(v.List)
		return func(req Request) bool { return set.contains(req.IP(name)) }
	}
	// eq
	want := netip.MustParseAddr(v.One).Unmap()
	return func(req Request) bool { a := req.IP(name); return a.IsValid() && clientAddr(a) == want }
}

func compileInt(name, op string, v Value) Matcher {
	if op == "in" {
		set := make(map[int64]struct{}, len(v.List))
		for _, item := range v.List {
			n, _ := strconv.ParseInt(item, 10, 64)
			set[n] = struct{}{}
		}
		return func(req Request) bool {
			n, ok := req.Int(name)
			_, hit := set[n]
			return ok && hit
		}
	}
	want, _ := strconv.ParseInt(v.One, 10, 64)
	var cmp func(int64) bool
	switch op {
	case "gt":
		cmp = func(n int64) bool { return n > want }
	case "ge":
		cmp = func(n int64) bool { return n >= want }
	case "lt":
		cmp = func(n int64) bool { return n < want }
	case "le":
		cmp = func(n int64) bool { return n <= want }
	default: // eq
		cmp = func(n int64) bool { return n == want }
	}
	return func(req Request) bool { n, ok := req.Int(name); return ok && cmp(n) }
}
