package expr

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Env is what the checker and compiler need to know about the deployment.
type Env struct {
	Phase Phase
	// ViewerAvailable reports whether the deployment configured a trusted
	// source for a viewer field. Nil means none are available.
	ViewerAvailable func(field string) bool
	// AllowRegex enables the "matches" operator (off by default).
	AllowRegex bool
	// RelativePaths accepts a path literal without its leading "/", as
	// checks did before, so a version stored then still loads.
	RelativePaths bool
}

// Issue is one validation problem, located by a path such as "rules[1].rules[0]".
type Issue struct {
	Path string `json:"path"`
	Msg  string `json:"message"`
}

// Issues formats a list of issues as one error message.
type Issues []Issue

func (is Issues) Error() string {
	parts := make([]string, len(is))
	for i, x := range is {
		parts[i] = x.Path + ": " + x.Msg
	}
	return strings.Join(parts, "; ")
}

// MaxValueLen bounds one literal so a single condition can't be huge.
const MaxValueLen = 4096

// MaxKeyLen bounds header, cookie, argument and claim names.
const MaxKeyLen = 256

type checker struct {
	env        Env
	issues     []Issue
	conditions int
}

func (c *checker) add(path, format string, args ...any) {
	c.issues = append(c.issues, Issue{Path: path, Msg: fmt.Sprintf(format, args...)})
}

// Check validates n against the schema, the phase and the deployment. It
// returns every problem found, or nil. The result is a plain slice, not an
// error, so it can't become a non-nil error holding an empty list.
func Check(n Node, env Env) []Issue {
	n = Normalize(n)
	c := &checker{env: env}
	c.group(n, "expression", 1)
	if c.conditions > MaxConditions {
		c.add("expression", "has %d conditions; at most %d are allowed", c.conditions, MaxConditions)
	}
	if l := len(Render(n)); l > MaxTextLen {
		c.add("expression", "is %d characters as text; at most %d are allowed", l, MaxTextLen)
	}
	return c.issues
}

func (c *checker) group(g Node, path string, depth int) {
	if depth > MaxDepth {
		c.add(path, "nesting deeper than %d", MaxDepth)
		return
	}
	if g.Combinator != "and" && g.Combinator != "or" {
		c.add(path, "combinator must be \"and\" or \"or\"")
	}
	for i, r := range g.Rules {
		p := fmt.Sprintf("%s.rules[%d]", path, i)
		if r.IsGroup() {
			c.group(r, p, depth+1)
		} else {
			c.rule(r, p)
		}
	}
}

func (c *checker) rule(r Node, path string) {
	c.conditions++
	// The compiler reads only a condition's own fields, so a group field here
	// would be saved and shown but never enforced.
	if r.Combinator != "" || r.Not || r.Rules != nil {
		c.add(path, "a condition can't have group fields (combinator, not, rules); wrap it in a group")
	}
	f, ok := LookupField(r.Field)
	if !ok {
		c.add(path, "unknown field %q", r.Field)
		return
	}
	if f.Source == SourceViewer && (c.env.ViewerAvailable == nil || !c.env.ViewerAvailable(f.Name)) {
		c.add(path, "field %q has no trusted source configured in this deployment", f.Name)
	}
	if !f.InPhase(c.env.Phase) {
		c.add(path, "field %q is not available in the %s phase", f.Name, c.env.Phase)
	}
	c.key(f, r.Key, path)
	op, ok := LookupOp(r.Operator)
	if !ok {
		c.add(path, "unknown operator %q", r.Operator)
		return
	}
	if !op.accepts(f.Type) {
		c.add(path, "operator %q can't be used with field %q", op.Name, f.Name)
		return
	}
	c.value(f, op, r.Value, path)
}

func (c *checker) key(f FieldDef, key, path string) {
	switch {
	case f.Keyed && key == "":
		c.add(path, "field %q needs a name, e.g. %s[\"name\"]", f.Name, f.Name)
	case !f.Keyed && key != "":
		c.add(path, "field %q doesn't take a name", f.Name)
	case len(key) > MaxKeyLen:
		c.add(path, "name is longer than %d characters", MaxKeyLen)
	case HasControl(key):
		c.add(path, "name contains control characters")
	case !utf8.ValidString(key):
		c.add(path, "name is not valid UTF-8")
	case f.TokenKey && !IsToken(key):
		c.add(path, "%q can never match: header and cookie names contain only letters, digits and !#$%%&'*+-.^_`|~", key)
	}
}

func (c *checker) value(f FieldDef, op OpDef, v Value, path string) {
	f.Slash = f.Slash && !c.env.RelativePaths
	switch {
	case op.NoValue:
		if !v.IsZero() {
			c.add(path, "operator %q takes no value", op.Name)
		}
	case op.List:
		if !v.IsList {
			c.add(path, "operator %q needs a list of values", op.Name)
			return
		}
		// Size is bounded by MaxTextLen.
		if len(v.List) == 0 {
			c.add(path, "list must have at least 1 value")
			return
		}
		for _, item := range v.List {
			if msg := literalProblem(f, op, item, true); msg != "" {
				c.add(path, "%s", msg)
				return
			}
		}
	default:
		if v.IsList {
			c.add(path, "operator %q takes a single value", op.Name)
			return
		}
		if msg := literalProblem(f, op, v.One, false); msg != "" {
			c.add(path, "%s", msg)
			return
		}
		c.pattern(op, v.One, path)
	}
}

func (c *checker) pattern(op OpDef, v, path string) {
	switch op.Name {
	case "matches":
		if !c.env.AllowRegex {
			c.add(path, "the matches operator is disabled in this deployment")
			return
		}
		if len(v) > MaxRegexLen {
			c.add(path, "regex is longer than %d characters", MaxRegexLen)
			return
		}
		if _, err := regexp.Compile(v); err != nil {
			c.add(path, "invalid regex: %v", err)
		}
	case "wildcard", "strict_wildcard":
		if _, err := compileWildcard(v, false); err != nil {
			c.add(path, "%v", err)
		}
	}
}

// literalProblem returns why s is not a valid literal for field f with
// operator op, or "". inList allows CIDR prefixes for IP fields.
func literalProblem(f FieldDef, op OpDef, s string, inList bool) string {
	if len(s) > MaxValueLen {
		return fmt.Sprintf("value is longer than %d characters", MaxValueLen)
	}
	if HasControl(s) {
		return "value contains control characters"
	}
	if !utf8.ValidString(s) {
		return "value is not valid UTF-8"
	}
	if msg := neverMatches(f, op, s); msg != "" {
		return msg
	}
	switch f.Type {
	case TypeIP:
		if a, err := netip.ParseAddr(s); err == nil {
			// Client IPs never carry a zone, so a zoned literal can't match.
			if a.Zone() != "" {
				return fmt.Sprintf("%q can never match: client IPs have no zone", s)
			}
			return ""
		}
		if inList {
			if _, err := netip.ParsePrefix(s); err == nil {
				return ""
			}
			return fmt.Sprintf("%q is not an IP address or CIDR range", s)
		}
		return fmt.Sprintf("%q is not an IP address", s)
	case TypeInt:
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return fmt.Sprintf("%q is not an integer", s)
		}
	}
	return ""
}

// neverMatches reports a literal that a comparison can never match, because
// of how the edge delivers the field. Regex and case-insensitive wildcard are
// exempt from the letter checks: they don't compare letters exactly.
func neverMatches(f FieldDef, op OpDef, s string) string {
	name := op.Name
	if op.Negates != "" {
		name = op.Negates
	}
	// These compare from the first character, and a pattern without a
	// leading * must match it too.
	anchored := name == "eq" || name == "in" || name == "starts_with" || ((name == "wildcard" || name == "strict_wildcard") && !strings.HasPrefix(s, "*"))
	if f.Slash && anchored && !strings.HasPrefix(s, "/") {
		return fmt.Sprintf("%q can never match: paths start with \"/\", such as %q", s, "/"+s)
	}
	if name == "matches" || name == "wildcard" {
		return ""
	}
	switch {
	case f.Case == CaseLower && strings.ToLower(s) != s:
		return fmt.Sprintf("%q can never match: %s values are lowercase, use %q", s, f.Name, strings.ToLower(s))
	case f.Case == CaseUpper && strings.ToUpper(s) != s:
		return fmt.Sprintf("%q can never match: %s values are uppercase, use %q", s, f.Name, strings.ToUpper(s))
	case f.TokenValue && name != "strict_wildcard" && !IsToken(s):
		return fmt.Sprintf("%q can never match: %s values contain only letters, digits and !#$%%&'*+-.^_`|~", s, f.Name)
	}
	return ""
}

// IsToken reports whether s is an RFC 9110 token (section 5.6.2).
func IsToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(tchars, s[i]) < 0 {
			return false
		}
	}
	return true
}

const tchars = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// HasControl reports whether s has an ASCII control character.
func HasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
