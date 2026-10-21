package admin

import (
	"context"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// What a route's traffic meets: the edge's own Simulate on a sample request,
// and for every rule whether it always, never or only sometimes matches.

// routeFields are what a route fixes. Every other field depends on the
// client or on values the route doesn't record.
var routeFields = map[string]bool{"http.host": true, "http.request.method": true, "http.request.uri.path": true}

// placeholderSamples fill a template two ways. A condition on the path that
// gives different answers for them depends on the placeholder's value.
var placeholderSamples = [2]map[string]string{
	{"{id}": "1", "{uuid}": "00000000-0000-0000-0000-000000000000", "{hex}": "0123456789abcdef", "{token}": "a1b2c3d4e5f6g7h8i9j0", "{*}": "x"},                     //nolint:gosec // sample path segments, not credentials
	{"{id}": "987654321", "{uuid}": "ffffffff-ffff-4fff-bfff-ffffffffffff", "{hex}": "fedcba9876543210ab", "{token}": "Z9Y8X7W6V5U4T3S2R1Q0", "{*}": "other-value"}, //nolint:gosec // sample path segments, not credentials
}

// samplePath fills the template's placeholders with sample set i. A
// placeholder can be a whole segment or part of one, as in app.{hex}.js.
func samplePath(template string, i int) string {
	return fill(template, func(p string) string { return placeholderSamples[i][p] })
}

// fill replaces each placeholder in s with f's answer for it.
func fill(s string, f func(placeholder string) string) string {
	for p := range placeholderSamples[0] {
		s = strings.ReplaceAll(s, p, f(p))
	}
	return s
}

// valueSamples fill the template's placeholders from a condition's own
// values: aligned by position, so "path eq /users/42" is seen to match some
// /users/{id}, and each piece of a value in each placeholder, so "contains
// 42" is too. Agreement across samples is evidence, not proof.
func valueSamples(template string, v expr.Value) []string {
	tsegs := strings.Split(samplePath(template, 0), "/")
	var holes []int
	for i, s := range strings.Split(template, "/") {
		if hasPlaceholder(s) {
			holes = append(holes, i)
		}
	}
	var out []string
	for _, val := range append([]string{v.One}, v.List...) {
		vsegs := strings.Split(val, "/")
		aligned := slices.Clone(tsegs)
		for _, i := range holes {
			if i < len(vsegs) && vsegs[i] != "" {
				aligned[i] = vsegs[i]
			}
		}
		out = append(out, strings.Join(aligned, "/"))
		for _, piece := range vsegs {
			for _, i := range holes {
				if piece != "" {
					segs := slices.Clone(tsegs)
					segs[i] = piece
					out = append(out, strings.Join(segs, "/"))
				}
			}
		}
	}
	return out
}

func hasPlaceholder(s string) bool { return fill(s, func(string) string { return "" }) != s }

// routeRequest is a request that has only a route's fields.
type routeRequest struct{ host, method, path string }

func (q routeRequest) String(f string) string {
	switch f {
	case "http.host":
		return q.host
	case "http.request.method":
		return q.method
	}
	return q.path
}
func (routeRequest) List(string, string) []string { return nil }
func (routeRequest) IP(string) netip.Addr         { return netip.Addr{} }
func (routeRequest) Int(string) (int64, bool)     { return 0, false }
func (routeRequest) Bool(string) bool             { return false }

// Match outcomes of a rule for a route.
const (
	matchNever   = "never"
	matchDepends = "depends"
	matchAlways  = "always"
)

// ruleMatch says whether a rule applies to a route's traffic.
type ruleMatch struct {
	ID    string `json:"id"`
	Match string `json:"match"`
	// DependsOn names, by label, what decides a "depends" rule.
	DependsOn []string `json:"depends_on,omitempty"`
}

// classify evaluates n for the route with three-valued logic: conditions on
// route fields are run through the expression compiler against the sample
// paths; anything else is unknown, and its label is recorded in deps.
func classify(n expr.Node, phase expr.Phase, k routeKey, deps map[string]bool) int {
	if !n.IsGroup() {
		if !routeFields[n.Field] {
			f, _ := expr.LookupField(n.Field)
			// "Header x-beta" tells the reader which header, not just that one matters.
			deps[strings.TrimSpace(f.Label+" "+n.Key)] = true
			return 0
		}
		// A regex can't be sampled meaningfully against a placeholder.
		if n.Field == "http.request.uri.path" && n.Operator == "matches" && hasPlaceholder(k.template) {
			deps["Path value"] = true
			return 0
		}
		m, issues := expr.Compile(n, expr.Env{Phase: phase, ViewerAvailable: func(string) bool { return true }, AllowRegex: true, RelativePaths: true})
		if issues != nil {
			// Only a config that no longer compiles gets here, and that is
			// refused before classify runs.
			deps["this condition"] = true
			return 0
		}
		paths := append([]string{samplePath(k.template, 0), samplePath(k.template, 1)}, valueSamples(k.template, n.Value)...)
		a := m(routeRequest{k.host, k.method, paths[0]})
		for _, p := range paths[1:] {
			if m(routeRequest{k.host, k.method, p}) != a {
				deps["Path value"] = true
				return 0
			}
		}
		if a {
			return 1
		}
		return -1
	}
	// "and" is decided by any never, "or" by any always; otherwise one
	// unknown child leaves the group unknown. An empty group gives the
	// other value, as the compiler does.
	decide, other := -1, 1
	if n.Combinator == "or" {
		decide, other = 1, -1
	}
	seen := map[int]bool{}
	for _, c := range n.Rules {
		seen[classify(c, phase, k, deps)] = true
	}
	out := other
	switch {
	case seen[decide]:
		out = decide
	case seen[0]:
		out = 0
	}
	if n.Not {
		out = -out
	}
	return out
}

// matchRules classifies every rule of one phase for the route.
func matchRules(phase expr.Phase, k routeKey, ids []string, exprs []expr.Node) []ruleMatch {
	out := []ruleMatch{}
	for i, n := range exprs {
		deps := map[string]bool{}
		m := ruleMatch{ID: ids[i], Match: [...]string{matchNever, matchDepends, matchAlways}[classify(expr.Normalize(n), phase, k, deps)+1]}
		if m.Match == matchDepends {
			m.DependsOn = slices.Sorted(maps.Keys(deps))
		}
		out = append(out, m)
	}
	return out
}

// flowConfig compiles the version the flow is asked for: the active one by
// default, "draft", or a version number.
func (s *Server) flowConfig(ctx context.Context, v string) (*snapshot.Compiled, *int64, error) {
	var version *int64
	switch v {
	case "draft":
	case "":
		av, err := activeVersion(ctx, s.db)
		if err != nil {
			return nil, nil, err
		}
		if av == nil {
			return nil, nil, fail(http.StatusNotFound, "nothing published yet")
		}
		version = av
	default:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, nil, fail(http.StatusBadRequest, `version must be a number or "draft"`)
		}
		version = &n
	}
	c, _, err := s.compiledFor(ctx, version)
	return c, version, err
}

func (s *Server) routeFlow(w http.ResponseWriter, r *http.Request, _ *principal) error {
	id, err := routeID(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	k, err := s.loadRoute(ctx, s.db, id)
	if err != nil {
		return err
	}
	c, version, err := s.flowConfig(ctx, r.URL.Query().Get("version"))
	if err != nil {
		return err
	}
	// The most common query shape stands for the route's queries.
	var shapes map[string]int64
	if err := s.db.QueryRow(ctx, "SELECT sum_counts(query_shapes) FROM observed_route_hour WHERE route_id = $1", id).Scan(&shapes); err != nil {
		return err
	}
	delete(shapes, otherKey)
	shape := ""
	for sh, n := range shapes {
		if n > shapes[shape] || n == shapes[shape] && sh < shape {
			shape = sh
		}
	}
	target := (&url.URL{Path: samplePath(k.template, 0)}).EscapedPath()
	if shape != "" {
		target += "?" + strings.ReplaceAll(shape, "&", "=x&") + "=x"
	}
	host := k.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal
	}
	req := TestRequest{Method: k.method, Host: host, Path: target}
	sim, err := simulate(c, req)
	if err != nil {
		return fail(http.StatusUnprocessableEntity, "the route can't be simulated: "+err.Error())
	}
	cfg := c.Config
	out := struct {
		Version *int64                 `json:"version"`
		Draft   bool                   `json:"draft"`
		Sample  TestRequest            `json:"sample"`
		Result  SimView                `json:"result"`
		Rules   map[string][]ruleMatch `json:"rules"`
	}{Version: version, Draft: version == nil, Sample: req, Result: sim, Rules: map[string][]ruleMatch{}}
	var ids []string
	var exprs []expr.Node
	for _, x := range cfg.ConfigRules {
		ids, exprs = append(ids, x.ID), append(exprs, x.Expression)
	}
	out.Rules["config"] = matchRules(expr.PhaseConfig, k, ids, exprs)
	ids, exprs = nil, nil
	for _, x := range cfg.RateLimitRules {
		ids, exprs = append(ids, x.ID), append(exprs, x.Expression)
	}
	out.Rules["rate_limit"] = matchRules(expr.PhaseRateLimit, k, ids, exprs)
	ids, exprs = nil, nil
	for _, x := range cfg.RequestHeaderRules {
		ids, exprs = append(ids, x.ID), append(exprs, x.Expression)
	}
	out.Rules["request_headers"] = matchRules(expr.PhaseRequestHeaders, k, ids, exprs)
	return writeJSON(w, http.StatusOK, out)
}

// routeCondition returns an expression that matches the route, for a new
// rule to start from. A placeholder segment becomes "*" in a wildcard, which
// also matches deeper paths; the editor shows the condition to adjust.
func (s *Server) routeCondition(w http.ResponseWriter, r *http.Request, _ *principal) error {
	id, err := routeID(r)
	if err != nil {
		return err
	}
	k, err := s.loadRoute(r.Context(), s.db, id)
	if err != nil {
		return err
	}
	path := expr.Node{Field: "http.request.uri.path", Operator: "eq", Value: expr.Value{One: k.template}}
	if hasPlaceholder(k.template) {
		// Literal \ and * are escaped; {*} holds a * too, so each placeholder
		// is found by its escaped form.
		esc := strings.NewReplacer(`\`, `\\`, `*`, `\*`)
		pattern := esc.Replace(k.template)
		for p := range placeholderSamples[0] {
			pattern = strings.ReplaceAll(pattern, esc.Replace(p), "*")
		}
		path = expr.Node{Field: "http.request.uri.path", Operator: "wildcard", Value: expr.Value{One: pattern}}
	}
	n := expr.Node{Combinator: "and", Rules: []expr.Node{
		{Field: "http.host", Operator: "eq", Value: expr.Value{One: k.host}},
		{Field: "http.request.method", Operator: "eq", Value: expr.Value{One: k.method}},
		path,
	}}
	if issues := expr.Check(n, expr.Env{Phase: expr.PhaseConfig, AllowRegex: s.cfg.Deployment.AllowRegex}); issues != nil {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "No condition can match this route", Errors: issues}
	}
	return writeJSON(w, http.StatusOK, map[string]any{"expression": n, "text": expr.Render(n)})
}
