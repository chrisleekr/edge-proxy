package admin

import (
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// maxTests bounds the tests stored with one config.
const maxTests = 500

// ConfigTest checks that a valid config does what was meant,
// like Envoy's router_check_tool. It runs through the edge's own Simulate.
type ConfigTest struct {
	Name    string      `json:"name"`
	Request TestRequest `json:"request"`
	Expect  TestExpect  `json:"expect"`
}

// TestRequest is a synthetic request. Trust is deployment-specific, so the
// test states the client IP and viewer values directly.
type TestRequest struct {
	Method  string            `json:"method,omitempty"` // default GET
	Host    string            `json:"host"`
	Path    string            `json:"path"`         // as sent, query included
	IP      string            `json:"ip,omitempty"` // default 192.0.2.1
	Headers map[string]string `json:"headers,omitempty"`
	Country string            `json:"country,omitempty"`
	ASN     int64             `json:"asn,omitempty"`
	SSL     bool              `json:"ssl,omitempty"`
	// JA4, JA3 and HTTPVersion are what the CDN would send.
	JA4         string            `json:"ja4,omitempty"`
	JA3         string            `json:"ja3,omitempty"`
	HTTPVersion string            `json:"http_version,omitempty"`
	VerifiedBot bool              `json:"verified_bot,omitempty"`
	JWTClaims   map[string]string `json:"jwt_claims,omitempty"`
}

// TestExpect lists what must hold; anything left out isn't checked.
type TestExpect struct {
	Rejected       *string   `json:"rejected,omitempty"`
	Preflight      *bool     `json:"preflight,omitempty"`
	ConfigRules    *[]string `json:"config_rules,omitempty"`
	RateLimitRules *[]string `json:"rate_limit_rules,omitempty"`
	// Settings are compared by key; see edge.SimSettings for the keys.
	Settings map[string]any `json:"settings,omitempty"`
	// UpstreamHeaders map a header to its first value; "" means absent.
	UpstreamHeaders map[string]string `json:"upstream_headers,omitempty"`
}

// TestResult is one test's outcome.
type TestResult struct {
	Name     string   `json:"name"`
	Pass     bool     `json:"pass"`
	Failures []string `json:"failures,omitempty"`
}

// SimView is a simulation result as the API returns it.
type SimView struct {
	Rejected        string              `json:"rejected,omitempty"`
	ConfigRules     []string            `json:"config_rules"`
	RateLimitRules  []string            `json:"rate_limit_rules"`
	RateLimitCapped bool                `json:"rate_limit_capped"`
	Preflight       bool                `json:"preflight"`
	Settings        edge.SimSettings    `json:"settings"`
	UpstreamHeaders map[string][]string `json:"upstream_headers"`
}

func (r TestRequest) sim() edge.SimRequest {
	sr := edge.SimRequest{Method: r.Method, Host: r.Host, Target: r.Path, IP: r.IP, Country: r.Country, ASN: r.ASN, SSL: r.SSL,
		JA4: r.JA4, JA3: r.JA3, HTTPVersion: r.HTTPVersion, VerifiedBot: r.VerifiedBot,
		Headers: map[string][]string{}, JWTClaims: map[string][]string{}}
	if sr.Method == "" {
		sr.Method = "GET"
	}
	if sr.IP == "" {
		sr.IP = "192.0.2.1" // TEST-NET-1 (RFC 5737)
	}
	for k, v := range r.Headers {
		sr.Headers[k] = []string{v}
	}
	for k, v := range r.JWTClaims {
		sr.JWTClaims[k] = []string{v}
	}
	return sr
}

func simulate(c *snapshot.Compiled, r TestRequest) (SimView, error) {
	res, err := edge.Simulate(c, r.sim())
	if err != nil {
		return SimView{}, err
	}
	s := res.Settings
	s.Accepted = orEmpty(s.Accepted)
	return SimView{
		Rejected: res.Rejected, ConfigRules: orEmpty(res.ConfigRules), RateLimitRules: orEmpty(res.RateLimitRules), RateLimitCapped: res.RateLimitCapped, Preflight: res.Preflight,
		Settings:        s,
		UpstreamHeaders: res.UpstreamHeaders,
	}, nil
}

// orEmpty makes a nil slice encode as [] rather than null.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// checkTests reports problems with the test list itself.
func checkTests(tests []ConfigTest) []expr.Issue {
	var errs []expr.Issue
	if len(tests) > maxTests {
		errs = append(errs, expr.Issue{Path: "tests", Msg: fmt.Sprintf("has %d tests; at most %d are allowed", len(tests), maxTests)})
	}
	seen := map[string]bool{}
	for i, t := range tests {
		p := fmt.Sprintf("tests[%d]", i)
		if t.Name == "" || seen[t.Name] {
			errs = append(errs, expr.Issue{Path: p + ".name", Msg: "must be set and unique"})
		}
		seen[t.Name] = true
		for k := range t.Expect.Settings {
			if !slices.Contains(settingKeys, k) {
				errs = append(errs, expr.Issue{Path: p + ".expect.settings." + k, Msg: "unknown setting; use " + strings.Join(settingKeys, ", ")})
			}
		}
	}
	return errs
}

var settingKeys = func() []string {
	var out []string
	t := reflect.TypeFor[edge.SimSettings]()
	for field := range t.Fields() {
		out = append(out, field.Tag.Get("json"))
	}
	return out
}()

// runTests runs every test against c.
func runTests(c *snapshot.Compiled, tests []ConfigTest) []TestResult {
	out := make([]TestResult, 0, len(tests))
	for _, t := range tests {
		r := TestResult{Name: t.Name}
		got, err := simulate(c, t.Request)
		if err != nil {
			r.Failures = append(r.Failures, "request: "+err.Error())
		} else {
			r.Failures = t.Expect.mismatches(got)
		}
		r.Pass = len(r.Failures) == 0
		out = append(out, r)
	}
	return out
}

func (e TestExpect) mismatches(got SimView) []string {
	var f []string
	if e.Rejected != nil && *e.Rejected != got.Rejected {
		f = append(f, fmt.Sprintf("rejected: want %q, got %q", *e.Rejected, got.Rejected))
	}
	if e.Preflight != nil && *e.Preflight != got.Preflight {
		f = append(f, fmt.Sprintf("preflight: want %v, got %v", *e.Preflight, got.Preflight))
	}
	if e.ConfigRules != nil && !slices.Equal(*e.ConfigRules, got.ConfigRules) {
		f = append(f, fmt.Sprintf("config_rules: want %v, got %v", *e.ConfigRules, got.ConfigRules))
	}
	// Tests describe people's rules. Autopilot's come and go with attacks,
	// so a test that listed them would fail on every overlay change.
	if people := slices.DeleteFunc(slices.Clone(got.RateLimitRules), isOverlay); e.RateLimitRules != nil && !slices.Equal(*e.RateLimitRules, people) {
		f = append(f, fmt.Sprintf("rate_limit_rules: want %v, got %v", *e.RateLimitRules, people))
	}
	if len(e.Settings) > 0 {
		actual, _ := generic(got.Settings).(map[string]any)
		for _, k := range slices.Sorted(maps.Keys(e.Settings)) {
			want := generic(e.Settings[k])
			if !reflect.DeepEqual(want, actual[k]) {
				f = append(f, fmt.Sprintf("settings.%s: want %v, got %v", k, want, actual[k]))
			}
		}
	}
	h := http.Header(got.UpstreamHeaders)
	for _, k := range slices.Sorted(maps.Keys(e.UpstreamHeaders)) {
		if want, have := e.UpstreamHeaders[k], h.Get(k); want != have {
			f = append(f, fmt.Sprintf("upstream_headers.%s: want %q, got %q", k, want, have))
		}
	}
	return f
}
