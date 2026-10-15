package snapshot

import (
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/text/language"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// A realistic config using every feature compiles without errors or
// warnings, and the compiled form is what the request path needs.
func TestRealisticConfigCompiles(t *testing.T) {
	c := validConfig()
	out, warns, errs := Compile(c, testDeployment)
	if errs != nil || warns != nil {
		t.Fatalf("errors %v, warnings %v", errs, warns)
	}
	if len(out.SiteWide) != 1 || out.SiteWide[0] != 0 {
		t.Errorf("SiteWide = %v, want [0]", out.SiteWide)
	}
	login := fakeReq{str: map[string]string{"http.request.method": "POST", "http.request.uri.path": "/v1/login"}, ip: netip.MustParseAddr("192.0.2.1")}
	if !out.RateLimitRules[1](login) || out.RateLimitRules[1](fakeReq{}) {
		t.Error("login-per-ip doesn't match exactly the login request")
	}
	if !out.ConfigRules[0](fakeReq{str: map[string]string{"http.request.uri.path": "/v1/orders/1"}}) {
		t.Error("orders-auth doesn't match an orders path")
	}
	if len(out.HeaderRules) != 3 || len(out.HeaderValues[1]) != 4 {
		t.Fatalf("header rules not compiled: %d rules", len(out.HeaderRules))
	}
	got := string(out.HeaderValues[1][0].Render(nil, func(p Placeholder) string { return "acme" }))
	if got != "acme" {
		t.Errorf("X-Tenant renders %q", got)
	}
	body := out.Responses["rate_limited_json"].Render(nil, func(p Placeholder) string {
		return map[string]string{"retry_after": "30", "request_id": "r-1"}[p.Name]
	})
	if string(body) != `{"error":"rate_limited","retry_after":30,"request_id":"r-1"}` {
		t.Errorf("rate_limited_json renders %s", body)
	}
	tag, _, _ := out.Locale.Match(language.MustParse("zh-TW"))
	if base, _ := tag.Base(); base.String() != "zh" {
		t.Errorf("zh-TW matched %s, want a zh tag", tag)
	}
}

// The rule builder checks one expression with the same rules as a save.
func TestCheckExpression(t *testing.T) {
	c := validConfig()
	cases := []struct {
		name, src string
		phase     expr.Phase
		err, warn string
	}{
		{"valid", `http.host eq "api.example.com"`, expr.PhaseConfig, "", ""},
		{"field not available in this phase", `http.request.jwt.claims["sub"] eq "x"`, expr.PhaseConfig, "not available", ""},
		{"reads an edge-managed header", `http.request.headers["x-edge-auth-sub"] eq "admin"`, expr.PhaseRateLimit, "expression", ""},
		{"locale the edge never produces", `edge.locale eq "fr"`, expr.PhaseRateLimit, "never \"fr\"", ""},
		{"contradiction", `http.host eq "a.example.com" and http.host eq "b.example.com"`, expr.PhaseConfig, "", "can never all be true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs, warns := CheckExpression(mustParse(tc.src), tc.phase, c, testDeployment)
			if !hasIssue(errs, tc.err) || !hasIssue(warns, tc.warn) {
				t.Fatalf("errs %v, warns %v", errs, warns)
			}
		})
	}
}

// hasIssue: want "" means none; otherwise some issue mentions want.
func hasIssue(is []expr.Issue, want string) bool {
	if want == "" {
		return len(is) == 0
	}
	for _, i := range is {
		if strings.Contains(i.Path+" "+i.Msg, want) {
			return true
		}
	}
	return false
}

// A first draft starts from the starter config, so it must compile as is,
// on a deployment with no viewer fields.
func TestStarterCompiles(t *testing.T) {
	c := Starter()
	c.Version = 1 // admin numbers it at save
	if _, warns, errs := Compile(c, Deployment{Upstreams: []string{"app"}}); errs != nil || warns != nil {
		t.Fatalf("errors %v, warnings %v", errs, warns)
	}
	if r := c.Global.Responses["rate_limited"]; r.Status != 429 || r.Body != `{"status":429,"title":"Too Many Requests"}` {
		t.Fatalf("rate_limited %+v", r)
	}
}

// Edges and admin build their deployment from env in map order and header
// case; only a real difference may block publishing.
func TestDeploymentFingerprint(t *testing.T) {
	base := Deployment{Upstreams: []string{"app", "admin"}, ViewerFields: []string{"ip.src.country"}, SourceHeaders: []string{"CloudFront-Viewer-Country", "CloudFront-Viewer-Address"}}
	same := Deployment{Upstreams: []string{"admin", "app"}, ViewerFields: []string{"ip.src.country"}, SourceHeaders: []string{"cloudfront-viewer-address", "cloudfront-viewer-country"}}
	if base.Fingerprint() != same.Fingerprint() {
		t.Fatal("order or header case changed the fingerprint")
	}
	for name, d := range map[string]Deployment{
		"another upstream": {Upstreams: []string{"app", "admin", "legacy"}, ViewerFields: base.ViewerFields, SourceHeaders: base.SourceHeaders},
		"regex allowed":    {Upstreams: base.Upstreams, ViewerFields: base.ViewerFields, SourceHeaders: base.SourceHeaders, AllowRegex: true},
		"no viewer fields": {Upstreams: base.Upstreams, SourceHeaders: base.SourceHeaders},
	} {
		if d.Fingerprint() == base.Fingerprint() {
			t.Errorf("%s: same fingerprint", name)
		}
	}
}
