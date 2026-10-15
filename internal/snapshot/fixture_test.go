package snapshot

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// testDeployment is a CloudFront-style deployment with two upstreams.
var testDeployment = Deployment{
	Upstreams:     []string{"orders", "web"},
	ViewerFields:  []string{"ip.src.country", "ip.src.asnum", "ssl", "http.request.version"},
	SourceHeaders: []string{"CloudFront-Viewer-Address", "CloudFront-Viewer-Country", "X-Origin-Secret"},
}

func dur(s string) Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(err)
	}
	return Duration(d)
}

func mustParse(src string) expr.Node {
	n, err := expr.Parse(src)
	if err != nil {
		panic(fmt.Sprintf("Parse(%q): %v", src, err))
	}
	return n
}

// validConfig is a realistic production config that uses every feature. Each
// rejection scenario changes one thing in it.
func validConfig() *Config {
	responses := map[string]Response{
		"rate_limited_html": {Status: 429, ContentType: "text/html; charset=utf-8", Body: "<!doctype html><title>Too many requests</title><p>Try again in {{retry_after}} seconds.</p>"},
	}
	defaults := map[string]string{}
	for kind, status := range statusOf {
		name := kind + "_json"
		responses[name] = Response{Status: status, ContentType: "application/json", Body: `{"error":"` + kind + `","status":{{status}},"request_id":"{{request_id}}"}`}
		defaults[kind] = name
	}
	responses["rate_limited_json"] = Response{Status: 429, ContentType: "application/json", Body: `{"error":"rate_limited","retry_after":{{retry_after}},"request_id":"{{request_id}}"}`}

	return &Config{
		Schema:  1,
		Version: 7,
		Global: Global{
			Backstop: Backstop{Limit: 100, Period: dur("1s"), Burst: 200, MaxEntries: 100_000},
			Defaults: Defaults{
				BodyLimit:       10 << 20,
				BodyReadTimeout: dur("60s"),
				UpstreamTimeout: dur("30s"),
				Responses:       defaults,
			},
			CORSPolicies: map[string]CORSPolicy{
				"app": {
					Origins:        []string{"https://app.example.com", "http://localhost:3000"},
					Methods:        []string{"GET", "POST"},
					RequestHeaders: []string{"Authorization", "Content-Type"},
					ExposedHeaders: []string{"RateLimit"},
					Credentials:    true,
					MaxAge:         dur("10m"),
				},
				"public": {Origins: []string{"*"}, Methods: []string{"GET"}, RequestHeaders: []string{"*"}},
			},
			Responses: responses,
			Locale:    Locale{Supported: []string{"en", "ko", "zh-Hant"}, Default: "en", OutputHeader: "X-Edge-Locale"},
			RequestHeaders: RequestHeaders{
				Forward: Forward{Mode: "denylist", Names: []string{"X-Debug"}},
			},
		},
		Auth: Auth{
			Issuers: []Issuer{
				{ID: "corp", Issuer: "https://auth.example.com/", Audiences: []string{"api"}, JWKSURL: "https://auth.example.com/.well-known/jwks.json", Algorithm: "RS256"},
				{ID: "corp-new", Issuer: "https://id.example.com/", Audiences: []string{"api", "API"}, JWKSURL: "https://id.example.com/jwks", Algorithm: "ES256"},
			},
			DefaultAccepted: []string{"corp"},
		},
		ConfigRules: []ConfigRule{
			{
				ID:         "orders-auth",
				Expression: mustParse(`starts_with(http.request.uri.path, "/v1/orders")`),
				Settings: Settings{
					Auth:            &AuthSetting{Mode: "required", Accepted: []string{"corp", "corp-new"}},
					CORSPolicy:      new("app"),
					Upstream:        new("orders"),
					UpstreamTimeout: new(dur("10s")),
				},
			},
			{
				ID:         "pages",
				Expression: mustParse(`not starts_with(http.request.uri.path, "/v1/")`),
				Settings: Settings{
					Responses:        map[string]string{"rate_limited": "rate_limited_html"},
					Locale:           new(true),
					CORSPolicy:       new(""),
					BodyLimit:        new(int64(1 << 20)),
					RateLimitHeaders: new(true),
					Auth:             &AuthSetting{Mode: "optional"},
				},
			},
		},
		RateLimitRules: []RateLimitRule{
			{ID: "site-per-ip", Expression: expr.True(), Algorithm: "token_bucket", Limit: 300, Period: dur("1m"), Burst: 600, Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "local"},
			{ID: "login-per-ip", Expression: mustParse(`http.request.method eq "POST" and http.request.uri.path eq "/v1/login"`), Algorithm: "sliding_window", Limit: 5, Period: dur("1m"), Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", Penalty: dur("5m"), FailMode: "open"},
			{ID: "api-key", Expression: mustParse(`starts_with(http.request.uri.path, "/v1/")`), Algorithm: "fixed_window", Limit: 1000, Period: dur("1h"), Key: []string{"header:x-api-key"}, OnMissingKey: "skip", Action: "log", FailMode: "closed"},
			{ID: "tenant", Expression: mustParse(`ip.src.country in {"AU" "NZ"} and edge.locale ne "ko" and not starts_with(edge.locale, "zh")`), Algorithm: "leaky_bucket", Limit: 50, Period: dur("1s"), Burst: 10, Key: []string{"jwt_claim:tenant", "country", "asnum", "locale", "query:page"}, OnMissingKey: "reject", Action: "block", FailMode: "open"},
		},
		RequestHeaderRules: []HeaderRule{
			{ID: "keep-original-ua", Expression: mustParse(`http.user_agent ne ""`), Ops: []HeaderOp{{Op: "copy", From: "User-Agent", To: "X-Original-User-Agent"}}},
			{ID: "tenant-header", Expression: mustParse(`http.request.jwt.claims["tenant"] ne ""`), Ops: []HeaderOp{
				{Op: "set", Name: "X-Tenant", Value: "{{jwt_claim:tenant}}"},
				{Op: "append", Name: "X-Trace", Value: "edge {{request_id}} {{client_ip}} {{country}} {{locale}} {{header:user-agent}}"},
				{Op: "remove", Name: "X-Debug-Token"},
				{Op: "rename", From: "X-Old", To: "X-New"},
			}},
			{ID: "orders-allowlist", Expression: mustParse(`starts_with(http.request.uri.path, "/v1/orders")`), Ops: []HeaderOp{
				{Op: "forward", Mode: "allowlist", Names: []string{"Authorization", "Content-Type", "Accept", "Cookie", "User-Agent", "X-Old"}},
			}},
		},
	}
}

// addHugeHeaderRules pushes a config past MaxConfigBytes with values that
// are each within their own limits.
func addHugeHeaderRules(c *Config) {
	big := strings.Repeat("v", MaxHeaderValue)
	for i := range 21 {
		r := HeaderRule{ID: fmt.Sprintf("big-%d", i), Expression: expr.True()}
		for range MaxListLen {
			r.Ops = append(r.Ops, HeaderOp{Op: "set", Name: "X-Big", Value: big})
		}
		c.RequestHeaderRules = append(c.RequestHeaderRules, r)
	}
}

// fakeReq serves fixed field values to compiled matchers.
type fakeReq struct {
	str map[string]string
	ip  netip.Addr
}

func (r fakeReq) String(f string) string       { return r.str[f] }
func (r fakeReq) List(string, string) []string { return nil }
func (r fakeReq) IP(string) netip.Addr         { return r.ip }
func (r fakeReq) Int(string) (int64, bool)     { return 0, false }
func (r fakeReq) Bool(string) bool             { return false }
