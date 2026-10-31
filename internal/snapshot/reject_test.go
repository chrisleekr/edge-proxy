package snapshot

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

type rejectCase struct {
	name   string
	change func(c *Config)
	dep    *Deployment // nil means testDeployment
	path   string
	msg    string
}

// Every mistake an admin user can make is rejected with the path the UI
// highlights, and nothing is compiled. Each case changes one thing in the
// realistic config.
func TestCompileRejects(t *testing.T) {
	cases := []rejectCase{
		// Top level.
		{"newer schema than this build reads", func(c *Config) { c.Schema = SupportedSchema + 1 }, nil, "schema", "schema 6 is not supported"},
		{"version zero", func(c *Config) { c.Version = 0 }, nil, "version", "at least 1"},
		{"config over 8 MB", addHugeHeaderRules, nil, "", "bytes as JSON"},

		// Backstop.
		{"backstop limit zero", func(c *Config) { c.Global.Backstop.Limit = 0 }, nil, "global.backstop.limit", "must be 1 to"},
		{"backstop period over an hour", func(c *Config) { c.Global.Backstop.Period = dur("2h") }, nil, "global.backstop.period", "whole seconds from 1s to 1h0m0s"},
		{"backstop burst over the cap", func(c *Config) { c.Global.Backstop.Burst = MaxCount + 1 }, nil, "global.backstop.burst", "must be 1 to"},
		{"backstop without a memory bound", func(c *Config) { c.Global.Backstop.MaxEntries = 0 }, nil, "global.backstop.max_entries", "must be 1 to 10,000,000"},
		{"negative max in-flight", func(c *Config) { c.Global.MaxInflight = -1 }, nil, "global.max_inflight", "must be 1 to 1,000,000"},
		{"max in-flight over the cap", func(c *Config) { c.Global.MaxInflight = MaxInflight + 1 }, nil, "global.max_inflight", "must be 1 to 1,000,000"},

		// Response templates.
		{"too many templates", func(c *Config) {
			for i := range MaxListLen {
				c.Global.Responses[fmt.Sprintf("extra-%d", i)] = Response{Status: 400, ContentType: "text/plain; charset=utf-8", Body: "x"}
			}
		}, nil, "global.responses", "at most 100"},
		{"template name with spaces", func(c *Config) {
			c.Global.Responses["Bad Name"] = Response{Status: 400, ContentType: "text/plain; charset=utf-8"}
		}, nil, `global.responses["Bad Name"]`, "lowercase letters"},
		{"template status below 400", func(c *Config) { setResponse(c, "bad_request_json", func(r *Response) { r.Status = 200 }) }, nil, `global.responses["bad_request_json"].status`, "400 to 599"},
		{"template content type not allowed", func(c *Config) {
			setResponse(c, "bad_request_json", func(r *Response) { r.ContentType = "application/xml" })
		}, nil, `global.responses["bad_request_json"].content_type`, "must be one of"},
		{"template body over 32 KB", func(c *Config) {
			setResponse(c, "rate_limited_html", func(r *Response) { r.Body = strings.Repeat("x", MaxBodyTemplate+1) })
		}, nil, `global.responses["rate_limited_html"].body`, "at most 32768"},
		{"unclosed placeholder", func(c *Config) {
			setResponse(c, "rate_limited_html", func(r *Response) { r.Body = "wait {{retry_after" })
		}, nil, `global.responses["rate_limited_html"].body`, `has no closing "}}"`},
		{"malformed placeholder", func(c *Config) {
			setResponse(c, "rate_limited_html", func(r *Response) { r.Body = "{{Retry After}}" })
		}, nil, `global.responses["rate_limited_html"].body`, "invalid placeholder"},
		{"request value in a response template", func(c *Config) {
			setResponse(c, "rate_limited_html", func(r *Response) { r.Body = "hi {{header:user-agent}}" })
		}, nil, `global.responses["rate_limited_html"].body`, "unknown placeholder {{header}}"},
		{"response placeholder with a name", func(c *Config) {
			setResponse(c, "rate_limited_html", func(r *Response) { r.Body = "{{status:x}}" })
		}, nil, `global.responses["rate_limited_html"].body`, "unknown placeholder {{status}}"},
		{"JSON template that isn't JSON", func(c *Config) {
			setResponse(c, "rate_limited_json", func(r *Response) { r.Body = `{"retry_after":{{retry_after}}` })
		}, nil, `global.responses["rate_limited_json"].body`, "not valid JSON"},
		{"JSON template that quotes a number badly", func(c *Config) {
			setResponse(c, "rate_limited_json", func(r *Response) { r.Body = `{"id":{{request_id}}}` })
		}, nil, `global.responses["rate_limited_json"].body`, "not valid JSON"},

		// Defaults.
		{"zero default body limit", func(c *Config) { c.Global.Defaults.BodyLimit = 0 }, nil, "global.defaults.body_limit", "at least 1 byte"},
		{"zero body read timeout", func(c *Config) { c.Global.Defaults.BodyReadTimeout = 0 }, nil, "global.defaults.body_read_timeout", "from 1s to 1h0m0s"},
		{"upstream timeout over an hour", func(c *Config) { c.Global.Defaults.UpstreamTimeout = dur("61m") }, nil, "global.defaults.upstream_timeout", "from 1s to 1h0m0s"},
		{"default for an unknown kind", func(c *Config) { c.Global.Defaults.Responses["teapot"] = "bad_request_json" }, nil, "global.defaults.responses", `unknown response kind "teapot"`},
		{"default names a missing template", func(c *Config) { c.Global.Defaults.Responses["bad_request"] = "nope" }, nil, "global.defaults.responses", `bad_request uses template "nope", which doesn't exist`},
		{"default with the wrong status", func(c *Config) { c.Global.Defaults.Responses["rate_limited"] = "bad_request_json" }, nil, "global.defaults.responses", "rate_limited needs a template with status 429"},
		{"default missing a kind", func(c *Config) { delete(c.Global.Defaults.Responses, "bad_gateway") }, nil, "global.defaults.responses", `needs a template for "bad_gateway"`},

		// CORS.
		{"too many CORS policies", func(c *Config) {
			for i := range MaxListLen {
				c.Global.CORSPolicies[fmt.Sprintf("p%d", i)] = CORSPolicy{Origins: []string{"*"}}
			}
		}, nil, "global.cors_policies", "at most 100"},
		{"CORS policy name in capitals", func(c *Config) { c.Global.CORSPolicies["App"] = CORSPolicy{Origins: []string{"*"}} }, nil, `global.cors_policies["App"]`, "lowercase letters"},
		{"CORS policy without origins", func(c *Config) { setCORS(c, "app", func(p *CORSPolicy) { p.Origins = nil }) }, nil, `global.cors_policies["app"].origins`, "at least one origin"},
		{"any origin with credentials", func(c *Config) { setCORS(c, "app", func(p *CORSPolicy) { p.Origins = []string{"*"} }) }, nil, `global.cors_policies["app"].origins[0]`, `"*" can't be used with credentials`},
		{"origin with a path", func(c *Config) {
			setCORS(c, "app", func(p *CORSPolicy) { p.Origins = []string{"https://app.example.com/"} })
		}, nil, `global.cors_policies["app"].origins[0]`, "must be an origin"},
		{"origin without a scheme", func(c *Config) { setCORS(c, "app", func(p *CORSPolicy) { p.Origins = []string{"app.example.com"} }) }, nil, `global.cors_policies["app"].origins[0]`, "must be an origin"},
		{"origin with an empty query", func(c *Config) {
			setCORS(c, "app", func(p *CORSPolicy) { p.Origins = []string{"https://app.example.com?"} })
		}, nil, `global.cors_policies["app"].origins[0]`, "must be an origin"},
		{"origin with credentials in it", func(c *Config) {
			setCORS(c, "app", func(p *CORSPolicy) { p.Origins = []string{"https://u:p@app.example.com"} })
		}, nil, `global.cors_policies["app"].origins[0]`, "must be an origin"},
		{"origin in capitals", func(c *Config) {
			setCORS(c, "app", func(p *CORSPolicy) { p.Origins = []string{"https://App.example.com"} })
		}, nil, `global.cors_policies["app"].origins[0]`, "must be lowercase"},
		{"duplicate origin", func(c *Config) {
			setCORS(c, "app", func(p *CORSPolicy) { p.Origins = []string{"https://a.example.com", "https://a.example.com"} })
		}, nil, `global.cors_policies["app"].origins[1]`, "duplicate"},
		{"lowercase CORS method", func(c *Config) { setCORS(c, "app", func(p *CORSPolicy) { p.Methods = []string{"get"} }) }, nil, `global.cors_policies["app"].methods[0]`, "uppercase method"},
		{"any request header with credentials", func(c *Config) {
			setCORS(c, "app", func(p *CORSPolicy) { p.RequestHeaders = []string{"*"} })
		}, nil, `global.cors_policies["app"].request_headers[0]`, `"*" can't be used with credentials`},
		{"exposed header with a space", func(c *Config) { setCORS(c, "app", func(p *CORSPolicy) { p.ExposedHeaders = []string{"Rate Limit"} }) }, nil, `global.cors_policies["app"].exposed_headers[0]`, "is not a valid header name; use letters, digits and -, such as x-request-id"},
		{"header listed twice in different case", func(c *Config) {
			setCORS(c, "app", func(p *CORSPolicy) { p.RequestHeaders = []string{"Content-Type", "content-type"} })
		}, nil, `global.cors_policies["app"].request_headers[1]`, "duplicate"},
		{"CORS max age over a day", func(c *Config) { setCORS(c, "app", func(p *CORSPolicy) { p.MaxAge = dur("25h") }) }, nil, `global.cors_policies["app"].max_age`, "whole seconds"},
		{"too many origins", func(c *Config) {
			setCORS(c, "app", func(p *CORSPolicy) {
				for i := range MaxListLen + 1 {
					p.Origins = append(p.Origins, fmt.Sprintf("https://a%d.example.com", i))
				}
			})
		}, nil, `global.cors_policies["app"].origins`, "at most 100"},

		// Locale.
		{"locale on with no locales", func(c *Config) {
			c.Global.Locale = Locale{}
			c.Global.Defaults.Locale = true
			c.RateLimitRules[3].Key = []string{"jwt_claim:tenant"}
			c.RateLimitRules[3].Expression = expr.True()
			c.RateLimitRules[0].Expression = mustParse(`ssl`)
			c.ConfigRules[1].Settings.Locale = nil
			c.RequestHeaderRules[1].Ops[1].Value = "x"
		}, nil, "global.locale.supported", "at least one locale"},
		{"locale that isn't a tag", func(c *Config) { c.Global.Locale.Supported[1] = "korean!" }, nil, "global.locale.supported[1]", "not a BCP 47"},
		{"locale not in canonical form", func(c *Config) { c.Global.Locale.Supported[2] = "zh-hant" }, nil, "global.locale.supported[2]", `canonical form "zh-Hant"`},
		{"default locale not supported", func(c *Config) { c.Global.Locale.Default = "fr" }, nil, "global.locale.default", "one of the supported"},
		{"locale output header clients could send", func(c *Config) { c.Global.Locale.OutputHeader = "Accept-Language" }, nil, "global.locale.output_header", "starting with X-Edge-"},

		// Forward filter.
		{"forward all with names", func(c *Config) { c.Global.RequestHeaders.Forward = Forward{Mode: "all", Names: []string{"X-A"}} }, nil, "global.request_headers.forward.names", "empty when mode is all"},
		{"forward mode unknown", func(c *Config) { c.Global.RequestHeaders.Forward.Mode = "some" }, nil, "global.request_headers.forward.mode", "all, allowlist or denylist"},
		{"denylist with no names", func(c *Config) { c.Global.RequestHeaders.Forward.Names = nil }, nil, "global.request_headers.forward.names", "at least one header name"},
		{"denylist of an edge-managed header", func(c *Config) { c.Global.RequestHeaders.Forward.Names = []string{"x-forwarded-for"} }, nil, "global.request_headers.forward.names[0]", "X-Forwarded-For is managed by the edge"},

		// Auth.
		{"too many issuers", func(c *Config) {
			for i := range MaxListLen {
				c.Auth.Issuers = append(c.Auth.Issuers, Issuer{ID: fmt.Sprintf("i%d", i), Issuer: fmt.Sprintf("https://i%d/", i), Audiences: []string{"a"}, JWKSURL: "https://i/jwks", Algorithm: "RS256"})
			}
		}, nil, "auth.issuers", "at most 100"},
		{"issuer id with a colon", func(c *Config) {
			c.Auth.Issuers[0].ID = "corp:v1"
			c.Auth.DefaultAccepted = nil
			c.ConfigRules[0].Settings.Auth.Accepted = []string{"corp-new"}
			c.ConfigRules[1].Settings.Auth.Accepted = []string{"corp-new"}
		}, nil, "auth.issuers[0].id", "lowercase letters"},
		{"duplicate issuer id", func(c *Config) { c.Auth.Issuers[1].ID = "corp" }, nil, "auth.issuers[1].id", `duplicate issuer id "corp"`},
		{"empty issuer", func(c *Config) { c.Auth.Issuers[0].Issuer = "" }, nil, "auth.issuers[0].issuer", "1 to 256 characters"},
		{"two issuers with one iss", func(c *Config) { c.Auth.Issuers[1].Issuer = c.Auth.Issuers[0].Issuer }, nil, "auth.issuers[1].issuer", "another issuer already uses"},
		{"issuer without audiences", func(c *Config) { c.Auth.Issuers[0].Audiences = nil }, nil, "auth.issuers[0].audiences", "at least one audience"},
		{"empty audience", func(c *Config) { c.Auth.Issuers[0].Audiences = []string{""} }, nil, "auth.issuers[0].audiences[0]", "1 to 256 characters"},
		{"JWKS over plain HTTP", func(c *Config) { c.Auth.Issuers[0].JWKSURL = "http://auth.example.com/jwks" }, nil, "auth.issuers[0].jwks_url", "https URL"},
		{"JWKS URL with credentials", func(c *Config) { c.Auth.Issuers[0].JWKSURL = "https://u:p@auth.example.com/jwks" }, nil, "auth.issuers[0].jwks_url", "https URL"},
		{"JWKS URL that doesn't parse", func(c *Config) { c.Auth.Issuers[0].JWKSURL = "https://[::1" }, nil, "auth.issuers[0].jwks_url", "https URL"},
		{"HMAC algorithm", func(c *Config) { c.Auth.Issuers[0].Algorithm = "HS256" }, nil, "auth.issuers[0].algorithm", "must be one of"},
		{"default accepted issuer missing", func(c *Config) { c.Auth.DefaultAccepted = []string{"gone"} }, nil, "auth.default_accepted[0]", `issuer "gone" doesn't exist`},

		// Config rules.
		{"too many config rules", func(c *Config) {
			for i := range MaxRulesPerPhase {
				c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: fmt.Sprintf("r%d", i), Expression: expr.True(), Settings: Settings{BodyLimit: new(int64(1))}})
			}
		}, nil, "config_rules", "at most 200"},
		{"rule id reused across phases", func(c *Config) { c.RateLimitRules[1].ID = "orders-auth" }, nil, "rate_limit_rules[1].id", `duplicate rule id "orders-auth"`},
		{"rule without an id", func(c *Config) { c.ConfigRules[0].ID = "" }, nil, "config_rules[0].id", "lowercase letters"},
		{"JWT claim in the config phase", func(c *Config) {
			c.ConfigRules[0].Expression = mustParse(`http.request.jwt.claims["sub"] eq "a"`)
		}, nil, "config_rules[0].expression.rules[0]", "not available in the config phase"},
		{"rule that sets nothing", func(c *Config) { c.ConfigRules[0].Settings = Settings{} }, nil, "config_rules[0].settings", "sets nothing"},
		{"auth none with accepted issuers", func(c *Config) { c.ConfigRules[0].Settings.Auth.Mode = "none" }, nil, "config_rules[0].settings.auth.accepted", "empty when mode is none"},
		{"auth required with no issuers anywhere", func(c *Config) {
			c.Auth.DefaultAccepted = nil
			c.ConfigRules[0].Settings.Auth.Accepted = nil
		}, nil, "config_rules[0].settings.auth.accepted", "no issuers are accepted"},
		{"auth mode unknown", func(c *Config) { c.ConfigRules[0].Settings.Auth.Mode = "strict" }, nil, "config_rules[0].settings.auth.mode", "none, optional or required"},
		{"auth accepts a missing issuer", func(c *Config) { c.ConfigRules[0].Settings.Auth.Accepted = []string{"corp", "old"} }, nil, "config_rules[0].settings.auth.accepted[1]", `issuer "old" doesn't exist`},
		{"missing CORS policy", func(c *Config) { c.ConfigRules[0].Settings.CORSPolicy = new("mobile") }, nil, "config_rules[0].settings.cors_policy", `"mobile" doesn't exist`},
		{"locale on with no locales configured", func(c *Config) {
			c.Global.Locale = Locale{}
			c.RateLimitRules[3].Key = []string{"jwt_claim:tenant"}
			c.RateLimitRules[3].Expression = expr.True()
			c.RateLimitRules[0].Expression = mustParse(`ssl`)
			c.RequestHeaderRules[1].Ops[1].Value = "x"
		}, nil, "config_rules[1].settings.locale", "locale is not configured"},
		{"rule response with the wrong status", func(c *Config) { c.ConfigRules[1].Settings.Responses["unauthorized"] = "bad_request_json" }, nil, "config_rules[1].settings.responses", "unauthorized needs a template with status 401"},
		{"zero body limit", func(c *Config) { c.ConfigRules[1].Settings.BodyLimit = new(int64(0)) }, nil, "config_rules[1].settings.body_limit", "at least 1 byte"},
		{"upstream timeout of zero", func(c *Config) { c.ConfigRules[0].Settings.UpstreamTimeout = new(Duration(0)) }, nil, "config_rules[0].settings.upstream_timeout", "from 1s"},

		// Rate-limit rules.
		{"three rules matching all requests", func(c *Config) {
			for _, i := range []int{1, 2} {
				c.RateLimitRules[i].Expression = expr.True()
			}
		}, nil, "rate_limit_rules", "has 3 rules matching all requests; at most 2"},
		{"too many rate-limit rules", func(c *Config) {
			for i := range MaxRulesPerPhase {
				c.RateLimitRules = append(c.RateLimitRules, RateLimitRule{ID: fmt.Sprintf("r%d", i), Expression: mustParse("ssl"), Algorithm: "fixed_window", Limit: 1, Period: dur("1s"), Key: []string{"ip"}, OnMissingKey: "skip", Action: "log", FailMode: "open"})
			}
		}, nil, "rate_limit_rules", "at most 200"},
		{"unknown algorithm", func(c *Config) { c.RateLimitRules[1].Algorithm = "sliding_log" }, nil, "rate_limit_rules[1].algorithm", "must be one of fixed_window"},
		{"zero limit", func(c *Config) { c.RateLimitRules[1].Limit = 0 }, nil, "rate_limit_rules[1].limit", "must be 1 to 1,000,000,000"},
		{"fractional period", func(c *Config) { c.RateLimitRules[1].Period = dur("1500ms") }, nil, "rate_limit_rules[1].period", "whole seconds"},
		{"period over a day", func(c *Config) { c.RateLimitRules[1].Period = dur("25h") }, nil, "rate_limit_rules[1].period", "whole seconds from 1s to 24h0m0s"},
		{"token bucket without burst", func(c *Config) { c.RateLimitRules[0].Burst = 0 }, nil, "rate_limit_rules[0].burst", "must be 1 to"},
		{"bucket burst too large to count exactly over a day", func(c *Config) {
			c.RateLimitRules[0].Period = dur("24h")
			c.RateLimitRules[0].Burst = 100_000_000
		}, nil, "rate_limit_rules[0].burst", "at most 26062497 per 24h0m0s"},
		{"burst on a fixed window", func(c *Config) { c.RateLimitRules[2].Burst = 10 }, nil, "rate_limit_rules[2].burst", "only to token_bucket and leaky_bucket"},
		{"no key", func(c *Config) { c.RateLimitRules[1].Key = nil }, nil, "rate_limit_rules[1].key", "1 to 5 characteristics"},
		{"six key parts", func(c *Config) {
			c.RateLimitRules[1].Key = []string{"ip", "host", "method", "country", "asnum", "locale"}
		}, nil, "rate_limit_rules[1].key", "1 to 5 characteristics"},
		{"ip with a name", func(c *Config) { c.RateLimitRules[1].Key = []string{"ip:v4"} }, nil, "rate_limit_rules[1].key[0]", "ip takes no name"},
		{"header key with a bad name", func(c *Config) { c.RateLimitRules[1].Key = []string{"ip", "header:x api"} }, nil, "rate_limit_rules[1].key[1]", "header needs a valid name"},
		{"query key without a name", func(c *Config) { c.RateLimitRules[1].Key = []string{"ip", "query:"} }, nil, "rate_limit_rules[1].key[1]", "query needs a name"},
		{"unknown key", func(c *Config) { c.RateLimitRules[1].Key = []string{"session"} }, nil, "rate_limit_rules[1].key[0]", "must be ip, header:<n>"},
		{"country key with no country source", func(c *Config) {
			c.RateLimitRules[3].Expression = expr.True()
			c.RateLimitRules[0].Expression = mustParse("ssl")
			c.RequestHeaderRules[1].Ops[1].Value = "x"
		}, &Deployment{ViewerFields: []string{"ip.src.asnum", "ssl"}}, "rate_limit_rules[3].key[1]", "country has no trusted source"},
		{"asnum key with no ASN source", func(c *Config) {
			c.RateLimitRules[3].Key = []string{"jwt_claim:tenant", "asnum"}
		}, &Deployment{ViewerFields: []string{"ip.src.country", "ssl"}}, "rate_limit_rules[3].key[1]", "asnum has no trusted source"},
		{"locale key with no locales", func(c *Config) {
			c.Global.Locale = Locale{}
			c.ConfigRules[1].Settings.Locale = nil
			c.RateLimitRules[3].Expression = mustParse("ssl")
			c.RequestHeaderRules[1].Ops[1].Value = "x"
		}, nil, "rate_limit_rules[3].key[3]", "locale is not configured"},
		{"constant with another part", func(c *Config) { c.RateLimitRules[1].Key = []string{"constant", "ip"} }, nil, "rate_limit_rules[1].key[0]", "constant can't be combined"},
		{"same part twice", func(c *Config) { c.RateLimitRules[1].Key = []string{"ip", "ip"} }, nil, "rate_limit_rules[1].key[1]", "duplicate"},
		{"keyed only on a header with no ip rule", func(c *Config) { c.RateLimitRules[0].Key = []string{"host"} }, nil, "rate_limit_rules[2].key", "keys only on client-controlled values"},
		// Any uppercase token is a valid method, and a Host can be anything
		// when a config rule routes every host, so both rotate freely.
		{"keyed only on the method with no ip rule", func(c *Config) {
			c.RateLimitRules[0].Key = []string{"constant"}
			c.RateLimitRules[1].Key = []string{"method"}
		}, nil, "rate_limit_rules[1].key", "keys only on client-controlled values"},
		{"keyed only on the host with no ip rule", func(c *Config) {
			c.RateLimitRules[0].Key = []string{"constant"}
			c.RateLimitRules[1].Key = []string{"host"}
		}, nil, "rate_limit_rules[1].key", "keys only on client-controlled values"},
		{"unknown on_missing_key", func(c *Config) { c.RateLimitRules[1].OnMissingKey = "" }, nil, "rate_limit_rules[1].on_missing_key", "skip, fallback_ip or reject"},
		{"unknown action", func(c *Config) { c.RateLimitRules[1].Action = "challenge" }, nil, "rate_limit_rules[1].action", "block or log"},
		{"penalty under a second", func(c *Config) { c.RateLimitRules[1].Penalty = dur("500ms") }, nil, "rate_limit_rules[1].penalty", "whole seconds"},
		{"unknown fail mode", func(c *Config) { c.RateLimitRules[1].FailMode = "retry" }, nil, "rate_limit_rules[1].fail_mode", "open, closed or local"},
		{"edge.locale with no locales", func(c *Config) {
			c.Global.Locale = Locale{}
			c.ConfigRules[1].Settings.Locale = nil
			c.RateLimitRules[3].Key = []string{"jwt_claim:tenant"}
			c.RequestHeaderRules[1].Ops[1].Value = "x"
		}, nil, "rate_limit_rules[3].expression", "uses edge.locale, but locale is not configured"},
		{"edge.locale value that is never produced", func(c *Config) {
			c.RateLimitRules[3].Expression = mustParse(`edge.locale in {"en" "fr"}`)
		}, nil, "rate_limit_rules[3].expression", `edge.locale is never "fr"`},
		{"edge.locale in a non-canonical form", func(c *Config) {
			c.RateLimitRules[3].Expression = mustParse(`edge.locale eq "zh-hant"`)
		}, nil, "rate_limit_rules[3].expression", `edge.locale is never "zh-hant"`},

		// Header rules.
		{"too many header rules", func(c *Config) {
			for i := range MaxRulesPerPhase {
				c.RequestHeaderRules = append(c.RequestHeaderRules, HeaderRule{ID: fmt.Sprintf("h%d", i), Expression: expr.True(), Ops: []HeaderOp{{Op: "remove", Name: "X-A"}}})
			}
		}, nil, "request_header_rules", "at most 200"},
		{"header rule without ops", func(c *Config) { c.RequestHeaderRules[0].Ops = nil }, nil, "request_header_rules[0].ops", "1 to 100 operations"},
		{"unknown op", func(c *Config) { c.RequestHeaderRules[0].Ops[0].Op = "move" }, nil, "request_header_rules[0].ops[0].op", "must be set, append"},
		{"set the Host header", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Name = "host" }, nil, "request_header_rules[1].ops[0].name", "Host is managed by the edge"},
		{"set an edge header", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Name = "X-Edge-Auth-Sub" }, nil, "request_header_rules[1].ops[0].name", "X-Edge-Auth-Sub is managed by the edge"},
		{"set a CDN source header", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Name = "cloudfront-viewer-country" }, nil, "request_header_rules[1].ops[0].name", "Cloudfront-Viewer-Country is managed by the edge"},
		{"remove the ingress secret", func(c *Config) { c.RequestHeaderRules[1].Ops[2].Name = "X-Origin-Secret" }, nil, "request_header_rules[1].ops[2].name", "is managed by the edge"},
		{"copy from a hop-by-hop header", func(c *Config) { c.RequestHeaderRules[0].Ops[0].From = "Connection" }, nil, "request_header_rules[0].ops[0].from", "Connection is managed by the edge"},
		{"rename to an invalid name", func(c *Config) { c.RequestHeaderRules[1].Ops[3].To = "X New" }, nil, "request_header_rules[1].ops[3].to", `"X New" is not a valid header name; use letters, digits and -, such as x-tenant`},
		{"header value with CRLF", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = "a\r\nX-Admin: 1" }, nil, "request_header_rules[1].ops[0].value", "no control characters"},
		{"header value over 4 KB", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = strings.Repeat("v", MaxHeaderValue+1) }, nil, "request_header_rules[1].ops[0].value", "at most 4096 bytes"},
		{"header value with invalid UTF-8", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = "\xff" }, nil, "request_header_rules[1].ops[0].value", "valid UTF-8"},
		{"header value with an unclosed placeholder", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = "{{client_ip" }, nil, "request_header_rules[1].ops[0].value", `has no closing "}}"`},
		{"unknown header placeholder", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = "{{retry_after}}" }, nil, "request_header_rules[1].ops[0].value", "{{retry_after}}: unknown placeholder"},
		{"header placeholder without a name", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = "{{header}}" }, nil, "request_header_rules[1].ops[0].value", "{{header}}: needs a header name"},
		{"claim placeholder without a name", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = "{{jwt_claim}}" }, nil, "request_header_rules[1].ops[0].value", "{{jwt_claim}}: needs a claim name"},
		{"client_ip placeholder with a name", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = "{{client_ip:v4}}" }, nil, "request_header_rules[1].ops[0].value", "{{client_ip}}: takes no name"},
		{"country placeholder with no country source", func(c *Config) {
			c.RateLimitRules[3] = RateLimitRule{ID: "tenant", Expression: mustParse("ssl"), Algorithm: "fixed_window", Limit: 1, Period: dur("1s"), Key: []string{"ip"}, OnMissingKey: "skip", Action: "log", FailMode: "open"}
		}, &Deployment{ViewerFields: []string{"ssl"}}, "request_header_rules[1].ops[1].value", "{{country}}: country has no trusted source"},
		{"locale placeholder with no locales", func(c *Config) {
			c.Global.Locale = Locale{}
			c.ConfigRules[1].Settings.Locale = nil
			c.RateLimitRules[3].Key = []string{"jwt_claim:tenant"}
			c.RateLimitRules[3].Expression = mustParse("ssl")
		}, nil, "request_header_rules[1].ops[1].value", "{{locale}}: locale is not configured"},
		// Reading a header is checked like writing one: X-Edge-* from clients is
		// forged until the edge replaces it, and source headers carry secrets.
		{"placeholder reading a forgeable edge header", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = "{{header:x-edge-auth-sub}}" }, nil, "request_header_rules[1].ops[0].value", "X-Edge-Auth-Sub is managed by the edge"},
		{"placeholder reading the ingress secret", func(c *Config) { c.RequestHeaderRules[1].Ops[0].Value = "{{header:x-origin-secret}}" }, nil, "request_header_rules[1].ops[0].value", "X-Origin-Secret is managed by the edge"},
		{"rate-limit key on a CDN source header", func(c *Config) { c.RateLimitRules[1].Key = []string{"ip", "header:cloudfront-viewer-country"} }, nil, "rate_limit_rules[1].key[1]", "is managed by the edge"},
		{"expression reading a forgeable edge header", func(c *Config) {
			c.RequestHeaderRules[0].Expression = mustParse(`http.request.headers["x-edge-auth-sub"] eq "admin"`)
		}, nil, "request_header_rules[0].expression", "X-Edge-Auth-Sub is managed by the edge"},
		{"set op with a from field", func(c *Config) { c.RequestHeaderRules[1].Ops[0].From = "X-A" }, nil, "request_header_rules[1].ops[0].from", "doesn't apply to set"},
		{"forward op with a name", func(c *Config) { c.RequestHeaderRules[2].Ops[0].Name = "X-A" }, nil, "request_header_rules[2].ops[0].name", "doesn't apply to forward"},
		{"forward op with no mode", func(c *Config) { c.RequestHeaderRules[2].Ops[0].Mode = "" }, nil, "request_header_rules[2].ops[0].mode", "all, allowlist or denylist"},

		// Bot detection.
		{"block setting that isn't block or log", func(c *Config) { c.ConfigRules[0].Settings.Block = new("deny") }, nil, "config_rules[0].settings.block", "must be block or log"},
		{"count status with a letter inside", func(c *Config) { c.RateLimitRules[1].CountStatuses = []string{"4x4"} }, nil, "rate_limit_rules[1].count_statuses[0]", "must be a status from 100 to 499"},
		{"distinct path with a name", func(c *Config) {
			c.RateLimitRules[1].Algorithm, c.RateLimitRules[1].DistinctOf = "distinct", "path:x"
		}, nil, "rate_limit_rules[1].distinct_of", "path takes no name"},
	}
	runRejects(t, cases)
}

func runRejects(t *testing.T, cases []rejectCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.change(c)
			d := testDeployment
			if tc.dep != nil {
				d = *tc.dep
			}
			out, _, errs := Compile(c, d)
			if out != nil {
				t.Fatal("compiled a config with errors")
			}
			for _, e := range errs {
				if e.Path == tc.path && strings.Contains(e.Msg, tc.msg) {
					return
				}
			}
			t.Fatalf("no error at %q mentioning %q; got %v", tc.path, tc.msg, expr.Issues(errs))
		})
	}
}

// The admin UI asks for a name for exactly the NamedKeyKinds, so each of
// them must need one and every other kind must refuse one.
func TestNamedKeyKindsAgreeWithValidation(t *testing.T) {
	for _, kind := range KeyKinds {
		part := kind
		if !slices.Contains(NamedKeyKinds, kind) {
			part += ":x"
		}
		c := validConfig()
		c.RateLimitRules[1].Key = []string{part}
		_, _, errs := Compile(c, testDeployment)
		if !slices.ContainsFunc(errs, func(e expr.Issue) bool {
			return e.Path == "rate_limit_rules[1].key[0]" && strings.Contains(e.Msg, "name")
		}) {
			t.Errorf("key %q: no error about its name; got %v", part, expr.Issues(errs))
		}
	}
}

func setResponse(c *Config, name string, f func(*Response)) {
	r := c.Global.Responses[name]
	f(&r)
	c.Global.Responses[name] = r
}

func setCORS(c *Config, name string, f func(*CORSPolicy)) {
	p := c.Global.CORSPolicies[name]
	f(&p)
	c.Global.CORSPolicies[name] = p
}
