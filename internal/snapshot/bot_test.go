package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

const (
	chromeJA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	chromeJA3 = "e7d705a3286e19ea42f587b344ee6865"
)

// botDeployment is CloudFront with the opt-in JA4 and JA3 headers mapped,
// validated as an edge validates, with client.verified_bot allowed.
var botDeployment = Deployment{
	ViewerFields:  append([]string{"tls.client.ja4", "tls.client.ja3"}, testDeployment.ViewerFields...),
	SourceHeaders: append([]string{"CloudFront-Viewer-JA4-Fingerprint", "CloudFront-Viewer-JA3-Fingerprint"}, testDeployment.SourceHeaders...),
	VerifiedBots:  true,
}

// olderConfig is validConfig as a version saved under schema, before the
// forbidden response kind existed.
func olderConfig(schema int) *Config {
	c := validConfig()
	c.Schema = schema
	delete(c.Global.Defaults.Responses, "forbidden")
	delete(c.Global.Responses, "forbidden_json")
	return c
}

// compileJSON compiles c after patch edits its JSON form, decoded strictly
// as the edge decodes a snapshot, so a test also checks the JSON shape of
// what it sets.
func compileJSON(t *testing.T, c *Config, d Deployment, patch func(m map[string]any)) (*Compiled, []expr.Issue, []expr.Issue) {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if patch != nil {
		patch(m)
	}
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out Config
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return Compile(&out, d)
}

// ruleJSON returns rule i of a phase in a config's JSON form.
func ruleJSON(m map[string]any, phase string, i int) map[string]any {
	return m[phase].([]any)[i].(map[string]any)
}

// hasIssueAt reports an issue whose path starts with path and whose
// message contains msg.
func hasIssueAt(is []expr.Issue, path, msg string) bool {
	for _, e := range is {
		if strings.HasPrefix(e.Path, path) && strings.Contains(e.Msg, msg) {
			return true
		}
	}
	return false
}

// A bot field is only as good as the deployment's sources. A rule that
// reads one the deployment never sets, or a literal that can't occur, is
// rejected at save, never discovered as a rule that silently never matches.
func TestCompileRejectsBotFieldsThatCanNeverMatch(t *testing.T) {
	noVersion := Deployment{ViewerFields: []string{"ip.src.country", "ip.src.asnum", "ssl", "tls.client.ja4"}, SourceHeaders: botDeployment.SourceHeaders}
	cases := []struct {
		name, src string
		dep       Deployment
		msg       string // "" means it compiles
	}{
		{"every bot field with its sources configured", `client.signals in {"ua_tool" "browser_http1" "browser_tls_mismatch"} and not client.verified_bot and tls.client.ja4 ne "` + chromeJA4 + `" and tls.client.ja3 ne "` + chromeJA3 + `"`, botDeployment, ""},
		{"JA4 in a deployment without its header", `tls.client.ja4 eq "` + chromeJA4 + `"`, testDeployment, "no trusted source configured"},
		{"JA3 in a deployment without its header", `tls.client.ja3 eq "` + chromeJA3 + `"`, testDeployment, "no trusted source configured"},
		{"TLS signal in a deployment without JA4", `client.signals eq "browser_tls_mismatch"`, testDeployment, `"browser_tls_mismatch" can never match`},
		{"HTTP/1 signal in a deployment without the HTTP version", `client.signals eq "browser_http1"`, noVersion, `"browser_http1" can never match`},
		{"misspelled signal", `client.signals in {"ua_tools"}`, botDeployment, `unknown signal "ua_tools"`},
		{"verified crawler flag in admin without VERIFIED_BOT_SOURCES", `not client.verified_bot`, testDeployment, "client.verified_bot needs VERIFIED_BOT_SOURCES"},
		{"JA4 literal of the wrong shape", `tls.client.ja4 eq "t13d1516h2"`, botDeployment, `"t13d1516h2" can never match`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.ConfigRules[0].Expression = mustParse(tc.src)
			out, _, errs := Compile(c, tc.dep)
			if tc.msg == "" {
				if errs != nil {
					t.Fatal(expr.Issues(errs))
				}
				return
			}
			if out != nil || !hasIssueAt(errs, "config_rules[0].expression", tc.msg) {
				t.Fatalf("no error at config_rules[0].expression mentioning %q; got %v", tc.msg, expr.Issues(errs))
			}
		})
	}
}

// Many real users share one browser's JA4, and a client picks its own
// ClientHello, so ja4 is client-controlled like a header: it needs an ip or
// jwt_claim partner or a site-wide ip rule, and a configured source.
func TestJA4KeyNeedsAPartnerAndASource(t *testing.T) {
	cases := []struct {
		name   string
		change func(c *Config)
		dep    Deployment
		path   string
		msg    string // "" means it compiles
	}{
		{"ja4 with an ip partner", func(c *Config) { c.RateLimitRules[1].Key = []string{"ja4", "ip"} }, botDeployment, "", ""},
		{"ja4 and asnum behind a site-wide ip rule", func(c *Config) { c.RateLimitRules[1].Key = []string{"ja4", "asnum"} }, botDeployment, "", ""},
		{"ja4 and asnum with no site-wide ip rule", func(c *Config) {
			c.RateLimitRules[0].Key = []string{"asnum"}
			c.RateLimitRules[1].Key = []string{"ja4", "asnum"}
		}, botDeployment, "rate_limit_rules[1].key", "keys only on client-controlled values"},
		{"ja4 in a deployment without its header", func(c *Config) { c.RateLimitRules[1].Key = []string{"ja4", "ip"} }, testDeployment, "rate_limit_rules[1].key[0]", "ja4 has no trusted source configured"},
		{"ja4 with a name", func(c *Config) { c.RateLimitRules[1].Key = []string{"ja4:x", "ip"} }, botDeployment, "rate_limit_rules[1].key[0]", "ja4 takes no name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.change(c)
			out, _, errs := Compile(c, tc.dep)
			if tc.msg == "" {
				if errs != nil {
					t.Fatal(expr.Issues(errs))
				}
				return
			}
			if out != nil || !hasIssueAt(errs, tc.path, tc.msg) {
				t.Fatalf("no error at %q mentioning %q; got %v", tc.path, tc.msg, expr.Issues(errs))
			}
		})
	}
}

// A version saved before the forbidden kind existed still loads: the
// compiled copy gains an HTML 403 template mapped as the default, the
// stored config is left as it was, and the edges it needs stay the same.
func TestOlderConfigsGetTheHTMLForbiddenTemplate(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		c := olderConfig(schema)
		out, _, errs := Compile(c, testDeployment)
		if errs != nil {
			t.Fatalf("schema %d: %v", schema, expr.Issues(errs))
		}
		name := out.Config.Global.Defaults.Responses["forbidden"]
		r, ok := out.Config.Global.Responses[name]
		if name != "forbidden" || !ok || r.Status != 403 || r.ContentType != "text/html; charset=utf-8" {
			t.Fatalf("schema %d: forbidden maps to %q, template %+v", schema, name, r)
		}
		if _, ok := out.Responses[name]; !ok {
			t.Fatalf("schema %d: forbidden template not compiled", schema)
		}
		if out.NeedsSchema != schema {
			t.Fatalf("schema %d: needs schema %d; the added template must not raise it", schema, out.NeedsSchema)
		}
		if _, ok := c.Global.Defaults.Responses["forbidden"]; ok {
			t.Fatalf("schema %d: Compile changed the stored config", schema)
		}
	}
}

// An older config may already have a template called forbidden. One with
// status 403 is used as it is; any other keeps its name and the added HTML
// template takes the first free name.
func TestForbiddenTemplateNameCollision(t *testing.T) {
	plain := func(status int) Response {
		return Response{Status: status, ContentType: "text/plain; charset=utf-8", Body: "no"}
	}
	cases := []struct {
		name     string
		existing map[string]Response
		want     string
	}{
		{"a 403 template named forbidden is used", map[string]Response{"forbidden": plain(403)}, "forbidden"},
		{"a 400 template named forbidden keeps its name", map[string]Response{"forbidden": plain(400)}, "forbidden_html"},
		{"forbidden_html taken too", map[string]Response{"forbidden": plain(400), "forbidden_html": plain(400)}, "forbidden_html_2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := olderConfig(3)
			maps.Copy(c.Global.Responses, tc.existing)
			out, _, errs := Compile(c, testDeployment)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			got := out.Config.Global.Defaults.Responses["forbidden"]
			if got != tc.want || out.Config.Global.Responses[got].Status != 403 {
				t.Fatalf("forbidden maps to %q (%+v), want %q", got, out.Config.Global.Responses[got], tc.want)
			}
			for n, r := range tc.existing {
				if out.Config.Global.Responses[n] != r {
					t.Fatalf("template %q changed to %+v", n, out.Config.Global.Responses[n])
				}
			}
		})
	}
}

// count_statuses counts upstream responses by status. A 5xx is usually the
// upstream's fault: counting it would lock real users out right after an
// outage, so 5xx codes and the 5xx class are rejected with everything that
// isn't a status at all.
func TestCountStatusesRejects5xxAndNonsense(t *testing.T) {
	cases := []struct {
		name     string
		statuses []any
		path     string
		msg      string // "" with no path means it compiles
	}{
		{"404 and 410", []any{"404", "410"}, "", ""},
		{"failed logins as 401 and 403", []any{"401", "403"}, "", ""},
		{"every client error", []any{"4xx"}, "", ""},
		{"a 5xx code", []any{"404", "503"}, "rate_limit_rules[1].count_statuses", "5xx"},
		{"the 5xx class", []any{"5xx"}, "rate_limit_rules[1].count_statuses", "5xx"},
		{"below 100", []any{"99"}, "rate_limit_rules[1].count_statuses", ""},
		{"above 599", []any{"600"}, "rate_limit_rules[1].count_statuses", ""},
		{"not a status", []any{"not_found"}, "rate_limit_rules[1].count_statuses", ""},
		{"a class that doesn't exist", []any{"6xx"}, "rate_limit_rules[1].count_statuses", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, errs := compileJSON(t, validConfig(), testDeployment, func(m map[string]any) {
				ruleJSON(m, "rate_limit_rules", 1)["count_statuses"] = tc.statuses
			})
			if tc.path == "" {
				if errs != nil {
					t.Fatal(expr.Issues(errs))
				}
				return
			}
			if out != nil || !hasIssueAt(errs, tc.path, tc.msg) {
				t.Fatalf("no error at %q mentioning %q; got %v", tc.path, tc.msg, expr.Issues(errs))
			}
		})
	}
}

// A count rule counts in memory after the response, so Valkey's fail mode
// never applies to it. Setting one is a warning, not an error: the UI's
// default must still save.
func TestCountStatusesWarnsThatFailModeHasNoEffect(t *testing.T) {
	out, warns, errs := compileJSON(t, validConfig(), testDeployment, func(m map[string]any) {
		r := ruleJSON(m, "rate_limit_rules", 1)
		r["count_statuses"] = []any{"404"}
		r["fail_mode"] = "closed"
	})
	if errs != nil || out == nil {
		t.Fatal(expr.Issues(errs))
	}
	if !hasIssueAt(warns, "rate_limit_rules[1].fail_mode", "") {
		t.Fatalf("no warning at rate_limit_rules[1].fail_mode; got %v", expr.Issues(warns))
	}
}

// distinct counts distinct values of one field per subject in a 1024-bit
// bitmap in Valkey. A local fallback would put a bitmap per subject in the
// bounded store, and the estimate drifts past about 1000, so both are
// rejected, as is anything distinct_of can't name.
func TestDistinctRejectsLocalFailModeAndHighLimits(t *testing.T) {
	cases := []struct {
		name string
		edit map[string]any
		dep  Deployment
		path string // "" means it compiles
		msg  string
	}{
		{"distinct paths at the highest limit", map[string]any{"distinct_of": "path", "limit": 1000}, testDeployment, "", ""},
		{"distinct values of one query argument", map[string]any{"distinct_of": "query:id"}, testDeployment, "", ""},
		{"distinct client IPs", map[string]any{"distinct_of": "ip"}, testDeployment, "", ""},
		{"distinct JA4 fingerprints", map[string]any{"distinct_of": "ja4"}, botDeployment, "", ""},
		{"local fail mode", map[string]any{"distinct_of": "path", "fail_mode": "local"}, testDeployment, "rate_limit_rules[1].fail_mode", "local"},
		{"limit over 1000", map[string]any{"distinct_of": "path", "limit": 1001}, testDeployment, "rate_limit_rules[1].limit", ""},
		{"with a burst", map[string]any{"distinct_of": "path", "burst": 10}, testDeployment, "rate_limit_rules[1].burst", ""},
		{"without distinct_of", map[string]any{}, testDeployment, "rate_limit_rules[1].distinct_of", ""},
		{"query without a name", map[string]any{"distinct_of": "query:"}, testDeployment, "rate_limit_rules[1].distinct_of", ""},
		{"unknown field", map[string]any{"distinct_of": "cookie:sid"}, testDeployment, "rate_limit_rules[1].distinct_of", ""},
		{"JA4 in a deployment without its header", map[string]any{"distinct_of": "ja4"}, testDeployment, "rate_limit_rules[1].distinct_of", "no trusted source configured"},
		{"together with count_statuses", map[string]any{"distinct_of": "path", "count_statuses": []any{"404"}}, testDeployment, "rate_limit_rules[1]", "distinct"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, errs := compileJSON(t, validConfig(), tc.dep, func(m map[string]any) {
				r := ruleJSON(m, "rate_limit_rules", 1)
				r["algorithm"] = "distinct"
				maps.Copy(r, tc.edit)
			})
			if tc.path == "" {
				if errs != nil {
					t.Fatal(expr.Issues(errs))
				}
				return
			}
			if out != nil || !hasIssueAt(errs, tc.path, tc.msg) {
				t.Fatalf("no error at %q mentioning %q; got %v", tc.path, tc.msg, expr.Issues(errs))
			}
		})
	}
	// distinct_of means nothing to the other algorithms.
	out, _, errs := compileJSON(t, validConfig(), testDeployment, func(m map[string]any) {
		ruleJSON(m, "rate_limit_rules", 1)["distinct_of"] = "path"
	})
	if out != nil || !hasIssueAt(errs, "rate_limit_rules[1].distinct_of", "") {
		t.Fatalf("distinct_of on sliding_window: %v", expr.Issues(errs))
	}
}

// Every bot feature came with schema 4. A config of any schema may use one,
// and then needs edges that read schema 4, so admin holds the publish until
// every live edge does. Without them a config needs only its own schema.
func TestBotFeaturesNeedSchema4Edges(t *testing.T) {
	expression := func(src string) func(m map[string]any) {
		return func(m map[string]any) {
			b, _ := json.Marshal(mustParse(src))
			var n any
			_ = json.Unmarshal(b, &n)
			ruleJSON(m, "config_rules", 0)["expression"] = n
		}
	}
	cases := []struct {
		name  string
		patch func(m map[string]any)
		want  int
	}{
		{"schema 3 policy without them", nil, 3},
		{"a block rule", func(m map[string]any) { ruleJSON(m, "config_rules", 2)["settings"].(map[string]any)["block"] = "log" }, 4},
		{"the block kill switch", func(m map[string]any) { m["kill_switch"].(map[string]any)["block"] = true }, 4},
		{"client.signals", expression(`client.signals in {"ua_tool"}`), 4},
		{"client.verified_bot", expression(`client.verified_bot`), 4},
		{"tls.client.ja4", expression(`tls.client.ja4 eq "` + chromeJA4 + `"`), 4},
		{"tls.client.ja3", expression(`tls.client.ja3 eq "` + chromeJA3 + `"`), 4},
		{"a ja4 key", func(m map[string]any) { ruleJSON(m, "rate_limit_rules", 1)["key"] = []any{"ja4", "ip"} }, 4},
		{"count_statuses", func(m map[string]any) { ruleJSON(m, "rate_limit_rules", 1)["count_statuses"] = []any{"404"} }, 4},
		{"distinct", func(m map[string]any) {
			r := ruleJSON(m, "rate_limit_rules", 1)
			r["algorithm"], r["distinct_of"] = "distinct", "path"
		}, 4},
		{"a stored forbidden mapping", func(m map[string]any) {
			g := m["global"].(map[string]any)
			g["responses"].(map[string]any)["forbidden_json"] = map[string]any{"status": 403, "content_type": "application/json", "body": `{"error":"forbidden"}`}
			g["defaults"].(map[string]any)["responses"].(map[string]any)["forbidden"] = "forbidden_json"
		}, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, errs := compileJSON(t, olderConfig(3), botDeployment, tc.patch)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got.NeedsSchema != tc.want {
				t.Fatalf("needs schema %d, want %d", got.NeedsSchema, tc.want)
			}
		})
	}
}

// Admin ships crawler ranges to a snapshot only when a rule in any phase
// reads client.verified_bot.
func TestReadsFieldSeesEveryPhase(t *testing.T) {
	cases := []struct {
		name   string
		change func(c *Config)
		want   bool
	}{
		{"no rule reads it", func(*Config) {}, false},
		{"a config rule", func(c *Config) { c.ConfigRules[2].Expression = mustParse(`client.verified_bot`) }, true},
		{"a rate-limit rule", func(c *Config) { c.RateLimitRules[1].Expression = mustParse(`not client.verified_bot`) }, true},
		{"a request header rule", func(c *Config) { c.RequestHeaderRules[0].Expression = mustParse(`client.verified_bot`) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.change(c)
			if got := ReadsField(c, "client.verified_bot"); got != tc.want {
				t.Fatalf("ReadsField = %v, want %v", got, tc.want)
			}
		})
	}
}

// A block rule that a client-set value excludes can be skipped by sending
// that value, as a rate limit can. A block: log rule that a client-set
// value matches can turn an earlier block rule's refusal back into a log,
// because the last matching rule's block setting wins. Matching tools by
// their own User-Agent in a block rule is the point, so it is not warned.
func TestBlockRulesWarnOnClientControlledFields(t *testing.T) {
	cases := []struct {
		name, src, mode string
		blockFirst      bool   // an earlier rule sets block: block
		blockAfter      bool   // a later rule sets block: block
		msg             string // "" means no warning
	}{
		{"block rule skipped by sending a header", `http.user_agent contains "curl" and http.request.headers["x-internal"] ne "1"`, "block", false, false, "client-controlled http.request.headers; clients can set it to skip this rule"},
		{"block rule skipped through a negated group", `not (http.user_agent contains "Mozilla" or ssl)`, "block", false, false, "client-controlled http.user_agent; clients can set it to skip this rule"},
		{"block rule matching tools by User-Agent", `http.user_agent contains "curl"`, "block", false, false, ""},
		{"log rule a header turns on", `http.request.headers["x-debug"] eq "1"`, "log", true, false, "client-controlled http.request.headers; clients can set it to turn an earlier block rule off"},
		{"log rule a User-Agent turns on", `http.user_agent contains "uptime-monitor"`, "log", true, false, "client-controlled http.user_agent"},
		{"log rule by network", `ip.src in {192.0.2.0/24}`, "log", true, false, ""},
		{"log rule with no earlier block rule", `http.request.headers["x-debug"] eq "1"`, "log", false, false, ""},
		{"log rule before a later block rule", `http.request.headers["x-debug"] eq "1"`, "log", false, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			if tc.blockFirst {
				c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "scanners", Expression: mustParse(`http.user_agent contains "sqlmap"`), Settings: Settings{Block: new("block")}})
			}
			c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "tools", Expression: mustParse(tc.src), Settings: Settings{Block: new(tc.mode)}})
			path := fmt.Sprintf("config_rules[%d].expression", len(c.ConfigRules)-1)
			if tc.blockAfter {
				c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "scanners", Expression: mustParse(`http.user_agent contains "sqlmap"`), Settings: Settings{Block: new("block")}})
			}
			out, warns, errs := Compile(c, botDeployment)
			if out == nil {
				t.Fatal(expr.Issues(errs))
			}
			if tc.msg == "" {
				if hasIssueAt(warns, path, "client-controlled") {
					t.Fatalf("unexpected warning: %v", expr.Issues(warns))
				}
				return
			}
			if !hasIssueAt(warns, path, tc.msg) {
				t.Fatalf("no warning at %s mentioning %q; got %v", path, tc.msg, expr.Issues(warns))
			}
		})
	}
}

// Every spelling the edge writes for the HTTP version validates cleanly,
// and so does a prefix match such as every HTTP/1 version.
func TestHTTPVersionsTheEdgeWritesDoNotWarn(t *testing.T) {
	c := validConfig()
	c.ConfigRules[0].Expression = mustParse(`http.request.version in {"1.0" "1.1" "2.0" "3.0"} or starts_with(http.request.version, "1.")`)
	out, warns, errs := Compile(c, testDeployment)
	if out == nil || hasIssueAt(warns, "config_rules[0].expression", "http.request.version") {
		t.Fatalf("errors %v, warnings %v", expr.Issues(errs), expr.Issues(warns))
	}
}

// Admin reads a range list's ipv4Prefix and ipv6Prefix keys, and the edge
// the prefixes admin shipped, through BotPrefix: a range under the wrong
// family's key, an IPv4 range written in IPv6, or one wider than any
// crawler list publishes is refused; a good range comes back masked.
func TestBotPrefixRefusesWrongFamilyAndWideRanges(t *testing.T) {
	cases := []struct {
		name, s string
		want6   bool
		want    string // the masked prefix, or "" when refused
		msg     string
	}{
		{"Googlebot IPv4 range", "66.249.64.0/27", false, "66.249.64.0/27", ""},
		{"Googlebot IPv6 range with host bits", "2001:4860:4801:10::7/64", true, "2001:4860:4801:10::/64", ""},
		{"IPv4 range at /16", "66.249.0.0/16", false, "66.249.0.0/16", ""},
		{"IPv6 range under ipv4Prefix", "2001:4860:4801:10::/64", false, "", "is not an IPv4 range"},
		{"IPv4 range under ipv6Prefix", "66.249.64.0/27", true, "", "is not an IPv6 range"},
		{"IPv4 written in IPv6", "::ffff:66.249.64.0/123", true, "", "is not an IPv6 range"},
		{"IPv4 wider than /16", "66.0.0.0/8", false, "", "wider than /16"},
		{"IPv6 wider than /32", "2001::/16", true, "", "or /32 for IPv6"},
		{"not a range", "66.249.64.0", false, "", "is not a CIDR range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := BotPrefix(tc.s, tc.want6)
			if tc.want != "" {
				if err != nil || p.String() != tc.want {
					t.Fatalf("BotPrefix(%q) = %v, %v; want %s", tc.s, p, err, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("BotPrefix(%q) = %v, %v; want an error mentioning %q", tc.s, p, err, tc.msg)
			}
		})
	}
}
