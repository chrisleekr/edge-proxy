package edge

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

func compiled(t *testing.T, c *snapshot.Config) *snapshot.Compiled {
	t.Helper()
	out, _, errs := snapshot.Compile(c, snapshot.Deployment{ViewerFields: []string{"ip.src.country"}})
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	return out
}

// Config tests run the edge's own checks, config phase and rate-limit
// selection, so an encoded path is judged exactly as live traffic is.
func TestSimulate(t *testing.T) {
	c := testConfig(1)
	c.Auth = snapshot.Auth{Issuers: []snapshot.Issuer{{ID: "corp", Issuer: "https://id/", Audiences: []string{"api"}, JWKSURL: "https://id/jwks", Algorithm: "RS256"}}, DefaultAccepted: []string{"corp"}}
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "au-auth", Expression: mustParse(`ip.src.country eq "AU" and http.request.headers["x-app"] eq "mobile"`), Settings: snapshot.Settings{Auth: &snapshot.AuthSetting{Mode: "required"}, Responses: map[string]string{"unauthorized": "unauthorized"}}},
	)
	rl := func(id, src string) snapshot.RateLimitRule {
		return snapshot.RateLimitRule{ID: id, Expression: mustParse(src), Algorithm: "fixed_window", Limit: 1, Period: dur(time.Second), Key: []string{"ip"}, OnMissingKey: "skip", Action: "block", FailMode: "open"}
	}
	c.RateLimitRules = []snapshot.RateLimitRule{rl("tenant", `http.request.jwt.claims["tenant"] eq "acme"`)}
	for i := range 6 {
		c.RateLimitRules = append(c.RateLimitRules, rl(fmt.Sprintf("admin-%d", i), `starts_with(http.request.uri.path, "/admin/")`))
	}
	// A site-wide rule written as a group wrapping "true" still counts once.
	c.RateLimitRules = append(c.RateLimitRules, snapshot.RateLimitRule{ID: "site", Expression: expr.Node{Combinator: "and", Rules: []expr.Node{expr.True()}}, Algorithm: "fixed_window", Limit: 1, Period: dur(time.Second), Key: []string{"ip"}, OnMissingKey: "skip", Action: "block", FailMode: "open"})
	cc := compiled(t, c)

	got, err := Simulate(cc, SimRequest{Method: "GET", Host: "api.example.com", Target: "/%61dmin/users?x=1", IP: "::ffff:198.51.100.1", Country: "au",
		Headers: map[string][]string{"X-App": {"mobile"}}, JWTClaims: map[string][]string{"tenant": {"acme"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"admin-route", "au-auth"}
	if !reflect.DeepEqual(got.ConfigRules, want) || got.Settings.AuthMode != "required" || !reflect.DeepEqual(got.Settings.Accepted, []string{"corp"}) || got.Settings.UpstreamTimeout != dur(time.Second) {
		t.Fatalf("config phase = %+v", got)
	}
	wantRL := []string{"site", "tenant", "admin-0", "admin-1", "admin-2", "admin-3"}
	if !reflect.DeepEqual(got.RateLimitRules, wantRL) || !got.RateLimitCapped {
		t.Fatalf("rate-limit selection = %v capped %v", got.RateLimitRules, got.RateLimitCapped)
	}
	if got.Settings.Responses["unauthorized"] != "unauthorized" || got.Settings.BodyLimit != 1024 {
		t.Fatalf("settings = %+v", got.Settings)
	}

	plain, err := Simulate(cc, SimRequest{Method: "GET", Host: "api.example.com", Target: "/v1/items", IP: "2001:db8::1"})
	if err != nil || !reflect.DeepEqual(plain.RateLimitRules, []string{"site"}) || plain.ConfigRules != nil || plain.RateLimitCapped {
		t.Fatalf("plain request = %+v %v", plain, err)
	}

	for _, tc := range []struct {
		req  SimRequest
		want string
	}{
		{SimRequest{Method: "GET", Host: "h", Target: "/a%5Cb", IP: "1.2.3.4"}, "path"},
		{SimRequest{Method: "get", Host: "h", Target: "/", IP: "1.2.3.4"}, "method"},
	} {
		if got, err := Simulate(cc, tc.req); err != nil || got.Rejected != tc.want {
			t.Errorf("%+v: %+v %v", tc.req, got, err)
		}
	}
	for _, bad := range []SimRequest{{Method: "GET", Host: "h", Target: "/", IP: "nope"}, {Method: "GET", Host: "h", Target: "/%zz", IP: "1.2.3.4"}} {
		if _, err := Simulate(cc, bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// A config test judges a rule's expiry against the time it runs, as live
// traffic would: an expired rule is not selected, one expiring later is.
func TestSimulateSkipsExpiredRule(t *testing.T) {
	cases := []struct {
		name    string
		expires time.Time
		want    []string
	}{
		{"a rule past its expiry is not selected", time.Now().Add(-time.Minute), []string{"login"}},
		{"a rule expiring later is selected", time.Now().Add(time.Hour), []string{"ap-scraper", "login"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(1)
			c.RateLimitRules = []snapshot.RateLimitRule{
				rlRule("ap-scraper", `http.request.uri.path eq "/login"`, "sliding_window", 10, "ip"),
				rlRule("login", `http.request.uri.path eq "/login"`, "sliding_window", 10, "ip"),
			}
			expireRule(t, c, 0, tc.expires)
			got, err := Simulate(compiled(t, c), SimRequest{Method: "POST", Host: "api.example.com", Target: "/login", IP: "198.51.100.1"})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.RateLimitRules, tc.want) {
				t.Fatalf("rate-limit selection %v, want %v", got.RateLimitRules, tc.want)
			}
		})
	}
}

// The kill switch turns auth off whatever the rules say.
func TestKillSwitchAuth(t *testing.T) {
	c := testConfig(1)
	c.Auth = snapshot.Auth{Issuers: []snapshot.Issuer{{ID: "corp", Issuer: "https://id/", Audiences: []string{"api"}, JWKSURL: "https://id/jwks", Algorithm: "RS256"}}, DefaultAccepted: []string{"corp"}}
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "all-auth", Expression: expr.True(), Settings: snapshot.Settings{Auth: &snapshot.AuthSetting{Mode: "required", Accepted: []string{"corp"}}, CORSPolicy: new(""), Locale: new(false), RateLimitHeaders: new(true)}})
	c.KillSwitch.Auth = true
	got, err := Simulate(compiled(t, c), SimRequest{Method: "GET", Host: "h", Target: "/", IP: "1.2.3.4"})
	if err != nil || got.Settings.AuthMode != "none" || !got.Settings.RateLimitHeaders {
		t.Fatalf("%+v %v", got.Settings, err)
	}
}

// A config test must see what live traffic does after the config phase, not
// a request that skips the edge's own steps.
func TestSimulateFollowsTheLivePipeline(t *testing.T) {
	c := testConfig(1)
	c.Auth = snapshot.Auth{Issuers: []snapshot.Issuer{{ID: "corp", Issuer: "https://id/", Audiences: []string{"api"}, JWKSURL: "https://id/jwks", Algorithm: "RS256"}}, DefaultAccepted: []string{"corp"}}
	c.Global.CORSPolicies = map[string]snapshot.CORSPolicy{"public": {Origins: []string{"*"}}}
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "api-cors", Expression: mustParse(`starts_with(http.request.uri.path, "/api/")`), Settings: snapshot.Settings{CORSPolicy: new("public")}},
		snapshot.ConfigRule{ID: "account-auth", Expression: mustParse(`starts_with(http.request.uri.path, "/account")`), Settings: snapshot.Settings{Auth: &snapshot.AuthSetting{Mode: "required"}}},
	)
	c.RateLimitRules = []snapshot.RateLimitRule{
		{ID: "site", Expression: expr.True(), Algorithm: "fixed_window", Limit: 1, Period: dur(time.Second), Key: []string{"ip"}, OnMissingKey: "skip", Action: "block", FailMode: "open"},
		{ID: "per-key", Expression: mustParse(`starts_with(http.request.uri.path, "/keyed")`), Algorithm: "fixed_window", Limit: 1, Period: dur(time.Second), Key: []string{"ip", "header:x-api-key"}, OnMissingKey: "reject", Action: "block", FailMode: "open"},
	}
	cc, _, errs := snapshot.Compile(c, snapshot.Deployment{ViewerFields: []string{"ip.src.country"}, SourceHeaders: []string{"cdn-country", "true-client-ip"}})
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}

	t.Run("client copies of edge-managed headers never reach the upstream", func(t *testing.T) {
		got, err := Simulate(cc, SimRequest{Method: "GET", Host: "h", Target: "/", IP: "1.2.3.4",
			Headers: map[string][]string{"X-Edge-Auth-Sub": {"admin"}, "Cdn-Country": {"AU"}, "True-Client-Ip": {"10.0.0.1"}, "X-Kept": {"1"}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range []string{"X-Edge-Auth-Sub", "Cdn-Country", "True-Client-Ip"} {
			if v := got.UpstreamHeaders.Get(h); v != "" {
				t.Errorf("%s forwarded as %q", h, v)
			}
		}
		if got.UpstreamHeaders.Get("X-Kept") != "1" {
			t.Errorf("ordinary header dropped: %v", got.UpstreamHeaders)
		}
	})
	t.Run("a preflight under a CORS policy is answered before rate limits", func(t *testing.T) {
		got, err := Simulate(cc, SimRequest{Method: "OPTIONS", Host: "h", Target: "/api/x", IP: "1.2.3.4",
			Headers: map[string][]string{"Origin": {"https://a.example"}, "Access-Control-Request-Method": {"PUT"}}})
		if err != nil || !got.Preflight || got.RateLimitRules != nil || got.UpstreamHeaders != nil || got.Settings.CORSPolicy != "public" {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("required auth without a token is rejected", func(t *testing.T) {
		got, err := Simulate(cc, SimRequest{Method: "GET", Host: "h", Target: "/account", IP: "1.2.3.4"})
		if err != nil || got.Rejected != "auth" || got.RateLimitRules != nil || got.UpstreamHeaders != nil {
			t.Fatalf("%+v %v", got, err)
		}
		got, err = Simulate(cc, SimRequest{Method: "GET", Host: "h", Target: "/account", IP: "1.2.3.4", JWTClaims: map[string][]string{"sub": {"u1"}}})
		if err != nil || got.Rejected != "" || got.UpstreamHeaders == nil {
			t.Fatalf("with claims: %+v %v", got, err)
		}
	})
	t.Run("a missing rate-limit key under reject is never forwarded", func(t *testing.T) {
		got, err := Simulate(cc, SimRequest{Method: "GET", Host: "h", Target: "/keyed", IP: "1.2.3.4"})
		if err != nil || got.Rejected != "rate_limit_key" || got.UpstreamHeaders != nil {
			t.Fatalf("%+v %v", got, err)
		}
	})
}

// A request that fills the cap and is then rejected for a missing key reports
// the cap too, as live traffic counts it.
func TestSimulateCappedThenRejected(t *testing.T) {
	c := testConfig(1)
	for i := range 6 {
		c.RateLimitRules = append(c.RateLimitRules, rlRule(fmt.Sprint("cap-", i), `http.request.uri.path eq "/x"`, "sliding_window", 100, "ip"))
	}
	// A count rule has its own cap, so it is checked after rule cap-5 is skipped.
	tenant := rlRule("tenant", `http.request.uri.path eq "/x"`, "sliding_window", 100, "ip", "header:x-tenant")
	tenant.OnMissingKey = "reject"
	tenant.CountStatuses = []string{"404"}
	c.RateLimitRules = append(c.RateLimitRules, tenant)
	got, err := Simulate(compiled(t, c), SimRequest{Method: "GET", Host: "h", Target: "/x", IP: "1.2.3.4"})
	if err != nil || got.Rejected != "rate_limit_key" || !got.RateLimitCapped || got.UpstreamHeaders != nil {
		t.Fatalf("%+v %v", got, err)
	}
}

// Every name validation accepts must have its own behavior in the edge: a
// name the edge doesn't handle would silently act as another one.
func TestEdgeHandlesEveryValidatedName(t *testing.T) {
	for _, tc := range []struct {
		what      string
		got, want []string
	}{
		{"forward modes", slices.Collect(maps.Keys(forwardModes)), snapshot.ForwardModes},
		{"header ops", slices.Collect(maps.Keys(opKinds)), snapshot.HeaderOps},
	} {
		if got, want := slices.Sorted(slices.Values(tc.got)), slices.Sorted(slices.Values(tc.want)); !slices.Equal(got, want) {
			t.Errorf("%s %v, validation accepts %v", tc.what, got, want)
		}
	}

	t.Run("a request without a token passes or is rejected the same live and in config tests", func(t *testing.T) {
		rejects := map[string]bool{"none": false, "optional": false, "required": true}
		h, idp := newAuthHarness(t)
		for i, mode := range snapshot.AuthModes {
			want, ok := rejects[mode]
			if !ok {
				t.Fatalf("auth mode %s has no expected outcome here", mode)
			}
			c := authConfig(idp)
			c.Version = int64(i + 2)
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "mode", Expression: mustParse(`starts_with(http.request.uri.path, "/mode")`),
				Settings: snapshot.Settings{Auth: &snapshot.AuthSetting{Mode: mode}}})
			h.load(authEnvelope(c))
			resp := h.do("GET", "/mode", nil)
			resp.Body.Close()
			if live := resp.StatusCode == http.StatusUnauthorized; live != want {
				t.Errorf("%s: live status %d", mode, resp.StatusCode)
			}
			got, err := Simulate(compiled(t, c), SimRequest{Method: "GET", Host: "h", Target: "/mode", IP: "1.2.3.4"})
			if sim := got.Rejected == "auth"; err != nil || sim != want {
				t.Errorf("%s: simulated %+v %v", mode, got, err)
			}
		}
	})

	t.Run("every placeholder renders its own value", func(t *testing.T) {
		want := map[string]struct{ arg, value string }{
			"header":     {"x-customer", "acme"},
			"client_ip":  {"", "1.2.3.4"},
			"jwt_claim":  {"sub", "u1"},
			"country":    {"", "AU"},
			"locale":     {"", "en-AU"},
			"request_id": {"", "simulated"},
		}
		c := testConfig(1)
		c.Auth = snapshot.Auth{Issuers: []snapshot.Issuer{{ID: "corp", Issuer: "https://id/", Audiences: []string{"api"}, JWKSURL: "https://id/jwks", Algorithm: "RS256"}}, DefaultAccepted: []string{"corp"}}
		c.Global.Locale = snapshot.Locale{Supported: []string{"en-AU", "en-US"}, Default: "en-US"}
		c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "all", Expression: expr.True(), Settings: snapshot.Settings{Auth: &snapshot.AuthSetting{Mode: "optional"}, Locale: new(true)}})
		rule := snapshot.HeaderRule{ID: "placeholders", Expression: expr.True()}
		for _, name := range snapshot.PlaceholderNames {
			w, ok := want[name]
			if !ok {
				t.Fatalf("placeholder %s has no expected value here", name)
			}
			ph := name
			if w.arg != "" {
				ph += ":" + w.arg
			}
			rule.Ops = append(rule.Ops, snapshot.HeaderOp{Op: "set", Name: "X-P-" + strings.ReplaceAll(name, "_", "-"), Value: "{{" + ph + "}}"})
		}
		c.RequestHeaderRules = []snapshot.HeaderRule{rule}
		got, err := Simulate(compiled(t, c), SimRequest{Method: "GET", Host: "h", Target: "/", IP: "1.2.3.4", Country: "au",
			Headers: map[string][]string{"X-Customer": {"acme"}, "Accept-Language": {"en-AU"}}, JWTClaims: map[string][]string{"sub": {"u1"}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range snapshot.PlaceholderNames {
			if v := got.UpstreamHeaders.Get("X-P-" + strings.ReplaceAll(name, "_", "-")); v != want[name].value {
				t.Errorf("{{%s}} = %q, want %q", name, v, want[name].value)
			}
		}
	})
}

// simRequest builds a SimRequest from JSON naming its fields, so a field
// the struct lacks fails the test instead of being left out.
func simRequest(t *testing.T, js string) SimRequest {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(js))
	dec.DisallowUnknownFields()
	var r SimRequest
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("SimRequest %s: %v", js, err)
	}
	return r
}

// A config test can state the JA4, JA3, HTTP version and verified-crawler
// flag a CDN and admin would give the edge, and rules and signals see them
// exactly as they see live traffic.
func TestSimulateEvaluatesJA4AndHTTPVersion(t *testing.T) {
	c := testConfig(1)
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "old-tls", Expression: mustParse(`starts_with(tls.client.ja4, "t12")`), Settings: snapshot.Settings{CORSPolicy: new("")}},
		snapshot.ConfigRule{ID: "http1", Expression: mustParse(`http.request.version in {"1.0" "1.1"}`), Settings: snapshot.Settings{Locale: new(false)}},
		snapshot.ConfigRule{ID: "known-ja3", Expression: mustParse(`tls.client.ja3 eq "` + chromeJA3 + `"`), Settings: snapshot.Settings{RateLimitHeaders: new(true)}},
		snapshot.ConfigRule{ID: "crawlers", Expression: mustParse(`client.verified_bot`), Settings: snapshot.Settings{BodyLimit: new(int64(2048))}},
		snapshot.ConfigRule{ID: "tls-mismatch", Expression: mustParse(`client.signals eq "browser_tls_mismatch"`), Settings: snapshot.Settings{UpstreamTimeout: new(dur(time.Second))}},
	)
	cc, _, errs := snapshot.Compile(c, snapshot.Deployment{ViewerFields: []string{"http.request.version", "ssl", "tls.client.ja3", "tls.client.ja4"}, VerifiedBots: true})
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	const base = `"Method": "GET", "Host": "api.example.com", "Target": "/", "IP": "198.51.100.7"`
	cases := []struct {
		name, req string
		want      []string
	}{
		{"TLS 1.2 client", `{` + base + `, "SSL": true, "JA4": "t12d1209h1_8daaf6152771_02713d6af862"}`, []string{"old-tls"}},
		{"HTTP/1.1 client", `{` + base + `, "HTTPVersion": "1.1"}`, []string{"http1"}},
		{"known JA3", `{` + base + `, "SSL": true, "JA3": "` + chromeJA3 + `"}`, []string{"known-ja3"}},
		{"fingerprint on a plain request is absent", `{` + base + `, "JA4": "t12d1209h1_8daaf6152771_02713d6af862", "JA3": "` + chromeJA3 + `"}`, nil},
		{"verified crawler", `{` + base + `, "VerifiedBot": true}`, []string{"crawlers"}},
		{"modern client", `{` + base + `, "SSL": true, "JA4": "` + chromeJA4 + `", "HTTPVersion": "2.0"}`, nil},
		{"Chrome on TLS 1.2", `{` + base + `, "SSL": true, "HTTPVersion": "2.0", "JA4": "t12d1516h2_8daaf6152771_02713d6af862",
			"Headers": {"User-Agent": ["` + chromeUA + `"], "Accept-Language": ["en"], "Sec-Fetch-Mode": ["navigate"], "Sec-Ch-Ua": ["` + strings.ReplaceAll(hints("124"), `"`, `\"`) + `"]}}`, []string{"old-tls", "tls-mismatch"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Simulate(cc, simRequest(t, tc.req))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.ConfigRules, tc.want) {
				t.Fatalf("config rules %v, want %v", got.ConfigRules, tc.want)
			}
		})
	}
}

// A config test sees a block rule refuse the request at the config phase,
// and the block setting it resolved.
func TestSimulateBlockRule(t *testing.T) {
	c := testConfig(1)
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent contains "curl"`), Settings: snapshot.Settings{Block: new("block")}},
		snapshot.ConfigRule{ID: "crawlers", Expression: mustParse(`http.user_agent contains "bot"`), Settings: snapshot.Settings{Block: new("log")}},
	)
	cc := compiled(t, c)
	for _, tc := range []struct{ ua, rejected, block string }{
		{"curl/8.5.0", "blocked", "block"},
		{"examplebot/1.0", "", "log"},
	} {
		got, err := Simulate(cc, SimRequest{Method: "GET", Host: "h", Target: "/", IP: "198.51.100.7", Headers: map[string][]string{"User-Agent": {tc.ua}}})
		if err != nil || got.Rejected != tc.rejected || got.Settings.Block != tc.block {
			t.Fatalf("%s: %+v %v", tc.ua, got, err)
		}
	}
}
