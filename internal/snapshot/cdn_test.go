package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// cloudflare is a Cloudflare deployment as the edge's preset builds it: the
// client-IP and country headers are source headers, and only the headers it
// adds to every request are trusted by default. validConfig keys on the AS
// number, so VIEWER_HEADERS adds it and the HTTP version from X-Asn and
// X-Http-Version.
func cloudflare() Deployment {
	return Deployment{
		ViewerFields:      []string{"http.request.version", "ip.src.asnum", "ip.src.country", "ssl"},
		SourceHeaders:     []string{"CF-IPCountry", "X-Forwarded-Proto", "X-Asn", "X-Http-Version", "CF-Connecting-IP"},
		CDNHeaders:        []string{"Cf-Ipcountry", "Cf-Ipcity", "Cf-Ray", "Cf-Visitor", "Cf-Bot-Score", "Cf-Verified-Bot"},
		CDNTrustedDefault: []string{"Cf-Ray", "Cf-Visitor"},
	}
}

// cloudfront is a CloudFront deployment as the edge's preset builds it, with
// nothing trusted by default.
func cloudfront() Deployment {
	return Deployment{
		ViewerFields:  []string{"http.request.version", "ip.src.asnum", "ip.src.country", "ssl"},
		SourceHeaders: []string{"CloudFront-Viewer-Country", "CloudFront-Viewer-ASN", "CloudFront-Forwarded-Proto", "CloudFront-Viewer-Http-Version", "CloudFront-Viewer-Address"},
		CDNHeaders:    []string{"Cloudfront-Viewer-Country", "Cloudfront-Viewer-City", "Cloudfront-Viewer-Tls"},
	}
}

// trustedList is never a nil slice: that would marshal as null, which is unset.
func trustedList(hs ...string) *[]string {
	hs = append([]string{}, hs...)
	return &hs
}

// signalRule is a config whose policy trusts trusted and that has a rule
// naming signal.
func signalRule(signal string, trusted *[]string) *Config {
	c := validConfig()
	c.Global.CDNTrustedHeaders = trusted
	c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "sig", Expression: mustParse(`client.signals eq "` + signal + `"`), Settings: Settings{BodyLimit: new(int64(1))}})
	return c
}

// A header the policy trusts is the CDN's value, not the client's, so
// excluding traffic by it is not skippable. A header outside the trusted set
// still warns, whatever its case.
func TestCDNHeaderConditionsAreNotClientControlled(t *testing.T) {
	cases := []struct {
		name, src, mode string
		blockFirst      bool
		warns           bool
	}{
		{"exclusion on a trusted header", `http.user_agent contains "curl" and http.request.headers["cf-ipcity"] ne "Sydney"`, "block", false, false},
		{"exclusion on a trusted header spelled with capitals", `http.user_agent contains "curl" and http.request.headers["CF-IPCity"] ne "Sydney"`, "block", false, false},
		{"exclusion on a header the policy doesn't trust", `http.user_agent contains "curl" and http.request.headers["x-internal"] ne "1"`, "block", false, true},
		{"log rule on a trusted header after a block rule", `http.request.headers["cf-ipcity"] eq "Sydney"`, "log", true, false},
		{"log rule on a header the policy doesn't trust after a block rule", `http.request.headers["x-debug"] eq "1"`, "log", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Global.CDNTrustedHeaders = trustedList("Cf-Ipcity")
			if tc.blockFirst {
				c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "scanners", Expression: mustParse(`http.user_agent contains "sqlmap"`), Settings: Settings{Block: new("block")}})
			}
			c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "tools", Expression: mustParse(tc.src), Settings: Settings{Block: new(tc.mode)}})
			_, warns, errs := Compile(c, cloudflare())
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got := hasIssueAt(warns, fmt.Sprintf("config_rules[%d].expression", len(c.ConfigRules)-1), "client-controlled"); got != tc.warns {
				t.Fatalf("client-controlled warning = %v, want %v: %v", got, tc.warns, expr.Issues(warns))
			}
		})
	}
}

// A CDN signal is refused when the headers it reads are not trusted, since it
// could never fire. cdn_tor reads the country the edge takes from
// ip.src.country's header, so cf-ipcountry counts only as that header, which
// is trusted whenever it is listed.
func TestCDNSignalsNeedTheirHeadersTrusted(t *testing.T) {
	countryElsewhere := cloudflare()
	countryElsewhere.SourceHeaders = []string{"X-Country", "X-Forwarded-Proto", "X-Asn", "X-Http-Version", "CF-Connecting-IP"}
	unlistedCountry := cloudflare()
	unlistedCountry.CDNHeaders = []string{"Cf-Ipcity", "Cf-Ray", "Cf-Visitor", "Cf-Bot-Score", "Cf-Verified-Bot"}
	cases := []struct {
		name, signal string
		d            Deployment
		trusted      *[]string
		msg          string
	}{
		{"bot score with only the score trusted", "cdn_likely_automated", cloudflare(), trustedList("Cf-Bot-Score"), `"cdn_likely_automated" can never match: it needs the cf-verified-bot header listed in CDN_HEADERS and trusted in global.cdn_trusted_headers`},
		{"bot score with only the verdict trusted", "cdn_likely_automated", cloudflare(), trustedList("Cf-Verified-Bot"), `"cdn_likely_automated" can never match: it needs the cf-bot-score header listed in CDN_HEADERS and trusted in global.cdn_trusted_headers`},
		{"bot score with both trusted", "cdn_likely_automated", cloudflare(), trustedList("Cf-Bot-Score", "Cf-Verified-Bot"), ""},
		{"impersonated crawler by default", "crawler_impersonated", cloudflare(), nil, `"crawler_impersonated" can never match: it needs the cf-verified-bot header listed in CDN_HEADERS and trusted in global.cdn_trusted_headers`},
		{"impersonated crawler with the verdict trusted", "crawler_impersonated", cloudflare(), trustedList("Cf-Verified-Bot"), ""},
		{"old TLS on a Cloudflare deployment", "browser_tls_old", cloudflare(), nil, `"browser_tls_old" can never match: it needs the cloudfront-viewer-tls header listed in CDN_HEADERS and trusted in global.cdn_trusted_headers`},
		{"old TLS with the CloudFront header trusted", "browser_tls_old", cloudfront(), trustedList("Cloudfront-Viewer-Tls"), ""},
		{"Tor without a country source", "cdn_tor", Deployment{ViewerFields: []string{"ssl"}}, nil, `"cdn_tor" can never match: it needs ip.src.country, which has no trusted source configured in this deployment`},
		{"Tor on a CloudFront deployment, which never reports T1", "cdn_tor", cloudfront(), nil, `"cdn_tor" can never match: it needs ip.src.country read from the cf-ipcountry header`},
		{"Tor on Cloudflare by default", "cdn_tor", cloudflare(), nil, ""},
		{"Tor on Cloudflare without the country header listed", "cdn_tor", unlistedCountry, nil, `"cdn_tor" can never match: it needs the cf-ipcountry header listed in CDN_HEADERS`},
		{"Tor with the country header trusted but the country read from another header", "cdn_tor", countryElsewhere, trustedList("Cf-Ipcountry"), `"cdn_tor" can never match: it needs ip.src.country read from the cf-ipcountry header`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, errs := Compile(signalRule(tc.signal, tc.trusted), tc.d)
			if tc.msg == "" {
				if out == nil {
					t.Fatal(expr.Issues(errs))
				}
				return
			}
			if out != nil || !slices.ContainsFunc(errs, func(e expr.Issue) bool { return e.Msg == tc.msg }) {
				t.Fatalf("want the error %q, got %v", tc.msg, expr.Issues(errs))
			}
		})
	}
}

// The edge reports cdn_tor only from the country header ip.src.country is
// read from, so trusting cf-ipcountry when the country comes from another
// header sets no flag, and the edge never computes the signal.
func TestCDNTorFlagNeedsTheCountrySource(t *testing.T) {
	countryElsewhere := cloudflare()
	countryElsewhere.SourceHeaders = []string{"X-Country", "X-Forwarded-Proto", "X-Asn", "X-Http-Version", "CF-Connecting-IP"}
	cases := []struct {
		name    string
		d       Deployment
		trusted *[]string
		want    bool
	}{
		{"Cloudflare reads the country from cf-ipcountry", cloudflare(), nil, true},
		{"the country comes from another header", countryElsewhere, trustedList("Cf-Ipcountry"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Global.CDNTrustedHeaders = tc.trusted
			out, _, errs := Compile(c, tc.d)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if out.CDN.Country != tc.want {
				t.Fatalf("country flag %v, want %v", out.CDN.Country, tc.want)
			}
		})
	}
}

// The CDN signals came with schema 8. A config naming cdn_tor, as a literal
// or in a list, needs edges that read it; one naming an older signal does
// not. The other CDN signals need a trust list, which is schema 8 itself.
func TestCDNSignalsNeedSchema8Edges(t *testing.T) {
	cases := []struct {
		name, src string
		d         Deployment
		trusted   *[]string
		want      int
	}{
		{"no signal", `http.host eq "a.example.com"`, cloudflare(), nil, 7},
		{"an older signal", `client.signals eq "ua_tool"`, cloudflare(), nil, 7},
		{"cdn_tor", `client.signals eq "cdn_tor"`, cloudflare(), nil, 8},
		{"cdn_tor in a list", `client.signals in {"ua_tool" "cdn_tor"}`, cloudflare(), nil, 8},
		{"cdn_likely_automated", `client.signals eq "cdn_likely_automated"`, cloudflare(), trustedList("Cf-Bot-Score", "Cf-Verified-Bot"), 8},
		{"crawler_impersonated", `client.signals eq "crawler_impersonated"`, cloudflare(), trustedList("Cf-Verified-Bot"), 8},
		{"browser_tls_old", `client.signals eq "browser_tls_old"`, cloudfront(), trustedList("Cloudfront-Viewer-Tls"), 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Schema = 7
			c.Global.CDNTrustedHeaders = tc.trusted
			c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "sig", Expression: mustParse(tc.src), Settings: Settings{BodyLimit: new(int64(1))}})
			got, _, errs := Compile(c, tc.d)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got.NeedsSchema != tc.want {
				t.Fatalf("needs schema %d, want %d", got.NeedsSchema, tc.want)
			}
		})
	}
}

// Admin refuses to publish while an edge's deployment differs from its own,
// so the CDN list is part of it, in any order or case. A deployment without
// one keeps the fingerprint edges reported before CDN headers existed, so a
// rolling upgrade doesn't hold publishing.
func TestDeploymentFingerprintCDNHeaders(t *testing.T) {
	// c628717b8f8cd3d5 is what edges before CDN headers report for this deployment.
	noCDN := Deployment{ViewerFields: []string{"ip.src.country"}, SourceHeaders: []string{"CloudFront-Viewer-Country", "CloudFront-Viewer-Address"}}
	if got := noCDN.Fingerprint(); got != "c628717b8f8cd3d5" {
		t.Fatalf("deployment without CDN headers: fingerprint %s, want the older edges' c628717b8f8cd3d5", got)
	}
	withList := noCDN
	withList.CDNHeaders = []string{"CF-Ray", "CF-IPCity"}
	if withList.Fingerprint() == noCDN.Fingerprint() {
		t.Error("adding CDN headers kept the fingerprint")
	}
	same := noCDN
	same.CDNHeaders = []string{"cf-ipcity", "cf-ray"}
	if same.Fingerprint() != withList.Fingerprint() {
		t.Error("CDN header order or case changed the fingerprint")
	}
	fewer := noCDN
	fewer.CDNHeaders = []string{"CF-Ray"}
	if fewer.Fingerprint() == withList.Fingerprint() {
		t.Error("one CDN header fewer kept the fingerprint")
	}
}

// ruleOn is a config with a block rule that excludes by header h, which warns
// when h is client-controlled.
func ruleOn(h string) *Config {
	c := validConfig()
	c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent contains "curl" and http.request.headers["` + h + `"] ne "1"`), Settings: Settings{Block: new("block")}})
	return c
}

// The policy decides which listed headers are the CDN's. Unset uses the
// deployment's default, a list replaces it and an empty list trusts none.
func TestCDNTrustedHeadersPolicy(t *testing.T) {
	cases := []struct {
		name    string
		trusted *[]string
		header  string
		warns   bool
	}{
		{"default trusts a header the CDN adds to every request", nil, "cf-ray", false},
		{"default doesn't trust a header that needs a feature", nil, "cf-bot-score", true},
		{"a list replaces the default", trustedList("Cf-Bot-Score"), "cf-ray", true},
		{"a listed header is trusted in any case", trustedList("Cf-Bot-Score"), "CF-BOT-SCORE", false},
		{"an empty list trusts none", trustedList(), "cf-ray", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ruleOn(tc.header)
			c.Global.CDNTrustedHeaders = tc.trusted
			_, warns, errs := Compile(c, cloudflare())
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got := hasIssueAt(warns, "config_rules[", "client-controlled"); got != tc.warns {
				t.Fatalf("client-controlled warning = %v, want %v: %v", got, tc.warns, expr.Issues(warns))
			}
		})
	}
}

func TestCDNTrustedHeadersRefused(t *testing.T) {
	many := make([]string, MaxCDNHeaders+1)
	d := cloudflare()
	for i := range many {
		many[i] = fmt.Sprintf("X-H%d", i)
		d.CDNHeaders = append(d.CDNHeaders, many[i])
	}
	d.CDNHeaders = append(d.CDNHeaders, "X-Edge-Foo")
	cases := []struct {
		name    string
		trusted *[]string
		msg     string
	}{
		{"an edge-managed name", trustedList("x-edge-foo"), "x-edge-foo is managed by the edge and can't be trusted by policy"},
		{"an edge-managed name outside CDN_HEADERS", trustedList("X-Edge-Bar"), "X-Edge-Bar is managed by the edge and can't be trusted by policy"},
		{"a repeat in another case", trustedList("Cf-Ray", "cf-ray"), `duplicate "cf-ray"`},
		{"a name that isn't a header", trustedList("Cf Ray"), `"Cf Ray" is not a header name`},
		{"more than a record holds", &many, "has 49 headers; at most 48 are allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Global.CDNTrustedHeaders = tc.trusted
			out, _, errs := Compile(c, d)
			if out != nil || !slices.ContainsFunc(errs, func(e expr.Issue) bool {
				return strings.HasPrefix(e.Path, "global.cdn_trusted_headers") && e.Msg == tc.msg
			}) {
				t.Fatalf("want the error %q, got %v", tc.msg, expr.Issues(errs))
			}
		})
	}
}

// An operator maps tls.client.ja4 to Cf-Ja4 after the policy trusted it. New
// edges must still load the live policy, and the header stays trusted as a
// listed source header.
func TestCDNTrustedHeaderThatBecameASourceHeaderWarns(t *testing.T) {
	d := cloudflare()
	d.ViewerFields = append(d.ViewerFields, "tls.client.ja4")
	d.SourceHeaders = append(d.SourceHeaders, "Cf-Ja4")
	d.CDNHeaders = append(d.CDNHeaders, "Cf-Ja4")
	c := validConfig()
	c.Global.CDNTrustedHeaders = trustedList("Cf-Ja4", "Cf-Verified-Bot")
	_, warns, errs := Compile(c, d)
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	if !slices.ContainsFunc(warns, func(e expr.Issue) bool {
		return e.Path == "global.cdn_trusted_headers" && e.Msg == "Cf-Ja4 is a source header, always trusted when listed in CDN_HEADERS, so the entry does nothing"
	}) {
		t.Fatalf("warnings %v", expr.Issues(warns))
	}
	if got := CDNTrusted(c, d); !slices.Equal(got, []string{"cf-ipcountry", "cf-ja4", "cf-verified-bot"}) {
		t.Fatalf("trusted %v", got)
	}
}

// Removing a header from CDN_HEADERS must not stop edges loading the live
// policy that trusts it: the entry warns and is no longer trusted.
func TestCDNTrustedHeaderDroppedFromCDNHeadersWarns(t *testing.T) {
	d := cloudflare()
	d.CDNHeaders = []string{"Cf-Ipcountry", "Cf-Ipcity", "Cf-Ray", "Cf-Visitor", "Cf-Verified-Bot"}
	c := ruleOn("cf-bot-score")
	c.Global.CDNTrustedHeaders = trustedList("Cf-Bot-Score", "Cf-Verified-Bot")
	out, warns, errs := Compile(c, d)
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	if !slices.ContainsFunc(warns, func(e expr.Issue) bool {
		return e.Path == "global.cdn_trusted_headers" && e.Msg == "Cf-Bot-Score is not in CDN_HEADERS, so the edge doesn't log, offer or trust it"
	}) {
		t.Fatalf("warnings %v", expr.Issues(warns))
	}
	if !hasIssueAt(warns, "config_rules[", "client-controlled") {
		t.Fatalf("a rule on the dropped header is not client-controlled: %v", expr.Issues(warns))
	}
	if out.CDN.BotScore || !out.CDN.VerifiedBot {
		t.Fatalf("flags %+v", out.CDN)
	}
	if got := CDNTrusted(c, d); !slices.Equal(got, []string{"cf-ipcountry", "cf-verified-bot"}) {
		t.Fatalf("trusted %v", got)
	}
}

// CDNTrusted is the effective set admin shows: lower case, sorted, with the
// listed source headers, and [] rather than null when nothing is trusted.
func TestCDNTrustedList(t *testing.T) {
	if got := CDNTrusted(validConfig(), cloudflare()); !slices.Equal(got, []string{"cf-ipcountry", "cf-ray", "cf-visitor"}) {
		t.Fatalf("Cloudflare default %v", got)
	}
	if got := CDNTrusted(validConfig(), cloudfront()); !slices.Equal(got, []string{"cloudfront-viewer-country"}) {
		t.Fatalf("CloudFront default %v", got)
	}
	none := cloudfront()
	none.CDNHeaders = nil
	b, err := json.Marshal(CDNTrusted(validConfig(), none))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[]" {
		t.Fatalf("CDN_HEADERS none: %s, want []", b)
	}
}

// Setting the list, even to nothing, is a field older edges reject.
func TestCDNTrustedHeadersNeedSchema8Edges(t *testing.T) {
	for name, trusted := range map[string]*[]string{"unset": nil, "a list": trustedList("Cf-Ray"), "an empty list": trustedList()} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			c.Schema = 7
			c.Global.CDNTrustedHeaders = trusted
			out, _, errs := Compile(c, cloudflare())
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if want := map[bool]int{false: 7, true: 8}[trusted != nil]; out.NeedsSchema != want {
				t.Fatalf("needs schema %d, want %d", out.NeedsSchema, want)
			}
		})
	}
}

// Unset and empty differ, and both survive the strict decoder and a marshal.
func TestCDNTrustedHeadersRoundTrip(t *testing.T) {
	for name, trusted := range map[string]*[]string{"unset": nil, "empty": trustedList(), "a list": trustedList("Cf-Ray")} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			c.Global.CDNTrustedHeaders = trusted
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			var got Config
			if err := dec.Decode(&got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Global.CDNTrustedHeaders, trusted) {
				t.Fatalf("got %v, want %v", got.Global.CDNTrustedHeaders, trusted)
			}
		})
	}
}

// The signals are refused until the policy trusts the headers they read, and
// cdn_tor needs only the country header, which a Cloudflare deployment maps.
func TestCDNSignalsNeedTrust(t *testing.T) {
	d := cloudflare()
	if out, _, errs := Compile(signalRule("cdn_likely_automated", nil), d); out != nil || !hasIssueAt(errs, "", "trusted in global.cdn_trusted_headers") {
		t.Fatalf("by default: %v", expr.Issues(errs))
	}
	if out, _, errs := Compile(signalRule("cdn_likely_automated", trustedList("Cf-Bot-Score")), d); out != nil || !hasIssueAt(errs, "", "needs the cf-verified-bot header") {
		t.Fatalf("with the score only: %v", expr.Issues(errs))
	}
	out, _, errs := Compile(signalRule("cdn_likely_automated", trustedList("Cf-Bot-Score", "Cf-Verified-Bot")), d)
	if out == nil || !out.CDN.BotScore || !out.CDN.VerifiedBot || out.CDN.TLS {
		t.Fatalf("with both: %v", expr.Issues(errs))
	}
	out, _, errs = Compile(signalRule("cdn_tor", trustedList()), d)
	if out == nil || !out.CDN.Country {
		t.Fatalf("cdn_tor with an empty list: %v", expr.Issues(errs))
	}
}

// The default is part of the fingerprint only when it has entries, so a
// deployment without one keeps what older edges report.
func TestDeploymentFingerprintCDNTrustedDefault(t *testing.T) {
	a := Deployment{CDNHeaders: []string{"Cf-Ray"}}
	b := a
	b.CDNTrustedDefault = []string{"Cf-Ray"}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("a trusted default kept the fingerprint")
	}
}
