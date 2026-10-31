package edge

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

const (
	chromeJA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	chromeJA3 = "e7d705a3286e19ea42f587b344ee6865"
	// ja4Viewer maps CloudFront's opt-in fingerprint headers.
	ja4Viewer = "tls.client.ja4=CloudFront-Viewer-JA4-Fingerprint,tls.client.ja3=CloudFront-Viewer-JA3-Fingerprint"

	chromeUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
)

// marker is a header rule that sets name to value when src matches, so a
// test sees what rules see through the request the upstream receives.
func marker(id, src, name, value string) snapshot.HeaderRule {
	return snapshot.HeaderRule{ID: id, Expression: mustParse(src), Ops: []snapshot.HeaderOp{{Op: "set", Name: name, Value: value}}}
}

// versionMarkers set X-Seen-Version to the HTTP version rules see.
func versionMarkers() []snapshot.HeaderRule {
	var out []snapshot.HeaderRule
	for _, v := range []string{"1.0", "1.1", "2.0", "3.0"} {
		out = append(out, marker("version-"+strings.ReplaceAll(v, ".", "-"), `http.request.version eq "`+v+`"`, "X-Seen-Version", v))
	}
	return out
}

// forwarded sends a GET through the edge and returns the headers the
// upstream received.
func (h *harness) forwarded(headers ...string) http.Header {
	h.t.Helper()
	if body := readBody(h.t, h.do("GET", "/", nil, headers...)); body != "upstream ok" {
		h.t.Fatalf("request not forwarded: %s", body)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastApp.Header.Clone()
}

// setBlock sets a config rule's block setting in a config's JSON form.
func setBlock(cfg map[string]any, id, mode string) {
	for _, r := range cfg["config_rules"].([]any) {
		if r := r.(map[string]any); r["id"] == id {
			r["settings"].(map[string]any)["block"] = mode
		}
	}
}

// A JA4 or JA3 fingerprint from the CDN reaches rules, and the JA4 goes to
// the upstream as X-Edge-TLS-JA4 with the CDN's own header stripped. An
// empty or malformed value is missing: it matches nothing and is not sent.
func TestJA4FromATrustedCDNReachesRulesAndUpstream(t *testing.T) {
	h := newHarness(t, map[string]string{"VIEWER_HEADERS": ja4Viewer})
	c := testConfig(1)
	c.RequestHeaderRules = []snapshot.HeaderRule{
		marker("saw-ja4", `tls.client.ja4 eq "`+chromeJA4+`"`, "X-Saw-Ja4", "yes"),
		marker("saw-ja3", `tls.client.ja3 eq "`+chromeJA3+`"`, "X-Saw-Ja3", "yes"),
	}
	h.load(envelope(c))
	cases := []struct {
		name      string
		proto     string
		ja4, ja3  string
		wantJA4   string
		wantMatch string
	}{
		{"fingerprints from the CDN", "https", chromeJA4, chromeJA3, chromeJA4, "yes"},
		{"empty values the CDN sends when it can't tell", "https", "", "", "", ""},
		{"a JA4 of the wrong shape", "https", "t13d1516h2", "e7d705a3", "", ""},
		{"fingerprints on a plain HTTP request came from the client", "http", chromeJA4, chromeJA3, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.forwarded("CloudFront-Forwarded-Proto", tc.proto,
				"CloudFront-Viewer-JA4-Fingerprint", tc.ja4, "CloudFront-Viewer-JA3-Fingerprint", tc.ja3)
			if got.Get("X-Edge-Tls-Ja4") != tc.wantJA4 || got.Get("X-Saw-Ja4") != tc.wantMatch || got.Get("X-Saw-Ja3") != tc.wantMatch {
				t.Fatalf("upstream headers %v", got)
			}
			if _, ok := got["Cloudfront-Viewer-Ja4-Fingerprint"]; ok {
				t.Fatal("CDN source header forwarded")
			}
			if _, ok := got["Cloudfront-Viewer-Ja3-Fingerprint"]; ok {
				t.Fatal("CDN source header forwarded")
			}
		})
	}
}

// A fingerprint header is trusted only from TRUSTED_PROXIES: anyone else
// gets the 400 every untrusted peer gets. A client behind the CDN can't
// forge the forwarded copy either.
func TestJA4HeaderFromAnUntrustedPeerIsNeverForwarded(t *testing.T) {
	untrusted := newHarness(t, map[string]string{"VIEWER_HEADERS": ja4Viewer, "TRUSTED_PROXIES": "10.0.0.0/8"})
	untrusted.load(envelope(testConfig(1)))
	edgeError(t, untrusted.do("GET", "/", nil, "CloudFront-Viewer-JA4-Fingerprint", chromeJA4), 400, "bad_request")
	if untrusted.lastApp != nil {
		t.Fatal("an untrusted peer reached the upstream")
	}

	h := newHarness(t, map[string]string{"VIEWER_HEADERS": ja4Viewer})
	h.load(envelope(testConfig(1)))
	if got := h.forwarded("X-Edge-Tls-Ja4", chromeJA4); got.Get("X-Edge-Tls-Ja4") != "" {
		t.Fatalf("forged X-Edge-TLS-JA4 forwarded: %v", got)
	}
}

// gcpOptIn maps the LB's ASN and fingerprint headers, which the gcp preset
// leaves to VIEWER_HEADERS.
const gcpOptIn = "ip.src.asnum=X-Gclb-Asn,tls.client.ja4=X-Gclb-Ja4,tls.client.ja3=X-Gclb-Ja3"

// gcpRequest is what an external Application Load Balancer adds with the
// custom request headers the gcp preset and gcpOptIn document.
func gcpRequest(asn, region, ja4, ja3 string) []string {
	return []string{"X-Gclb-Client-Ip", "198.51.100.20", "X-Gclb-Asn", asn, "X-Gclb-Region", region,
		"X-Gclb-Ja4", ja4, "X-Gclb-Ja3", ja3, "X-Gclb-Protocol", "HTTP/2", "X-Gclb-Encrypted", "true"}
}

// With CLIENT_IP_SOURCE=gcp the client IP and viewer fields come from the
// load balancer's custom headers. The LB writes an empty string for a value
// it doesn't know, which counts as missing.
func TestGCPPresetReadsLoadBalancerHeaders(t *testing.T) {
	h := newHarness(t, map[string]string{"CLIENT_IP_SOURCE": "gcp", "VIEWER_HEADERS": gcpOptIn})
	c := testConfig(1)
	c.RequestHeaderRules = []snapshot.HeaderRule{marker("saw-ja3", `tls.client.ja3 eq "`+chromeJA3+`"`, "X-Saw-Ja3", "yes")}
	h.load(envelope(c))

	got := h.forwarded(gcpRequest("64500", "AU", chromeJA4, chromeJA3)...)
	if got.Get("X-Edge-Client-Ip") != "198.51.100.20" || got.Get("X-Edge-Geo-Country") != "AU" || got.Get("X-Edge-Geo-Asn") != "64500" ||
		got.Get("X-Edge-Tls-Ja4") != chromeJA4 || got.Get("X-Saw-Ja3") != "yes" {
		t.Fatalf("upstream headers %v", got)
	}
	for name := range got {
		if strings.HasPrefix(name, "X-Gclb-") {
			t.Fatalf("load balancer header %s forwarded", name)
		}
	}

	got = h.forwarded(gcpRequest("", "", "", "")...)
	if got.Get("X-Edge-Client-Ip") != "198.51.100.20" || got.Get("X-Edge-Geo-Country") != "" || got.Get("X-Edge-Geo-Asn") != "" ||
		got.Get("X-Edge-Tls-Ja4") != "" || got.Get("X-Saw-Ja3") != "" {
		t.Fatalf("unknown values were used: %v", got)
	}
}

// Without the opt-in, the gcp preset never reads ASN or fingerprint headers:
// the LB may not add them, and then the client's own value would arrive.
func TestGCPPresetIgnoresASNAndFingerprintsUnlessMapped(t *testing.T) {
	h := newHarness(t, map[string]string{"CLIENT_IP_SOURCE": "gcp"})
	h.load(envelope(testConfig(1)))
	got := h.forwarded(gcpRequest("64500", "AU", chromeJA4, chromeJA3)...)
	if got.Get("X-Edge-Geo-Country") != "AU" || got.Get("X-Edge-Geo-Asn") != "" || got.Get("X-Edge-Tls-Ja4") != "" {
		t.Fatalf("upstream headers %v", got)
	}
}

// The LB writes the protocol as HTTP/1.0, HTTP/1.1, HTTP/2 or HTTP/3, and
// whether the client used TLS as true or false. Rules see the version in
// CloudFront's form and ssl as a bool, as with every other CDN.
func TestGCPPresetNormalisesProtocolAndEncryption(t *testing.T) {
	h := newHarness(t, map[string]string{"CLIENT_IP_SOURCE": "gcp"})
	c := testConfig(1)
	c.RequestHeaderRules = versionMarkers()
	h.load(envelope(c))
	cases := []struct {
		protocol, encrypted string
		version, scheme     string
	}{
		{"HTTP/1.0", "false", "1.0", "http"},
		{"HTTP/1.1", "true", "1.1", "https"},
		{"HTTP/2", "true", "2.0", "https"},
		{"HTTP/3", "true", "3.0", "https"},
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			got := h.forwarded("X-Gclb-Client-Ip", "198.51.100.20", "X-Gclb-Protocol", tc.protocol, "X-Gclb-Encrypted", tc.encrypted)
			if got.Get("X-Seen-Version") != tc.version || got.Get("X-Forwarded-Proto") != tc.scheme {
				t.Fatalf("version %q, scheme %q", got.Get("X-Seen-Version"), got.Get("X-Forwarded-Proto"))
			}
		})
	}
}

// Rules see one spelling of the HTTP version whatever header carries it:
// CloudFront's 2.0 as sent, and a Cloudflare Transform Rule's HTTP/2 as 2.0.
func TestHTTPVersionIsNormalisedForEverySource(t *testing.T) {
	cf := newHarness(t, nil)
	flare := newHarness(t, map[string]string{"CLIENT_IP_SOURCE": "cloudflare", "VIEWER_HEADERS": "http.request.version=X-Http-Version"})
	c := testConfig(1)
	c.RequestHeaderRules = versionMarkers()
	cf.load(envelope(c))
	flare.load(envelope(c))
	cases := []struct {
		name    string
		h       *harness
		headers []string
		want    string
	}{
		{"CloudFront HTTP/2", cf, []string{"CloudFront-Viewer-Http-Version", "2.0"}, "2.0"},
		{"CloudFront HTTP/1.1", cf, []string{"CloudFront-Viewer-Http-Version", "1.1"}, "1.1"},
		{"Cloudflare HTTP/1.0", flare, []string{"CF-Connecting-IP", "198.51.100.7", "X-Http-Version", "HTTP/1.0"}, "1.0"},
		{"Cloudflare HTTP/1.1", flare, []string{"CF-Connecting-IP", "198.51.100.7", "X-Http-Version", "HTTP/1.1"}, "1.1"},
		{"Cloudflare HTTP/2", flare, []string{"CF-Connecting-IP", "198.51.100.7", "X-Http-Version", "HTTP/2"}, "2.0"},
		{"Cloudflare HTTP/3", flare, []string{"CF-Connecting-IP", "198.51.100.7", "X-Http-Version", "HTTP/3"}, "3.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.h.forwarded(tc.headers...).Get("X-Seen-Version"); got != tc.want {
				t.Fatalf("rules saw version %q, want %q", got, tc.want)
			}
		})
	}
}

// client.verified_bot is true only for an address in the crawler ranges
// admin ships in the snapshot. Without ranges it is false, so a rule that
// exempts crawlers exempts no one.
func TestVerifiedBotMatchesOnlyCrawlerAddresses(t *testing.T) {
	h := newHarness(t, nil)
	c := testConfig(1)
	c.RequestHeaderRules = []snapshot.HeaderRule{
		marker("crawler", `client.verified_bot`, "X-Verified-Bot", "yes"),
		marker("not-crawler", `not client.verified_bot`, "X-Verified-Bot", "no"),
	}
	googlebot := map[string]any{
		"source":   "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
		"prefixes": []any{"66.249.64.0/27", "2001:4860:4801:10::/64"},
	}
	h.loadJSON(envelope(c), func(env map[string]any) { env["verified_bots"] = []any{googlebot} })
	cases := []struct{ addr, want string }{
		{"66.249.64.5:40000", "yes"},
		{"[2001:4860:4801:10::7]:443", "yes"},
		{"66.249.64.32:40000", "no"}, // just past the /27
		{"198.51.100.7:40000", "no"},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			if got := h.forwarded("CloudFront-Viewer-Address", tc.addr).Get("X-Verified-Bot"); got != tc.want {
				t.Fatalf("verified bot %q, want %q", got, tc.want)
			}
		})
	}

	c2 := testConfig(2)
	c2.RequestHeaderRules = c.RequestHeaderRules
	h.load(envelope(c2))
	if got := h.forwarded("CloudFront-Viewer-Address", "66.249.64.5:40000").Get("X-Verified-Bot"); got != "no" {
		t.Fatalf("verified bot without ranges: %q", got)
	}
}

// signalRules append each signal a request has to X-Signals.
func signalRules() []snapshot.HeaderRule {
	var out []snapshot.HeaderRule
	for _, s := range []string{"ua_missing", "ua_tool", "ua_headless", "browser_no_accept_language", "browser_no_sec_fetch",
		"chromium_no_client_hints", "client_hints_mismatch", "browser_http1", "browser_tls_mismatch"} {
		out = append(out, snapshot.HeaderRule{ID: "signal-" + s, Expression: mustParse(`client.signals eq "` + s + `"`),
			Ops: []snapshot.HeaderOp{{Op: "append", Name: "X-Signals", Value: s}}})
	}
	return out
}

// hints is a Chromium Sec-CH-UA header for major version v.
func hints(v string) string {
	return `"Chromium";v="` + v + `", "Google Chrome";v="` + v + `", "Not-A.Brand";v="99"`
}

// browser is what a browser sends over HTTPS and HTTP/2 through CloudFront.
// edits are header pairs; an empty value removes the header.
func browser(ua string, edits ...string) []string {
	m := map[string]string{
		"User-Agent": ua, "Accept-Language": "en-AU,en;q=0.9", "Sec-Fetch-Mode": "navigate",
		"CloudFront-Forwarded-Proto": "https", "CloudFront-Viewer-Http-Version": "2.0", "CloudFront-Viewer-JA4-Fingerprint": chromeJA4,
	}
	for i := 0; i+1 < len(edits); i += 2 {
		if edits[i+1] == "" {
			delete(m, edits[i])
		} else {
			m[edits[i]] = edits[i+1]
		}
	}
	var out []string
	for k, v := range m {
		out = append(out, k, v)
	}
	return out
}

// Each signal fires for the clients that really send that shape of request
// and for no real browser. A browser counts only from the version that
// sends the header a signal looks for, and the Sec-Fetch and client hints
// signals only over HTTPS, where browsers send those headers.
func TestClientSignalsClassifyRealUserAgents(t *testing.T) {
	h := newHarness(t, map[string]string{"VIEWER_HEADERS": ja4Viewer})
	c := testConfig(1)
	c.RequestHeaderRules = signalRules()
	h.load(envelope(c))
	const (
		safari17   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
		safari15   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15"
		chrome85   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36"
		headless   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.6367.60 Safari/537.36"
		phantom    = "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1"
		criOS      = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.88 Mobile/15E148 Safari/604.1"
		tls12JA4   = "t12d1516h2_8daaf6152771_02713d6af862"
		h1JA4      = "t13d1516h1_8daaf6152771_02713d6af862"
		tls12h1JA4 = "t12d1516h1_8daaf6152771_02713d6af862"
		wsKey      = "dGhlIHNhbXBsZSBub25jZQ=="
	)
	cases := []struct {
		name    string
		headers []string
		want    []string
	}{
		{"curl", []string{"User-Agent", "curl/8.5.0"}, []string{"ua_tool"}},
		{"python-requests", []string{"User-Agent", "python-requests/2.31.0"}, []string{"ua_tool"}},
		{"Go's HTTP client", []string{"User-Agent", "Go-http-client/1.1"}, []string{"ua_tool"}},
		{"sqlmap", []string{"User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)"}, []string{"ua_tool"}},
		{"no User-Agent", []string{"User-Agent", ""}, []string{"ua_missing"}},
		{"PhantomJS", []string{"User-Agent", phantom}, []string{"ua_headless"}},
		{"headless Chrome with every header", browser(headless, "Sec-CH-UA", `"Chromium";v="124", "HeadlessChrome";v="124", "Not-A.Brand";v="99"`), []string{"ua_headless"}},
		{"Chrome", browser(chromeUA, "Sec-CH-UA", hints("124")), nil},
		{"Chrome without Accept-Language", browser(chromeUA, "Sec-CH-UA", hints("124"), "Accept-Language", ""), []string{"browser_no_accept_language"}},
		{"Chrome without Sec-Fetch-Mode", browser(chromeUA, "Sec-CH-UA", hints("124"), "Sec-Fetch-Mode", ""), []string{"browser_no_sec_fetch"}},
		{"Chrome without client hints", browser(chromeUA), []string{"chromium_no_client_hints"}},
		{"Chrome claiming another version in its client hints", browser(chromeUA, "Sec-CH-UA", hints("120")), []string{"client_hints_mismatch"}},
		{"Chrome over HTTP/1.1", browser(chromeUA, "Sec-CH-UA", hints("124"), "CloudFront-Viewer-Http-Version", "1.1"), []string{"browser_http1"}},
		{"Chrome on TLS 1.2", browser(chromeUA, "Sec-CH-UA", hints("124"), "CloudFront-Viewer-JA4-Fingerprint", tls12JA4), []string{"browser_tls_mismatch"}},
		{"Chrome without h2 in ALPN", browser(chromeUA, "Sec-CH-UA", hints("124"), "CloudFront-Viewer-JA4-Fingerprint", h1JA4), []string{"browser_tls_mismatch"}},
		{"Chrome with no JA4 from the CDN", browser(chromeUA, "Sec-CH-UA", hints("124"), "CloudFront-Viewer-JA4-Fingerprint", ""), nil},
		{"Chrome over plain HTTP", browser(chromeUA, "CloudFront-Forwarded-Proto", "http", "Sec-Fetch-Mode", ""), nil},
		{"Chrome over plain HTTP/1.1", browser(chromeUA, "CloudFront-Forwarded-Proto", "http", "Sec-Fetch-Mode", "", "CloudFront-Viewer-Http-Version", "1.1"), nil},
		{"Chrome opening a WebSocket over HTTP/1.1", browser(chromeUA, "Sec-CH-UA", hints("124"), "Upgrade", "websocket", "Connection", "Upgrade",
			"Sec-WebSocket-Key", wsKey, "Sec-Fetch-Mode", "websocket", "CloudFront-Viewer-Http-Version", "1.1", "CloudFront-Viewer-JA4-Fingerprint", h1JA4), nil},
		{"Chrome opening a WebSocket on TLS 1.2", browser(chromeUA, "Sec-CH-UA", hints("124"), "Upgrade", "websocket", "Connection", "Upgrade",
			"Sec-WebSocket-Key", wsKey, "Sec-Fetch-Mode", "websocket", "CloudFront-Viewer-Http-Version", "1.1", "CloudFront-Viewer-JA4-Fingerprint", tls12h1JA4),
			[]string{"browser_tls_mismatch"}},
		{"WebSocket handshake with an empty key over HTTP/1.1", append(browser(chromeUA, "Sec-CH-UA", hints("124"), "Upgrade", "websocket", "Connection", "Upgrade",
			"Sec-Fetch-Mode", "websocket", "CloudFront-Viewer-Http-Version", "1.1"), "Sec-WebSocket-Key", ""), []string{"browser_http1"}},
		{"Upgrade: websocket without Connection: upgrade over HTTP/1.1", browser(chromeUA, "Sec-CH-UA", hints("124"), "Upgrade", "websocket",
			"Sec-WebSocket-Key", wsKey, "CloudFront-Viewer-Http-Version", "1.1"), []string{"browser_http1"}},
		{"Chrome 85, before client hints", browser(chrome85), nil},
		{"Chrome on iOS", browser(criOS), nil},
		{"Firefox", browser(firefoxUA), nil},
		{"Firefox without Sec-Fetch-Mode", browser(firefoxUA, "Sec-Fetch-Mode", ""), []string{"browser_no_sec_fetch"}},
		{"Safari 17.4", browser(safari17), nil},
		{"Safari 15.6, before Sec-Fetch", browser(safari15, "Sec-Fetch-Mode", ""), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, v := range h.forwarded(tc.headers...).Values("X-Signals") {
				for s := range strings.SplitSeq(v, ",") {
					got = append(got, strings.TrimSpace(s))
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("signals %v, want %v", got, tc.want)
			}
		})
	}
}

// A block rule answers 403 from the forbidden template at the end of the
// config phase: before the backstop, auth and rate limits, so a blocked
// tool spends no token check or quota. The response still carries the
// headers every edge response does, CORS included.
func TestBlockRuleAnswers403BeforeAuthAndRateLimits(t *testing.T) {
	idp := newFakeIdP(t)
	h := newHarness(t, map[string]string{"JWKS_ALLOWED_HOSTS": "127.0.0.1"})
	c := authConfig(idp)
	c.Global.Backstop = snapshot.Backstop{Limit: 1, Period: dur(time.Minute), Burst: 1, MaxEntries: 1000}
	c.Global.CORSPolicies = map[string]snapshot.CORSPolicy{"app": {Origins: []string{"https://app.example.com"}, Methods: []string{"GET"}}}
	r := rlRule("per-ip", "true", "sliding_window", 1, "ip")
	r.FailMode = "local"
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "app-cors", Expression: expr.True(), Settings: snapshot.Settings{CORSPolicy: new("app")}},
		snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent contains "curl"`)},
	)
	hits := 0
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { hits++ }
	h.loadJSON(authEnvelope(c), func(env map[string]any) { setBlock(activeJSON(env), "tools", "block") })

	for range 3 {
		resp := h.do("GET", "/private/orders", nil, "User-Agent", "curl/8.5.0", "Origin", "https://app.example.com")
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
			t.Errorf("Access-Control-Allow-Origin %q", got)
		}
		edgeError(t, resp, 403, "forbidden")
	}
	if hits != 0 || h.ruleStats(0).evaluated.Load() != 0 || h.srv.m.rejected[reasonBackstop].Load() != 0 {
		t.Fatalf("upstream hits %d, rate-limit evaluations %d, backstop rejections %d", hits, h.ruleStats(0).evaluated.Load(), h.srv.m.rejected[reasonBackstop].Load())
	}
	// A browser on the same path meets the token check.
	unauthorized(t, h.do("GET", "/private/orders", nil, "User-Agent", firefoxUA, "CloudFront-Viewer-Address", "198.51.100.8:1"), "Bearer")
	waitFor(t, func() bool {
		n := 0
		for _, l := range h.logs.lines("access") {
			if l["edge.decision"] == "blocked" && l["http.response.status_code"] == 403.0 {
				n++
			}
		}
		return n == 3
	})
}

// block: log forwards the request and logs it as would_block, even with
// allowed requests sampled out, so a new block rule can be watched in shadow
// before it refuses anyone.
func TestLogBlockRuleForwardsAsWouldBlock(t *testing.T) {
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "0"})
	c := testConfig(1)
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent contains "curl"`)})
	h.loadJSON(envelope(c), func(env map[string]any) { setBlock(activeJSON(env), "tools", "log") })
	// The allowed request goes first: lines are written in order, so once
	// curl's line is there, a line for it would be too.
	h.do("GET", "/", nil, "User-Agent", firefoxUA).Body.Close()
	if body := readBody(t, h.do("GET", "/", nil, "User-Agent", "curl/8.5.0")); body != "upstream ok" {
		t.Fatalf("log-only block rule blocked: %s", body)
	}
	waitFor(t, func() bool {
		return slices.ContainsFunc(h.logs.lines("access"), func(l map[string]any) bool { return l["user_agent.original"] == "curl/8.5.0" })
	})
	lines := h.logs.lines("access")
	if len(lines) != 1 || lines[0]["edge.decision"] != "would_block" || lines[0]["http.response.status_code"] != 200.0 {
		t.Fatalf("access lines = %v", lines)
	}
}

// The block kill switch turns every block rule into log at once, without
// editing rules: availability wins while an operator checks a bad rule.
func TestBlockKillSwitchTurnsBlocksIntoLogs(t *testing.T) {
	h := newHarness(t, nil)
	c := testConfig(1)
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent contains "curl"`)})
	h.loadJSON(envelope(c), func(env map[string]any) {
		cfg := activeJSON(env)
		setBlock(cfg, "tools", "block")
		cfg["kill_switch"].(map[string]any)["block"] = true
	})
	if body := readBody(t, h.do("GET", "/", nil, "User-Agent", "curl/8.5.0")); body != "upstream ok" {
		t.Fatalf("blocked under the kill switch: %s", body)
	}
	waitFor(t, func() bool {
		lines := h.logs.lines("access")
		return len(lines) == 1 && lines[0]["edge.decision"] == "would_block"
	})

	c.Version = 2
	h.loadJSON(envelope(c), func(env map[string]any) { setBlock(activeJSON(env), "tools", "block") })
	edgeError(t, h.do("GET", "/", nil, "User-Agent", "curl/8.5.0"), 403, "forbidden")
}
