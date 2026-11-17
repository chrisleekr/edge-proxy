package edge

import (
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// The signal bits follow expr.Signals, the list validation accepts, so a
// name added there without a bit here fails.
func TestSignalBitsFollowTheValidatedNames(t *testing.T) {
	if len(expr.Signals) != numSignals {
		t.Fatalf("%d signal names, %d bits", len(expr.Signals), numSignals)
	}
	for i, d := range expr.Signals {
		if got := signalLists[1<<i]; !slices.Equal(got, []string{d.Name}) {
			t.Errorf("bit %d lists %v, want %s", i, got, d.Name)
		}
	}
}

var (
	refChrome  = regexp.MustCompile(`Chrome/(\d{1,9})(?:\.(\d{1,9}))?`)
	refFirefox = regexp.MustCompile(`Firefox/(\d{1,9})(?:\.(\d{1,9}))?`)
	refSafari  = regexp.MustCompile(`Version/(\d{1,9})(?:\.(\d{1,9}))?`)
	refIOS     = regexp.MustCompile(`(?:CriOS|FxiOS|EdgiOS)/`)
	refBrand   = regexp.MustCompile(`"(?:Chromium|Google Chrome)";v="(\d{1,9})"`)
)

func refVersion(m []string) version2 {
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return version2{major, minor}
}

// signalsReference classifies with regular expressions and whole strings:
// obviously right, too slow and allocating for the request path.
func signalsReference(ua, acceptLanguage, secFetch, hints, upgrade, connection, wsKey, score, verified, tlsValue string, c *client, floor [4]int) []string {
	// The CDN's verdict and facts apply with or without a User-Agent; the
	// four CDN signals come last in bit order.
	trueVerdict := asciiLower(verified) == "true"
	n, _ := strconv.Atoi(score)
	var cdn []string
	if c.cdn.BotScore && c.cdn.VerifiedBot && regexp.MustCompile(`^\d{1,2}$`).MatchString(score) && n >= 1 && n <= 29 && !trueVerdict {
		cdn = append(cdn, "cdn_likely_automated")
	}
	if ua != "" && c.cdn.VerifiedBot && hasToken(verified, "false") && regexp.MustCompile(`googlebot|bingbot|applebot|duckduckbot|yandexbot|baiduspider`).MatchString(asciiLower(ua[:min(len(ua), uaScan)])) {
		cdn = append(cdn, "crawler_impersonated")
	}
	if c.cdn.Country && c.country == "T1" {
		cdn = append(cdn, "cdn_tor")
	}
	if ua == "" {
		return append([]string{"ua_missing"}, cdn...)
	}
	var out []string
	low := asciiLower(ua[:min(len(ua), uaScan)])
	if slices.ContainsFunc(toolTokens, func(t []byte) bool { return strings.Contains(low, string(t)) }) {
		out = append(out, "ua_tool")
	}
	if strings.Contains(low, "headlesschrome") || strings.Contains(low, "phantomjs") || strings.Contains(low, "lightpanda") {
		out = append(out, "ua_headless")
	}
	kind, v := notBrowser, version2{}
	switch {
	case !strings.Contains(ua, "Mozilla/5.0") || refIOS.MatchString(ua):
	case refChrome.MatchString(ua):
		kind, v = chromium, refVersion(refChrome.FindStringSubmatch(ua))
	case refFirefox.MatchString(ua):
		kind, v = firefox, refVersion(refFirefox.FindStringSubmatch(ua))
	case refSafari.MatchString(ua) && strings.Contains(ua, "Safari/"):
		kind, v = safari, refVersion(refSafari.FindStringSubmatch(ua))
	}
	// browser_outdated is the last signal in bit order, so it is appended last.
	outdated := kind != notBrowser && floor[kind] > 0 && v.major < floor[kind]
	if kind == notBrowser || !v.atLeast(secFetchSince[kind]) {
		if outdated {
			out = append(out, "browser_outdated")
		}
		return append(out, cdn...)
	}
	if acceptLanguage == "" {
		out = append(out, "browser_no_accept_language")
	}
	if secFetch == "" && c.ssl {
		out = append(out, "browser_no_sec_fetch")
	}
	if kind == chromium && c.ssl {
		if hints == "" && v.atLeast(clientHintsSince) {
			out = append(out, "chromium_no_client_hints")
		}
		if m := refBrand.FindStringSubmatch(hints); m != nil {
			if b, _ := strconv.Atoi(m[1]); b != v.major {
				out = append(out, "client_hints_mismatch")
			}
		}
	}
	if kind != chromium && hints != "" {
		out = append(out, "client_hints_mismatch")
	}
	ws := hasToken(connection, "upgrade") && hasToken(upgrade, "websocket") && wsKey != ""
	if c.ssl && (c.version == "1.0" || c.version == "1.1") && !ws {
		out = append(out, "browser_http1")
	}
	if j := c.ja4; j != "" && (j[1:3] != "13" || (!ws && j[8:10] != "h2" && j[8:10] != "h3")) {
		out = append(out, "browser_tls_mismatch")
	}
	if outdated {
		out = append(out, "browser_outdated")
	}
	out = append(out, cdn...)
	if c.cdn.TLS && (!c.hasSSL || c.ssl) && tlsValue != "" && !strings.HasPrefix(tlsValue, "TLSv1.3:") {
		out = append(out, "browser_tls_old")
	}
	return out
}

// hasToken reports whether a comma-separated header value lists token,
// ignoring ASCII case and spaces or tabs around each element.
func hasToken(v, token string) bool {
	return slices.ContainsFunc(strings.Split(v, ","), func(e string) bool { return asciiLower(strings.Trim(e, " \t")) == token })
}

// asciiLower lowercases A to Z only, as HTTP token comparison does.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

func fuzzHeader(ua, acceptLanguage, secFetch, hints, upgrade, connection, wsKey string) http.Header {
	h := http.Header{}
	for k, v := range map[string]string{"User-Agent": ua, "Accept-Language": acceptLanguage, "Sec-Fetch-Mode": secFetch, "Sec-Ch-Ua": hints,
		"Upgrade": upgrade, "Connection": connection, "Sec-Websocket-Key": wsKey} {
		if v != "" {
			h[k] = []string{v}
		}
	}
	return h
}

// The allocation-free classifier agrees with the reference for any headers
// a client sends and any viewer fields a CDN sends.
func FuzzClientSignalsMatchReference(f *testing.F) {
	f.Add(chromeUA, "en", "navigate", hints("124"), "", "", "", true, "2.0", chromeJA4, "", "", "", "", false, false, false, false)
	f.Add(chromeUA, "", "", hints("120"), "", "", "", true, "1.1", "t12d1516h1_8daaf6152771_02713d6af862", "", "", "", "", false, false, false, false)
	f.Add(chromeUA, "en", "websocket", hints("124"), "WebSocket", "", "", true, "1.1", "t13d1516h1_8daaf6152771_02713d6af862", "", "", "", "", false, false, false, false)
	f.Add(chromeUA, "en", "websocket", hints("124"), "websocket", "keep-alive, Upgrade", "dGhlIHNhbXBsZSBub25jZQ==", true, "1.1", "t12d1516h1_8daaf6152771_02713d6af862", "", "", "", "", false, false, false, false)
	f.Add(firefoxUA, "en", "", "", "", "", "", true, "HTTP/2", "", "", "", "", "", false, false, false, false)
	f.Add(firefoxUA, "en", "", "", "", "", "", false, "1.1", "", "", "", "", "", false, false, false, false)
	f.Add("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15", "", "", "", "", "", "", false, "3.0", "", "", "", "", "", false, false, false, false)
	f.Add("Mozilla/5.0 CriOS/124.0 Safari/604.1", "", "", "", "", "", "", true, "", "", "", "", "", "", false, false, false, false)
	f.Add("curl/8.5.0", "", "", "", "", "", "", false, "", "", "", "", "", "", false, false, false, false)
	f.Add(firefoxUA, "en", "navigate", hints("125"), "", "", "", false, "2.0", "", "", "", "", "", false, false, false, false)
	f.Add("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", "en", "navigate", hints("124"), "", "", "", true, "2.0", "", "", "", "", "", false, false, false, false)
	f.Add("Mozilla/5.0 Chrome/60.0 Safari/537.36", "", "", "", "", "", "", true, "2.0", "", "", "", "", "", false, false, false, false)
	f.Add("Lightpanda/1.0", "", "", "", "", "", "", true, "2.0", "", "", "", "", "", false, false, false, false)
	f.Add("Mozilla/5.0 HeadlessChrome/ Chrome/x Chrome/89.1", "", "", `"Chromium";v=""Google Chrome";v="88"`, "h2c", "", "", true, "1.0", "", "", "", "", "", false, false, false, false)
	f.Add("", "en", "cors", "", "", "", "", true, "2.0", chromeJA4, "", "", "", "", false, false, false, false)
	f.Add("Googlebot/2.1", "", "", "", "", "", "", true, "2.0", "", "", "false", "", "", false, true, false, false)
	f.Add("Googlebot/2.1", "", "", "", "", "", "", true, "2.0", "", "", "TRUE", "", "", false, true, false, false)
	f.Add("", "", "", "", "", "", "", true, "2.0", "", "15", "", "", "T1", true, true, false, true)
	f.Add(chromeUA, "en", "navigate", hints("124"), "", "", "", true, "2.0", chromeJA4, "7", "true", "TLSv1.2:ECDHE-RSA-AES128-GCM-SHA256:fullHandshake", "", true, true, true, false)
	f.Fuzz(func(t *testing.T, ua, acceptLanguage, secFetch, hintsValue, upgrade, connection, wsKey string, ssl bool, version, ja4, score, verified, tlsValue, country string, hasScore, hasVerified, hasTLS, hasCountry bool) {
		floor := [4]int{chromium: 130, firefox: 130}
		// ssl is true only with an ssl source. The harness gives one to every
		// deployment listing the TLS header, as the CloudFront preset does.
		c := &client{ssl: ssl, hasSSL: ssl || hasTLS, version: expr.HTTPVersion(version), country: isoCode(country),
			cdn: snapshot.CDNTrust{BotScore: hasScore, VerifiedBot: hasVerified, TLS: hasTLS, Country: hasCountry}}
		if expr.ValidJA4(ja4) {
			c.ja4 = ja4
		}
		h := fuzzHeader(ua, acceptLanguage, secFetch, hintsValue, upgrade, connection, wsKey)
		for k, v := range map[string]string{"Cf-Bot-Score": score, "Cf-Verified-Bot": verified, "Cloudfront-Viewer-Tls": tlsValue} {
			if v != "" {
				h[k] = []string{v}
			}
		}
		got := signalLists[signalsOf(h, c, floor)]
		if want := signalsReference(ua, acceptLanguage, secFetch, hintsValue, upgrade, connection, wsKey, score, verified, tlsValue, c, floor); !slices.Equal(got, want) {
			t.Fatalf("signals %v, reference %v", got, want)
		}
	})
}

// Bot fields run on the request path, so reading them allocates nothing:
// the signals, a fingerprint header, the verified crawler lookup, a count
// rule counting a response and caching its block, and a distinct bit.
func TestBotFieldsAllocateNothing(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts differ under -race")
	}
	id := identityFor(t, map[string]string{"VIEWER_HEADERS": ja4Viewer})
	r := cdnRequest("10.0.0.1:1", "CloudFront-Viewer-Address", "66.249.64.5:1", "CloudFront-Forwarded-Proto", "https",
		"CloudFront-Viewer-Http-Version", "HTTP/2", "CloudFront-Viewer-JA4-Fingerprint", chromeJA4,
		"User-Agent", chromeUA, "Accept-Language", "en", "Sec-Ch-Ua", hints("120"))
	c, err := id.identify(r)
	if err != nil || c.ja4 != chromeJA4 || c.version != "2.0" {
		t.Fatalf("identify = %+v, %v", c, err)
	}
	// With the Cloudflare and CloudFront preset lists, every CDN header the
	// signals read is set, and each signal fires.
	browser := []string{"User-Agent", chromeUA + " Googlebot/2.1", "Accept-Language", "en", "Sec-Ch-Ua", hints("124"), "Sec-Fetch-Mode", "navigate"}
	flareReq := cdnRequest("10.0.0.1:1", append([]string{"CF-Connecting-IP", "66.249.64.5", "X-Forwarded-Proto", "https",
		"CF-IPCountry", "T1", "Cf-Bot-Score", "12", "Cf-Verified-Bot", "false"}, browser...)...)
	flareClient, err := identityFor(t, map[string]string{"CLIENT_IP_SOURCE": "cloudflare"}).identify(flareReq)
	if err != nil {
		t.Fatal(err)
	}
	// What the handler copies from the snapshot that serves the request.
	flareClient.cdn = snapshot.CDNTrust{BotScore: true, VerifiedBot: true, Country: true}
	frontReq := cdnRequest("10.0.0.1:1", append([]string{"CloudFront-Viewer-Address", "66.249.64.5:1", "CloudFront-Forwarded-Proto", "https",
		"CloudFront-Viewer-Http-Version", "HTTP/2", "CloudFront-Viewer-TLS", "TLSv1.2:ECDHE-RSA-AES128-GCM-SHA256:fullHandshake"}, browser...)...)
	frontClient, err := identityFor(t, nil).identify(frontReq)
	if err != nil {
		t.Fatal(err)
	}
	frontClient.cdn = snapshot.CDNTrust{TLS: true}
	bots := expr.NewIPSet([]netip.Prefix{netip.MustParsePrefix("66.249.64.0/27")})
	var set snapshot.StatusSet
	compiled, _, errs := snapshot.Compile(func() *snapshot.Config {
		cfg := testConfig(1)
		cfg.RateLimitRules = []snapshot.RateLimitRule{rlRule("sweep", "true", "sliding_window", 3, "ip")}
		cfg.RateLimitRules[0].CountStatuses = []string{"4xx"}
		return cfg
	}(), testDeployment())
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	set = compiled.Counts[0]
	penalties := ratelimit.NewPenalties(10)
	local := ratelimit.NewLocalStore(10)
	params := ratelimit.Params{Algo: ratelimit.SlidingWindow, Limit: 1, Period: 60_000, Penalty: 60_000}
	// Built once, as the edge builds a rule's key once per request; that
	// allocation is counted by TestRequestAllocations.
	key := compiled.Config.RateLimitRules[0].ID + ":" + c.ip.String()
	local.Take(key, params, 1) // the first 404, within the limit
	cases := []struct {
		name string
		run  func()
	}{
		{"identify with fingerprint headers", func() { _, _ = id.identify(r) }},
		{"websocket handshake Connection header", func() {
			if !hasHeaderToken([]string{"keep-alive", " Keep-Alive, Upgrade\t"}, "upgrade") {
				t.Fatal("upgrade token not found")
			}
		}},
		{"signals", func() {
			if signalsOf(r.Header, &c, [4]int{chromium: 130, firefox: 130}) != sigNoSecFetch|sigHintsMismatch|sigBrowserOutdated {
				t.Fatal("unexpected signals")
			}
		}},
		{"signals from every Cloudflare header", func() {
			const want = sigCDNAutomated | sigCrawlerImpersonated | sigCDNTor
			if got := signalsOf(flareReq.Header, &flareClient, [4]int{}); got != want {
				t.Fatalf("signals %v, want %v", signalLists[got], signalLists[want])
			}
		}},
		{"signals from the CloudFront TLS header", func() {
			if got := signalsOf(frontReq.Header, &frontClient, [4]int{}); got != sigBrowserTLSOld {
				t.Fatalf("signals %v, want %v", signalLists[got], signalLists[sigBrowserTLSOld])
			}
		}},
		{"verified crawler lookup", func() {
			f := newFields(r, &c, "/")
			f.bots = &bots
			if !f.Bool("client.verified_bot") {
				t.Fatal("crawler not verified")
			}
		}},
		{"count rule counts a 404 and caches the block", func() {
			if !set.Has(404) {
				t.Fatal("404 not counted")
			}
			r, _ := local.Take(key, params, 1)
			if r.Allowed || !penalties.Block(key, r.Blocked) || penalties.Until(key, 1) != r.Blocked {
				t.Fatalf("second 404 over a limit of 1: %+v", r)
			}
		}},
		{"distinct bit of the client IP", func() {
			var b [24]byte
			if ratelimit.DistinctBit(ratelimit.AppendIP(b[:0], c.ip)) < 0 {
				t.Fatal("negative bit")
			}
		}},
	}
	for _, tc := range cases {
		if n := testing.AllocsPerRun(100, tc.run); n != 0 {
			t.Errorf("%s: %v allocations", tc.name, n)
		}
	}
}

// Each case is a request a real client or a scraper sends, judged with the
// floor the case sets.
func TestSignalsOfStaleAndRewrittenUserAgents(t *testing.T) {
	const (
		chrome120  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		chrome130  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
		chrome60   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.0.0 Safari/537.36"
		firefox121 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
		safari9    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.8 (KHTML, like Gecko) Version/9.1.3 Safari/601.7.8"
		safari17   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
	)
	both := func(n int) [4]int { return [4]int{chromium: n, firefox: n} }
	cases := []struct {
		name   string
		ua     string
		hints  string
		floor  [4]int
		secure bool
		want   uint16
	}{
		{"chrome 120 under a chromium floor of 130 is outdated", chrome120, hints("120"), both(130), true, sigBrowserOutdated},
		{"chrome at the floor is not outdated", chrome130, hints("130"), both(130), true, 0},
		{"chrome 60 is outdated even before browsers sent Sec-Fetch", chrome60, "", both(130), true, sigBrowserOutdated},
		{"firefox 121 under a firefox floor of 130 is outdated", firefox121, "", both(130), true, sigBrowserOutdated},
		{"firefox floor does not outdate chrome", chrome120, hints("120"), [4]int{firefox: 130}, true, 0},
		{"no floor set, old chrome is not outdated", chrome120, hints("120"), [4]int{}, true, 0},
		{"safari never has a floor", safari9, "", both(999), true, 0},
		{"firefox user agent with sec-ch-ua is a hints mismatch", firefox121, hints("121"), [4]int{}, true, sigHintsMismatch},
		{"firefox user agent with sec-ch-ua over plain http is a hints mismatch", firefox121, hints("121"), [4]int{}, false, sigHintsMismatch},
		{"safari user agent with sec-ch-ua is a hints mismatch", safari17, hints("124"), [4]int{}, true, sigHintsMismatch},
		{"lightpanda user agent is headless", "Lightpanda/1.0", "", both(130), true, sigUAHeadless},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"User-Agent": {tc.ua}, "Accept-Language": {"en"}, "Sec-Fetch-Mode": {"navigate"}}
			if tc.hints != "" {
				h["Sec-Ch-Ua"] = []string{tc.hints}
			}
			if got := signalsOf(h, &client{ssl: tc.secure}, tc.floor); got != tc.want {
				t.Fatalf("signals %v, want %v", signalLists[got], signalLists[tc.want])
			}
		})
	}
}

// The CDN's verdicts and facts become signals only when the policy trusts
// the headers they read, and each judges what it measured, not the client's
// claim alone.
func TestCDNSignals(t *testing.T) {
	const chromeTLS12 = "TLSv1.2:ECDHE-RSA-AES128-GCM-SHA256:fullHandshake"
	const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	cf := snapshot.CDNTrust{BotScore: true, VerifiedBot: true}
	cases := []struct {
		name    string
		ua      string
		headers map[string]string
		country string
		cdn     snapshot.CDNTrust
		want    uint16
		// plain is a request the CDN saw as plain HTTP.
		plain bool
	}{
		{"score 15 not verified is likely automated", chromeUA, map[string]string{"Cf-Bot-Score": "15", "Cf-Verified-Bot": "false"}, "", cf, sigCDNAutomated, false},
		{"score 15 with no User-Agent is still likely automated", "", map[string]string{"Cf-Bot-Score": "15", "Cf-Verified-Bot": "false"}, "", cf, sigCDNAutomated | sigUAMissing, false},
		{"score 1 is automated", chromeUA, map[string]string{"Cf-Bot-Score": "1"}, "", cf, sigCDNAutomated, false},
		{"score 29 is likely automated", chromeUA, map[string]string{"Cf-Bot-Score": "29"}, "", cf, sigCDNAutomated, false},
		{"score 15 on a verified bot is left out", chromeUA, map[string]string{"Cf-Bot-Score": "15", "Cf-Verified-Bot": "true"}, "", cf, 0, false},
		{"score 30 is not automated", chromeUA, map[string]string{"Cf-Bot-Score": "30"}, "", cf, 0, false},
		{"score 0 means no score", chromeUA, map[string]string{"Cf-Bot-Score": "0"}, "", cf, 0, false},
		{"a score that is not a number is ignored", chromeUA, map[string]string{"Cf-Bot-Score": "abc"}, "", cf, 0, false},
		{"a two character score with a letter is ignored", chromeUA, map[string]string{"Cf-Bot-Score": "1x"}, "", cf, 0, false},
		{"a three digit score is ignored", chromeUA, map[string]string{"Cf-Bot-Score": "015"}, "", cf, 0, false},
		{"score 15 with the headers not trusted is ignored", chromeUA, map[string]string{"Cf-Bot-Score": "15"}, "", snapshot.CDNTrust{}, 0, false},
		{"googlebot the CDN did not verify is impersonated", googlebotUA, map[string]string{"Cf-Verified-Bot": "false"}, "", snapshot.CDNTrust{VerifiedBot: true}, sigCrawlerImpersonated, false},
		{"googlebot with no verdict header is not judged", googlebotUA, nil, "", snapshot.CDNTrust{VerifiedBot: true}, 0, false},
		{"googlebot the CDN verified is real", googlebotUA, map[string]string{"Cf-Verified-Bot": "true"}, "", snapshot.CDNTrust{VerifiedBot: true}, 0, false},
		{"googlebot with the verdict header not trusted is ignored", googlebotUA, map[string]string{"Cf-Verified-Bot": "false"}, "", snapshot.CDNTrust{}, 0, false},
		{"a browser User-Agent is not a crawler claim", chromeUA, map[string]string{"Cf-Verified-Bot": "false"}, "", snapshot.CDNTrust{VerifiedBot: true}, 0, false},
		{"Tor exit country", chromeUA, nil, "T1", snapshot.CDNTrust{Country: true}, sigCDNTor, false},
		{"Tor exit country with cf-ipcountry not trusted is not flagged", chromeUA, nil, "T1", snapshot.CDNTrust{}, 0, false},
		{"an ordinary country is not Tor", chromeUA, nil, "AU", snapshot.CDNTrust{Country: true}, 0, false},
		{"modern chrome on TLS 1.2 is an old stack", chromeUA, map[string]string{"Cloudfront-Viewer-Tls": chromeTLS12}, "", snapshot.CDNTrust{TLS: true}, sigBrowserTLSOld, false},
		{"modern chrome on TLS 1.3 is fine", chromeUA, map[string]string{"Cloudfront-Viewer-Tls": "TLSv1.3:TLS_AES_128_GCM_SHA256:fullHandshake"}, "", snapshot.CDNTrust{TLS: true}, 0, false},
		{"modern chrome with no TLS header is fine", chromeUA, nil, "", snapshot.CDNTrust{TLS: true}, 0, false},
		{"old TLS on a plain HTTP request is not flagged", chromeUA, map[string]string{"Cloudfront-Viewer-Tls": chromeTLS12}, "", snapshot.CDNTrust{TLS: true}, 0, true},
		{"curl on TLS 1.2 is not a browser", "curl/8.5.0", map[string]string{"Cloudfront-Viewer-Tls": chromeTLS12}, "", snapshot.CDNTrust{TLS: true}, sigUATool, false},
		{"TLS 1.2 with the header not trusted is ignored", chromeUA, map[string]string{"Cloudfront-Viewer-Tls": chromeTLS12}, "", snapshot.CDNTrust{}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Accept-Language": {"en"}, "Sec-Fetch-Mode": {"navigate"}, "Sec-Ch-Ua": {hints("124")}}
			if tc.ua != "" {
				h["User-Agent"] = []string{tc.ua}
			}
			for k, v := range tc.headers {
				h[k] = []string{v}
			}
			// Browsers speak HTTP/2 only over TLS.
			c := &client{ssl: !tc.plain, hasSSL: true, country: tc.country, cdn: tc.cdn, version: "2.0"}
			if tc.plain {
				c.version = "1.1"
			}
			if got := signalsOf(h, c, [4]int{}); got != tc.want {
				t.Fatalf("signals %v, want %v", signalLists[got], signalLists[tc.want])
			}
		})
	}
}
