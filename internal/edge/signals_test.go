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
func signalsReference(ua, acceptLanguage, secFetch, hints, upgrade, connection, wsKey string, c *client) []string {
	if ua == "" {
		return []string{"ua_missing"}
	}
	var out []string
	low := asciiLower(ua[:min(len(ua), uaScan)])
	if slices.ContainsFunc(toolTokens, func(t []byte) bool { return strings.Contains(low, string(t)) }) {
		out = append(out, "ua_tool")
	}
	if strings.Contains(low, "headlesschrome") || strings.Contains(low, "phantomjs") {
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
	if kind == notBrowser || !v.atLeast(secFetchSince[kind]) {
		return out
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
	ws := hasToken(connection, "upgrade") && hasToken(upgrade, "websocket") && wsKey != ""
	if c.ssl && (c.version == "1.0" || c.version == "1.1") && !ws {
		out = append(out, "browser_http1")
	}
	if j := c.ja4; j != "" && (j[1:3] != "13" || (!ws && j[8:10] != "h2" && j[8:10] != "h3")) {
		out = append(out, "browser_tls_mismatch")
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
	f.Add(chromeUA, "en", "navigate", hints("124"), "", "", "", true, "2.0", chromeJA4)
	f.Add(chromeUA, "", "", hints("120"), "", "", "", true, "1.1", "t12d1516h1_8daaf6152771_02713d6af862")
	f.Add(chromeUA, "en", "websocket", hints("124"), "WebSocket", "", "", true, "1.1", "t13d1516h1_8daaf6152771_02713d6af862")
	f.Add(chromeUA, "en", "websocket", hints("124"), "websocket", "keep-alive, Upgrade", "dGhlIHNhbXBsZSBub25jZQ==", true, "1.1", "t12d1516h1_8daaf6152771_02713d6af862")
	f.Add(firefoxUA, "en", "", "", "", "", "", true, "HTTP/2", "")
	f.Add(firefoxUA, "en", "", "", "", "", "", false, "1.1", "")
	f.Add("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15", "", "", "", "", "", "", false, "3.0", "")
	f.Add("Mozilla/5.0 CriOS/124.0 Safari/604.1", "", "", "", "", "", "", true, "", "")
	f.Add("curl/8.5.0", "", "", "", "", "", "", false, "", "")
	f.Add("Mozilla/5.0 HeadlessChrome/ Chrome/x Chrome/89.1", "", "", `"Chromium";v=""Google Chrome";v="88"`, "h2c", "", "", true, "1.0", "")
	f.Add("", "en", "cors", "", "", "", "", true, "2.0", chromeJA4)
	f.Fuzz(func(t *testing.T, ua, acceptLanguage, secFetch, hintsValue, upgrade, connection, wsKey string, ssl bool, version, ja4 string) {
		c := &client{ssl: ssl, version: httpVersion(version)}
		if expr.ValidJA4(ja4) {
			c.ja4 = ja4
		}
		got := signalLists[signalsOf(fuzzHeader(ua, acceptLanguage, secFetch, hintsValue, upgrade, connection, wsKey), c)]
		if want := signalsReference(ua, acceptLanguage, secFetch, hintsValue, upgrade, connection, wsKey, c); !slices.Equal(got, want) {
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
			if signalsOf(r.Header, &c) != sigNoSecFetch|sigHintsMismatch {
				t.Fatal("unexpected signals")
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
