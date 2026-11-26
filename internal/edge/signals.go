package edge

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// Signal bits, in expr.Signals order.
const (
	sigUAMissing uint16 = 1 << iota
	sigUATool
	sigUAHeadless
	sigNoAcceptLanguage
	sigNoSecFetch
	sigNoClientHints
	sigHintsMismatch
	sigHTTP1
	sigTLSMismatch
	sigBrowserOutdated
	sigCDNAutomated
	sigCrawlerImpersonated
	sigCDNTor
	sigBrowserTLSOld
	// The bits are uint16, which leaves room for 16 signals. Past that, and
	// 1<<numSignals entries in signalLists, it needs a different structure.
	numSignals = iota
)

// signalLists holds the names for every bit set, built once, so List
// returns a shared slice and a request allocates nothing for its signals.
var signalLists = func() (t [1 << numSignals][]string) {
	for m := range t {
		for i, d := range expr.Signals {
			if m&(1<<i) != 0 {
				t[m] = append(t[m], d.Name)
			}
		}
	}
	return t
}()

// crawlerTokens are lowercase User-Agent names of search crawlers the CDN
// verifies by address.
var crawlerTokens = [][]byte{[]byte("googlebot"), []byte("bingbot"), []byte("applebot"), []byte("duckduckbot"), []byte("yandexbot"), []byte("baiduspider")}

// toolTokens are lowercase User-Agent substrings of HTTP libraries, CLI
// tools and scanners. The scanners come from the OWASP Core Rule Set's
// rules/scanners-user-agents.data
// (https://github.com/coreruleset/coreruleset/blob/main/rules/scanners-user-agents.data).
var toolTokens = func() [][]byte {
	var out [][]byte
	for _, s := range []string{
		// HTTP libraries and CLI tools.
		"curl/", "wget/", "python-requests/", "python-urllib/", "aiohttp/", "httpx/", "go-http-client/",
		"okhttp/", "apache-httpclient/", "libwww-perl/", "lwp::simple", "scrapy/", "java/", "node-fetch/", "axios/",
		"undici", "httpie/", "guzzlehttp/", "postmanruntime/", "powershell/", "winhttp", "ruby",
		// Scanners from the Core Rule Set.
		"arachni", "betabot", "bewica-security-scan", "bfac", "commix", "detectify", "dirbuster", "fimap", "fuzz faster",
		"whatwaf", "gobuster", "havij", "hexometer", "jbrofuzz", "jorgee", "libwhisker", "masscan", "morfeus", "mozlila", "mozilla/6.0",
		"mozilla/5.g", "nessus", "netlab360", "netsparker", "nettacker", "nikto", "nmap", "nuclei", "openvas", "php2shell",
		"securityagent", "sitelockspider", "sqlmap", "sysscan", "tsunamisecurityscanner", "w3af.org", "webbandit", "webshag",
		"wfuzz", "whatweb", "wprecon", "wpscan", "feroxbuster", "l9explore", "l9tcpid", "wapiti", "vega/", "appspider",
		"ironwasp", "skipfish", "qualysguard", "n-stalker", "acunetix", "cmsmap", "sqlninja", "xsstrike", "xsser", "joomscan",
		"droopescan", "zgrab", "ghauri", "zmeu", "wpprobe", "sstimap", "(hydra)", "tplmap", "dotdotpwn", "shortscan",
		"kadimus", "lfisuite", "panoptic", "lfimap", "graphw00f", "graphql-cop", "jsql", "noseyparker", "trufflehog",
		"yeswehack-hunter", "tinja", "appscan",
	} {
		out = append(out, []byte(s))
	}
	return out
}()

// A browser User-Agent matches no tool token, so a check per token costs
// every browser request about a hundred scans. toolPairs marks each token's
// first two bytes and toolByFirst groups the tokens by first byte, so one
// pass over the User-Agent compares in full only where a token could start.
var toolPairs, toolByFirst = func() (pairs [1 << 16 / 64]uint64, by [256][][]byte) {
	for _, t := range toolTokens {
		k := uint16(t[0])<<8 | uint16(t[1])
		pairs[k/64] |= 1 << (k % 64)
		by[t[0]] = append(by[t[0]], t)
	}
	return pairs, by
}()

// hasToolToken reports whether s contains any of toolTokens.
func hasToolToken(s []byte) bool {
	for i := 0; i+1 < len(s); i++ {
		k := uint16(s[i])<<8 | uint16(s[i+1])
		if toolPairs[k/64]&(1<<(k%64)) == 0 {
			continue
		}
		for _, t := range toolByFirst[s[i]] {
			if bytes.HasPrefix(s[i:], t) {
				return true
			}
		}
	}
	return false
}

// headlessTokens name automation browsers that say so in their User-Agent.
// Lightpanda's default is "Lightpanda/1.0" and it refuses any User-Agent
// containing "Mozilla" (src/Config.zig in
// https://github.com/lightpanda-io/browser).
var headlessTokens = [][]byte{[]byte("headlesschrome"), []byte("phantomjs"), []byte("lightpanda")}

// uaScan bounds how much of a User-Agent the tool and headless checks read.
// A tool that pads its User-Agent past it could as well send another one.
const uaScan = 512

// Browser kinds a User-Agent claims.
const (
	notBrowser = iota
	chromium
	firefox
	safari
)

// secFetchSince is the first version of each browser that sends
// Sec-Fetch-Mode, from MDN browser-compat-data http/headers/Sec-Fetch-Mode
// (https://github.com/mdn/browser-compat-data/blob/main/http/headers/Sec-Fetch-Mode.json):
// Chrome 76 (Edge, Opera and Samsung Internet mirror it), Firefox 90,
// Safari 16.4. A browser from then on counts as modern.
var secFetchSince = [...]version2{chromium: {76, 0}, firefox: {90, 0}, safari: {16, 4}}

// clientHintsSince is the first Chrome that sends Sec-CH-UA, from
// http/headers/Sec-CH-UA in the same data. Firefox and Safari never do.
var clientHintsSince = version2{89, 0}

// version2 is a major and minor version.
type version2 struct{ major, minor int }

func (v version2) atLeast(w version2) bool {
	return v.major > w.major || v.major == w.major && v.minor >= w.minor
}

// signalsOf computes a request's client signals. It reads only headers and
// the trusted viewer fields, and allocates nothing. floor is the lowest
// major version per browser kind a User-Agent may claim; 0 is off.
func signalsOf(h http.Header, c *client, floor [4]int) uint16 {
	// The CDN's facts hold whatever the User-Agent says, so they come first.
	m := cdnSignals(h, c)
	ua, _ := first(h["User-Agent"])
	if ua == "" {
		return m | sigUAMissing
	}
	var lower [uaScan]byte
	n := copy(lower[:], ua)
	for i, b := range lower[:n] {
		if 'A' <= b && b <= 'Z' {
			lower[i] = b + 'a' - 'A'
		}
	}
	if hasToolToken(lower[:n]) {
		m |= sigUATool
	}
	for _, t := range headlessTokens {
		if bytes.Contains(lower[:n], t) {
			m |= sigUAHeadless
			break
		}
	}
	// A crawler claim the CDN refused to verify is a forged User-Agent.
	// Cloudflare sends cf-verified-bot only with Bot Management; a missing
	// header is no verdict.
	if c.cdn.VerifiedBot && hasHeaderToken(h["Cf-Verified-Bot"], "false") {
		for _, t := range crawlerTokens {
			if bytes.Contains(lower[:n], t) {
				m |= sigCrawlerImpersonated
				break
			}
		}
	}
	kind, v := browserOf(ua)
	if kind == notBrowser {
		return m
	}
	// Before the modern gate: a claim older than Sec-Fetch is the stalest.
	if f := floor[kind]; f > 0 && v.major < f {
		m |= sigBrowserOutdated
	}
	if !v.atLeast(secFetchSince[kind]) {
		return m
	}
	if s, _ := first(h["Accept-Language"]); s == "" {
		m |= sigNoAcceptLanguage
	}
	// Browsers send Sec-Fetch-* and client hints only in secure contexts.
	if s, _ := first(h["Sec-Fetch-Mode"]); s == "" && c.ssl {
		m |= sigNoSecFetch
	}
	if kind == chromium && c.ssl {
		hints, _ := first(h["Sec-Ch-Ua"])
		switch b, ok := brandVersion(hints); {
		case hints == "" && v.atLeast(clientHintsSince):
			m |= sigNoClientHints
		case ok && b != v.major:
			m |= sigHintsMismatch
		}
	} else if kind != chromium {
		// Only Chromium sends Sec-CH-UA, so a Firefox or Safari User-Agent
		// with it was rewritten.
		if hints, _ := first(h["Sec-Ch-Ua"]); hints != "" {
			m |= sigHintsMismatch
		}
	}
	// Browsers open WebSockets over HTTP/1.1 with only http/1.1 in ALPN, so
	// a real handshake skips the protocol checks. It is the test ReverseProxy
	// applies before forwarding an upgrade, plus the non-empty key RFC 6455 requires, so
	// a bare Upgrade header does not exempt a request. TLS 1.3 still applies.
	key, _ := first(h["Sec-Websocket-Key"])
	ws := hasHeaderToken(h["Connection"], "upgrade") &&
		hasHeaderToken(h["Upgrade"], "websocket") && key != ""
	// Browsers negotiate HTTP/2 only over TLS.
	if c.ssl && (c.version == "1.0" || c.version == "1.1") && !ws {
		m |= sigHTTP1
	}
	// JA4 characters 2 and 3 are the TLS version and 9 and 10 the ALPN.
	if j := c.ja4; j != "" && (j[1:3] != "13" || !ws && j[8:10] != "h2" && j[8:10] != "h3") {
		m |= sigTLSMismatch
	}
	// Every modern browser negotiates TLS 1.3, and the CDN offers it. On a
	// request the CDN saw as plain HTTP, any TLS value came from the client.
	if c.cdn.TLS && (!c.hasSSL || c.ssl) {
		if t, _ := first(h["Cloudfront-Viewer-Tls"]); t != "" && !strings.HasPrefix(t, "TLSv1.3:") {
			m |= sigBrowserTLSOld
		}
	}
	return m
}

// cdnSignals are the signals from the CDN's own verdicts and facts.
func cdnSignals(h http.Header, c *client) uint16 {
	var m uint16
	// Cloudflare's scale: 1 is automated and 2 to 29 likely automated.
	// Verified crawlers score low too, so they are left out.
	if c.cdn.BotScore && c.cdn.VerifiedBot {
		s, _ := first(h["Cf-Bot-Score"])
		if n := smallInt(s); n >= 1 && n <= 29 && !cdnVerified(h) {
			m |= sigCDNAutomated
		}
	}
	// Cloudflare reports Tor exits as country T1 in cf-ipcountry.
	if c.cdn.Country && c.country == "T1" {
		m |= sigCDNTor
	}
	return m
}

func cdnVerified(h http.Header) bool {
	v, _ := first(h["Cf-Verified-Bot"])
	return strings.EqualFold(v, "true")
}

// smallInt parses one or two digits, or returns 0. strconv would allocate an
// error for a malformed value.
func smallInt(v string) int {
	if len(v) == 0 || len(v) > 2 {
		return 0
	}
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0
		}
		n = n*10 + int(v[i]-'0')
	}
	return n
}

// hasHeaderToken reports whether any comma-separated element of values,
// trimmed of spaces and tabs, equals the lowercase token, ignoring ASCII case
// (RFC 9110 §5.6.1). strings.EqualFold is not used: its Unicode folding
// matches U+017F to "s" and the Kelvin sign to "k".
func hasHeaderToken(values []string, token string) bool {
	for _, v := range values {
		for v != "" {
			var e string
			e, v, _ = strings.Cut(v, ",")
			e = strings.Trim(e, " \t")
			i := 0
			for i < len(e) && i < len(token) && (e[i] == token[i] || 'A' <= e[i] && e[i] <= 'Z' && e[i]+'a'-'A' == token[i]) {
				i++
			}
			if i == len(e) && i == len(token) {
				return true
			}
		}
	}
	return false
}

// browserOf is the browser and version a User-Agent claims. Chrome, Firefox
// and Edge on iOS are WebKit and send what Safari of that iOS sends, so
// they never count as a browser here.
func browserOf(ua string) (int, version2) {
	if !strings.Contains(ua, "Mozilla/5.0") || strings.Contains(ua, "CriOS/") || strings.Contains(ua, "FxiOS/") || strings.Contains(ua, "EdgiOS/") {
		return notBrowser, version2{}
	}
	if v, ok := versionAfter(ua, "Chrome/"); ok {
		return chromium, v
	}
	if v, ok := versionAfter(ua, "Firefox/"); ok {
		return firefox, v
	}
	if v, ok := versionAfter(ua, "Version/"); ok && strings.Contains(ua, "Safari/") {
		return safari, v
	}
	return notBrowser, version2{}
}

// versionAfter reads major[.minor] after the first tok that a digit follows.
func versionAfter(s, tok string) (version2, bool) {
	for {
		i := strings.Index(s, tok)
		if i < 0 {
			return version2{}, false
		}
		s = s[i+len(tok):]
		major, n := leadingInt(s)
		if n == 0 {
			continue
		}
		v := version2{major: major}
		if rest := s[n:]; len(rest) > 1 && rest[0] == '.' {
			v.minor, _ = leadingInt(rest[1:])
		}
		return v, true
	}
}

// brandVersion is the major version of the first Chromium or Google Chrome
// brand in a Sec-CH-UA list, such as "Chromium";v="124".
func brandVersion(s string) (int, bool) {
	const chromiumBrand, chromeBrand = `"Chromium";v="`, `"Google Chrome";v="`
	for {
		i, tok := strings.Index(s, chromiumBrand), chromiumBrand
		if j := strings.Index(s, chromeBrand); j >= 0 && (i < 0 || j < i) {
			i, tok = j, chromeBrand
		}
		if i < 0 {
			return 0, false
		}
		rest := s[i+len(tok):]
		if v, n := leadingInt(rest); n > 0 && n < len(rest) && rest[n] == '"' {
			return v, true
		}
		// Resume one byte on, not past the token: in a malformed list such as
		// "Chromium";v="Google Chrome";v="0" the closing quote of v=" opens
		// the next brand.
		s = s[i+1:]
	}
}

// leadingInt reads up to 9 leading digits, so the value fits an int.
func leadingInt(s string) (v, n int) {
	for n < len(s) && n < 9 && '0' <= s[n] && s[n] <= '9' {
		v = v*10 + int(s[n]-'0')
		n++
	}
	return v, n
}

// browserFloor is the compiled floors indexed by browser kind. Safari has
// none: its version follows the OS, so an old one is a real user.
func browserFloor(c *snapshot.Compiled) [4]int {
	return [4]int{chromium: c.ChromiumFloor, firefox: c.FirefoxFloor}
}
