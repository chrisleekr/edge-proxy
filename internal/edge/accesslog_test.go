package edge

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// Rejections are always logged; allowed requests follow the sample rate; the
// query string never appears in a log line.
func TestAccessLog(t *testing.T) {
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "0"})
	h.load(envelope(testConfig(1)))
	h.do("GET", "/v1/ok?token=secret", nil).Body.Close()
	h.do("GET", "/a%5Cb?token=secret", nil).Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.logs.lines("access")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	lines := h.logs.lines("access")
	if len(lines) != 1 || lines[0]["edge.action"] != "path" || lines[0]["http.response.status_code"] != 400.0 || lines[0]["client.address"] != "198.51.100.7" {
		t.Fatalf("access lines = %v", lines)
	}
	if strings.Contains(h.logs.String(), "secret") {
		t.Fatal("query string logged")
	}
}

// A sampled line carries the sample rate, so a reader can count it as
// 1/rate requests; an always-logged rejection does not.
func TestAccessLogSampleRate(t *testing.T) {
	old := logDraw
	logDraw = func() float64 { return 0 }
	t.Cleanup(func() { logDraw = old })
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "0.25"})
	h.load(envelope(testConfig(1)))
	h.do("GET", "/v1/ok", nil).Body.Close()
	h.do("GET", "/a%5Cb", nil).Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.logs.lines("access")) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	lines := h.logs.lines("access")
	if len(lines) != 2 || lines[0]["edge.action"] != "allow" || lines[0]["edge.sample_rate"] != 0.25 {
		t.Fatalf("access lines = %v", lines)
	}
	if _, ok := lines[1]["edge.sample_rate"]; ok || lines[1]["edge.action"] != "path" {
		t.Fatalf("rejection line = %v", lines[1])
	}
}

// An access line names the host and the query's parameter names, never
// values, so routes can be grouped by host, path and query shape. A key
// that could itself be a secret is counted, not logged.
func TestAccessLogHostAndQueryKeys(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	// Dropped: a bare token, a 65-character key and a bad escape.
	h.do("GET", "/v1/ok?token=secret&b=1&a=2&a=3&&secretbare&secret"+strings.Repeat("x", 59)+"=1&%zz=1", nil, "Host", "API.example.com:443").Body.Close()
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("k%02d=1", i)
	}
	h.do("GET", "/v1/ok?"+strings.Join(many, "&"), nil).Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.logs.lines("access")) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	lines := h.logs.lines("access")
	if len(lines) != 2 {
		t.Fatalf("access lines = %v", lines)
	}
	// Unsampled lines stand for one request each and say nothing of a rate.
	if _, ok := lines[0]["edge.sample_rate"]; ok {
		t.Fatalf("unsampled line = %v", lines[0])
	}
	if fmt.Sprint(lines[0]["edge.query_keys"]) != "[a b token]" || lines[0]["edge.query_keys_dropped"] != 3.0 || lines[0]["server.address"] != "api.example.com" {
		t.Fatalf("first line = %v", lines[0])
	}
	// Keys past the cap are counted, not logged.
	if keys, _ := lines[1]["edge.query_keys"].([]any); len(keys) != 32 || keys[31] != "k31" || lines[1]["edge.query_keys_dropped"] != 1.0 {
		t.Fatalf("second line = %v", lines[1])
	}
	if strings.Contains(h.logs.String(), "secret") {
		t.Fatal("query value or secret-like key logged")
	}
}

// A full log buffer drops lines instead of blocking requests.
func TestAccessLogDropsWhenFull(t *testing.T) {
	h := newHarness(t, nil)
	// No buffer and no reader: every send would block.
	h.srv.edge.alog = &accessLog{ch: make(chan accessRecord), log: h.srv.log, m: h.srv.m, sample: 1}
	h.load(envelope(testConfig(1)))
	h.do("GET", "/", nil).Body.Close()
	if h.srv.m.logDropped.Load() != 1 {
		t.Fatal("line not dropped")
	}
}

// On shutdown the access log writes out what is buffered before exiting.
func TestAccessLogDrainsOnShutdown(t *testing.T) {
	var buf syncBuffer
	a := newAccessLog(newTestLogger(&buf), &metrics{}, 1, 8, nil)
	for range 3 {
		a.ch <- accessRecord{method: "GET", path: "/", status: 200}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	a.run(ctx)
	if n := len(buf.lines("access")); n != 3 {
		t.Fatalf("drained %d lines, want 3", n)
	}
}

// An access line carries what bot rules are tuned from: the User-Agent,
// ASN, country, JA4 when the CDN sent one and the signals when any fired.
// Authorization, cookies and query values stay out.
func TestAccessLogCarriesBotFields(t *testing.T) {
	h := newHarness(t, map[string]string{"VIEWER_HEADERS": ja4Viewer})
	c := testConfig(1)
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "tools", Expression: mustParse(`client.signals in {"ua_tool"}`), Settings: snapshot.Settings{RateLimitHeaders: new(false)}})
	h.load(envelope(c))
	h.do("GET", "/v1/ok?token=secret-query", nil, "User-Agent", "curl/8.5.0", "CloudFront-Viewer-Country", "AU", "CloudFront-Viewer-ASN", "64500",
		"CloudFront-Forwarded-Proto", "https", "CloudFront-Viewer-JA4-Fingerprint", chromeJA4, "Authorization", "Bearer secret-token", "Cookie", "sid=secret-cookie",
		"Referer", "https://shop.example.com/cart?token=secret-referer", "Accept-Language", "en-AU").Body.Close()
	h.do("GET", "/v1/ok", nil, browser(firefoxUA, "CloudFront-Viewer-JA4-Fingerprint", "")...).Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.logs.lines("access")) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	lines := h.logs.lines("access")
	if len(lines) != 2 {
		t.Fatalf("access lines = %v", lines)
	}
	tool := lines[0]
	if tool["user_agent.original"] != "curl/8.5.0" || tool["client.as.number"] != 64500.0 || tool["client.geo.country_iso_code"] != "AU" ||
		tool["tls.client.ja4"] != chromeJA4 || fmt.Sprint(tool["client.signals"]) != "[ua_tool]" || tool["http.request.header.referer"] != "https://shop.example.com/cart" {
		t.Fatalf("tool line = %v", tool)
	}
	browserLine := lines[1]
	_, hasJA4 := browserLine["tls.client.ja4"]
	_, hasSignals := browserLine["client.signals"]
	if browserLine["user_agent.original"] != firefoxUA || hasJA4 || hasSignals {
		t.Fatalf("browser line = %v", browserLine)
	}
	if strings.Contains(h.logs.String(), "secret") {
		t.Fatal("a token, cookie or query value was logged")
	}
}

// A client padding its User-Agent can't make each logged rejection as big
// as the header limit: the line keeps the first 512 bytes, whole characters.
func TestAccessLogCutsALongUserAgent(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	ua := "x" + strings.Repeat("é", 2000) // byte 512 falls inside an é
	h.do("GET", "/a%5Cb", nil, "User-Agent", ua).Body.Close()
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
	got, _ := h.logs.lines("access")[0]["user_agent.original"].(string)
	if len(got) != 511 || !utf8.ValidString(got) || !strings.HasPrefix(ua, got) {
		t.Fatalf("user_agent.original is %d bytes, want the first 511 of the User-Agent: %q", len(got), got)
	}
}

// An access line says whether the upstream answered, which the action
// alone can't: a CORS preflight the edge answers itself is allowed too.
func TestAccessLogSaysWhetherTheUpstreamAnswered(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(corsConfig()))
	for _, tc := range []struct {
		name, method, path string
		headers            []string
		action             string
		answered           bool
	}{
		{"a proxied request was answered by the upstream", "GET", "/v1/ok", nil, "allow", true},
		{"a CORS preflight is answered by the edge", "OPTIONS", "/app/x", []string{"Origin", "https://a.example", "Access-Control-Request-Method", "PUT"}, "allow", false},
		{"a rejection is answered by the edge", "GET", "/a%5Cb", nil, "path", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.logs.lines("access"))
			h.do(tc.method, tc.path, nil, tc.headers...).Body.Close()
			waitFor(t, func() bool { return len(h.logs.lines("access")) == before+1 })
			line := h.logs.lines("access")[before]
			if line["edge.action"] != tc.action || line["edge.upstream_answered"] != tc.answered {
				t.Fatalf("access line %v, want action %s and upstream_answered %v", line, tc.action, tc.answered)
			}
		})
	}
}

// accessLines waits for n access lines and returns them.
func (h *harness) accessLines(n int) []map[string]any {
	h.t.Helper()
	waitFor(h.t, func() bool { return len(h.logs.lines("access")) >= n })
	return h.logs.lines("access")
}

// A log-only rate-limit rule over its limit is written with a logged entry
// and in logged_rules, even when allowed requests are not logged at all. The
// request is still forwarded. A count rule over its limit does the same
// once the response has counted.
func TestAccessLogLogged(t *testing.T) {
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "0"})
	c := testConfig(1)
	logOnly := rlRule("login-watch", `http.request.uri.path eq "/login"`, "sliding_window", 1, "ip")
	logOnly.Action, logOnly.FailMode = "log", "local"
	sweep := rlRule("sweep-watch", `http.request.uri.path eq "/missing"`, "sliding_window", 1, "ip")
	sweep.Action, sweep.CountStatuses = "log", []string{"404"}
	c.RateLimitRules = []snapshot.RateLimitRule{logOnly, sweep}
	h.load(envelope(c))
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
		}
	}
	for _, tc := range []struct{ name, path, rule string }{
		{"a log-only rule over its limit", "/login", "login-watch"},
		{"a log-only count rule over its limit", "/missing", "sweep-watch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.logs.lines("access"))
			if got := h.statuses(2, "GET", tc.path); got[0] == 429 || got[1] == 429 {
				t.Fatalf("a log-only rule refused: %v", got)
			}
			lines := h.accessLines(before + 1)
			line := lines[before]
			if len(lines) != before+1 || line["edge.action"] != "allow" || line["edge.decided_by"] != nil || ruleResults(line) != tc.rule+"=logged" || fmt.Sprint(line["edge.logged_rules"]) != "["+tc.rule+"]" {
				t.Fatalf("access lines = %v", lines[before:])
			}
			if _, ok := line["edge.sample_rate"]; ok {
				t.Fatalf("an always-logged line carries a sample rate: %v", line)
			}
		})
	}
}

// Every rate-limit rule the request matched is listed in evaluation order, and
// a 429 line names the rule that answered it as decided_by.
func TestAccessLogListsMatchedRateLimitRules(t *testing.T) {
	h := newHarness(t, nil)
	c := testConfig(1)
	all := rlRule("everyone", "true", "sliding_window", 1000, "ip")
	login := rlRule("login-cap", `http.request.uri.path eq "/login"`, "sliding_window", 1, "ip")
	all.FailMode, login.FailMode = "local", "local"
	c.RateLimitRules = []snapshot.RateLimitRule{all, login}
	h.load(envelope(c))
	h.statuses(1, "GET", "/other")
	h.statuses(2, "GET", "/login")
	lines := h.accessLines(3)
	for i, want := range []struct{ rules, answered string }{{"everyone=under", ""}, {"everyone=under login-cap=under", ""}, {"everyone=under login-cap=blocked", "login-cap"}} {
		got, _ := lines[i]["edge.decided_by"].(string)
		if ruleResults(lines[i]) != want.rules || got != want.answered {
			t.Fatalf("line %d: rules %s, answered %q, want %s and %q", i, ruleResults(lines[i]), got, want.rules, want.answered)
		}
	}
	if lines[2]["edge.action"] != "rate_limited" {
		t.Fatalf("third line = %v", lines[2])
	}
}

// A browser over HTTPS and HTTP/2 logs what the CDN and the browser sent.
func TestAccessLogCarriesBrowserFields(t *testing.T) {
	h := newHarness(t, map[string]string{"VIEWER_HEADERS": ja4Viewer + ",ip.src.continent=CloudFront-Viewer-Continent"})
	c := testConfig(1)
	c.Global.Locale = snapshot.Locale{Supported: []string{"en", "ko"}, Default: "en"}
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "locale", Expression: mustParse("true"), Settings: snapshot.Settings{Locale: new(true)}})
	h.load(envelope(c))
	h.do("GET", "/v1/ok", nil, browser(chromeUA, "CloudFront-Viewer-JA3-Fingerprint", chromeJA3, "CloudFront-Viewer-Continent", "oc", "Accept-Language", "ko-KR,ko;q=0.9",
		"Sec-CH-UA", `"Chromium";v="124"`, "Sec-CH-UA-Mobile", "?0", "Sec-CH-UA-Platform", `"Windows"`,
		"Sec-Fetch-Site", "same-origin", "Sec-Fetch-Dest", "document", "Sec-Fetch-User", "?1",
		"Accept", "text/html", "Accept-Encoding", "gzip, br", "Referer", "https://shop.example.com/cart")...).Body.Close()
	line := h.accessLines(1)[0]
	for k, want := range map[string]any{
		"network.protocol.version": "2", "url.scheme": "https", "tls.client.ja4": chromeJA4, "tls.client.ja3": chromeJA3,
		"client.geo.continent_code": "OC", "edge.locale": "ko", "http.request.body.size": 0.0, "http.response.body.size": 11.0,
		"http.request.header.sec-ch-ua": `"Chromium";v="124"`, "http.request.header.sec-ch-ua-mobile": "?0", "http.request.header.sec-ch-ua-platform": `"Windows"`,
		"http.request.header.sec-fetch-site": "same-origin", "http.request.header.sec-fetch-mode": "navigate", "http.request.header.sec-fetch-dest": "document",
		"http.request.header.sec-fetch-user": "?1", "http.request.header.accept": "text/html", "http.request.header.accept-language": "ko-KR,ko;q=0.9",
		"http.request.header.accept-encoding": "gzip, br", "http.request.header.referer": "https://shop.example.com/cart",
	} {
		if line[k] != want {
			t.Errorf("%s = %v, want %v", k, line[k], want)
		}
	}
	for _, tc := range []struct{ sent, want string }{{"HTTP/1.0", "1.0"}, {"1.1", "1.1"}, {"HTTP/2", "2"}, {"3.0", "3"}} {
		before := len(h.logs.lines("access"))
		h.do("GET", "/v1/ok", nil, "CloudFront-Viewer-Http-Version", tc.sent).Body.Close()
		if got := h.accessLines(before + 1)[before]["network.protocol.version"]; got != tc.want {
			t.Errorf("viewer version %q logged as %v, want %s", tc.sent, got, tc.want)
		}
	}
	// A request the CDN saw as plain HTTP1.1, with no fingerprint.
	before := len(h.logs.lines("access"))
	h.do("GET", "/v1/ok", nil, "CloudFront-Forwarded-Proto", "http", "CloudFront-Viewer-Http-Version", "HTTP/1.1").Body.Close()
	plain := h.accessLines(before + 1)[before]
	if plain["url.scheme"] != "http" || plain["network.protocol.version"] != "1.1" {
		t.Fatalf("plain line = %v", plain)
	}
	for _, k := range []string{"tls.client.ja3", "client.geo.continent_code", "http.request.header.referer", "http.request.header.sec-ch-ua"} {
		if _, ok := plain[k]; ok {
			t.Errorf("%s logged for a request without it: %v", k, plain)
		}
	}
}

// The Referer is logged as scheme, host and path. Its query, fragment and
// user info can carry tokens, and a value that is not an absolute URL says
// nothing useful.
func TestAccessLogRefererIsTrimmed(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	for _, tc := range []struct{ name, referer, want string }{
		{"query and fragment are removed", "https://shop.example.com/cart/1?token=secret-ref#frag-secret", "https://shop.example.com/cart/1"},
		{"user info is removed", "https://user:secret-pw@shop.example.com/a", "https://shop.example.com/a"},
		{"a relative reference is not logged", "/cart?token=secret-ref", ""},
		{"an unparsable value is not logged", "https://shop.example.com/%zz?token=secret-ref", ""},
		{"a value with no host is not logged", "mailto:a@example.com", ""},
		{"a long path is cut to 512 bytes", "https://shop.example.com/" + strings.Repeat("p", 600), "https://shop.example.com/" + strings.Repeat("p", 512-len("https://shop.example.com/"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.logs.lines("access"))
			h.do("GET", "/v1/ok", nil, "Referer", tc.referer).Body.Close()
			got, _ := h.accessLines(before + 1)[before]["http.request.header.referer"].(string)
			if got != tc.want {
				t.Fatalf("referer logged as %q, want %q", got, tc.want)
			}
		})
	}
	if strings.Contains(h.logs.String(), "secret") {
		t.Fatal("a referer query, fragment or password was logged")
	}
}

// A client picks its headers and rejections are always logged, so each
// header is cut to 256 bytes, at a character boundary.
func TestAccessLogCutsClientHeaders(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	long := strings.Repeat("a", 300)
	h.do("GET", "/v1/ok", nil, "Sec-CH-UA", long, "Accept", "x"+strings.Repeat("é", 200)).Body.Close()
	line := h.accessLines(1)[0]
	if got, _ := line["http.request.header.sec-ch-ua"].(string); got != long[:256] {
		t.Fatalf("sec-ch-ua is %d bytes", len(got))
	}
	if got, _ := line["http.request.header.accept"].(string); len(got) != 255 || !utf8.ValidString(got) {
		t.Fatalf("accept is %d bytes: %q", len(got), got)
	}
}

// The subject is logged only for a token the edge verified, from the cache
// too. A token that fails verification is not read at all.
func TestAccessLogAuthSubjectOnlyWhenVerified(t *testing.T) {
	h, _ := newAuthHarness(t)
	tok := corpToken()
	forged := mint(jwt.SigningMethodRS256, "k1", corpKey2, corpClaims())
	for _, tc := range []struct{ name, token, auth, sub string }{
		{"a verified token", tok, "verified", "user-1"},
		{"a cached token", tok, "cached", "user-1"},
		{"a token signed with another key", forged, "invalid", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.logs.lines("access"))
			h.do("GET", "/private/orders", nil, bearerOf(tc.token)...).Body.Close()
			line := h.accessLines(before + 1)[before]
			sub, _ := line["edge.auth_sub"].(string)
			if line["edge.auth"] != tc.auth || sub != tc.sub {
				t.Fatalf("line = %v", line)
			}
		})
	}
	if strings.Contains(h.logs.String(), tok) {
		t.Fatal("the token was logged")
	}
}

// The body sizes are what the client declared and what the edge wrote to it,
// whether the upstream or an edge template answered. An unknown request
// length is not logged.
func TestAccessLogBodySizes(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 5000)) }
	for _, tc := range []struct {
		name, method, path string
		body               io.Reader
		reqSize, respSize  any
	}{
		{"a proxied response over several writes", "POST", "/v1/ok", strings.NewReader("hello"), 5.0, 5000.0},
		{"a chunked request has no declared size", "POST", "/v1/ok", io.NopCloser(strings.NewReader("hello")), nil, 5000.0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.logs.lines("access"))
			h.do(tc.method, tc.path, tc.body).Body.Close()
			line := h.accessLines(before + 1)[before]
			if line["http.request.body.size"] != tc.reqSize || line["http.response.body.size"] != tc.respSize {
				t.Fatalf("line = %v", line)
			}
		})
	}
	t.Run("an edge template response", func(t *testing.T) {
		before := len(h.logs.lines("access"))
		resp := h.do("GET", "/a%5Cb", nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := h.accessLines(before + 1)[before]["http.response.body.size"]; got != float64(len(body)) || len(body) == 0 {
			t.Fatalf("logged %v bytes for a %d byte template", got, len(body))
		}
	})
}

// An access rule in log mode and a log-only rate-limit rule over its limit
// are both listed as logged, and a refusal by another rule is the action.
func TestAccessLogListsEveryLoggedRule(t *testing.T) {
	for _, tc := range []struct{ name, path, action, rule, results, logged string }{
		{"a log-only access rule matched too", "/both", "allow", "", "tools=logged watch=logged", "[tools watch]"},
		{"a blocking rate-limit rule is over its limit too", "/hard", "rate_limited", "hard", "watch=logged hard=blocked", "[watch]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			c := testConfig(1)
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.request.uri.path eq "/both"`), Settings: snapshot.Settings{Block: new("log")}})
			watch := rlRule("watch", "true", "sliding_window", 1, "ip")
			watch.Action, watch.FailMode = "log", "local"
			hard := rlRule("hard", `http.request.uri.path eq "/hard"`, "sliding_window", 1, "ip")
			hard.FailMode = "local"
			c.RateLimitRules = []snapshot.RateLimitRule{watch, hard}
			h.load(envelope(c))
			// The second request is over the log-only rule's limit of 1 per client.
			h.statuses(2, "GET", tc.path)
			line := h.accessLines(2)[1]
			if got, _ := line["edge.decided_by"].(string); line["edge.action"] != tc.action || got != tc.rule || ruleResults(line) != tc.results || fmt.Sprint(line["edge.logged_rules"]) != tc.logged {
				t.Fatalf("action %v, decided by %q, rules %s, logged %v", line["edge.action"], got, ruleResults(line), line["edge.logged_rules"])
			}
		})
	}
}

// The CDN's headers show on the access line as received, under the
// attribute names the browser headers use, so a log search finds both, and
// the query value is not.
func TestAccessLogCarriesTheCDNsHeaders(t *testing.T) {
	cases := []struct {
		name    string
		set     map[string]string
		headers []string
		want    map[string]string
		absent  []string
	}{
		{"cloudflare preset", map[string]string{"CLIENT_IP_SOURCE": "cloudflare"},
			[]string{"CF-Connecting-IP", "198.51.100.7", "CF-IPCity", "Sydney", "CF-IPCountry", "AU", "CF-Bot-Score", "12", "CF-JA4", chromeJA4, "Accept-Language", "en-AU", "X-Geo-City", "Perth"},
			map[string]string{"http.request.header.cf-ipcity": "Sydney", "http.request.header.cf-ipcountry": "AU", "http.request.header.cf-bot-score": "12", "http.request.header.cf-ja4": chromeJA4, "http.request.header.accept-language": "en-AU"},
			[]string{"http.request.header.x-geo-city"}},
		{"cloudfront preset", nil,
			[]string{"CloudFront-Viewer-City", "Melbourne", "CloudFront-Viewer-TLS", "TLSv1.3:TLS_AES_128_GCM_SHA256:fullHandshake"},
			map[string]string{"http.request.header.cloudfront-viewer-city": "Melbourne", "http.request.header.cloudfront-viewer-tls": "TLSv1.3:TLS_AES_128_GCM_SHA256:fullHandshake"},
			nil},
		{"CDN_HEADERS replaces the preset", map[string]string{"CDN_HEADERS": "X-Geo-City"},
			[]string{"X-Geo-City", "Perth", "CloudFront-Viewer-City", "Melbourne"},
			map[string]string{"http.request.header.x-geo-city": "Perth"},
			[]string{"http.request.header.cloudfront-viewer-city"}},
		{"none logs only the browser headers", map[string]string{"CDN_HEADERS": "none"},
			[]string{"CloudFront-Viewer-City", "Melbourne", "Sec-Fetch-Mode", "navigate"},
			map[string]string{"http.request.header.sec-fetch-mode": "navigate"},
			[]string{"http.request.header.cloudfront-viewer-city"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.set)
			h.load(envelope(testConfig(1)))
			h.do("GET", "/v1/ok?token=query-secret", nil, tc.headers...).Body.Close()
			waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
			line := h.logs.lines("access")[0]
			for attr, v := range tc.want {
				if line[attr] != v {
					t.Errorf("%s = %v, want %q in %v", attr, line[attr], v, line)
				}
			}
			for _, attr := range tc.absent {
				if _, ok := line[attr]; ok {
					t.Errorf("%s logged: %v", attr, line)
				}
			}
			if out := h.logs.String(); strings.Contains(out, "secret") {
				t.Errorf("a query value was logged: %s", out)
			}
		})
	}
}

// A request through a Cloudflare deployment gets the CDN signals from its
// headers: the handler copies the pinned version's CDN trust to each client.
func TestLiveRequestsGetCDNSignals(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		want    string
	}{
		{"every header the signals read is trusted", []string{"Cf-Bot-Score", "Cf-Verified-Bot"}, "[cdn_likely_automated crawler_impersonated cdn_tor]"},
		{"a bot score the policy doesn't trust sends no signal", []string{"Cf-Verified-Bot"}, "[crawler_impersonated cdn_tor]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, map[string]string{"CLIENT_IP_SOURCE": "cloudflare"})
			c := testConfig(1)
			c.Global.CDNTrustedHeaders = &tc.trusted
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "cdn", Expression: mustParse(`client.signals in {"crawler_impersonated" "cdn_tor"}`), Settings: snapshot.Settings{RateLimitHeaders: new(false)}})
			h.load(envelope(c))
			h.do("GET", "/v1/ok", nil, "CF-Connecting-IP", "198.51.100.7", "CF-IPCountry", "T1", "CF-Bot-Score", "12", "CF-Verified-Bot", "false", "User-Agent", "Googlebot/2.1").Body.Close()
			waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
			if got := fmt.Sprint(h.logs.lines("access")[0]["client.signals"]); got != tc.want {
				t.Fatalf("client.signals = %s, want %s", got, tc.want)
			}
		})
	}
}

// During a canary a request gets the CDN trust of the version it is pinned
// to: only the candidate trusts the bot score, so only its cohort gets
// cdn_likely_automated.
func TestCanaryUsesThePinnedVersionsCDNTrust(t *testing.T) {
	in, out := ipWithCohort(t, true, 5000), ipWithCohort(t, false, 5000)
	cfg := func(version int64, trusted ...string) *snapshot.Config {
		c := testConfig(version)
		c.Global.CDNTrustedHeaders = &trusted
		c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "cdn", Expression: mustParse(`client.signals eq "crawler_impersonated"`), Settings: snapshot.Settings{RateLimitHeaders: new(false)}})
		return c
	}
	cases := []struct {
		name, client string
		automated    bool
	}{
		{"in-cohort client meets the candidate, which trusts the score", in, true},
		{"out-of-cohort client meets the active version, which doesn't", out, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, map[string]string{"CLIENT_IP_SOURCE": "cloudflare"})
			e := envelope(cfg(1, "Cf-Verified-Bot"))
			e.Candidate, e.CanaryPercent, e.CanaryExpiresAt = cfg(2, "Cf-Bot-Score", "Cf-Verified-Bot"), 50, time.Now().Add(time.Hour)
			h.load(e)
			h.do("GET", "/v1/ok", nil, "CF-Connecting-IP", tc.client, "CF-Bot-Score", "12", "CF-Verified-Bot", "false").Body.Close()
			waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
			got := fmt.Sprint(h.logs.lines("access")[0]["client.signals"])
			if strings.Contains(got, "cdn_likely_automated") != tc.automated {
				t.Fatalf("client.signals = %s, want cdn_likely_automated %v", got, tc.automated)
			}
		})
	}
}

// cdn_tor reads the country the edge takes from ip.src.country's header.
// When VIEWER_HEADERS takes it from another header, a T1 in cf-ipcountry, even
// one the policy trusts, sends no cdn_tor.
func TestCDNTorNeedsTheCountrySource(t *testing.T) {
	h := newHarness(t, map[string]string{"CLIENT_IP_SOURCE": "cloudflare", "VIEWER_HEADERS": "ip.src.country=X-Country"})
	c := testConfig(1)
	c.Global.CDNTrustedHeaders = &[]string{"Cf-Ipcountry", "Cf-Verified-Bot"}
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "cdn", Expression: mustParse(`client.signals eq "crawler_impersonated"`), Settings: snapshot.Settings{RateLimitHeaders: new(false)}})
	h.load(envelope(c))
	h.do("GET", "/v1/ok", nil, "CF-Connecting-IP", "198.51.100.7", "X-Country", "T1", "CF-IPCountry", "T1", "CF-Verified-Bot", "false", "User-Agent", "Googlebot/2.1").Body.Close()
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
	if got := fmt.Sprint(h.logs.lines("access")[0]["client.signals"]); got != "[crawler_impersonated]" {
		t.Fatalf("client.signals = %s, want [crawler_impersonated]", got)
	}
}

// ruleResults lists a line's matched_rules as "rule=result", in order.
func ruleResults(line map[string]any) string {
	var out []string
	entries, _ := line["edge.matched_rules"].([]any)
	for _, e := range entries {
		m := e.(map[string]any)
		out = append(out, fmt.Sprintf("%v=%v", m["rule"], m["result"]))
	}
	return strings.Join(out, " ")
}

// ruleNumbers lists the numbers on a line's rate-limit entries: left as a
// value, retry_after and blocked_until (which move with the clock) only as
// present.
func ruleNumbers(line map[string]any) string {
	var out []string
	entries, _ := line["edge.matched_rules"].([]any)
	for _, e := range entries {
		m := e.(map[string]any)
		if m["type"] != "rate_limit" {
			continue
		}
		s := fmt.Sprint(m["rule"])
		if v, ok := m["left"]; ok {
			s += fmt.Sprintf(" left=%v", v)
		}
		if _, ok := m["retry_after"]; ok {
			s += " retry_after"
		}
		if _, ok := m["blocked_until"]; ok {
			s += " blocked_until"
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

// Each access line says what the edge did, which rule decided it and what
// every matched rule did. There is no Valkey here, so a rule that does not
// fail local has no count.
func TestAccessLogMatchedRules(t *testing.T) {
	const curl = "curl/8.7.1"
	type send struct {
		path    string
		headers []string
		home    bool // from the office range, where the default client is
	}
	req := func(path string, headers ...string) send { return send{path: path, headers: headers} }
	local := func(id, src string, limit int64) snapshot.RateLimitRule {
		r := rlRule(id, src, "sliding_window", limit, "ip")
		r.FailMode = "local"
		return r
	}
	count404 := func(id string, limit int64) snapshot.RateLimitRule {
		r := local(id, "true", limit)
		r.CountStatuses = []string{"404"}
		return r
	}
	with := func(r snapshot.RateLimitRule, f func(*snapshot.RateLimitRule)) snapshot.RateLimitRule {
		f(&r)
		return r
	}
	logOnly := func(r *snapshot.RateLimitRule) { r.Action = "log" }
	penalty := func(r *snapshot.RateLimitRule) { r.Penalty = dur(5 * time.Minute) }
	failClosed := func(r *snapshot.RateLimitRule) { r.FailMode = "closed" }
	access := func(id, src string, s snapshot.Settings) snapshot.ConfigRule {
		return snapshot.ConfigRule{ID: id, Expression: mustParse(src), Settings: s}
	}
	blockCurl := access("block-curl", `http.user_agent contains "curl"`, snapshot.Settings{Block: new("block")})
	blockProbe := access("block-probe", `starts_with(http.request.uri.path, "/.")`, snapshot.Settings{Block: new("block")})
	home := access("allow-home", "ip.src in {"+trustedRange+"}", snapshot.Settings{Allow: true})
	tools := access("unblock-tools", `http.user_agent contains "Tool"`, snapshot.Settings{Block: new("log")})
	notFound := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }
	perIP := func() snapshot.RateLimitRule { return local("per-ip", "true", 100) }
	for _, tc := range []struct {
		name    string
		access  []snapshot.ConfigRule
		limits  []snapshot.RateLimitRule
		headers []snapshot.HeaderRule
		kill    snapshot.KillSwitch
		// appHandler answers upstream requests; appDown closes the upstream.
		appHandler http.HandlerFunc
		appDown    bool
		sends      []send
		// The last line's action, deciding rule, rules, numbers and logged_rules.
		action, by, rules, numbers, logged string
	}{
		{name: "a page the 4xx rule did not count", limits: []snapshot.RateLimitRule{perIP(), count404("four-xx", 20)},
			sends: []send{req("/")}, action: "allow", rules: "per-ip=under four-xx=not_counted", numbers: "per-ip left=99, four-xx"},
		{name: "a 404 the 4xx rule counted", limits: []snapshot.RateLimitRule{perIP(), count404("four-xx", 20)}, appHandler: notFound,
			sends: []send{req("/")}, action: "allow", rules: "per-ip=under four-xx=under", numbers: "per-ip left=99, four-xx left=19"},
		{name: "a request over its limit is refused with a penalty", limits: []snapshot.RateLimitRule{with(local("per-ip", "true", 1), penalty), count404("four-xx", 20)},
			sends: []send{req("/"), req("/")}, action: "rate_limited", by: "per-ip", rules: "per-ip=blocked four-xx=not_counted", numbers: "per-ip left=0 retry_after blocked_until, four-xx"},
		{name: "a client whose penalty is running is refused by the rule that set it", limits: []snapshot.RateLimitRule{with(local("per-ip", "true", 1), penalty)},
			sends: []send{req("/"), req("/"), req("/")}, action: "rate_limited", by: "per-ip", rules: "per-ip=blocked", numbers: "per-ip left=0 retry_after blocked_until"},
		{name: "the response that takes a count rule over its limit is allowed", limits: []snapshot.RateLimitRule{with(count404("four-xx", 1), penalty)}, appHandler: notFound,
			sends: []send{req("/"), req("/")}, action: "allow", rules: "four-xx=over", numbers: "four-xx left=0 blocked_until"},
		{name: "a blocked request lists only the access rules", access: []snapshot.ConfigRule{blockCurl}, limits: []snapshot.RateLimitRule{perIP()},
			sends: []send{req("/", "User-Agent", curl)}, action: "blocked", by: "block-curl", rules: "block-curl=blocked"},
		{name: "the later block rule wins and the earlier one is overridden", access: []snapshot.ConfigRule{blockCurl, blockProbe},
			sends: []send{req("/.env", "User-Agent", curl)}, action: "blocked", by: "block-probe", rules: "block-curl=overridden block-probe=blocked"},
		{name: "an always-allow rule decides and skips rate limits", access: []snapshot.ConfigRule{blockCurl, home}, limits: []snapshot.RateLimitRule{perIP()},
			sends: []send{{path: "/", headers: []string{"User-Agent", curl}, home: true}}, action: "allow", by: "allow-home", rules: "block-curl=overridden allow-home=allowed"},
		{name: "a log-only rule after a block logs and the block is overridden", access: []snapshot.ConfigRule{blockCurl, tools}, limits: []snapshot.RateLimitRule{perIP()},
			sends: []send{req("/", "User-Agent", curl+" Tool")}, action: "allow", rules: "block-curl=overridden unblock-tools=logged per-ip=under", numbers: "per-ip left=99", logged: "[unblock-tools]"},
		{name: "a log-only rule logs a request nothing else would block", access: []snapshot.ConfigRule{blockCurl, tools},
			sends: []send{req("/", "User-Agent", "Tool/1")}, action: "allow", rules: "unblock-tools=logged", logged: "[unblock-tools]"},
		{name: "a block rule after a log-only rule blocks and the log-only one is overridden", access: []snapshot.ConfigRule{blockCurl, tools, blockProbe},
			sends: []send{req("/.git/config", "User-Agent", curl+" Tool")}, action: "blocked", by: "block-probe", rules: "block-curl=overridden unblock-tools=overridden block-probe=blocked"},
		{name: "a log-only rate limit over its limit is listed as logged", limits: []snapshot.RateLimitRule{perIP(), with(local("search", "true", 1), logOnly)},
			sends: []send{req("/"), req("/")}, action: "allow", rules: "per-ip=under search=logged", numbers: "per-ip left=98, search left=0 retry_after", logged: "[search]"},
		{name: "a log-only access rule and a 429 are both listed", access: []snapshot.ConfigRule{tools}, limits: []snapshot.RateLimitRule{with(local("per-ip", "true", 1), penalty)},
			sends: []send{req("/", "User-Agent", "Tool/1"), req("/", "User-Agent", "Tool/1")}, action: "rate_limited", by: "per-ip", rules: "unblock-tools=logged per-ip=blocked", numbers: "per-ip left=0 retry_after blocked_until", logged: "[unblock-tools]"},
		{name: "the block kill switch turns the winning block into logged", access: []snapshot.ConfigRule{blockCurl}, limits: []snapshot.RateLimitRule{perIP()}, kill: snapshot.KillSwitch{Block: true},
			sends: []send{req("/", "User-Agent", curl)}, action: "allow", rules: "block-curl=logged per-ip=under", numbers: "per-ip left=99", logged: "[block-curl]"},
		{name: "the rate-limit kill switch turns a limit into logged", limits: []snapshot.RateLimitRule{local("per-ip", "true", 1)}, kill: snapshot.KillSwitch{RateLimit: true},
			sends: []send{req("/"), req("/")}, action: "allow", rules: "per-ip=logged", numbers: "per-ip left=0 retry_after", logged: "[per-ip]"},
		{name: "a rule that fails open has an error and no count", limits: []snapshot.RateLimitRule{rlRule("per-ip", "true", "sliding_window", 100, "ip")},
			sends: []send{req("/")}, action: "allow", rules: "per-ip=error", numbers: "per-ip"},
		{name: "a rule that fails closed refuses and names itself", limits: []snapshot.RateLimitRule{with(rlRule("partner-per-key", "true", "sliding_window", 100, "ip"), failClosed)},
			sends: []send{req("/")}, action: "rate_limit_unavailable", by: "partner-per-key", rules: "partner-per-key=error", numbers: "partner-per-key"},
		{name: "the first rule that fails closed is the one named", limits: []snapshot.RateLimitRule{
			with(rlRule("closed-a", "true", "sliding_window", 100, "ip"), failClosed), with(rlRule("closed-b", "true", "sliding_window", 100, "ip"), failClosed)},
			sends: []send{req("/")}, action: "rate_limit_unavailable", by: "closed-a", rules: "closed-a=error closed-b=error", numbers: "closed-a, closed-b"},
		{name: "a log-only rule that fails closed refuses nothing", limits: []snapshot.RateLimitRule{with(with(rlRule("watch", "true", "sliding_window", 100, "ip"), failClosed), logOnly)},
			sends: []send{req("/")}, action: "allow", rules: "watch=error", numbers: "watch"},
		{name: "a rule that rejects a missing key refuses with 400 and names itself", limits: []snapshot.RateLimitRule{with(rlRule("per-key", "true", "sliding_window", 100, "ip", "header:x-api-key"), func(r *snapshot.RateLimitRule) { r.OnMissingKey = "reject" })},
			sends: []send{req("/")}, action: "rate_limit_key", by: "per-key"},
		{name: "a request header rule is listed after the others", limits: []snapshot.RateLimitRule{perIP()}, headers: []snapshot.HeaderRule{marker("add-locale", "true", "X-Locale", "en")},
			sends: []send{req("/")}, action: "allow", rules: "per-ip=under add-locale=matched", numbers: "per-ip left=99"},
		{name: "an upstream failure lists the rules and decides nothing", limits: []snapshot.RateLimitRule{perIP(), count404("four-xx", 20)}, headers: []snapshot.HeaderRule{marker("add-locale", "true", "X-Locale", "en")}, appDown: true,
			sends: []send{req("/")}, action: "upstream_error", rules: "per-ip=under four-xx=not_counted add-locale=matched", numbers: "per-ip left=99, four-xx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
			c := testConfig(1)
			c.ConfigRules = append(c.ConfigRules, tc.access...)
			c.RateLimitRules, c.RequestHeaderRules, c.KillSwitch = tc.limits, tc.headers, tc.kill
			h.load(envelope(c))
			if tc.appHandler != nil {
				h.appHandler = tc.appHandler
			}
			if tc.appDown {
				h.app.Close()
			}
			for _, s := range tc.sends {
				headers := s.headers
				if !s.home {
					headers = append(slices.Clone(headers), "CloudFront-Viewer-Address", otherClient)
				}
				h.do("GET", s.path, nil, headers...).Body.Close()
			}
			line := h.accessLines(len(tc.sends))[len(tc.sends)-1]
			if got, _ := line["edge.decided_by"].(string); line["edge.action"] != tc.action || got != tc.by {
				t.Fatalf("action %v decided by %q, want %s and %q: %v", line["edge.action"], got, tc.action, tc.by, line)
			}
			if got := ruleResults(line); got != tc.rules {
				t.Fatalf("matched_rules %q, want %q", got, tc.rules)
			}
			if got := ruleNumbers(line); got != tc.numbers && tc.numbers != "" {
				t.Fatalf("numbers %q, want %q", got, tc.numbers)
			}
			if got := fmt.Sprint(line["edge.logged_rules"]); tc.logged == "" && line["edge.logged_rules"] != nil || tc.logged != "" && got != tc.logged {
				t.Fatalf("logged_rules %v, want %q", line["edge.logged_rules"], tc.logged)
			}
		})
	}
}

// A rate-limit rule's numbers come from Valkey when it answers: left counts
// down, and a request over the limit carries the penalty end.
func TestAccessLogRateLimitNumbersFromValkey(t *testing.T) {
	h := valkeyHarness(t, nil)
	c := testConfig(1)
	r := rlRule(uniq("per-ip"), "true", "sliding_window", 2, "ip")
	r.Penalty = dur(5 * time.Minute)
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	h.load(envelope(c))
	h.statuses(3, "GET", "/")
	lines := h.accessLines(3)
	for i, want := range []struct{ results, numbers string }{
		{r.ID + "=under", r.ID + " left=1"},
		{r.ID + "=under", r.ID + " left=0"},
		{r.ID + "=blocked", r.ID + " left=0 retry_after blocked_until"},
	} {
		if ruleResults(lines[i]) != want.results || ruleNumbers(lines[i]) != want.numbers {
			t.Fatalf("line %d: %s (%s), want %s (%s)", i, ruleResults(lines[i]), ruleNumbers(lines[i]), want.results, want.numbers)
		}
	}
	if lines[2]["edge.action"] != "rate_limited" || lines[2]["edge.decided_by"] != r.ID {
		t.Fatalf("third line = %v", lines[2])
	}
	entries := lines[2]["edge.matched_rules"].([]any)
	until, err := time.Parse(time.RFC3339, entries[0].(map[string]any)["blocked_until"].(string))
	if err != nil || time.Until(until) < 4*time.Minute || time.Until(until) > 6*time.Minute {
		t.Fatalf("blocked_until %v (%v), want about 5 minutes ahead", entries[0], err)
	}
}
