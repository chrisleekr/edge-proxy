package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// cannedTransport answers every upstream request in memory with status, so
// the benchmark measures the edge, not the network.
type cannedTransport struct{ status int }

func (t cannedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: t.status, Header: http.Header{"Content-Length": {"2"}}, ContentLength: 2, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
}

// Cost of one allowed, proxied request through steps 1 to 5 and 10, with
// the upstream in memory. Tracks allocations per request.
// The backstop is set above the benchmark's rate: one client sends every
// request.
func BenchmarkAllowPath(b *testing.B) {
	c := testConfig(1)
	c.Global.Backstop.Limit, c.Global.Backstop.Burst = 1_000_000_000, 1_000_000_000
	s, req := inMemoryEdge(b, c, "/v1/items?id=1")
	b.ReportAllocs()
	for b.Loop() {
		w := httptest.NewRecorder()
		s.edge.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("status %d", w.Code)
		}
	}
}

// BenchmarkAllowPath as a real Chrome navigation sends it: Chrome's headers
// and a page path, so client signals and path handling read real input.
func BenchmarkAllowPathBrowser(b *testing.B) {
	c := testConfig(1)
	c.Global.Backstop.Limit, c.Global.Backstop.Burst = 1_000_000_000, 1_000_000_000
	s, req := inMemoryEdge(b, c, browserTarget)
	chromeHeaders(req.Header)
	b.ReportAllocs()
	for b.Loop() {
		w := httptest.NewRecorder()
		s.edge.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("status %d", w.Code)
		}
	}
}

// browserTarget is a page path with a query, as a browser requests it.
const browserTarget = "/v1/holidays/australia/new-south-wales/sydney?page=2&sort=price"

// chromeHeaders sets the request headers Chrome 142 on macOS sends for a
// top-level navigation.
func chromeHeaders(h http.Header) {
	h.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	h.Set("Accept-Language", "en-AU,en;q=0.9,ko;q=0.8")
	h.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	h.Set("Sec-Ch-Ua", `"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"`)
	h.Set("Sec-Ch-Ua-Mobile", "?0")
	h.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Sec-Fetch-User", "?1")
}

// Client signals alone, which every request that reaches the config step
// computes for stats: a browser User-Agent matches no token, a tool's does.
func BenchmarkSignalsOf(b *testing.B) {
	for _, tc := range []struct{ name, ua string }{
		{"chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"},
		{"tool", "python-requests/2.32.3"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			h := http.Header{}
			chromeHeaders(h)
			h.Set("User-Agent", tc.ua)
			c := &client{ssl: true, version: "2.0"}
			b.ReportAllocs()
			for b.Loop() {
				signalsOf(h, c, [4]int{})
			}
		})
	}
}

// inMemoryEdge is a replica running c with an in-memory upstream, and a
// request to target from one CloudFront client.
func inMemoryEdge(tb testing.TB, c *snapshot.Config, target string) (*Server, *http.Request) {
	tb.Helper()
	e := cloudfrontEnv()
	e["TRUSTED_PROXIES"] = "192.0.2.0/24"
	e["LOG_SAMPLE_RATE"] = "0"
	e["UPSTREAM_URL"] = "https://lb.internal"
	cfg, err := LoadConfig(env(e))
	if err != nil {
		tb.Fatal(err)
	}
	s := New(cfg, newTestLogger(io.Discard), nil)
	if err := s.poller.apply(envelope(c), "admin", 0); err != nil {
		tb.Fatal(err)
	}
	s.edge.rp.Transport = cannedTransport{200}
	req := httptest.NewRequest("GET", "http://api.example.com"+target, nil)
	req.RemoteAddr = "192.0.2.1:5000"
	req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:40000")
	req.Header.Set("CloudFront-Viewer-Country", "AU")
	req.Header.Set("User-Agent", "bench")
	return s, req
}

// A request allocates a bounded, known amount. ns/op is too noisy to gate
// in CI, but allocations are deterministic, so a regression on the request
// path fails here. Ceilings are the measured counts.
func TestRequestAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items at random under -race")
	}
	cases := []struct {
		name   string
		change func(c *snapshot.Config)
		target string
		status int
		max    float64
		// expires, when set, is when rate-limit rule 0 expires, from now.
		expires time.Duration
		// banned seeds a ban on the client, in a version with a ban rule.
		banned bool
		// deny is the IP list set the edge holds.
		deny string
		// chrome sends Chrome's navigation headers instead of the bench ones.
		chrome bool
	}{
		{"allowed and proxied", func(*snapshot.Config) {}, "/v1/items?id=1", 200, 36, 0, false, "", false},
		{"allowed with RateLimit headers", func(c *snapshot.Config) {
			r := rlRule("per-ip", "true", "token_bucket", 1_000_000_000, "ip")
			r.FailMode = "local"
			c.RateLimitRules = []snapshot.RateLimitRule{r}
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "headers", Expression: mustParse("true"), Settings: snapshot.Settings{RateLimitHeaders: new(true)}})
		}, "/v1/items?id=1", 200, 43, 0, false, "", false},
		{"rate limited with RateLimit headers", func(c *snapshot.Config) {
			r := rlRule("per-ip", "true", "token_bucket", 1, "ip")
			r.FailMode = "local"
			c.RateLimitRules = []snapshot.RateLimitRule{r}
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "headers", Expression: mustParse("true"), Settings: snapshot.Settings{RateLimitHeaders: new(true)}})
		}, "/v1/items", 429, 19, 0, false, "", false},
		{"blocked by a config rule", func(c *snapshot.Config) {
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent eq "bench"`), Settings: snapshot.Settings{Block: new("block")}})
		}, "/v1/items", 403, 13, 0, false, "", false},
		// A template with several bodies adds the Accept pick and Vary: Accept.
		{"blocked with a body picked by Accept", func(c *snapshot.Config) {
			r := c.Global.Responses["forbidden"]
			r.ContentType = "application/problem+json"
			r.Variants = []snapshot.Variant{{ContentType: "text/html; charset=utf-8", Body: "<h1>{{status}}</h1>"}, {ContentType: "text/plain; charset=utf-8", Body: "{{status}}"}}
			c.Global.Responses["forbidden"] = r
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.request.uri.path eq "/v1/items"`), Settings: snapshot.Settings{Block: new("block")}})
		}, "/v1/items", 403, 13, 0, false, "", true},
		{"count rule counts a 404", func(c *snapshot.Config) {
			r := rlRule("sweep", "true", "sliding_window", 1_000_000_000, "ip")
			r.CountStatuses = []string{"404"}
			c.RateLimitRules = []snapshot.RateLimitRule{r}
		}, "/v1/missing", 404, 37, 0, false, "", false},
		// The expiry check adds no allocation.
		{"rule expiring later", func(c *snapshot.Config) {
			r := rlRule("ap-scraper", "true", "token_bucket", 1_000_000_000, "ip")
			r.FailMode = "local"
			c.RateLimitRules = []snapshot.RateLimitRule{r}
		}, "/v1/items?id=1", 200, 37, time.Hour, false, "", false},
		{"expired rule skipped", func(c *snapshot.Config) {
			r := rlRule("ap-scraper", "true", "token_bucket", 1, "ip")
			r.FailMode = "local"
			c.RateLimitRules = []snapshot.RateLimitRule{r}
		}, "/v1/items?id=1", 200, 36, -time.Minute, false, "", false},
		// The allowlist match adds no allocation, for a client on it or not. A
		// client on it here is spared a block, and a lifted block's access line
		// is always written, unlike a sampled allowed line: that line is the
		// one allocation over a plain allowed request.
		{"client on the allowlist", func(c *snapshot.Config) {
			c.Global.ClientAllowlist = []string{"198.51.100.0/24", "2001:db8:f00::/48"}
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent eq "bench"`), Settings: snapshot.Settings{Block: new("block")}})
			c.RateLimitRules = []snapshot.RateLimitRule{rlRule("per-ip", "true", "token_bucket", 1, "ip")}
		}, "/v1/items?id=1", 200, 37, 0, false, "", false},
		// An allow rule's match adds no allocation either. Its lifted block's
		// line is written as above, and names the allow rule too.
		{"client matched by an always-allow rule", func(c *snapshot.Config) {
			c.ConfigRules = append(c.ConfigRules,
				snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent eq "bench"`), Settings: snapshot.Settings{Block: new("block")}},
				snapshot.ConfigRule{ID: "office", Expression: mustParse(`ip.src in {198.51.100.0/24}`), Settings: snapshot.Settings{Allow: true}})
			c.RateLimitRules = []snapshot.RateLimitRule{rlRule("per-ip", "true", "token_bucket", 1, "ip")}
		}, "/v1/items?id=1", 200, 37, 0, false, "", false},
		// A matching request header rule allocates for its header write; the
		// access line is sampled out, so the copy of the match is not counted.
		{"request header rule matches", func(c *snapshot.Config) {
			c.RequestHeaderRules = []snapshot.HeaderRule{marker("mark", `http.user_agent eq "bench"`, "X-Seen", "yes")}
		}, "/v1/items?id=1", 200, 38, 0, false, "", false},
		{"client not on the allowlist", func(c *snapshot.Config) {
			c.Global.ClientAllowlist = []string{"203.0.113.0/24", "2001:db8:f00::/48"}
		}, "/v1/items?id=1", 200, 36, 0, false, "", false},
		// The ban lookup adds no allocation to a blocked request, or to a
		// request in a version with ban rules whose client is not banned.
		{"banned client", func(c *snapshot.Config) { addTrap(c) }, "/v1/items", 403, 13, 0, true, "", false},
		{"client not banned with ban rules present", func(c *snapshot.Config) { addTrap(c) }, "/v1/items?id=1", 200, 36, 0, false, "", false},
		// The list lookup adds no allocation, for a client on a list or not.
		{"client on an IP list", addDenyRule, "/v1/items", 403, 13, 0, false, "198.51.100.0/24", false},
		{"client not on an IP list", addDenyRule, "/v1/items?id=1", 200, 36, 0, false, "203.0.113.0/24", false},
		// A real browser's headers and page path, which signals and stats read.
		{"Chrome navigation allowed and proxied", func(*snapshot.Config) {}, browserTarget, 200, 40, 0, false, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(1)
			c.Global.Backstop.Limit, c.Global.Backstop.Burst = 1_000_000_000, 1_000_000_000
			tc.change(c)
			if tc.expires != 0 {
				expireRule(t, c, 0, time.Now().Add(tc.expires))
			}
			s, req := inMemoryEdge(t, c, tc.target)
			if tc.chrome {
				chromeHeaders(req.Header)
			}
			if tc.banned {
				s.edge.bans.Add(netip.MustParseAddr("198.51.100.7"), ratelimit.Ban{Rule: "trap", End: time.Now().Add(time.Hour).UnixMilli(), Host: "api.example.com", Path: "/wp-login.php"}, map[string]bool{"trap": true})
			}
			if tc.deny != "" {
				lists, err := expr.NewIPLists([]string{"aws"}, [][]netip.Prefix{{netip.MustParsePrefix(tc.deny)}})
				if err != nil {
					t.Fatal(err)
				}
				s.edge.lists.Store(lists)
			}
			if tc.status == 404 {
				s.edge.rp.Transport = cannedTransport{404}
			}
			serve := func() {
				w := httptest.NewRecorder()
				s.edge.ServeHTTP(w, req)
				if w.Code != tc.status {
					t.Fatalf("status %d, want %d", w.Code, tc.status)
				}
			}
			// The first request fills caches, and uses up a bucket of 1.
			s.edge.ServeHTTP(httptest.NewRecorder(), req)
			n := testing.AllocsPerRun(200, serve)
			t.Logf("%v allocations per request", n)
			if tc.status == 404 && s.store.load().active.local[0].Len() != 1 {
				t.Fatal("the count rule did not count the 404")
			}
			if n > tc.max {
				t.Fatalf("%v allocations per request, ceiling %v", n, tc.max)
			}
		})
	}
}

func addDenyRule(c *snapshot.Config) {
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "listed", Expression: mustParse(`client.ip_lists in {"aws"}`), Settings: snapshot.Settings{Block: new("block")}})
}

// addTrap adds a rule that bans, matching no benchmark request, so ban rules
// are present without the request tripping one.
func addTrap(c *snapshot.Config) {
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "trap", Expression: mustParse(`http.user_agent eq "trap"`), Settings: snapshot.Settings{Block: new("block"), Ban: new(dur(time.Hour))}})
}

// Locale resolution: a cache hit is one map read; a miss parses and
// matches.
func BenchmarkLocale(b *testing.B) {
	c := testConfig(1)
	c.Global.Locale = snapshot.Locale{Supported: []string{"en", "ko", "zh-Hant", "ja", "de", "fr"}, Default: "en"}
	compiled, _, errs := snapshot.Compile(c, testDeployment())
	if errs != nil {
		b.Fatal(errs)
	}
	b.Run("hit", func(b *testing.B) {
		l := newLocaleResolver(compiled)
		l.resolve("ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
		b.ReportAllocs()
		for b.Loop() {
			l.resolve("ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
		}
	})
	b.Run("miss", func(b *testing.B) {
		l := newLocaleResolver(compiled)
		b.ReportAllocs()
		for b.Loop() {
			l.match("ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
		}
	})
}
