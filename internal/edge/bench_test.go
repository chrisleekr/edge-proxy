package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// cannedTransport answers every upstream request in memory, so the
// benchmark measures the edge, not the network.
type cannedTransport struct{}

func (cannedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": {"2"}}, ContentLength: 2, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
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
	s := New(cfg, newTestLogger(io.Discard))
	if err := s.poller.apply(envelope(c), "admin", 0); err != nil {
		tb.Fatal(err)
	}
	s.edge.rp.Transport = cannedTransport{}
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
	}{
		{"allowed and proxied", func(*snapshot.Config) {}, "/v1/items?id=1", 200, 36},
		{"allowed with RateLimit headers", func(c *snapshot.Config) {
			r := rlRule("per-ip", "true", "token_bucket", 1_000_000_000, "ip")
			r.FailMode = "local"
			c.RateLimitRules = []snapshot.RateLimitRule{r}
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "headers", Expression: mustParse("true"), Settings: snapshot.Settings{RateLimitHeaders: new(true)}})
		}, "/v1/items?id=1", 200, 43},
		{"rate limited with RateLimit headers", func(c *snapshot.Config) {
			r := rlRule("per-ip", "true", "token_bucket", 1, "ip")
			r.FailMode = "local"
			c.RateLimitRules = []snapshot.RateLimitRule{r}
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "headers", Expression: mustParse("true"), Settings: snapshot.Settings{RateLimitHeaders: new(true)}})
		}, "/v1/items", 429, 19},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(1)
			c.Global.Backstop.Limit, c.Global.Backstop.Burst = 1_000_000_000, 1_000_000_000
			tc.change(c)
			s, req := inMemoryEdge(t, c, tc.target)
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
			if n > tc.max {
				t.Fatalf("%v allocations per request, ceiling %v", n, tc.max)
			}
		})
	}
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
