package edge

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// corsConfig has three policies, selected by path prefix.
func corsConfig() *snapshot.Config {
	c := testConfig(1)
	c.Global.CORSPolicies = map[string]snapshot.CORSPolicy{
		"app": {Origins: []string{"https://a.example", "https://b.example"}, Methods: []string{"PUT"}, RequestHeaders: []string{"X-Api-Key"},
			ExposedHeaders: []string{"X-Total"}, Credentials: true, MaxAge: dur(10 * time.Minute)},
		"public": {Origins: []string{"*"}, RequestHeaders: []string{"*"}},
		"single": {Origins: []string{"https://only.example"}},
	}
	for _, p := range []string{"app", "public", "single"} {
		c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "cors-" + p, Expression: mustParse(`starts_with(http.request.uri.path, "/` + p + `/")`), Settings: snapshot.Settings{CORSPolicy: new(p)}})
	}
	return c
}

// Preflight is answered by the edge per the Fetch standard when a policy
// applies, and never reaches the upstream.
func TestCORSPreflight(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(corsConfig()))
	hits := 0
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { hits++ }
	pre := func(path, origin, method, headers string) *http.Response {
		hs := []string{"Origin", origin, "Access-Control-Request-Method", method}
		if headers != "" {
			hs = append(hs, "Access-Control-Request-Headers", headers)
		}
		resp := h.do("OPTIONS", path, nil, hs...)
		resp.Body.Close()
		return resp
	}
	cases := []struct {
		name, path, origin, method, headers string
		allowed                             bool
	}{
		{"listed origin, method and header", "/app/x", "https://a.example", "PUT", "x-api-key", true},
		{"a safelisted method needs no listing", "/app/x", "https://b.example", "GET", "", true},
		{"an unlisted origin", "/app/x", "https://evil.example", "PUT", "", false},
		{"an unlisted method", "/app/x", "https://a.example", "DELETE", "", false},
		{"an unlisted header", "/app/x", "https://a.example", "PUT", "x-api-key, x-other", false},
		{"any header under a wildcard policy", "/public/x", "https://any.example", "GET", "x-anything", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := pre(tc.path, tc.origin, tc.method, tc.headers)
			if resp.StatusCode != 204 || resp.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("status %d, headers %v", resp.StatusCode, resp.Header)
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin") != ""; got != tc.allowed {
				t.Fatalf("allowed=%v, headers %v", got, resp.Header)
			}
		})
	}

	resp := pre("/app/x", "https://a.example", "PUT", "x-api-key")
	want := map[string]string{
		"Access-Control-Allow-Origin": "https://a.example", "Access-Control-Allow-Credentials": "true",
		"Access-Control-Allow-Methods": "PUT", "Access-Control-Allow-Headers": "x-api-key",
		"Access-Control-Max-Age": "600", "Vary": "Origin",
	}
	for k, v := range want {
		if resp.Header.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, resp.Header.Get(k), v)
		}
	}
	if hits != 0 {
		t.Fatalf("preflight reached the upstream %d times", hits)
	}
	if h.srv.m.corsPreflight.Load() != 4 || h.srv.m.corsPreflightDenied.Load() != 3 {
		t.Fatalf("preflight metrics %d/%d", h.srv.m.corsPreflight.Load(), h.srv.m.corsPreflightDenied.Load())
	}

	// Without a policy, preflight is the upstream's business.
	pre("/none", "https://a.example", "PUT", "")
	if hits != 1 {
		t.Fatal("preflight without a policy was not forwarded")
	}
}

// Responses under a policy carry CORS headers from the policy alone; the
// upstream's own Access-Control-* headers are replaced.
func TestCORSResponses(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(corsConfig()))
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "DELETE")
		w.Header().Set("Vary", "Accept-Encoding")
	}
	cases := []struct {
		name, path, origin string
		want               map[string]string
		vary               []string
	}{
		{"an allowed origin is echoed with credentials and exposed headers", "/app/x", "https://a.example",
			map[string]string{"Access-Control-Allow-Origin": "https://a.example", "Access-Control-Allow-Credentials": "true", "Access-Control-Expose-Headers": "X-Total", "Access-Control-Allow-Methods": ""},
			[]string{"Accept-Encoding", "Origin"}},
		{"another origin gets no CORS headers but still varies", "/app/x", "https://evil.example",
			map[string]string{"Access-Control-Allow-Origin": "", "Access-Control-Allow-Credentials": ""},
			[]string{"Accept-Encoding", "Origin"}},
		{"a wildcard policy doesn't vary by origin", "/public/x", "https://any.example",
			map[string]string{"Access-Control-Allow-Origin": "*"},
			[]string{"Accept-Encoding"}},
		{"a single-origin policy always names it", "/single/x", "",
			map[string]string{"Access-Control-Allow-Origin": "https://only.example"},
			[]string{"Accept-Encoding"}},
		{"without a policy the upstream's headers pass through", "/none", "https://a.example",
			map[string]string{"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "DELETE"},
			[]string{"Accept-Encoding"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hs []string
			if tc.origin != "" {
				hs = []string{"Origin", tc.origin}
			}
			resp := h.do("GET", tc.path, nil, hs...)
			resp.Body.Close()
			for k, v := range tc.want {
				if resp.Header.Get(k) != v {
					t.Errorf("%s = %q, want %q", k, resp.Header.Get(k), v)
				}
			}
			if got := resp.Header.Values("Vary"); fmt.Sprint(got) != fmt.Sprint(tc.vary) {
				t.Errorf("Vary = %v, want %v", got, tc.vary)
			}
		})
	}

	// Edge-generated responses after step 4 carry the request's CORS
	// headers, so browser code can read a 429 or 503.
	c := corsConfig()
	c.Version = 2
	r := rlRule("cors-closed", `starts_with(http.request.uri.path, "/app/")`, "sliding_window", 1, "ip")
	r.FailMode = "closed"
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	h.load(envelope(c))
	resp := h.do("GET", "/app/x", nil, "Origin", "https://b.example")
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://b.example" {
		t.Fatalf("edge 503 without CORS: %v", resp.Header)
	}
	edgeError(t, resp, 503, "unavailable")
}
