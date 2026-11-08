package edge

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

const (
	// trustedRange holds the harness's default client, 198.51.100.7.
	trustedRange = "198.51.100.0/24"
	// otherClient is outside every allowlist these tests use.
	otherClient = "203.0.113.9:1"
)

// allowlistConfig blocks curl by config rule and trusts entries.
func allowlistConfig(version int64, entries ...string) *snapshot.Config {
	c := testConfig(version)
	c.Global.ClientAllowlist = entries
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "tools", Expression: mustParse(`http.user_agent contains "curl"`), Settings: snapshot.Settings{Block: new("block")}})
	return c
}

// ruleReport is what the edge reports for config rule id since the last
// report: how often it blocked and would have blocked.
func ruleReport(t *testing.T, h *harness, id string) (blocked, wouldBlock float64) {
	t.Helper()
	b, err := json.Marshal(h.srv.poller.reg.deltas()[0])
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Rules {
		if r["id"] == id {
			blocked, _ = r["blocked"].(float64)
			wouldBlock, _ = r["would_block"].(float64)
		}
	}
	return blocked, wouldBlock
}

// valkeyKeys lists the Valkey keys that contain part.
func valkeyKeys(t *testing.T, part string) []string {
	t.Helper()
	raw, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{testenv.Valkey(t)}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	keys, err := raw.Do(t.Context(), raw.B().Keys().Pattern("*"+part+"*").Build()).AsStrSlice()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// A client on the allowlist is not blocked by a config rule, neither one
// that blocks nor one that only logs, and is not counted as blocked or as
// would-block. Everyone else is judged as before.
func TestTrustedClientSkipsConfigBlocks(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		client   string
		status   int
		decision string
		blocked  float64
		// The rule's own report: requests it blocked and would have blocked.
		ruleBlocked, ruleWouldBlock float64
	}{
		{"trusted client on a block rule", "block", "198.51.100.7:1", 200, "allow", 0, 0, 0},
		{"other client on a block rule", "block", otherClient, 403, "blocked", 1, 1, 0},
		{"trusted client on a log rule", "log", "198.51.100.7:1", 200, "allow", 0, 0, 0},
		{"other client on a log rule", "log", otherClient, 200, "would_block", 0, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
			c := allowlistConfig(1, trustedRange)
			c.ConfigRules[2].Settings.Block = &tc.mode
			h.load(envelope(c))
			resp := h.do("GET", "/", nil, "User-Agent", "curl/8.5.0", "CloudFront-Viewer-Address", tc.client)
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
			waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
			if got := h.logs.lines("access")[0]["edge.decision"]; got != tc.decision {
				t.Fatalf("decision %v, want %s", got, tc.decision)
			}
			if got := h.metrics()[`edge_rejected_total{reason="blocked"}`]; got != tc.blocked {
				t.Fatalf("blocked count %v, want %v", got, tc.blocked)
			}
			if b, w := ruleReport(t, h, "tools"); b != tc.ruleBlocked || w != tc.ruleWouldBlock {
				t.Fatalf("rule report blocked %v would_block %v, want %v and %v", b, w, tc.ruleBlocked, tc.ruleWouldBlock)
			}
		})
	}
}

// A client on the allowlist skips every configured rate-limit rule: no
// quota is used, no Valkey key is written, and nothing is counted as
// evaluated. Other clients are limited as before.
func TestTrustedClientSkipsRateLimits(t *testing.T) {
	t.Run("rule that blocks over its limit", func(t *testing.T) {
		h := valkeyHarness(t, nil)
		c := allowlistConfig(1, trustedRange)
		id := uniq("login")
		c.RateLimitRules = []snapshot.RateLimitRule{rlRule(id, "true", "sliding_window", 1, "ip")}
		h.load(envelope(c))
		if got := h.statuses(5, "GET", "/"); !eqInts(got, 200, 200, 200, 200, 200) {
			t.Fatalf("trusted client: %v", got)
		}
		if n := h.ruleOutcome(id, "evaluated"); n != 0 {
			t.Fatalf("evaluated %v", n)
		}
		if keys := valkeyKeys(t, id); len(keys) != 0 {
			t.Fatalf("Valkey keys for a trusted client: %v", keys)
		}
		if got := h.statuses(2, "GET", "/", "CloudFront-Viewer-Address", otherClient); !eqInts(got, 200, 429) {
			t.Fatalf("other client: %v", got)
		}
	})

	t.Run("autopilot rule that expires later", func(t *testing.T) {
		h := valkeyHarness(t, nil)
		c := allowlistConfig(1, trustedRange)
		id := uniq("ap-scraper")
		c.RateLimitRules = []snapshot.RateLimitRule{rlRule(id, "true", "sliding_window", 1, "ip")}
		expireRule(t, c, 0, time.Now().Add(time.Hour))
		h.load(envelope(c))
		if got := h.statuses(3, "GET", "/"); !eqInts(got, 200, 200, 200) {
			t.Fatalf("trusted client: %v", got)
		}
		if keys := valkeyKeys(t, id); len(keys) != 0 {
			t.Fatalf("Valkey keys for a trusted client: %v", keys)
		}
		if got := h.statuses(2, "GET", "/", "CloudFront-Viewer-Address", otherClient); !eqInts(got, 200, 429) {
			t.Fatalf("other client: %v", got)
		}
	})

	t.Run("rule that rejects a request missing its key", func(t *testing.T) {
		h := valkeyHarness(t, nil)
		c := allowlistConfig(1, trustedRange)
		r := rlRule(uniq("api-key"), "true", "sliding_window", 100, "header:x-api-key", "ip")
		r.OnMissingKey = "reject"
		c.RateLimitRules = []snapshot.RateLimitRule{r}
		h.load(envelope(c))
		if got := h.statuses(1, "GET", "/"); !eqInts(got, 200) {
			t.Fatalf("trusted client without a key: %v", got)
		}
		edgeError(t, h.do("GET", "/", nil, "CloudFront-Viewer-Address", otherClient), 400, "bad_request")
	})

	t.Run("rule that counts response statuses", func(t *testing.T) {
		h := newHarness(t, nil)
		c := allowlistConfig(1, trustedRange)
		c.RateLimitRules = []snapshot.RateLimitRule{rlRule("not-found", "true", "sliding_window", 1, "ip")}
		h.appHandler = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }
		h.loadJSON(envelope(c), countStatuses(0, "404"))
		if got := h.statuses(3, "GET", "/missing"); !eqInts(got, 404, 404, 404) {
			t.Fatalf("trusted client: %v", got)
		}
		if got := h.statuses(3, "GET", "/missing", "CloudFront-Viewer-Address", otherClient); !eqInts(got, 404, 404, 429) {
			t.Fatalf("other client: %v", got)
		}
	})

	t.Run("client under a penalty", func(t *testing.T) {
		h := valkeyHarness(t, nil)
		r := rlRule(uniq("penalty"), "true", "sliding_window", 1, "ip")
		r.Penalty = dur(10 * time.Minute)
		without := func(version int64) *snapshot.Config {
			c := allowlistConfig(version)
			c.RateLimitRules = []snapshot.RateLimitRule{r}
			return c
		}
		h.load(envelope(without(1)))
		if got := h.statuses(2, "GET", "/"); !eqInts(got, 200, 429) {
			t.Fatalf("before trusting: %v", got)
		}
		trusted := without(2)
		trusted.Global.ClientAllowlist = []string{trustedRange}
		h.load(envelope(trusted))
		hits := h.srv.m.penaltyHits.Load()
		if got := h.statuses(2, "GET", "/"); !eqInts(got, 200, 200) {
			t.Fatalf("while trusted: %v", got)
		}
		if h.srv.m.penaltyHits.Load() != hits {
			t.Fatal("the penalty cache answered a trusted client")
		}
		h.load(envelope(without(3)))
		edgeError(t, h.do("GET", "/", nil), 429, "rate_limited")
	})
}

// A client on the allowlist needs no token on a route that requires one, but
// a token it sends is still verified: a bad one is refused, a good one
// gives the upstream its identity and claims as for anyone. Others still
// need a token.
func TestTrustedClientNeedsNoToken(t *testing.T) {
	h, idp := newAuthHarness(t)
	c := authConfig(idp)
	c.Version = 2
	c.Global.ClientAllowlist = []string{trustedRange}
	h.load(authEnvelope(c))
	noIdentity := func(t *testing.T) {
		t.Helper()
		if h.upstreamHeader("X-Edge-Auth-Issuer") != "" || h.upstreamHeader("X-Edge-Auth-Sub") != "" || h.upstreamHeader("X-Tenant") != "" {
			t.Fatalf("identity sent for a request without a verified token: %v", h.lastApp.Header)
		}
	}

	t.Run("required route without a token", func(t *testing.T) {
		if body := readBody(t, h.do("GET", "/private/x", nil)); body != "upstream ok" {
			t.Fatalf("body %q", body)
		}
		noIdentity(t)
	})
	t.Run("a forged identity header is still stripped", func(t *testing.T) {
		readBody(t, h.do("GET", "/private/x", nil, "X-Edge-Auth-Sub", "admin"))
		noIdentity(t)
	})
	t.Run("route for another issuer without a token", func(t *testing.T) {
		if body := readBody(t, h.do("GET", "/partner/x", nil)); body != "upstream ok" {
			t.Fatalf("body %q", body)
		}
		noIdentity(t)
	})
	t.Run("a malformed token is refused", func(t *testing.T) {
		h.lastApp = nil
		unauthorized(t, h.do("GET", "/private/x", nil, bearerOf("garbage")...), `Bearer error="invalid_token"`)
		if h.lastApp != nil {
			t.Fatal("reached the upstream")
		}
	})
	t.Run("a valid token gives identity and claims", func(t *testing.T) {
		tok := corpToken()
		if body := readBody(t, h.do("GET", "/private/x", nil, bearerOf(tok)...)); body != "upstream ok" {
			t.Fatalf("body %q", body)
		}
		if h.upstreamHeader("X-Edge-Auth-Issuer") != "corp" || h.upstreamHeader("X-Edge-Auth-Sub") != "user-1" || h.upstreamHeader("X-Tenant") != "acme" || h.upstreamHeader("Authorization") != "Bearer "+tok {
			t.Fatalf("upstream headers %v", h.lastApp.Header)
		}
	})

	m := h.metrics()
	for result, want := range map[string]float64{"missing": 3, "invalid": 1, "verified": 1, "cached": 0} {
		if got := m[`edge_auth_total{result="`+result+`"}`]; got != want {
			t.Errorf("auth result %s counted %v times, want %v", result, got, want)
		}
	}
	t.Run("another client still needs a token", func(t *testing.T) {
		unauthorized(t, h.do("GET", "/private/x", nil, "CloudFront-Viewer-Address", otherClient), "Bearer")
	})
}

// Everything that is not enforcement still applies to a client on the
// allowlist.
func TestTrustedClientKeepsRetainedProtections(t *testing.T) {
	newTrusted := func(t *testing.T, set map[string]string, change func(c *snapshot.Config)) *harness {
		t.Helper()
		h := newHarness(t, set)
		c := allowlistConfig(1, trustedRange)
		if change != nil {
			change(c)
		}
		h.load(envelope(c))
		return h
	}

	t.Run("backstop still limits", func(t *testing.T) {
		h := newTrusted(t, nil, func(c *snapshot.Config) {
			c.Global.Backstop = snapshot.Backstop{Limit: 2, Period: dur(time.Minute), Burst: 2, MaxEntries: 1000}
		})
		if got := h.statuses(3, "GET", "/"); !eqInts(got, 200, 200, 429) {
			t.Fatalf("got %v", got)
		}
		if h.srv.m.rejected[reasonBackstop].Load() != 1 {
			t.Fatal("backstop rejection not counted")
		}
	})

	t.Run("CORS headers still sent", func(t *testing.T) {
		h := newTrusted(t, nil, func(c *snapshot.Config) {
			c.Global.CORSPolicies = map[string]snapshot.CORSPolicy{"app": {Origins: []string{"https://a.example"}}}
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "cors", Expression: mustParse("true"), Settings: snapshot.Settings{CORSPolicy: new("app")}})
		})
		resp := h.do("GET", "/", nil, "Origin", "https://a.example")
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "https://a.example" {
			t.Fatalf("status %d, headers %v", resp.StatusCode, resp.Header)
		}
	})

	t.Run("header rules and sanitation still run", func(t *testing.T) {
		h := newTrusted(t, nil, func(c *snapshot.Config) {
			c.RequestHeaderRules = []snapshot.HeaderRule{{ID: "mark", Expression: mustParse("true"), Ops: []snapshot.HeaderOp{{Op: "set", Name: "X-Seen", Value: "yes"}}}}
		})
		readBody(t, h.do("GET", "/", nil, "X-Edge-Auth-Sub", "admin"))
		if h.upstreamHeader("X-Seen") != "yes" || h.upstreamHeader("X-Edge-Auth-Sub") != "" {
			t.Fatalf("upstream headers %v", h.lastApp.Header)
		}
	})

	t.Run("body limit still applies", func(t *testing.T) {
		h := newTrusted(t, nil, nil)
		edgeError(t, h.do("POST", "/", strings.NewReader(strings.Repeat("x", 2048))), 413, "payload_too_large")
	})

	t.Run("ambiguous path still rejected", func(t *testing.T) {
		h := newTrusted(t, nil, nil)
		resp := h.do("GET", "/a%5Cb", nil)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("peer outside TRUSTED_PROXIES still rejected", func(t *testing.T) {
		h := newTrusted(t, map[string]string{"TRUSTED_PROXIES": "10.0.0.0/8"}, nil)
		hits := 0
		h.appHandler = func(w http.ResponseWriter, r *http.Request) { hits++ }
		edgeError(t, h.do("GET", "/", nil), 400, "bad_request")
		if hits != 0 {
			t.Fatalf("upstream hits %d", hits)
		}
	})
}

// Only the client IP the edge derives from its trusted proxies matches. A
// header the client forged never puts it on the list.
func TestTrustedClientMatchesOnlyTheDerivedClientIP(t *testing.T) {
	cases := []struct {
		name      string
		set       map[string]string
		allowlist string
		headers   []string
		status    int
	}{
		{"forged viewer header with the TCP peer as the client", map[string]string{"CLIENT_IP_SOURCE": "remote_addr", "TRUSTED_PROXIES": ""}, trustedRange,
			[]string{"CloudFront-Viewer-Address", "198.51.100.7:1", "X-Forwarded-For", "198.51.100.7"}, 403},
		{"TCP peer on the allowlist", map[string]string{"CLIENT_IP_SOURCE": "remote_addr", "TRUSTED_PROXIES": ""}, "127.0.0.1", nil, 200},
		{"forged left-hand X-Forwarded-For entry", map[string]string{"CLIENT_IP_SOURCE": "xff"}, trustedRange,
			[]string{"X-Forwarded-For", "198.51.100.7, 203.0.113.9"}, 403},
		{"real client in X-Forwarded-For on the allowlist", map[string]string{"CLIENT_IP_SOURCE": "xff"}, trustedRange,
			[]string{"X-Forwarded-For", "203.0.113.9, 198.51.100.7"}, 200},
		{"mapped IPv4 viewer address", nil, trustedRange, []string{"CloudFront-Viewer-Address", "[::ffff:198.51.100.7]:1"}, 200},
		{"IPv6 viewer inside an IPv6 range", nil, "2001:db8:f00::/48", []string{"CloudFront-Viewer-Address", "[2001:db8:f00::9]:1"}, 200},
		{"IPv6 viewer outside an IPv6 range", nil, "2001:db8:f00::/48", []string{"CloudFront-Viewer-Address", "[2001:db8:f01::9]:1"}, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.set)
			h.load(envelope(allowlistConfig(1, tc.allowlist)))
			resp := h.do("GET", "/", nil, append([]string{"User-Agent", "curl/8.5.0"}, tc.headers...)...)
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

// An access line names the matched entry beside the final outcome, so a
// trusted request that a retained protection rejects is still reported as
// rejected. The match is counted, and logging is not forced for it.
func TestTrustedClientIsLoggedAndCounted(t *testing.T) {
	t.Run("sampled in", func(t *testing.T) {
		h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
		c := allowlistConfig(1, trustedRange)
		c.Global.Backstop = snapshot.Backstop{Limit: 1, Period: dur(time.Minute), Burst: 1, MaxEntries: 1000}
		h.load(envelope(c))
		if got := h.statuses(2, "GET", "/", "User-Agent", "curl/8.5.0"); !eqInts(got, 200, 429) {
			t.Fatalf("trusted client: %v", got)
		}
		if got := h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", otherClient); !eqInts(got, 200) {
			t.Fatalf("other client: %v", got)
		}
		waitFor(t, func() bool { return len(h.logs.lines("access")) == 3 })
		lines := h.logs.lines("access")
		want := []struct{ decision, allowlist any }{{"allow", trustedRange}, {"backstop", trustedRange}, {"allow", nil}}
		for i, w := range want {
			if lines[i]["edge.decision"] != w.decision || lines[i]["edge.allowlist"] != w.allowlist {
				t.Fatalf("line %d: decision %v allowlist %v, want %v %v", i, lines[i]["edge.decision"], lines[i]["edge.allowlist"], w.decision, w.allowlist)
			}
		}
		m := h.metrics()
		if m["edge_allowlisted_total"] != 2 || m[`edge_rejected_total{reason="blocked"}`] != 0 {
			t.Fatalf("allowlisted %v, blocked %v", m["edge_allowlisted_total"], m[`edge_rejected_total{reason="blocked"}`])
		}
	})

	t.Run("sampled out", func(t *testing.T) {
		h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "0"})
		h.load(envelope(allowlistConfig(1, trustedRange)))
		h.statuses(1, "GET", "/")
		// Rejections are always logged and lines are written in order, so
		// once this one is there a line for the trusted request would be too.
		h.statuses(1, "GET", "/", "User-Agent", "curl/8.5.0", "CloudFront-Viewer-Address", otherClient)
		waitFor(t, func() bool { return len(h.logs.lines("access")) >= 1 })
		lines := h.logs.lines("access")
		if _, ok := lines[0]["edge.allowlist"]; len(lines) != 1 || ok || lines[0]["edge.decision"] != "blocked" {
			t.Fatalf("access lines = %v", lines)
		}
		if got := h.metrics()["edge_allowlisted_total"]; got != 1 {
			t.Fatalf("allowlisted %v, want 1", got)
		}
	})
}

// During a canary a request meets the allowlist of the version it is pinned
// to, not the other one's.
func TestCanaryUsesThePinnedVersionsAllowlist(t *testing.T) {
	in, out := ipWithCohort(t, true, 5000), ipWithCohort(t, false, 5000)
	cases := []struct {
		name              string
		active, candidate []string
		client            string
		status            int
	}{
		{"in-cohort client listed only by the candidate", nil, []string{in}, in, 200},
		{"out-of-cohort client listed only by the candidate", nil, []string{out}, out, 403},
		{"out-of-cohort client listed only by the active version", []string{out}, nil, out, 200},
		{"in-cohort client listed only by the active version", []string{in}, nil, in, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			e := envelope(allowlistConfig(1, tc.active...))
			e.Candidate, e.CanaryPercent, e.CanaryExpiresAt = allowlistConfig(2, tc.candidate...), 50, time.Now().Add(time.Hour)
			h.load(e)
			resp := h.do("GET", "/", nil, "User-Agent", "curl/8.5.0", "CloudFront-Viewer-Address", tc.client+":1")
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}
