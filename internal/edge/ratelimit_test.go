package edge

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

// uniq makes rule IDs unique per test, so Valkey keys never collide between
// tests sharing the container.
func uniq(name string) string {
	return name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// valkeyHarness is a replica connected to the shared test Valkey. The
// production 50ms VALKEY_TIMEOUT is shorter than the Docker round trip
// under a loaded test run, and a timed-out call fails open, so enforcement
// assertions would depend on host load.
func valkeyHarness(t *testing.T, set map[string]string) *harness {
	t.Helper()
	e := map[string]string{"VALKEY_URL": "redis://" + testenv.Valkey(t), "VALKEY_TIMEOUT": "5s"}
	maps.Copy(e, set)
	h := newHarness(t, e)
	if err := h.srv.edge.valkey.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.srv.edge.valkey.Run(canceled()) })
	return h
}

// canceled is a done context: Run then closes the client and returns.
func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func (h *harness) ruleStats(i int) *ruleStats { return &h.srv.store.load().active.stats.rules[i] }

func netipMust(s string) netip.Addr { return netip.MustParseAddr(s) }

func eqInts(a []int, b ...int) bool {
	return fmt.Sprint(a) == fmt.Sprint(b)
}

// The backstop answers 429 per client IP before any rule runs, and keeps
// its state across snapshots unless its own settings change.
func TestBackstop(t *testing.T) {
	h := newHarness(t, nil)
	c := testConfig(1)
	c.Global.Backstop = snapshot.Backstop{Limit: 2, Period: dur(time.Minute), Burst: 2, MaxEntries: 1000}
	h.load(envelope(c))
	if got := h.statuses(2, "GET", "/"); !eqInts(got, 200, 200) {
		t.Fatalf("under the backstop: %v", got)
	}
	m := edgeError(t, h.do("GET", "/", nil), 429, "rate_limited")
	if m["retry_after"].(float64) < 25 {
		t.Fatalf("retry_after %v; a token takes 30s at 2/min", m["retry_after"])
	}
	if h.srv.m.rejected[reasonBackstop].Load() != 1 {
		t.Fatal("backstop rejection not counted")
	}
	if got := h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", "198.51.100.8:1"); !eqInts(got, 200) {
		t.Fatalf("another client was limited: %v", got)
	}

	c2 := testConfig(2)
	c2.Global.Backstop = c.Global.Backstop
	h.load(envelope(c2))
	if got := h.statuses(1, "GET", "/"); !eqInts(got, 429) {
		t.Fatalf("a publish reset the backstop: %v", got)
	}
	c3 := testConfig(3)
	c3.Global.Backstop = snapshot.Backstop{Limit: 3, Period: dur(time.Minute), Burst: 3, MaxEntries: 1000}
	h.load(envelope(c3))
	if got := h.statuses(1, "GET", "/"); !eqInts(got, 200) {
		t.Fatalf("new backstop settings kept old state: %v", got)
	}
}

// A full backstop table lets new clients pass untracked and counts them.
func TestBackstopFull(t *testing.T) {
	h := newHarness(t, nil)
	c := testConfig(1)
	c.Global.Backstop.MaxEntries = 1 // one client per shard
	h.load(envelope(c))
	for i := range 300 {
		h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", fmt.Sprintf("10.0.%d.%d:1", i/250, i%250))
	}
	if h.srv.m.backstopUntracked.Load() == 0 {
		t.Fatal("no client went untracked with a full table")
	}
}

// A blocking rule over its limit answers 429 from the rate_limited template
// without reaching the upstream, and the access log names the rule.
func TestRateLimitBlocks(t *testing.T) {
	h := valkeyHarness(t, nil)
	c := testConfig(1)
	id := uniq("login")
	c.RateLimitRules = []snapshot.RateLimitRule{rlRule(id, `http.request.uri.path eq "/login"`, "sliding_window", 2, "ip")}
	h.load(envelope(c))
	hits := 0
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { hits++ }
	if got := h.statuses(2, "POST", "/login"); !eqInts(got, 200, 200) {
		t.Fatalf("under the limit: %v", got)
	}
	resp := h.do("POST", "/login", nil)
	ra, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
	edgeError(t, resp, 429, "rate_limited")
	// Up to the window end, plus period/limit while the current window is full.
	if ra < 1 || ra > 90 || hits != 2 {
		t.Fatalf("Retry-After %d, upstream hits %d", ra, hits)
	}
	if got := h.statuses(1, "GET", "/other"); !eqInts(got, 200) {
		t.Fatalf("a path the rule doesn't match was limited: %v", got)
	}
	waitFor(t, func() bool {
		for _, l := range h.logs.lines("access") {
			if l["edge.rate_limit_rule"] == id {
				return true
			}
		}
		return false
	})
	if s := h.ruleStats(0); s.evaluated.Load() != 3 || s.limited.Load() != 1 {
		t.Fatalf("stats evaluated=%d limited=%d", s.evaluated.Load(), s.limited.Load())
	}
}

// After a penalty starts, this replica answers from its local copy without
// calling Valkey. When the local copy is full, Valkey still enforces it.
func TestPenalty(t *testing.T) {
	h := valkeyHarness(t, nil)
	c := testConfig(1)
	r := rlRule(uniq("penalty"), "true", "sliding_window", 1, "ip")
	r.Penalty = dur(10 * time.Minute)
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	h.load(envelope(c))
	if got := h.statuses(2, "GET", "/"); !eqInts(got, 200, 429) {
		t.Fatalf("got %v", got)
	}
	resp := h.do("GET", "/", nil)
	if ra, _ := strconv.Atoi(resp.Header.Get("Retry-After")); ra < 590 {
		t.Fatalf("Retry-After %d during a 10m penalty", ra)
	}
	edgeError(t, resp, 429, "rate_limited")
	if h.srv.m.penaltyHits.Load() != 1 {
		t.Fatalf("penalty cache hits %d", h.srv.m.penaltyHits.Load())
	}

	h.srv.edge.penalties = ratelimit.NewPenalties(1)
	for i := range 1000 {
		h.srv.edge.penalties.Block(fmt.Sprint("other", i), time.Now().Add(time.Hour).UnixMilli())
	}
	if got := h.statuses(2, "GET", "/"); !eqInts(got, 429, 429) {
		t.Fatalf("penalty lost with a full local cache: %v", got)
	}
	if h.srv.m.penaltyDropped.Load() == 0 {
		t.Fatal("dropped penalty not counted")
	}
}

// A shadow rule counts what it would limit and never blocks. The kill switch
// makes every rule a shadow rule; counting continues underneath it.
func TestShadowAndKillSwitch(t *testing.T) {
	h := valkeyHarness(t, nil)
	c := testConfig(1)
	shadow := rlRule(uniq("shadow"), `http.request.uri.path eq "/s"`, "sliding_window", 1, "ip")
	shadow.Action = "log"
	block := rlRule(uniq("block"), `http.request.uri.path eq "/b"`, "sliding_window", 1, "ip")
	block.Penalty = dur(time.Hour)
	c.RateLimitRules = []snapshot.RateLimitRule{shadow, block}
	h.load(envelope(c))
	if got := h.statuses(3, "GET", "/s"); !eqInts(got, 200, 200, 200) {
		t.Fatalf("shadow rule blocked: %v", got)
	}
	if h.ruleStats(0).wouldLimit.Load() != 2 {
		t.Fatalf("would-limit %d", h.ruleStats(0).wouldLimit.Load())
	}

	k := testConfig(2)
	k.RateLimitRules = c.RateLimitRules
	k.KillSwitch.RateLimit = true
	h.load(envelope(k))
	if got := h.statuses(3, "GET", "/b"); !eqInts(got, 200, 200, 200) {
		t.Fatalf("kill switch blocked: %v", got)
	}
	if h.ruleStats(1).wouldLimit.Load() != 2 {
		t.Fatalf("would-limit under kill switch %d", h.ruleStats(1).wouldLimit.Load())
	}
	if h.srv.edge.penalties.Len() != 0 {
		t.Fatal("a penalty started under the kill switch")
	}
	c3 := testConfig(3)
	c3.RateLimitRules = c.RateLimitRules
	h.load(envelope(c3))
	// Counting continued underneath, so the subject is already over.
	edgeError(t, h.do("GET", "/b", nil), 429, "rate_limited")
}

// on_missing_key decides what happens when a characteristic is absent.
func TestOnMissingKey(t *testing.T) {
	h := valkeyHarness(t, nil)
	c := testConfig(1)
	mk := func(path, mode string) snapshot.RateLimitRule {
		r := rlRule(uniq(mode), `http.request.uri.path eq "`+path+`"`, "sliding_window", 1, "ip", "header:x-tenant")
		r.OnMissingKey = mode
		return r
	}
	c.RateLimitRules = []snapshot.RateLimitRule{mk("/skip", "skip"), mk("/fallback", "fallback_ip"), mk("/reject", "reject")}
	h.load(envelope(c))
	cases := []struct {
		name    string
		path    string
		headers []string
		want    []int
	}{
		{"skip lets requests without the header bypass the rule", "/skip", nil, []int{200, 200, 200}},
		{"skip still limits requests with the header", "/skip", []string{"X-Tenant", "a"}, []int{200, 429}},
		{"fallback_ip limits requests without the header by IP", "/fallback", nil, []int{200, 429}},
		{"fallback_ip keys requests with the header on it", "/fallback", []string{"X-Tenant", "a"}, []int{200, 429}},
		{"reject answers 400 without the header", "/reject", nil, []int{400}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.statuses(len(tc.want), "GET", tc.path, tc.headers...); !eqInts(got, tc.want...) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	if h.srv.m.rejected[reasonRateLimitKey].Load() != 1 {
		t.Fatal("missing-key rejection not counted")
	}
}

// Requests share a bucket exactly when every key characteristic matches.
// Each case sends request a, then b, against a limit of 1.
func TestKeyCharacteristics(t *testing.T) {
	cases := []struct {
		name   string
		key    []string
		a, b   []string // header pairs
		shared bool
	}{
		{"same IP shares", []string{"ip"}, nil, nil, true},
		{"different IPs don't share", []string{"ip"}, nil, []string{"CloudFront-Viewer-Address", "198.51.100.8:1"}, false},
		{"one IPv6 /64 shares", []string{"ip"}, []string{"CloudFront-Viewer-Address", "[2001:db8::1]:1"}, []string{"CloudFront-Viewer-Address", "[2001:db8::2]:1"}, true},
		{"header values split buckets", []string{"ip", "header:x-api-key"}, []string{"X-Api-Key", "a"}, []string{"X-Api-Key", "b"}, false},
		{"equal header values share", []string{"ip", "header:x-api-key"}, []string{"X-Api-Key", "a"}, []string{"X-Api-Key", "a"}, true},
		{"cookies split buckets", []string{"ip", "cookie:session"}, []string{"Cookie", "session=a"}, []string{"Cookie", "session=b"}, false},
		{"query arguments split buckets", []string{"ip", "query:page"}, nil, []string{"_target", "/?page=2"}, false},
		{"hosts split buckets", []string{"ip", "host"}, nil, []string{"Host", "www.example.com"}, false},
		{"a trailing-dot host is the same host", []string{"ip", "host"}, nil, []string{"Host", "api.example.com."}, true},
		{"methods split buckets", []string{"ip", "method"}, nil, []string{"_method", "POST"}, false},
		{"countries split buckets", []string{"country"}, []string{"CloudFront-Viewer-Country", "AU"}, []string{"CloudFront-Viewer-Country", "NZ"}, false},
		{"a missing country falls back to the IP", []string{"country"}, nil, nil, true},
		{"AS numbers split buckets", []string{"asnum"}, []string{"CloudFront-Viewer-ASN", "13335"}, []string{"CloudFront-Viewer-ASN", "15169"}, false},
		{"a missing AS number falls back to the IP", []string{"asnum"}, nil, []string{"CloudFront-Viewer-Address", "198.51.100.8:1"}, false},
		{"constant puts everyone in one bucket", []string{"constant"}, nil, []string{"CloudFront-Viewer-Address", "198.51.100.8:1"}, true},
		// Claims arrive with JWT verification (M6); until then they are missing.
		{"an absent JWT claim falls back to the IP", []string{"jwt_claim:sub"}, nil, nil, true},
		// The locale is resolved in M5; until then it is missing.
		{"an unresolved locale falls back to the IP", []string{"locale"}, nil, nil, true},
	}
	h := valkeyHarness(t, nil)
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(int64(i + 1))
			c.Global.Locale = snapshot.Locale{Supported: []string{"en"}, Default: "en"}
			c.RateLimitRules = []snapshot.RateLimitRule{rlRule(uniq("key"), "true", "sliding_window", 1, tc.key...)}
			h.load(envelope(c))
			send := func(hs []string) int {
				method, target := "GET", "/"
				var rest []string
				for j := 0; j+1 < len(hs); j += 2 {
					switch hs[j] {
					case "_method":
						method = hs[j+1]
					case "_target":
						target = hs[j+1]
					default:
						rest = append(rest, hs[j], hs[j+1])
					}
				}
				return h.statuses(1, method, target, rest...)[0]
			}
			if send(tc.a) != 200 {
				t.Fatal("first request limited")
			}
			if got := send(tc.b); (got == 429) != tc.shared {
				t.Fatalf("second request %d, shared=%v", got, tc.shared)
			}
		})
	}
}

// Without Valkey every rule takes its fail_mode, and readiness is unaffected.
func TestFailModes(t *testing.T) {
	h := newHarness(t, nil) // no VALKEY_URL
	c := testConfig(1)
	mk := func(path, mode string, limit int64) snapshot.RateLimitRule {
		r := rlRule(uniq(mode), `http.request.uri.path eq "`+path+`"`, "sliding_window", limit, "ip")
		r.FailMode = mode
		return r
	}
	shadowClosed := mk("/shadow-closed", "closed", 1)
	shadowClosed.Action = "log"
	c.RateLimitRules = []snapshot.RateLimitRule{mk("/open", "open", 1), mk("/closed", "closed", 1), mk("/local", "local", 4), shadowClosed}
	e := envelope(c)
	e.FleetSize = 2
	h.load(e)
	if got := h.statuses(3, "GET", "/open"); !eqInts(got, 200, 200, 200) {
		t.Fatalf("open: %v", got)
	}
	resp := h.do("GET", "/closed", nil)
	if resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("closed Retry-After %q", resp.Header.Get("Retry-After"))
	}
	edgeError(t, resp, 503, "unavailable")
	// limit 4 across 2 replicas: 2 here.
	if got := h.statuses(3, "GET", "/local"); !eqInts(got, 200, 200, 429) {
		t.Fatalf("local: %v", got)
	}
	if got := h.statuses(2, "GET", "/shadow-closed"); !eqInts(got, 200, 200) {
		t.Fatalf("a shadow rule failed closed: %v", got)
	}
	if h.srv.m.rejected[reasonRateLimitUnavailable].Load() != 1 || h.srv.m.valkeyErrors.Load() != 9 || h.ruleStats(0).failed.Load() != 3 {
		t.Fatalf("unavailable=%d valkey errors=%d failed=%d", h.srv.m.rejected[reasonRateLimitUnavailable].Load(), h.srv.m.valkeyErrors.Load(), h.ruleStats(0).failed.Load())
	}

	t.Run("EXPECTED_REPLICAS divides the limit without a fleet size", func(t *testing.T) {
		h := newHarness(t, map[string]string{"EXPECTED_REPLICAS": "4"})
		c := testConfig(1)
		c.RateLimitRules = []snapshot.RateLimitRule{mk("/local", "local", 4)}
		h.load(envelope(c))
		if got := h.statuses(2, "GET", "/local"); !eqInts(got, 200, 429) {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("admin's report answer resizes the share without a new snapshot", func(t *testing.T) {
		admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"fleet_size":4}`)
		}))
		defer admin.Close()
		h := newHarness(t, map[string]string{"ADMIN_URL": admin.URL, "EDGE_SERVICE_TOKEN": "t0k"})
		c := testConfig(1)
		c.RateLimitRules = []snapshot.RateLimitRule{mk("/local", "local", 4)}
		e := envelope(c)
		e.FleetSize = 2
		h.load(e)
		h.srv.reporter.report(t.Context())
		if got := h.statuses(2, "GET", "/local"); !eqInts(got, 200, 429) {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("a bucket rule keeps a share of its burst", func(t *testing.T) {
		h := newHarness(t, map[string]string{"EXPECTED_REPLICAS": "2"})
		c := testConfig(1)
		r := mk("/local", "local", 4)
		r.Algorithm, r.Burst = "token_bucket", 4
		c.RateLimitRules = []snapshot.RateLimitRule{r}
		h.load(envelope(c))
		if got := h.statuses(3, "GET", "/local"); !eqInts(got, 200, 200, 429) {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("the kill switch keeps local mode from blocking", func(t *testing.T) {
		h := newHarness(t, nil)
		c := testConfig(1)
		r := mk("/local", "local", 1)
		r.Penalty = dur(time.Hour)
		c.RateLimitRules = []snapshot.RateLimitRule{r}
		c.KillSwitch.RateLimit = true
		h.load(envelope(c))
		if got := h.statuses(3, "GET", "/local"); !eqInts(got, 200, 200, 200) {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("a client-keyed rule can't fill another rule's local state", func(t *testing.T) {
		old := maxLocalState
		// 128 per rule here, two subjects per shard: the shard comes from a
		// per-process random seed, so the login rule's default client and
		// the new one may share one, and both must fit.
		maxLocalState = 256
		t.Cleanup(func() { maxLocalState = old })
		h := newHarness(t, nil)
		c := testConfig(1)
		key := mk("/login", "local", 1000)
		key.Key = []string{"ip", "header:x-api-key"}
		c.RateLimitRules = []snapshot.RateLimitRule{key, mk("/login", "local", 1)}
		h.load(envelope(c))
		for i := range 300 {
			h.statuses(1, "POST", "/login", "X-Api-Key", fmt.Sprint("k", i))
		}
		// A new client is still limited by the login rule.
		if got := h.statuses(2, "POST", "/login", "CloudFront-Viewer-Address", "198.51.100.99:1"); !eqInts(got, 200, 429) {
			t.Fatalf("login rule untracked for a new client: %v", got)
		}
	})

	t.Run("a publish during an outage keeps local counts", func(t *testing.T) {
		h := newHarness(t, nil)
		c := testConfig(1)
		c.RateLimitRules = []snapshot.RateLimitRule{mk("/local", "local", 1)}
		h.load(envelope(c))
		h.statuses(1, "GET", "/local")
		c2 := testConfig(2)
		c2.RateLimitRules = c.RateLimitRules
		h.load(envelope(c2))
		if got := h.statuses(1, "GET", "/local"); !eqInts(got, 429) {
			t.Fatalf("a publish reset local state: %v", got)
		}
	})

	t.Run("a full local store lets new subjects pass", func(t *testing.T) {
		old := maxLocalState
		maxLocalState = 1
		t.Cleanup(func() { maxLocalState = old })
		h := newHarness(t, nil)
		c := testConfig(1)
		c.RateLimitRules = []snapshot.RateLimitRule{mk("/local", "local", 1)}
		h.load(envelope(c))
		for i := range 1000 {
			h.srv.store.load().active.local[0].Take(fmt.Sprint("other", i), ratelimit.Params{Algo: ratelimit.FixedWindow, Limit: 1, Period: 3_600_000}, time.Now().UnixMilli())
		}
		if got := h.statuses(2, "GET", "/local"); !eqInts(got, 200, 200) {
			t.Fatalf("got %v", got)
		}
		if h.srv.m.localUntracked.Load() == 0 {
			t.Fatal("untracked subject not counted")
		}
	})
}

// A Valkey that refuses the scripts (an ACL without EVALSHA) fails every
// call; after a few the node's breaker opens and calls fail fast.
func TestValkeyErrorsOpenTheBreaker(t *testing.T) {
	addr := testenv.Valkey(t)
	raw, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.Do(t.Context(), raw.B().AclSetuser().Username("noeval").Rule("on", ">pw", "~*", "+@all", "-evalsha", "-eval").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	h := valkeyHarness(t, map[string]string{"VALKEY_URL": "redis://noeval:pw@" + addr})
	c := testConfig(1)
	c.RateLimitRules = []snapshot.RateLimitRule{rlRule(uniq("acl"), "true", "sliding_window", 1, "ip")}
	h.load(envelope(c))
	if got := h.statuses(7, "GET", "/"); !eqInts(got, 200, 200, 200, 200, 200, 200, 200) {
		t.Fatalf("fail_mode open blocked: %v", got)
	}
	if h.srv.m.valkeyErrors.Load() != 5 || h.srv.m.valkeyBreakerOpen.Load() != 2 {
		t.Fatalf("errors=%d breaker open=%d", h.srv.m.valkeyErrors.Load(), h.srv.m.valkeyBreakerOpen.Load())
	}
}

// A Valkey reply slower than VALKEY_TIMEOUT takes the rule's fail_mode;
// one within it still enforces the limit.
func TestValkeyTimeout(t *testing.T) {
	addr := testenv.Valkey(t)
	raw, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cases := []struct {
		name, timeout string
		want          int
		errors        uint64
	}{
		{"reply within the timeout is enforced", "5s", 429, 0},
		{"reply after the timeout fails open", "50ms", 200, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := valkeyHarness(t, map[string]string{"VALKEY_TIMEOUT": tc.timeout})
			c := testConfig(1)
			c.RateLimitRules = []snapshot.RateLimitRule{rlRule(uniq("slow"), "true", "sliding_window", 1, "ip")}
			h.load(envelope(c))
			if got := h.statuses(1, "GET", "/"); !eqInts(got, 200) {
				t.Fatalf("first request: %v", got)
			}
			// The first request can time out on a loaded host and still pass by
			// failing open, so count only errors from the paused request.
			before := h.srv.m.valkeyErrors.Load()
			// Valkey holds every script call for 2s, then runs it. The pause
			// starts when Valkey runs it, so it must outlast any stall before
			// the next request reaches Valkey. WRITE, not ALL: ALL also holds
			// the handshake of a newly dialed connection past its 1s dial timeout.
			if err := raw.Do(t.Context(), raw.B().ClientPause().Timeout(2000).Write().Build()).Error(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { raw.Do(context.Background(), raw.B().ClientUnpause().Build()) }) //nolint:usetesting // t.Context is already cancelled when Cleanup runs
			if got, errs := h.statuses(1, "GET", "/"), h.srv.m.valkeyErrors.Load()-before; !eqInts(got, tc.want) || errs != tc.errors {
				t.Fatalf("second request %v, valkey errors %d", got, errs)
			}
		})
	}
}

// A site-wide rule that requires a key part rejects requests without it,
// and the config test runner reports the same decision.
func TestSiteWideRuleRejectsMissingKey(t *testing.T) {
	c := testConfig(1)
	r := rlRule("tenant", "true", "sliding_window", 100, "ip", "header:x-tenant")
	r.OnMissingKey = "reject"
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	h := newHarness(t, nil)
	h.load(envelope(c))
	edgeError(t, h.do("GET", "/", nil), 400, "bad_request")

	compiled, _, errs := snapshot.Compile(c, testDeployment())
	if errs != nil {
		t.Fatal(errs)
	}
	res, err := Simulate(compiled, SimRequest{Method: "GET", Host: "api.example.com", Target: "/", IP: "203.0.113.9"})
	if err != nil || res.Rejected != "rate_limit_key" {
		t.Fatalf("simulate: %+v %v", res, err)
	}
}

// Rules that can't block don't use up the per-request cap: five matching
// shadow rules, or five rules skipped for a missing key, never push a
// blocking rule out of evaluation. Clients choose which of those match.
func TestCapCountsOnlyEnforcingRules(t *testing.T) {
	cases := []struct {
		name string
		mk   func(i int) snapshot.RateLimitRule
	}{
		{"shadow rules", func(i int) snapshot.RateLimitRule {
			r := rlRule(uniq(fmt.Sprint("shadow", i)), `http.request.uri.args["ref"] eq "x"`, "sliding_window", 1000, "ip")
			r.Action = "log"
			return r
		}},
		{"rules skipped for a missing key", func(i int) snapshot.RateLimitRule {
			r := rlRule(uniq(fmt.Sprint("skip", i)), `http.request.uri.args["ref"] eq "x"`, "sliding_window", 1000, "ip", "header:x-api-key")
			r.OnMissingKey = "skip"
			return r
		}},
	}
	h := valkeyHarness(t, nil)
	for v, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(int64(v + 1))
			for i := range 5 {
				c.RateLimitRules = append(c.RateLimitRules, tc.mk(i))
			}
			c.RateLimitRules = append(c.RateLimitRules, rlRule(uniq("login"), `http.request.uri.path eq "/login"`, "sliding_window", 1, "ip"))
			h.load(envelope(c))
			if got := h.statuses(2, "POST", "/login?ref=x"); !eqInts(got, 200, 429) {
				t.Fatalf("login limit bypassed: %v", got)
			}
		})
	}
}

// Replicas share one quota through Valkey.
func TestReplicasShareQuota(t *testing.T) {
	a, b := valkeyHarness(t, nil), valkeyHarness(t, nil)
	c := testConfig(1)
	c.RateLimitRules = []snapshot.RateLimitRule{rlRule(uniq("shared"), "true", "sliding_window", 3, "ip")}
	a.load(envelope(c))
	b.load(envelope(c))
	got := []int{a.statuses(1, "GET", "/")[0], b.statuses(1, "GET", "/")[0], a.statuses(1, "GET", "/")[0], b.statuses(1, "GET", "/")[0]}
	if !eqInts(got, 200, 200, 200, 429) {
		t.Fatalf("got %v", got)
	}
}

// With ratelimit_headers on, responses carry the IETF draft RateLimit
// fields for enforced rules, replacing any the upstream sent.
func TestRateLimitHeaders(t *testing.T) {
	h := valkeyHarness(t, nil)
	c := testConfig(1)
	a, b := uniq("a"), uniq("b")
	shadow := rlRule(uniq("shadow"), `http.request.method eq "GET"`, "sliding_window", 1, "ip")
	shadow.Action = "log"
	c.RateLimitRules = []snapshot.RateLimitRule{rlRule(a, "true", "sliding_window", 2, "ip"), rlRule(b, "true", "token_bucket", 10, "ip"), shadow}
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "headers", Expression: mustParse(`http.request.uri.path ne "/quiet"`), Settings: snapshot.Settings{RateLimitHeaders: new(true)}})
	h.load(envelope(c))
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { w.Header().Set("RateLimit", "upstream") }

	resp := h.do("GET", "/", nil)
	resp.Body.Close()
	wantPolicy := fmt.Sprintf(`%q;q=2;w=60, %q;q=10;w=60`, a, b)
	if p := resp.Header.Get("RateLimit-Policy"); p != wantPolicy {
		t.Fatalf("RateLimit-Policy %q, want %q", p, wantPolicy)
	}
	if s := resp.Header.Values("RateLimit"); len(s) != 1 || !strings.HasPrefix(s[0], fmt.Sprintf(`%q;r=1;t=`, a)) || !strings.Contains(s[0], fmt.Sprintf(`%q;r=9;t=6`, b)) {
		t.Fatalf("RateLimit %q", s)
	}
	h.do("GET", "/", nil).Body.Close()
	resp = h.do("GET", "/", nil)
	if !strings.HasPrefix(resp.Header.Get("RateLimit"), fmt.Sprintf(`%q;r=0;t=`, a)) {
		t.Fatalf("429 RateLimit %q", resp.Header.Get("RateLimit"))
	}
	edgeError(t, resp, 429, "rate_limited")

	resp = h.do("GET", "/quiet", nil, "CloudFront-Viewer-Address", "198.51.100.9:1")
	resp.Body.Close()
	if resp.Header.Get("RateLimit-Policy") != "" || resp.Header.Get("RateLimit") != "upstream" {
		t.Fatalf("headers sent with the setting off: %v", resp.Header)
	}
}

// At most 5 non-site-wide rules run per request; the rest are skipped and
// counted, so a request never costs more than 7 Valkey calls.
func TestRulesCapped(t *testing.T) {
	h := valkeyHarness(t, nil)
	c := testConfig(1)
	for i := range 7 {
		c.RateLimitRules = append(c.RateLimitRules, rlRule(uniq(fmt.Sprint("cap", i)), `http.request.uri.path eq "/x"`, "sliding_window", 100, "ip"))
	}
	h.load(envelope(c))
	h.statuses(1, "GET", "/x")
	if h.srv.m.rulesCapped.Load() != 1 || h.ruleStats(4).evaluated.Load() != 1 || h.ruleStats(5).evaluated.Load() != 0 {
		t.Fatalf("capped=%d rule4=%d rule5=%d", h.srv.m.rulesCapped.Load(), h.ruleStats(4).evaluated.Load(), h.ruleStats(5).evaluated.Load())
	}
}

// Per-rule counts reach admin as deltas, so the guard and the UI see what
// each rule did since the last report.
func TestRateLimitStatsReported(t *testing.T) {
	h := valkeyHarness(t, nil)
	c := testConfig(1)
	id := uniq("stats")
	c.RateLimitRules = []snapshot.RateLimitRule{rlRule(id, "true", "sliding_window", 1, "ip")}
	h.load(envelope(c))
	h.statuses(2, "GET", "/")
	d := h.srv.poller.reg.deltas()
	if len(d) != 1 || len(d[0].RateLimit) != 1 || d[0].RateLimit[0] != (RuleCounts{ID: id, Evaluated: 2, Limited: 1}) {
		t.Fatalf("first delta %+v", d)
	}
	h.statuses(1, "GET", "/")
	d = h.srv.poller.reg.deltas()
	if d[0].RateLimit[0] != (RuleCounts{ID: id, Evaluated: 1, Limited: 1}) {
		t.Fatalf("second delta repeats counts: %+v", d[0].RateLimit)
	}
	b, _ := json.Marshal(d[0])
	if !strings.Contains(string(b), `"rate_limit_rules":[{"id":"`+id+`","evaluated":1,"limited":1,"would_limit":0,"failed":0}]`) {
		t.Fatalf("report JSON %s", b)
	}
}

// A running replica warms Valkey before ready and drops expired rate-limit
// state in the background, for both canary versions.
func TestServerRateLimitLoops(t *testing.T) {
	old := sweepEvery
	sweepEvery = 20 * time.Millisecond
	t.Cleanup(func() { sweepEvery = old })

	active, cand := testConfig(1), testConfig(2)
	cand.Global.Backstop.Limit = 50 // its own backstop
	cand.RateLimitRules = []snapshot.RateLimitRule{rlRule("loop", "true", "sliding_window", 1, "ip")}
	e := envelope(active)
	e.Candidate, e.CanaryPercent, e.CanaryExpiresAt = cand, 50, time.Now().Add(time.Hour)
	admin := newFakeAdmin(t, e)

	for _, tc := range []struct {
		name, url string
		warned    bool
	}{
		{"reachable", "redis://" + testenv.Valkey(t), false},
		{"unreachable", "redis://127.0.0.1:1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, map[string]string{"ADMIN_URL": admin.srv.URL, "EDGE_SERVICE_TOKEN": "t0k", "VALKEY_URL": tc.url, "DRAIN_DELAY": "1ms"})
			pub, in := listen(t), listen(t)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error)
			go func() { done <- h.srv.Run(ctx, pub, in) }()
			waitFor(t, func() bool { return h.srv.ready() })
			if warned := len(h.logs.lines("valkey unavailable at start")) == 1; warned != tc.warned {
				t.Fatalf("warned=%v", warned)
			}
			ld := h.srv.store.load()
			for i := range 20 {
				ip := fmt.Sprintf("192.0.2.%d", i)
				ld.active.backstop.Allow(netipMust(ip), time.Now())
				ld.candidate.backstop.Allow(netipMust(ip), time.Now())
			}
			h.srv.edge.penalties.Block("k", time.Now().UnixMilli()+10)
			ld.candidate.local[0].Take("k", ratelimit.Params{Algo: ratelimit.FixedWindow, Limit: 1, Period: 10}, time.Now().UnixMilli())
			waitFor(t, func() bool {
				return ld.active.backstop.Len() == 0 && ld.candidate.backstop.Len() == 0 && h.srv.edge.penalties.Len() == 0 && ld.candidate.local[0].Len() == 0
			})
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Admin shows limited subjects without revealing values a client may
// treat as secrets, such as API keys.
func TestLimitedSubjectDisplay(t *testing.T) {
	cases := []struct {
		name    string
		key     []string
		headers []string
		ip      string
		want    string
		query   string
	}{
		{"IPv4 as is", []string{"ip"}, nil, "198.51.100.7", "198.51.100.7", ""},
		{"IPv6 by the /64 it is keyed on", []string{"ip"}, nil, "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64", ""},
		{"API key cut to 4 characters", []string{"ip", "header:x-api-key"}, []string{"X-Api-Key", "sk_live_51Hx"}, "198.51.100.7", "198.51.100.7 X-Api-Key=sk_l…", ""},
		{"short value never shown whole", []string{"header:x-api-key"}, []string{"X-Api-Key", "abcd"}, "198.51.100.7", "X-Api-Key=ab…", ""},
		{"empty value", []string{"header:x-api-key"}, []string{"X-Api-Key", ""}, "198.51.100.7", "X-Api-Key=…", ""},
		{"one-character value hidden", []string{"header:x-api-key"}, []string{"X-Api-Key", "7"}, "198.51.100.7", "X-Api-Key=…", ""},
		{"characters, not bytes", []string{"header:x-user"}, []string{"X-User", "가나다라마바사아"}, "198.51.100.7", "X-User=가나다라…", ""},
		{"cookie", []string{"cookie:session"}, []string{"Cookie", "session=0123456789"}, "198.51.100.7", "session=0123…", ""},
		{"query argument", []string{"query:token"}, nil, "198.51.100.7", "token=abcd…", ""},
		{"verified claim", []string{"jwt_claim:sub"}, nil, "198.51.100.7", "sub=user…", ""},
		{"host, method and country in full", []string{"host", "method", "country"}, nil, "198.51.100.7", "api.example.com GET AU", ""},
		{"AS number", []string{"asnum"}, nil, "198.51.100.7", "AS13335", ""},
		{"constant key", []string{"constant"}, nil, "198.51.100.7", "all", ""},
		{"missing value falls back to the IP", []string{"header:x-api-key"}, nil, "198.51.100.9", "198.51.100.9", ""},
		// Postgres refuses NUL in jsonb, so one would fail the whole stats flush.
		{name: "control characters shown as ?", key: []string{"query:token"}, ip: "198.51.100.7", want: "token=??ab…", query: "token=%00%01abcdef"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://api.example.com/?"+cmp.Or(tc.query, "token=abcdefgh"), nil)
			for i := 0; i+1 < len(tc.headers); i += 2 {
				r.Header.Set(tc.headers[i], tc.headers[i+1])
			}
			st := &reqState{client: client{ip: netip.MustParseAddr(tc.ip), country: "AU", asn: 13335, hasASN: true}}
			st.fields = newFields(r, &st.client, "/")
			st.fields.claims = map[string][]string{"sub": {"user-12345"}}
			v := &version{rules: ratelimit.Compile([]snapshot.RateLimitRule{rlRule("r", "true", "sliding_window", 1, tc.key...)})}
			c, ok, _ := st.check(v, 0)
			if got := st.display(&c); !ok || got != tc.want {
				t.Fatalf("display = %q, want %q", got, tc.want)
			}
		})
	}
}
