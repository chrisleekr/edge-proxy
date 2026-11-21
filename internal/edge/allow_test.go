package edge

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// allowConfig has a block rule for curl before and after an always-allow rule
// for the office range, so rule order can't be what lets the office through.
func allowConfig(version int64) *snapshot.Config {
	c := testConfig(version)
	block := func(id string) snapshot.ConfigRule {
		return snapshot.ConfigRule{ID: id, Expression: mustParse(`http.user_agent contains "curl"`), Settings: snapshot.Settings{Block: new("block")}}
	}
	c.ConfigRules = append(c.ConfigRules, block("tools-early"),
		snapshot.ConfigRule{ID: "office", Expression: mustParse("ip.src in {" + trustedRange + "}"), Settings: snapshot.Settings{Allow: true}},
		block("tools-late"))
	return c
}

// An always-allow rule lets its client through the blocks of rules before and
// after it. Others are still blocked by the rule that wins the merge, the last.
func TestAlwaysAllowBeatsBlocksWhateverTheRuleOrder(t *testing.T) {
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
	h.load(envelope(allowConfig(1)))
	if body := readBody(t, h.do("GET", "/", nil, "User-Agent", "curl/8.5.0")); body != "upstream ok" {
		t.Fatalf("office client refused: %s", body)
	}
	edgeError(t, h.do("GET", "/", nil, "User-Agent", "curl/8.5.0", "CloudFront-Viewer-Address", otherClient), 403, "forbidden")

	office, other := accessLine(t, h, 0), accessLine(t, h, 1)
	if office["edge.decision"] != "allow" || office["edge.allowlist"] != nil || fmt.Sprint(office["edge.config_rules"]) != "[tools-early office tools-late]" {
		t.Fatalf("office line: %v", office)
	}
	if other["edge.decision"] != "blocked" || fmt.Sprint(other["edge.config_rules"]) != "[tools-early tools-late]" {
		t.Fatalf("other client's line: %v", other)
	}
	m := h.metrics()
	if m[`edge_rejected_total{reason="blocked"}`] != 1 || m["edge_allowlisted_total"] != 0 {
		t.Fatalf("blocked %v, allowlisted %v; an allow rule is not the allowlist", m[`edge_rejected_total{reason="blocked"}`], m["edge_allowlisted_total"])
	}
}

// The access line lists the config rules that matched, also when the winning
// block only logs, and for an allowlisted client the rule whose block it was
// spared.
func TestAccessLineListsTheMatchedRules(t *testing.T) {
	t.Run("a log-only rule that wins the merge is logged", func(t *testing.T) {
		h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
		c := allowConfig(1)
		c.ConfigRules[len(c.ConfigRules)-1].Settings.Block = new("log")
		h.load(envelope(c))
		readBody(t, h.do("GET", "/", nil, "User-Agent", "curl/8.5.0", "CloudFront-Viewer-Address", otherClient))
		line := accessLine(t, h, 0)
		if line["edge.decision"] != "would_block" || fmt.Sprint(line["edge.config_rules"]) != "[tools-early tools-late]" {
			t.Fatalf("line: %v", line)
		}
	})
	t.Run("an allowlisted client's line names the rule whose block it was spared", func(t *testing.T) {
		h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
		h.load(envelope(allowlistConfig(1, trustedRange)))
		readBody(t, h.do("GET", "/", nil, "User-Agent", "curl/8.5.0"))
		line := accessLine(t, h, 0)
		if line["edge.decision"] != "allow" || line["edge.allowlist"] != trustedRange || fmt.Sprint(line["edge.config_rules"]) != "[tools]" {
			t.Fatalf("line: %v", line)
		}
	})
	t.Run("an allow rule alone lists only itself", func(t *testing.T) {
		h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
		h.load(envelope(allowConfig(1)))
		readBody(t, h.do("GET", "/", nil))
		line := accessLine(t, h, 0)
		if line["edge.decision"] != "allow" || fmt.Sprint(line["edge.config_rules"]) != "[office]" {
			t.Fatalf("line: %v", line)
		}
	})
}

// A block an allow lifted is a refusal that did not happen, so its line is
// kept whatever the sample rate and, carrying no sample rate, counts as one
// request. The same client's other allowed requests are still sampled.
func TestALiftedBlockIsAlwaysLogged(t *testing.T) {
	old := logDraw
	logDraw = func() float64 { return 0.99 }
	t.Cleanup(func() { logDraw = old })
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "0.01"})
	h.load(envelope(allowConfig(1)))
	readBody(t, h.do("GET", "/", nil))
	readBody(t, h.do("GET", "/", nil, "User-Agent", "curl/8.5.0"))
	line := accessLine(t, h, 0)
	if line["edge.decision"] != "allow" || fmt.Sprint(line["edge.config_rules"]) != "[tools-early office tools-late]" || line["edge.sample_rate"] != nil {
		t.Fatalf("line: %v", line)
	}
	if n := len(h.logs.lines("access")); n != 1 {
		t.Fatalf("%d access lines; the request no block rule matched should be sampled out", n)
	}
}

// A client an allow rule matches is not refused for an earlier ban and is
// not counted against a rate limit, as a client on the allowlist.
func TestAlwaysAllowSkipsBansAndRateLimits(t *testing.T) {
	t.Run("a banned client is served once an allow rule matches it", func(t *testing.T) {
		h := newHarness(t, nil)
		h.load(envelope(trapConfig(1)))
		trip(t, h, "a.example.com")
		c := trapConfig(2)
		c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "office", Expression: mustParse("ip.src in {" + trustedRange + "}"), Settings: snapshot.Settings{Allow: true}})
		h.load(envelope(c))
		if body := readBody(t, h.do("GET", "/", nil)); body != "upstream ok" {
			t.Fatalf("banned office client refused: %s", body)
		}
	})

	t.Run("a rate limit never counts the client", func(t *testing.T) {
		h := valkeyHarness(t, nil)
		c := allowConfig(1)
		id := uniq("login")
		c.RateLimitRules = []snapshot.RateLimitRule{rlRule(id, "true", "sliding_window", 1, "ip")}
		h.load(envelope(c))
		if got := h.statuses(5, "GET", "/"); !eqInts(got, 200, 200, 200, 200, 200) {
			t.Fatalf("office client: %v", got)
		}
		if n := h.ruleOutcome(id, "evaluated"); n != 0 {
			t.Fatalf("evaluated %v", n)
		}
		if keys := valkeyKeys(t, id); len(keys) != 0 {
			t.Fatalf("Valkey keys for an allowed client: %v", keys)
		}
		if got := h.statuses(2, "GET", "/", "CloudFront-Viewer-Address", otherClient); !eqInts(got, 200, 429) {
			t.Fatalf("other client: %v", got)
		}
	})
}

// A required token becomes optional for an allowed client, one it sends is
// still verified, and the identity of a request without one is never sent.
func TestAlwaysAllowNeedsNoToken(t *testing.T) {
	h, idp := newAuthHarness(t)
	c := authConfig(idp)
	c.Version = 2
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "office", Expression: mustParse("ip.src in {" + trustedRange + "}"), Settings: snapshot.Settings{Allow: true}})
	h.load(authEnvelope(c))
	if body := readBody(t, h.do("GET", "/private/x", nil)); body != "upstream ok" {
		t.Fatalf("body %q", body)
	}
	if h.upstreamHeader("X-Edge-Auth-Sub") != "" {
		t.Fatalf("identity sent without a verified token: %v", h.lastApp.Header)
	}
	unauthorized(t, h.do("GET", "/private/x", nil, bearerOf("garbage")...), `Bearer error="invalid_token"`)
	unauthorized(t, h.do("GET", "/private/x", nil, "CloudFront-Viewer-Address", otherClient), "Bearer")
}

// An allow rule lifts enforcement, nothing else: the backstop, body limit and
// header rules still apply to the client, and so do the other rules' CORS
// policy and settings.
func TestAlwaysAllowKeepsRetainedProtections(t *testing.T) {
	newAllowed := func(t *testing.T, change func(c *snapshot.Config)) *harness {
		t.Helper()
		h := newHarness(t, nil)
		c := allowConfig(1)
		change(c)
		h.load(envelope(c))
		return h
	}
	t.Run("backstop still limits", func(t *testing.T) {
		h := newAllowed(t, func(c *snapshot.Config) {
			c.Global.Backstop = snapshot.Backstop{Limit: 2, Period: dur(time.Minute), Burst: 2, MaxEntries: 1000}
		})
		if got := h.statuses(3, "GET", "/"); !eqInts(got, 200, 200, 429) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("body limit still applies", func(t *testing.T) {
		h := newAllowed(t, func(*snapshot.Config) {})
		edgeError(t, h.do("POST", "/", strings.NewReader(strings.Repeat("x", 2048))), 413, "payload_too_large")
	})
	t.Run("CORS from another rule still applies", func(t *testing.T) {
		h := newAllowed(t, func(c *snapshot.Config) {
			c.Global.CORSPolicies = map[string]snapshot.CORSPolicy{"app": {Origins: []string{"https://a.example"}}}
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "cors", Expression: mustParse("true"), Settings: snapshot.Settings{CORSPolicy: new("app")}})
		})
		resp := h.do("GET", "/", nil, "Origin", "https://a.example")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "https://a.example" {
			t.Fatalf("status %d, headers %v", resp.StatusCode, resp.Header)
		}
	})
}

// A config test reports the allow rule and skips the rate limits it skips.
func TestSimulateReportsTheAllowRule(t *testing.T) {
	c := allowConfig(1)
	c.RateLimitRules = []snapshot.RateLimitRule{rlRule("site", "true", "sliding_window", 1, "ip")}
	cc := compiled(t, c)
	req := func(ip string) SimRequest {
		return SimRequest{Method: "GET", Host: "h", Target: "/", IP: ip, Headers: map[string][]string{"User-Agent": {"curl/8.5.0"}}}
	}
	office, err := Simulate(cc, req("198.51.100.7"))
	if err != nil || office.AllowRule != "office" || office.Rejected != "" || office.RateLimitRules != nil {
		t.Fatalf("office client: %+v %v", office, err)
	}
	other, err := Simulate(cc, req("203.0.113.9"))
	if err != nil || other.AllowRule != "" || other.Rejected != "blocked" {
		t.Fatalf("other client: %+v %v", other, err)
	}
}
