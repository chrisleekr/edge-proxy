package edge

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// trapConfig bans a client IP for an hour when it asks for a WordPress path
// the site does not serve.
func trapConfig(version int64) *snapshot.Config {
	c := testConfig(version)
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "trap", Expression: mustParse(`starts_with(http.request.uri.path, "/wp-")`), Settings: snapshot.Settings{Block: new("block"), Ban: new(dur(time.Hour))}})
	return c
}

// trip sends the request that trips the trap from the default client.
func trip(t *testing.T, h *harness, host string, headers ...string) {
	t.Helper()
	edgeError(t, h.do("GET", "/wp-login.php?token=secret", nil, append([]string{"Host", host}, headers...)...), 403, "forbidden")
}

// accessLine is the nth access line once it is written.
func accessLine(t *testing.T, h *harness, n int) map[string]any {
	t.Helper()
	waitFor(t, func() bool { return len(h.logs.lines("access")) > n })
	return h.logs.lines("access")[n]
}

// A client that trips the trap on one host is refused on every host and
// path, and the access lines say what set the ban.
func TestTrapBansTheClientOnEveryHost(t *testing.T) {
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
	h.load(envelope(trapConfig(1)))
	trip(t, h, "a.example.com")
	edgeError(t, h.do("GET", "/v1/items", nil, "Host", "b.example.com"), 403, "forbidden")
	if got := h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", otherClient); !eqInts(got, 200) {
		t.Fatalf("other client: %v", got)
	}
	m := h.metrics()
	if m[`edge_rejected_total{reason="banned"}`] != 1 || m[`edge_rejected_total{reason="blocked"}`] != 1 || m["edge_ban_hits_total"] != 1 || m["edge_bans"] != 1 {
		t.Fatalf("metrics: banned %v blocked %v hits %v bans %v", m[`edge_rejected_total{reason="banned"}`], m[`edge_rejected_total{reason="blocked"}`], m["edge_ban_hits_total"], m["edge_bans"])
	}

	trap, banned := accessLine(t, h, 0), accessLine(t, h, 1)
	if trap["edge.decision"] != "blocked" || trap["edge.ban.until"] == nil || trap["edge.ban.rule"] != nil || trap["edge.ban.dropped"] != nil {
		t.Fatalf("trap line: %v", trap)
	}
	until, since := trap["edge.ban.until"], banned["edge.ban.since"]
	if banned["edge.decision"] != "banned" || banned["edge.ban.rule"] != "trap" || banned["edge.ban.host"] != "a.example.com" || banned["edge.ban.path"] != "/wp-login.php" || banned["edge.ban.until"] != until || since == nil || since == until {
		t.Fatalf("banned line: %v", banned)
	}
	if got := banned["url.path"]; got != "/v1/items" {
		t.Fatalf("banned line names the new request's path: %v", got)
	}
}

// A banned client that trips the trap again is refused as blocked, so the
// rule's own stats stay right, and the ban is renewed.
func TestBannedClientTrippingTheTrapIsBlockedAndRenewed(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(trapConfig(1)))
	ip := netip.MustParseAddr("198.51.100.7")
	trip(t, h, "a.example.com")
	before, _ := h.srv.edge.bans.Get(ip, 0)
	time.Sleep(20 * time.Millisecond)
	trip(t, h, "a.example.com")
	m := h.metrics()
	if m[`edge_rejected_total{reason="blocked"}`] != 2 || m[`edge_rejected_total{reason="banned"}`] != 0 {
		t.Fatalf("blocked %v banned %v", m[`edge_rejected_total{reason="blocked"}`], m[`edge_rejected_total{reason="banned"}`])
	}
	if b, _ := ruleReport(t, h, "trap"); b != 2 {
		t.Fatalf("rule blocked %v, want 2", b)
	}
	if after, ok := h.srv.edge.bans.Get(ip, 0); !ok || after.End <= before.End {
		t.Fatalf("ban end %d did not move past the first trip's %d", after.End, before.End)
	}
}

// Trusted clients and the kill switch override a ban as they override block.
func TestBanYieldsToAllowlistAndKillSwitch(t *testing.T) {
	t.Run("an allowlisted client that hits the trap is not banned", func(t *testing.T) {
		h := newHarness(t, nil)
		c := trapConfig(1)
		c.Global.ClientAllowlist = []string{trustedRange}
		h.load(envelope(c))
		for range 2 {
			if body := readBody(t, h.do("GET", "/wp-login.php", nil)); body != "upstream ok" {
				t.Fatalf("allowlisted client refused: %s", body)
			}
		}
		if n := h.metrics()["edge_bans"]; n != 0 {
			t.Fatalf("bans %v", n)
		}
	})

	t.Run("a banned client is served once the client is allowlisted", func(t *testing.T) {
		h := newHarness(t, nil)
		h.load(envelope(trapConfig(1)))
		trip(t, h, "a.example.com")
		c := trapConfig(2)
		c.Global.ClientAllowlist = []string{trustedRange}
		h.load(envelope(c))
		if body := readBody(t, h.do("GET", "/", nil)); body != "upstream ok" {
			t.Fatalf("allowlisted banned client refused: %s", body)
		}
	})

	t.Run("a banned client is served while the block kill switch is on", func(t *testing.T) {
		h := newHarness(t, nil)
		h.load(envelope(trapConfig(1)))
		trip(t, h, "a.example.com")
		c := trapConfig(2)
		c.KillSwitch.Block = true
		h.load(envelope(c))
		if body := readBody(t, h.do("GET", "/", nil)); body != "upstream ok" {
			t.Fatalf("banned client refused under the kill switch: %s", body)
		}
		h.load(envelope(trapConfig(3)))
		edgeError(t, h.do("GET", "/", nil), 403, "forbidden")
	})
}

// A ban is honoured only while a rule that sets it is in the client's
// version.
func TestBanEndsWhenItsRuleIsGone(t *testing.T) {
	t.Run("rule removed by a publish", func(t *testing.T) {
		h := newHarness(t, nil)
		h.load(envelope(trapConfig(1)))
		trip(t, h, "a.example.com")
		h.load(envelope(testConfig(2)))
		if body := readBody(t, h.do("GET", "/", nil)); body != "upstream ok" {
			t.Fatalf("banned client refused after the rule was removed: %s", body)
		}
	})

	t.Run("rule keeps its block but drops the ban", func(t *testing.T) {
		h := newHarness(t, nil)
		h.load(envelope(trapConfig(1)))
		trip(t, h, "a.example.com")
		c := trapConfig(2)
		c.ConfigRules[2].Settings.Ban = nil
		h.load(envelope(c))
		if body := readBody(t, h.do("GET", "/", nil)); body != "upstream ok" {
			t.Fatalf("banned client refused after the ban was dropped: %s", body)
		}
	})
}

// During a canary a client is judged by the version it is pinned to: a ban
// recorded under the candidate's trap does not refuse a client pinned to the
// stable version, which has no trap.
func TestCanaryBanDoesNotReachTheStableCohort(t *testing.T) {
	in, out := ipWithCohort(t, true, 5000), ipWithCohort(t, false, 5000)
	h := newHarness(t, nil)
	e := envelope(testConfig(1))
	e.Candidate, e.CanaryPercent, e.CanaryExpiresAt = trapConfig(2), 50, time.Now().Add(time.Hour)
	h.load(e)
	trip(t, h, "a.example.com", "CloudFront-Viewer-Address", in+":1")
	edgeError(t, h.do("GET", "/", nil, "CloudFront-Viewer-Address", in+":1"), 403, "forbidden")
	// The out-of-cohort client held a ban from an earlier cohort assignment.
	h.srv.edge.bans.Add(netip.MustParseAddr(out), ratelimit.Ban{Rule: "trap", End: time.Now().Add(time.Hour).UnixMilli()}, map[string]bool{"trap": true})
	if body := readBody(t, h.do("GET", "/", nil, "CloudFront-Viewer-Address", out+":1")); body != "upstream ok" {
		t.Fatalf("stable cohort refused by the candidate's ban: %s", body)
	}
}

// The winning block rule decides, as for every setting.
func TestLaterBlockRuleOverridesTheTrap(t *testing.T) {
	cases := []struct {
		name  string
		block string
		want  int
	}{
		{"a later block rule without ban", "block", 403},
		{"a later log rule", "log", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			c := trapConfig(1)
			c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "later", Expression: mustParse(`http.user_agent contains "curl"`), Settings: snapshot.Settings{Block: &tc.block}})
			h.load(envelope(c))
			if got := h.statuses(1, "GET", "/wp-login.php", "User-Agent", "curl/8.5.0"); got[0] != tc.want {
				t.Fatalf("status %d, want %d", got[0], tc.want)
			}
			if body := readBody(t, h.do("GET", "/", nil)); body != "upstream ok" {
				t.Fatalf("client was banned: %s", body)
			}
			if n := h.metrics()["edge_bans"]; n != 0 {
				t.Fatalf("bans %v", n)
			}
		})
	}
}

// A full ban table fails open: the client is refused for the trap request
// only, and the drop is counted and logged.
func TestFullBanTableServesTheClient(t *testing.T) {
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
	h.srv.edge.bans = ratelimit.NewBans(1)
	h.srv.m.bans = h.srv.edge.bans
	for i := range 1000 {
		h.srv.edge.bans.Add(netip.AddrFrom4([4]byte{10, 1, byte(i / 250), byte(i % 250)}), ratelimit.Ban{Rule: "trap", End: time.Now().Add(time.Hour).UnixMilli()}, map[string]bool{"trap": true})
	}
	h.load(envelope(trapConfig(1)))
	trip(t, h, "a.example.com")
	if body := readBody(t, h.do("GET", "/", nil)); body != "upstream ok" {
		t.Fatalf("client refused though its ban did not fit: %s", body)
	}
	if n := h.metrics()["edge_ban_dropped_total"]; n != 1 {
		t.Fatalf("dropped %v", n)
	}
	if line := accessLine(t, h, 0); line["edge.ban.dropped"] != true || line["edge.ban.until"] != nil {
		t.Fatalf("trap line: %v", line)
	}
}

// A client banned for a day by one trap that then trips a shorter trap stays
// banned for the day, under the first trap's rule.
func TestShorterBanDoesNotCutALongerOne(t *testing.T) {
	h := newHarness(t, map[string]string{"LOG_SAMPLE_RATE": "1"})
	now := time.Now()
	clock := h.fakeClock(now)
	c := testConfig(1)
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "day", Expression: mustParse(`starts_with(http.request.uri.path, "/wp-")`), Settings: snapshot.Settings{Block: new("block"), Ban: new(dur(24 * time.Hour))}},
		snapshot.ConfigRule{ID: "minute", Expression: mustParse(`starts_with(http.request.uri.path, "/xmlrpc")`), Settings: snapshot.Settings{Block: new("block"), Ban: new(dur(time.Minute))}})
	h.load(envelope(c))
	edgeError(t, h.do("GET", "/wp-login.php", nil), 403, "forbidden")
	clock.Store(now.Add(10 * time.Second).UnixMilli())
	edgeError(t, h.do("GET", "/xmlrpc.php", nil), 403, "forbidden")
	clock.Store(now.Add(2 * time.Minute).UnixMilli())
	edgeError(t, h.do("GET", "/", nil), 403, "forbidden")
	if line := accessLine(t, h, 2); line["edge.decision"] != "banned" || line["edge.ban.rule"] != "day" || line["edge.ban.path"] != "/wp-login.php" {
		t.Fatalf("banned line: %v", line)
	}
}

// A client banned for a day by a trap that a later version removed is not
// protected by that dead ban: tripping a shorter trap that is still live
// bans it under the live rule.
func TestDeadLongBanDoesNotShadowALiveShorterBan(t *testing.T) {
	h := newHarness(t, nil)
	day := testConfig(1)
	day.ConfigRules = append(day.ConfigRules, snapshot.ConfigRule{ID: "day", Expression: mustParse(`starts_with(http.request.uri.path, "/wp-")`), Settings: snapshot.Settings{Block: new("block"), Ban: new(dur(24 * time.Hour))}})
	h.load(envelope(day))
	edgeError(t, h.do("GET", "/wp-login.php", nil), 403, "forbidden")
	minute := testConfig(2)
	minute.ConfigRules = append(minute.ConfigRules, snapshot.ConfigRule{ID: "minute", Expression: mustParse(`starts_with(http.request.uri.path, "/xmlrpc")`), Settings: snapshot.Settings{Block: new("block"), Ban: new(dur(time.Minute))}})
	h.load(envelope(minute))
	edgeError(t, h.do("GET", "/xmlrpc.php", nil), 403, "forbidden")
	edgeError(t, h.do("GET", "/", nil), 403, "forbidden")
	if n := h.metrics()[`edge_rejected_total{reason="banned"}`]; n != 1 {
		t.Fatalf("banned rejections %v, want 1", n)
	}
}

// A banned client that keeps tripping the trap queues one report, so one
// scanner can't fill the queue; a renewal a minute or more later is reported
// again.
func TestRenewalsAreReportedOncePerMinute(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer admin.Close()
	h := newHarness(t, map[string]string{"ADMIN_URL": admin.URL, "EDGE_SERVICE_TOKEN": "t0k", "STATS_INTERVAL": "30s"})
	now := time.Now()
	clock := h.fakeClock(now)
	h.load(envelope(trapConfig(1)))
	for range 5 {
		trip(t, h, "a.example.com")
	}
	if n := len(h.srv.edge.banReports); n != 1 {
		t.Fatalf("queued %d reports for one banned client, want 1", n)
	}
	clock.Store(now.Add(30 * time.Second).UnixMilli())
	trip(t, h, "a.example.com")
	if n := len(h.srv.edge.banReports); n != 1 {
		t.Fatalf("queued %d reports for a renewal 30s later, want 1", n)
	}
	clock.Store(now.Add(time.Minute).UnixMilli())
	trip(t, h, "a.example.com")
	if n := len(h.srv.edge.banReports); n != 2 {
		t.Fatalf("queued %d reports for a renewal a minute later, want 2", n)
	}
	if n := h.metrics()["edge_ban_reports_dropped_total"]; n != 0 {
		t.Fatalf("dropped %v", n)
	}
}

// A report dropped because the queue was full is queued again when the client
// trips the trap next, instead of waiting a minute or never.
func TestBanReportDroppedByAFullQueueIsQueuedOnTheNextTrip(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer admin.Close()
	h := newHarness(t, map[string]string{"ADMIN_URL": admin.URL, "EDGE_SERVICE_TOKEN": "t0k", "STATS_INTERVAL": "30s"})
	now := time.Now()
	clock := h.fakeClock(now)
	h.load(envelope(trapConfig(1)))
	for range MaxBanReports {
		h.srv.edge.banReports <- BanReport{}
	}
	trip(t, h, "a.example.com")
	if n := h.metrics()["edge_ban_reports_dropped_total"]; n != 1 {
		t.Fatalf("dropped %v reports with a full queue, want 1", n)
	}
	<-h.srv.edge.banReports // the stats loop drained one
	clock.Store(now.Add(time.Second).UnixMilli())
	trip(t, h, "a.example.com")
	if n := len(h.srv.edge.banReports); n != MaxBanReports {
		t.Fatalf("queued %d reports after the next trip, want %d", n, MaxBanReports)
	}
	var last BanReport
	for range MaxBanReports {
		last = <-h.srv.edge.banReports
	}
	if last.Rule != "trap" {
		t.Fatalf("the report queued on the next trip is %+v", last)
	}
}
