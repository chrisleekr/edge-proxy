package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// fakeDenylist serves GET /v1/denylist like admin: bearer auth, ETag, 304.
type fakeDenylist struct {
	srv      *httptest.Server
	body     atomic.Pointer[string]
	etag     atomic.Pointer[string]
	status   atomic.Int32 // non-zero forces this status
	requests atomic.Int32
	inm      atomic.Pointer[string] // If-None-Match of the last request
}

func newFakeDenylist(t *testing.T, resp string) *fakeDenylist {
	t.Helper()
	a := &fakeDenylist{}
	a.set(resp, "")
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/denylist" || r.Header.Get("Authorization") != "Bearer t0k" {
			http.NotFound(w, r)
			return
		}
		a.requests.Add(1)
		inm := r.Header.Get("If-None-Match")
		a.inm.Store(&inm)
		if s := a.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		if e := *a.etag.Load(); e != "" {
			if r.Header.Get("If-None-Match") == e {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", e)
		}
		_, _ = w.Write([]byte(*a.body.Load()))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeDenylist) set(body, etag string) {
	a.body.Store(&body)
	a.etag.Store(&etag)
}

// listsBody is admin's response for the given lists.
func listsBody(lists ...IPList) string {
	b, _ := json.Marshal(DenylistResponse{Lists: lists, Lifts: []BanLift{}, Dropped: []string{}})
	return string(b)
}

// awsBody puts the default client's network on the aws list.
var awsBody = listsBody(IPList{Name: "aws", Prefixes: []string{"198.51.100.0/24", "2001:db8::/32"}})

// denyConfig blocks a client on the aws IP list.
func denyConfig(version int64) *snapshot.Config {
	return ruleConfig(version, `client.ip_lists in {"aws"}`)
}

// ruleConfig blocks the clients expression matches.
func ruleConfig(version int64, expression string) *snapshot.Config {
	c := testConfig(version)
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "listed", Expression: mustParse(expression), Settings: snapshot.Settings{Block: new("block")}})
	return c
}

func denyHarness(t *testing.T, a *fakeDenylist) *harness {
	t.Helper()
	return newHarness(t, map[string]string{"ADMIN_URL": a.srv.URL, "EDGE_SERVICE_TOKEN": "t0k", "LOG_SAMPLE_RATE": "1"})
}

func (h *harness) pollDenylist() { h.t.Helper(); h.srv.denylist.poll(h.t.Context()) }

// served is the status a request from the default client gets.
func (h *harness) served() int { h.t.Helper(); return h.statuses(1, "GET", "/")[0] }

// A listed client is refused once the first poll has loaded the set, and
// another client is not.
func TestListedIPIsBlockedAfterTheFirstPoll(t *testing.T) {
	a := newFakeDenylist(t, `{"lists":[{"name":"aws","prefixes":["198.51.100.0/24","2001:db8::/32"]},{"name":"hetzner","prefixes":["203.0.113.0/24"]}],"lifts":[],"dropped_lists":[],"future_field":1}`)
	h := denyHarness(t, a)
	h.load(envelope(denyConfig(1)))
	if got := h.served(); got != 200 {
		t.Fatalf("before the first poll: %d", got)
	}
	h.pollDenylist()
	edgeError(t, h.do("GET", "/", nil), 403, "forbidden")
	if got := h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", otherClient); !eqInts(got, 200) {
		t.Fatalf("client only on hetzner: %v", got)
	}
	if got := h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", "[2001:db8::7]:1"); !eqInts(got, 403) {
		t.Fatalf("aws IPv6 client: %v", got)
	}
	if got := h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", "192.0.2.50:1"); !eqInts(got, 200) {
		t.Fatalf("client on no list: %v", got)
	}
	if n := h.metrics()["edge_denylist_entries"]; n != 3 {
		t.Fatalf("entries %v", n)
	}
}

// An address on two lists matches a rule naming either, and an exemption
// naming a list removes only the addresses on it.
func TestRulesMatchListsByName(t *testing.T) {
	body := listsBody(
		IPList{Name: "aws", Prefixes: []string{"198.51.100.0/24"}},
		IPList{Name: "github", Prefixes: []string{"198.51.100.7/32"}},
		IPList{Name: "statuscake", Prefixes: []string{"198.51.100.8/32"}})
	cases := []struct {
		name       string
		expression string
		addr       string
		want       int
	}{
		{"address on two lists matches the first name", `client.ip_lists in {"aws" "azure"}`, "198.51.100.7:1", 403},
		{"address on two lists matches the second name", `client.ip_lists in {"azure" "github"}`, "198.51.100.7:1", 403},
		{"address on two lists matches a name set it is not wholly in", `client.ip_lists in {"github"}`, "198.51.100.7:1", 403},
		{"address on one list does not match another name", `client.ip_lists in {"github"}`, "198.51.100.9:1", 200},
		{"exemption lets a statuscake address through", `client.ip_lists in {"aws"} and not client.ip_lists in {"statuscake"}`, "198.51.100.8:1", 200},
		{"exemption leaves other aws addresses blocked", `client.ip_lists in {"aws"} and not client.ip_lists in {"statuscake"}`, "198.51.100.9:1", 403},
		{"exemption alone blocks an address on no list", `not client.ip_lists in {"statuscake"}`, "192.0.2.50:1", 403},
		{"name of a list that does not exist matches no one", `client.ip_lists in {"azure"}`, "198.51.100.7:1", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := denyHarness(t, newFakeDenylist(t, body))
			h.load(envelope(ruleConfig(1, tc.expression)))
			h.pollDenylist()
			if got := h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", tc.addr); !eqInts(got, tc.want) {
				t.Fatalf("status %v, want %d", got, tc.want)
			}
		})
	}
}

// client.denylisted stays true for an address on any list, so policies written
// before client.ip_lists keep blocking.
func TestDenylistedFieldMatchesAnyList(t *testing.T) {
	body := listsBody(
		IPList{Name: "aws", Prefixes: []string{"198.51.100.0/24"}},
		IPList{Name: "hetzner", Prefixes: []string{"203.0.113.0/24"}})
	h := denyHarness(t, newFakeDenylist(t, body))
	h.load(envelope(ruleConfig(1, `client.denylisted`)))
	h.pollDenylist()
	for _, tc := range []struct {
		name, addr string
		want       int
	}{
		{"address on aws is blocked", "198.51.100.7:1", 403},
		{"address on hetzner is blocked", "203.0.113.9:1", 403},
		{"address on no list passes", "192.0.2.50:1", 200},
	} {
		if got := h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", tc.addr); !eqInts(got, tc.want) {
			t.Fatalf("%s: status %v, want %d", tc.name, got, tc.want)
		}
	}
}

// Admin answers 304 while nothing changed, and the edge keeps its set.
func TestDenylistNotModifiedKeepsTheSet(t *testing.T) {
	a := newFakeDenylist(t, awsBody)
	a.set(awsBody, `"v1"`)
	h := denyHarness(t, a)
	h.load(envelope(denyConfig(1)))
	h.pollDenylist()
	h.pollDenylist()
	if a.requests.Load() != 2 || h.served() != 403 || h.metrics()["edge_denylist_fetch_failures_total"] != 0 {
		t.Fatalf("requests %d", a.requests.Load())
	}
	if got := *a.inm.Load(); got != `"v1"` {
		t.Fatalf("second poll sent If-None-Match %q, want the first answer's ETag", got)
	}
}

// refuseIPLists makes the list builder refuse every set, as it does past its
// cap on name combinations, which no valid response here is large enough to hit.
func refuseIPLists(t *testing.T) {
	t.Helper()
	old := newIPLists
	t.Cleanup(func() { newIPLists = old })
	newIPLists = func([]string, [][]netip.Prefix) (*expr.IPLists, error) {
		return nil, errors.New("too many name combinations")
	}
}

// A response the list builder refuses counts as a fetch failure and the
// current set stays.
func TestDenylistRefusedByTheBuilderKeepsTheOldSet(t *testing.T) {
	a := newFakeDenylist(t, awsBody)
	h := denyHarness(t, a)
	h.load(envelope(denyConfig(1)))
	h.pollDenylist()
	refuseIPLists(t)
	a.set(listsBody(IPList{Name: "aws", Prefixes: []string{"203.0.113.0/24"}}), `"v2"`)
	h.pollDenylist()
	if h.served() != 403 || h.metrics()["edge_denylist_fetch_failures_total"] != 1 || h.metrics()["edge_denylist_entries"] != 2 {
		t.Fatalf("set changed or failure not counted: %v", h.metrics()["edge_denylist_fetch_failures_total"])
	}
}

// With admin down or wrong, the last set stays, the failure is counted and
// logged, and readiness is unaffected.
func TestDenylistFailureKeepsTheSetAndReadiness(t *testing.T) {
	a := newFakeDenylist(t, awsBody)
	h := denyHarness(t, a)
	h.load(envelope(denyConfig(1)))
	h.pollDenylist()
	a.status.Store(500)
	h.pollDenylist()
	a.srv.Close()
	h.pollDenylist()
	if h.served() != 403 {
		t.Fatal("set lost while admin was down")
	}
	if n := h.metrics()["edge_denylist_fetch_failures_total"]; n != 2 {
		t.Fatalf("failures %v", n)
	}
	if !strings.Contains(h.logs.String(), "denylist fetch failed") {
		t.Fatal("failure not logged")
	}
	in := httptest.NewServer(h.srv.internalMux())
	defer in.Close()
	resp, err := http.Get(in.URL + "/readyz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("readyz %v %v", resp, err)
	}
	_ = resp.Body.Close()
}

// A response with anything the edge can't read is refused whole.
func TestDenylistInvalidResponseKeepsTheOldSet(t *testing.T) {
	tooMany := `{"lists":[{"name":"a","prefixes":[` + strings.Repeat(`"10.0.0.1/32",`, MaxDenylistPrefixes) + `"10.0.0.2/32"]}]}`
	// List a is exactly at the cap, so only the total crosses it.
	overAcrossLists := `{"lists":[{"name":"a","prefixes":[` + strings.TrimSuffix(strings.Repeat(`"10.0.0.1/32",`, MaxDenylistPrefixes), ",") + `]},{"name":"b","prefixes":["10.0.0.3/32"]}]}`
	var many []IPList
	for i := range expr.MaxIPLists + 1 {
		many = append(many, IPList{Name: fmt.Sprintf("list-%d", i)})
	}
	cases := []struct{ name, body string }{
		{"a prefix that is not CIDR", listsBody(IPList{Name: "aws", Prefixes: []string{"198.51.100.0/24", "not-a-prefix"}})},
		{"a 4-in-6 prefix", listsBody(IPList{Name: "aws", Prefixes: []string{"::ffff:10.0.0.0/104"}})},
		{"a name with an uppercase letter", listsBody(IPList{Name: "AWS", Prefixes: []string{"10.0.0.0/8"}})},
		{"an empty name", listsBody(IPList{Prefixes: []string{"10.0.0.0/8"}})},
		{"a repeated name", listsBody(IPList{Name: "aws", Prefixes: []string{"10.0.0.0/8"}}, IPList{Name: "aws", Prefixes: []string{"11.0.0.0/8"}})},
		{"more lists than the limit", listsBody(many...)},
		{"more prefixes than the limit in one list", tooMany},
		{"more prefixes than the limit across lists", overAcrossLists},
		{"a lift IP that is not an address", `{"lists":[{"name":"aws","prefixes":["203.0.113.0/24"]}],"lifts":[{"ip":"nope","at":1}]}`},
		{"a body that is not JSON", `<html>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newFakeDenylist(t, awsBody)
			h := denyHarness(t, a)
			h.load(envelope(denyConfig(1)))
			h.pollDenylist()
			a.set(tc.body, `"v2"`)
			h.pollDenylist()
			if h.served() != 403 || h.metrics()["edge_denylist_fetch_failures_total"] != 1 || h.metrics()["edge_denylist_entries"] != 2 {
				t.Fatalf("set changed or failure not counted: %v", h.metrics()["edge_denylist_fetch_failures_total"])
			}
			// The refused response's ETag was not kept, so admin is asked again.
			if h.srv.denylist.etag != "" {
				t.Fatalf("etag %q kept", h.srv.denylist.etag)
			}
		})
	}
}

// A response over the byte cap is refused.
func TestDenylistOverTheByteCapIsRefused(t *testing.T) {
	a := newFakeDenylist(t, "")
	a.set(`{"lists":[],"pad":"`+strings.Repeat("x", maxDenylistBytes)+`"}`, "")
	h := denyHarness(t, a)
	h.load(envelope(denyConfig(1)))
	h.pollDenylist()
	if n := h.metrics()["edge_denylist_fetch_failures_total"]; n != 1 {
		t.Fatalf("failures %v", n)
	}
}

// A body that dies mid-read fails the poll.
func TestDenylistTruncatedBodyFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte(`{"lists"`))
	}))
	defer srv.Close()
	h := newHarness(t, map[string]string{"ADMIN_URL": srv.URL, "EDGE_SERVICE_TOKEN": "t0k"})
	h.load(envelope(denyConfig(1)))
	h.pollDenylist()
	if n := h.metrics()["edge_denylist_fetch_failures_total"]; n != 1 {
		t.Fatalf("failures %v", n)
	}
}

// The edge polls whatever its config reads, so access lines are labelled
// before any rule names a list. With no list on, it holds a nil set, labels
// nothing and counts no entries, and turning a list off again frees the set.
func TestDenylistPollsWhetherOrNotAConfigReadsTheField(t *testing.T) {
	a := newFakeDenylist(t, awsBody)
	h := denyHarness(t, a)
	h.pollDenylist() // no snapshot yet
	h.load(envelope(testConfig(1)))
	h.pollDenylist()
	if a.requests.Load() != 2 || h.srv.edge.lists.Load() == nil || h.metrics()["edge_denylist_entries"] != 2 {
		t.Fatalf("requests %d", a.requests.Load())
	}
	if h.served() != 200 {
		t.Fatal("a config not reading the field blocked a request")
	}

	a.set(listsBody(), "")
	h.pollDenylist()
	if h.served() != 200 || h.metrics()["edge_denylist_entries"] != 0 || h.srv.edge.lists.Load() != nil {
		t.Fatal("set not freed")
	}
	if got := fmt.Sprint(accessLine(t, h, 0)["client.ip_lists"]); got != "[aws]" {
		t.Fatalf("line with the list on: client.ip_lists = %s", got)
	}
	if _, has := accessLine(t, h, 1)["client.ip_lists"]; has {
		t.Fatal("line with no list on carries client.ip_lists")
	}
}

// The access line names the lists holding the client address, whether or not
// a rule reads the field, and leaves the attribute out for a client on none.
func TestAccessLogCarriesIPLists(t *testing.T) {
	body := listsBody(IPList{Name: "aws", Prefixes: []string{"198.51.100.0/24"}}, IPList{Name: "github", Prefixes: []string{"198.51.100.7/32"}})
	h := denyHarness(t, newFakeDenylist(t, body))
	h.load(envelope(testConfig(1)))
	h.pollDenylist()
	h.statuses(1, "GET", "/")
	h.statuses(1, "GET", "/", "CloudFront-Viewer-Address", otherClient)
	listed, unlisted := accessLine(t, h, 0), accessLine(t, h, 1)
	if got := fmt.Sprint(listed["client.ip_lists"]); got != "[aws github]" {
		t.Fatalf("listed line client.ip_lists = %s", got)
	}
	if _, has := unlisted["client.ip_lists"]; has {
		t.Fatalf("unlisted line = %v", unlisted)
	}
}

// The loop polls right after start, then on its interval, until cancelled.
func TestDenylistLoopPollsRepeatedly(t *testing.T) {
	a := newFakeDenylist(t, awsBody)
	h := denyHarness(t, a)
	h.load(envelope(denyConfig(1)))
	h.srv.denylist.every = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() { h.srv.denylist.run(ctx) })
	waitFor(t, func() bool { return a.requests.Load() >= 2 })
	cancel()
	wg.Wait()
	if h.served() != 403 {
		t.Fatal("set not loaded by the loop")
	}
}

// A lift ends a ban that started before it. A client that trips the trap
// again afterwards is banned again, and the same lift, sent again, leaves
// that new ban alone.
func TestLiftEndsOlderBansOnly(t *testing.T) {
	a := newFakeDenylist(t, "")
	h := denyHarness(t, a)
	now := time.Now()
	clock := h.fakeClock(now)
	c := trapConfig(1)
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "listed", Expression: mustParse(`client.ip_lists in {"aws"}`), Settings: snapshot.Settings{Block: new("log")}})
	h.load(envelope(c))
	lift := func(ip string, at time.Time) {
		b, _ := json.Marshal(DenylistResponse{Lists: []IPList{{Name: "aws", Prefixes: []string{"192.0.2.1/32"}}}, Lifts: []BanLift{{IP: ip, At: at.UnixMilli()}}})
		a.set(string(b), "")
		h.pollDenylist()
	}

	trip(t, h, "a.example.com")
	edgeError(t, h.do("GET", "/", nil), 403, "forbidden")
	clock.Store(now.Add(time.Second).UnixMilli())
	lift("198.51.100.99", now.Add(time.Second)) // another client: nothing to lift
	edgeError(t, h.do("GET", "/", nil), 403, "forbidden")
	lift("::ffff:198.51.100.7", now.Add(time.Second))
	if got := h.served(); got != 200 {
		t.Fatalf("after the lift: %d", got)
	}

	clock.Store(now.Add(2 * time.Second).UnixMilli())
	trip(t, h, "a.example.com")
	lift("198.51.100.7", now.Add(time.Second))
	edgeError(t, h.do("GET", "/", nil), 403, "forbidden")
}

// A response whose lists the builder refuses still lifts bans: an unban
// never waits on the lists.
func TestRefusedListsStillLiftBans(t *testing.T) {
	a := newFakeDenylist(t, "")
	h := denyHarness(t, a)
	now := time.Now()
	clock := h.fakeClock(now)
	h.load(envelope(trapConfig(1)))
	trip(t, h, "a.example.com")
	edgeError(t, h.do("GET", "/", nil), 403, "forbidden")
	clock.Store(now.Add(time.Second).UnixMilli())
	refuseIPLists(t)
	b, _ := json.Marshal(DenylistResponse{Lists: []IPList{{Name: "aws", Prefixes: []string{"192.0.2.1/32"}}}, Lifts: []BanLift{{IP: "198.51.100.7", At: now.Add(time.Second).UnixMilli()}}})
	a.set(string(b), "")
	h.pollDenylist()
	if got := h.served(); got != 200 || h.metrics()["edge_denylist_fetch_failures_total"] != 1 {
		t.Fatalf("after a refused response with a lift: %d, failures %v", got, h.metrics()["edge_denylist_fetch_failures_total"])
	}
}

// A config with a trap but no rule reading client.ip_lists still gets lifts,
// and holds the set, so its access lines are labelled.
func TestTrapOnlyConfigAppliesLiftsAndHoldsTheSet(t *testing.T) {
	a := newFakeDenylist(t, "")
	h := denyHarness(t, a)
	now := time.Now()
	clock := h.fakeClock(now)
	h.load(envelope(trapConfig(1)))
	trip(t, h, "a.example.com")
	clock.Store(now.Add(time.Second).UnixMilli())
	b, _ := json.Marshal(DenylistResponse{Lists: []IPList{{Name: "aws", Prefixes: []string{"198.51.100.0/24"}}}, Lifts: []BanLift{{IP: "198.51.100.7", At: now.Add(time.Second).UnixMilli()}}})
	a.set(string(b), "")
	h.pollDenylist()
	if h.served() != 200 || h.srv.edge.lists.Load() == nil || h.metrics()["edge_denylist_entries"] != 1 || h.metrics()["edge_denylist_fetch_failures_total"] != 0 {
		t.Fatal("lift not applied, or the set was not kept")
	}
}

// The bans an edge records go out with the next stats report, once.
func TestBanReportsReachTheNextStatsReport(t *testing.T) {
	var mu sync.Mutex
	var got []StatsReport
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep StatsReport
		_ = json.NewDecoder(r.Body).Decode(&rep)
		mu.Lock()
		got = append(got, rep)
		mu.Unlock()
	}))
	defer admin.Close()
	h := newHarness(t, map[string]string{"ADMIN_URL": admin.URL, "EDGE_SERVICE_TOKEN": "t0k"})
	h.load(envelope(trapConfig(1)))
	trip(t, h, "a.example.com")
	trip(t, h, "b.example.com", "CloudFront-Viewer-Address", "[2001:db8:1:2::9]:1")
	h.srv.reporter.report(t.Context())
	h.srv.reporter.report(t.Context())
	if len(got) != 2 || len(got[0].Bans) != 2 || len(got[1].Bans) != 0 {
		t.Fatalf("reports %+v", got)
	}
	v4, v6 := got[0].Bans[0], got[0].Bans[1]
	if v4.IP != "198.51.100.7" || v4.Rule != "trap" || v4.Host != "a.example.com" || v4.Path != "/wp-login.php" || v4.End-v4.Start != time.Hour.Milliseconds() || v6.IP != "2001:db8:1:2::" {
		t.Fatalf("bans %+v", got[0].Bans)
	}
}

// More bans than a report holds are dropped and counted, and a failed
// report loses what it carried.
func TestBanReportsBeyondTheCapAreDropped(t *testing.T) {
	var got atomic.Pointer[StatsReport]
	var status atomic.Int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep StatsReport
		_ = json.NewDecoder(r.Body).Decode(&rep)
		got.Store(&rep)
		if s := status.Load(); s != 0 {
			w.WriteHeader(int(s))
		}
	}))
	defer admin.Close()
	h := newHarness(t, map[string]string{"ADMIN_URL": admin.URL, "EDGE_SERVICE_TOKEN": "t0k"})
	h.load(envelope(trapConfig(1)))
	for i := range MaxBanReports + 5 {
		trip(t, h, fmt.Sprintf("h%d.example.com", i))
	}
	if n := h.metrics()["edge_ban_reports_dropped_total"]; n != 5 {
		t.Fatalf("dropped %v", n)
	}
	status.Store(500)
	h.srv.reporter.report(t.Context())
	if n := len(got.Load().Bans); n != MaxBanReports {
		t.Fatalf("report carried %d bans", n)
	}
	status.Store(0)
	h.srv.reporter.report(t.Context())
	if n := len(got.Load().Bans); n != 0 {
		t.Fatalf("the failed report's bans came back: %d", n)
	}
}

// Anything admin sends must be refused or applied, never panic.
func FuzzApplyDenylist(f *testing.F) {
	for _, s := range []string{
		`{"lists":[{"name":"aws","prefixes":["1.2.3.4/32","::ffff:1.2.3.0/120","2001:db8::/32","0.0.0.0/0"]},{"name":"aws","prefixes":[]}],"lifts":[{"ip":"::ffff:1.2.3.4","at":1},{"ip":"fe80::1%eth0","at":-1}],"dropped_lists":["x"]}`,
		`{"lists":[{"name":"a","prefixes":["1.2.3.4/33"]}]}`, `{"lists":[{"name":"a","prefixes":["10.0.0.0/8","10.1.0.0/16"]},{"name":"b","prefixes":["10.1.2.3/32"]}]}`,
		`{"lists":null,"lifts":null}`, `[]`, ``,
	} {
		f.Add([]byte(s))
	}
	s, _ := inMemoryEdge(f, testConfig(1), "/")
	d := &denylistPoller{p: s.poller, edge: s.edge}
	f.Fuzz(func(t *testing.T, b []byte) {
		before := s.edge.lists.Load()
		if err := d.apply(b); err != nil && s.edge.lists.Load() != before {
			t.Fatal("a refused body changed the set")
		}
	})
}

// Decoding and building a response of about 225,000 prefixes across 70 lists,
// the size of every default provider list turned on.
func BenchmarkApplyDenylist(b *testing.B) {
	const lists = 70
	resp := DenylistResponse{Lifts: []BanLift{}, Dropped: []string{}}
	for i := range lists {
		resp.Lists = append(resp.Lists, IPList{Name: fmt.Sprintf("list-%d", i)})
	}
	for k := range 225_000 {
		x := uint32(k) * 37
		bits := 24
		if k%10 == 0 {
			bits = 16
		}
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(x >> 16), byte(x >> 8), byte(x), 0}), bits).Masked()
		resp.Lists[k%lists].Prefixes = append(resp.Lists[k%lists].Prefixes, p.String())
	}
	body, _ := json.Marshal(resp)
	s, _ := inMemoryEdge(b, testConfig(1), "/")
	d := &denylistPoller{p: s.poller, edge: s.edge}
	b.ReportAllocs()
	for b.Loop() {
		if err := d.apply(body); err != nil {
			b.Fatal(err)
		}
	}
}
