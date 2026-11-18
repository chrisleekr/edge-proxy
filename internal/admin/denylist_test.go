package admin

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/jwks"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

// trustLists fetches IP lists through the SSRF-guarded client, trusting the
// fake sources' certificates.
func (h *harness) trustLists(fs ...*fakeRanges) {
	roots := x509.NewCertPool()
	for _, f := range fs {
		roots.AddCert(f.srv.Certificate())
	}
	h.s.lists = jwks.NewClient([]string{"127.0.0.1"}, 2*time.Second, roots)
}

// listActions are the audit actions about lists and bans, with their targets.
func (h *harness) listActions() []string {
	h.t.Helper()
	return slices.DeleteFunc(h.actions(), func(a string) bool { return !strings.HasPrefix(a, "denylist.") && !strings.HasPrefix(a, "ban.") })
}

// sampleList has comments, CRLF endings, a repeat, a range wider than lists
// carry, a line that is no address and an IPv6 address.
const sampleList = "# header\r\n1.2.3.4\r\n5.6.7.0/24 ; note\n1.2.3.4\n10.0.0.0/8\nnot-an-ip\n2001:db8::1 # x\n"

var samplePrefixes = []string{"1.2.3.4/32", "2001:db8::1/128", "5.6.7.0/24"}

// listHarness is admin with a publisher signed in, an edge client and one
// fake list source, fetched through the guarded client.
func listHarness(t *testing.T) (*harness, *client, *client, *fakeRanges) {
	t.Helper()
	f := newFakeRanges(t, sampleList)
	h := newHarness(t)
	h.trustLists(f)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	e := h.client()
	e.token = h.edgeToken(pub)
	return h, pub, e, f
}

type denylistBody struct {
	Lists []struct {
		Name     string   `json:"name"`
		Prefixes []string `json:"prefixes"`
	} `json:"lists"`
	Lifts []struct {
		IP string `json:"ip"`
		At int64  `json:"at"`
	} `json:"lifts"`
	DroppedLists []string `json:"dropped_lists"`
}

func edgeDenylist(t *testing.T, e *client) denylistBody {
	t.Helper()
	return decode[denylistBody](t, e.do("GET", "/v1/denylist", nil))
}

// prefixes is every prefix the edge response carries, list by list.
func prefixes(t *testing.T, e *client) []string {
	t.Helper()
	out := []string{}
	for _, l := range edgeDenylist(t, e).Lists {
		out = append(out, l.Prefixes...)
	}
	return out
}

// listName is the name addList gives the fake source.
const listName = "test-list"

// src is the list named n in GET /api/denylists.
func src(t *testing.T, c *client, n string) denylistSource {
	t.Helper()
	for _, s := range sources(t, c) {
		if s.Name == n {
			return s
		}
	}
	t.Fatalf("no list named %q", n)
	return denylistSource{}
}

// listPath is the route of the list named n, with an optional suffix.
func listPath(t *testing.T, c *client, n, suffix string) string {
	t.Helper()
	return fmt.Sprintf("/api/denylists/%d%s", src(t, c, n).ID, suffix)
}

// sources is GET /api/denylists.
func sources(t *testing.T, c *client) []denylistSource {
	t.Helper()
	return decode[[]denylistSource](t, c.do("GET", "/api/denylists", nil))
}

// addList adds the fake source as pub, on and not wide, and returns its URL.
func addList(t *testing.T, pub *client, f *fakeRanges) string {
	t.Helper()
	return addNamed(t, pub, f, listName, "/list.txt", false)
}

// addNamed adds the fake source under a name and path.
func addNamed(t *testing.T, pub *client, f *fakeRanges, name, path string, wide bool) string {
	t.Helper()
	url := f.srv.URL + path
	status(t, pub.do("POST", "/api/denylists", map[string]any{"name": name, "url": url, "wide": wide}), http.StatusCreated)
	return url
}

// An added list is audited, fetched by the leader within a tick through the
// SSRF guard, normalized, and served to edges apart from the snapshot, with
// the first fetch audited as an automated event.
func TestDenylistSourceIsAuditedFetchedAndServed(t *testing.T) {
	h, pub, e, f := listHarness(t)
	url := addList(t, pub, f)
	if got := h.listActions(); !slices.Equal(got, []string{"denylist.source_added " + url}) {
		t.Fatalf("audit %v", got)
	}
	var details map[string]any
	if err := h.db.QueryRow(t.Context(), "SELECT details FROM audit_events WHERE action = 'denylist.source_added'").Scan(&details); err != nil || details["name"] != listName || details["wide"] != false {
		t.Fatalf("audit details %v, %v", details, err)
	}
	// The status row is written after the set, so wait for it: stopping the
	// leader between the two leaves no status.
	leadBriefly(t, h, func() bool { return src(t, pub, listName).LastSuccessAt != nil })
	if got := prefixes(t, e); !slices.Equal(got, samplePrefixes) {
		t.Fatalf("prefixes %v", got)
	}
	if got := h.auditActors("denylist.changed"); !slices.Equal(got, []string{"system:denylist"}) {
		t.Fatalf("changes audited by %v", got)
	}
	if got := edgeDenylist(t, e); len(got.Lists) != 1 || got.Lists[0].Name != listName {
		t.Fatalf("lists %+v", got.Lists)
	}
	if s := src(t, pub, listName); s.Entries != 3 || s.Skipped != 2 || s.Failures != 0 || s.LastSuccessAt == nil || !s.Enabled || s.Wide {
		t.Fatalf("source %+v", s)
	}
}

// Only people who can publish change lists; a viewer reads them.
func TestDenylistChangesNeedThePermission(t *testing.T) {
	h, pub, _, f := listHarness(t)
	addList(t, pub, f)
	h.user("view", "viewer")
	v := h.signedIn("view")
	status(t, v.do("POST", "/api/denylists", map[string]string{"name": "a", "url": "https://example.com/a.txt"}), http.StatusForbidden)
	status(t, v.do("PATCH", listPath(t, pub, listName, ""), map[string]bool{"enabled": false}), http.StatusForbidden)
	status(t, v.do("DELETE", listPath(t, pub, listName, ""), nil), http.StatusForbidden)
	status(t, v.do("POST", listPath(t, pub, listName, "/refresh"), nil), http.StatusForbidden)
	status(t, v.do("POST", "/api/bans/lift", map[string]string{"ip": "1.2.3.4"}), http.StatusForbidden)
	status(t, v.do("GET", "/api/denylists", nil), http.StatusOK)
	status(t, v.do("GET", "/api/bans", nil), http.StatusOK)
}

// A list URL that could leak a secret, or reach a plain-text or local
// target, is refused with a message.
func TestDenylistSourceURLsAreChecked(t *testing.T) {
	_, pub, _, _ := listHarness(t)
	for _, tc := range []struct{ name, url string }{
		{"plain http", "http://example.com/a.txt"},
		{"credentials", "https://user:pw@example.com/a.txt"},
		{"query", "https://example.com/a.txt?key=secret"},
		{"fragment", "https://example.com/a.txt#x"},
		{"no host", "https:///a.txt"},
		{"over 2048 characters", "https://example.com/" + strings.Repeat("a", 2048)},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status(t, pub.do("POST", "/api/denylists", map[string]string{"name": "x", "url": tc.url}), http.StatusUnprocessableEntity)
		})
	}
}

// A name rules could not write, or that another list has, is refused: 422 for
// the form, 409 for a repeat, whether the name or the address repeats.
func TestDenylistNamesAreCheckedAndUnique(t *testing.T) {
	_, pub, _, _ := listHarness(t)
	for _, tc := range []struct{ name, list string }{
		{"empty", ""},
		{"capital letters", "AWS"},
		{"leading hyphen", "-aws"},
		{"underscore", "my_list"},
		{"space", "my list"},
		{"64 characters", strings.Repeat("a", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status(t, pub.do("POST", "/api/denylists", map[string]string{"name": tc.list, "url": "https://example.com/n.txt"}), http.StatusUnprocessableEntity)
		})
	}
	status(t, pub.do("POST", "/api/denylists", map[string]string{"name": strings.Repeat("a", 63), "url": "https://example.com/n.txt"}), http.StatusCreated)
	status(t, pub.do("POST", "/api/denylists", map[string]string{"name": "mine", "url": "https://example.com/m.txt"}), http.StatusCreated)
	status(t, pub.do("POST", "/api/denylists", map[string]string{"name": "mine", "url": "https://example.com/other.txt"}), http.StatusConflict)
	status(t, pub.do("POST", "/api/denylists", map[string]string{"name": "other", "url": "https://example.com/m.txt"}), http.StatusConflict)
	// A default's name is taken too.
	status(t, pub.do("POST", "/api/denylists", map[string]string{"name": "aws", "url": "https://example.com/aws.txt"}), http.StatusConflict)
}

// The defaults count toward the limit of 128 lists; the one after it is refused.
func TestDenylistCapsTheLists(t *testing.T) {
	_, pub, _, _ := listHarness(t)
	for i := len(sources(t, pub)); i < maxDenylistSources; i++ {
		status(t, pub.do("POST", "/api/denylists", map[string]string{"name": fmt.Sprintf("l%d", i), "url": fmt.Sprintf("https://example.com/%d.txt", i)}), http.StatusCreated)
	}
	status(t, pub.do("POST", "/api/denylists", map[string]string{"name": "extra", "url": "https://example.com/extra.txt"}), http.StatusUnprocessableEntity)
}

// A fresh database has the 73 default lists, every one off, each with a name
// rules can write, and edges are served no list.
func TestDenylistDefaultsAreSeededOff(t *testing.T) {
	_, pub, e, _ := listHarness(t)
	got := sources(t, pub)
	if len(got) != 73 {
		t.Fatalf("%d lists", len(got))
	}
	wide := 0
	for _, s := range got {
		if s.Enabled || !expr.ValidListName(s.Name) || s.AddedBy != "migration" || s.Entries != 0 {
			t.Fatalf("list %+v", s)
		}
		if s.Wide {
			wide++
		}
	}
	if wide != 32 {
		t.Fatalf("%d wide lists, want the 32 whose provider data has wide ranges", wide)
	}
	for _, n := range []string{"aws", "cloudflare", "zscaler"} {
		if !src(t, pub, n).Wide {
			t.Fatalf("%s is not wide", n)
		}
	}
	for _, n := range []string{"firehol-abusers", "spamhaus-drop", "googlebot", "datadog", "statuscake"} {
		if src(t, pub, n).Wide {
			t.Fatalf("%s is wide", n)
		}
	}
	// Empty arrays, never null, so an edge reads them as lists.
	resp := e.do("GET", "/v1/denylist", nil)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if want := `{"lists":[],"lifts":[],"dropped_lists":[]}`; strings.TrimSpace(string(raw)) != want {
		t.Fatalf("edges got %s, want %s", raw, want)
	}
}

// Turning a default on is audited and makes the leader fetch it, by its
// name. aws is a wide default, so it keeps the sample's /8.
func TestDenylistTurningADefaultOnFetchesIt(t *testing.T) {
	h, pub, e, f := listHarness(t)
	url := f.srv.URL + "/aws.txt"
	if _, err := h.db.Exec(t.Context(), "UPDATE denylist_sources SET url = $1 WHERE name = 'aws'", url); err != nil {
		t.Fatal(err)
	}
	if err := h.s.refreshDenylists(t.Context()); err != nil || src(t, pub, "aws").LastAttemptAt != nil {
		t.Fatalf("a list that is off was fetched: %v", err)
	}
	status(t, pub.do("PATCH", listPath(t, pub, "aws", ""), map[string]bool{"enabled": true}), http.StatusNoContent)
	if got := h.listActions(); !slices.Equal(got, []string{"denylist.source_enabled " + url}) {
		t.Fatalf("audit %v", got)
	}
	leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })
	if got := edgeDenylist(t, e); len(got.Lists) != 1 || got.Lists[0].Name != "aws" || !slices.Equal(got.Lists[0].Prefixes, []string{"1.2.3.4/32", "10.0.0.0/8", "2001:db8::1/128", "5.6.7.0/24"}) {
		t.Fatalf("lists %+v", got.Lists)
	}
}

// A wide list keeps a /10, as a cloud provider owns, and a plain list skips
// it; neither keeps a /7.
func TestDenylistWideListKeepsWideRanges(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	f := newFakeRanges(t, "100.64.0.0/10\n8.0.0.0/7\n1.2.3.4\n")
	h.trustLists(f)
	addNamed(t, pub, f, "plain", "/plain.txt", false)
	addNamed(t, pub, f, "broad", "/broad.txt", true)
	leadBriefly(t, h, func() bool {
		return src(t, pub, "plain").LastSuccessAt != nil && src(t, pub, "broad").LastSuccessAt != nil
	})
	got := map[string][]string{}
	for _, l := range edgeDenylist(t, e).Lists {
		got[l.Name] = l.Prefixes
	}
	if !slices.Equal(got["plain"], []string{"1.2.3.4/32"}) || !slices.Equal(got["broad"], []string{"1.2.3.4/32", "100.64.0.0/10"}) {
		t.Fatalf("lists %v", got)
	}
	if s := src(t, pub, "plain"); s.Skipped != 2 || s.Wide {
		t.Fatalf("plain %+v", s)
	}
	if s := src(t, pub, "broad"); s.Skipped != 1 || !s.Wide {
		t.Fatalf("broad %+v", s)
	}
}

// storeEntries stores n distinct /32 lines for a list, counted as stored, as
// storeDenylist does, starting at the address base.
func storeEntries(t *testing.T, h *harness, name string, n int, base string) {
	t.Helper()
	if _, err := h.db.Exec(t.Context(), `INSERT INTO denylist_sets (source_id, fetched_at, entries, prefixes)
		SELECT id, now(), $2::int, (SELECT string_agg(host($3::inet + g) || '/32', E'\n' ORDER BY g) FROM generate_series(0, $2::int - 1) g)
		FROM denylist_sources WHERE name = $1`, name, n, base); err != nil {
		t.Fatal(err)
	}
}

// Past the edge's cap a list is left out whole, never cut, and named; a later
// smaller list after it that still fits is served.
func TestDenylistCutsWholeListsAtTheCap(t *testing.T) {
	h, pub, e, f := listHarness(t)
	for i, l := range []struct {
		name string
		n    int
	}{{"first", edge.MaxDenylistPrefixes / 2}, {"second", edge.MaxDenylistPrefixes/2 + 1}, {"third", 10}} {
		addNamed(t, pub, f, l.name, fmt.Sprintf("/%d.txt", i), false)
		storeEntries(t, h, l.name, l.n, fmt.Sprintf("%d.0.0.0", i+1))
	}
	got := edgeDenylist(t, e)
	var names []string
	for _, l := range got.Lists {
		names = append(names, l.Name)
	}
	if !slices.Equal(names, []string{"first", "third"}) || !slices.Equal(got.DroppedLists, []string{"second"}) {
		t.Fatalf("served %v, dropped %v", names, got.DroppedLists)
	}
	if n := len(got.Lists[0].Prefixes); n != edge.MaxDenylistPrefixes/2 || got.Lists[0].Prefixes[0] != "1.0.0.0/32" {
		t.Fatalf("the first list was cut: %d prefixes, from %s", n, got.Lists[0].Prefixes[0])
	}
	if n := len(got.Lists[1].Prefixes); n != 10 || got.Lists[1].Prefixes[9] != "3.0.0.9/32" {
		t.Fatalf("the third list was cut: %d prefixes", n)
	}
}

// A refresh that finds the same list writes nothing: no audit row, and the
// edges' ETag stays. A list that changed is audited with what it added and
// removed, compared in the order the lists are stored in.
func TestDenylistChangeIsAuditedAndUnchangedIsNot(t *testing.T) {
	h, pub, e, f := listHarness(t)
	addList(t, pub, f)
	leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })
	tag := e.do("GET", "/v1/denylist", nil).Header.Get("ETag")

	status(t, pub.do("POST", listPath(t, pub, listName, "/refresh"), nil), http.StatusNoContent)
	leadBriefly(t, h, func() bool { return src(t, pub, listName).LastAttemptAt != nil })
	if s := src(t, pub, listName); s.Failures != 0 || s.LastError != "" {
		t.Fatalf("unchanged refresh failed: %+v", s)
	}
	if got := h.auditActors("denylist.changed"); len(got) != 1 {
		t.Fatalf("changes audited by %v", got)
	}
	status(t, e.do("GET", "/v1/denylist", nil, "If-None-Match", tag), http.StatusNotModified)

	// 1.2.3.10 sorts before 1.2.3.4 as text, not as an address.
	f.set(sampleList + "1.2.3.10\n")
	status(t, pub.do("POST", listPath(t, pub, listName, "/refresh"), nil), http.StatusNoContent)
	leadBriefly(t, h, func() bool { return len(h.auditActors("denylist.changed")) == 2 })
	var details map[string]any
	if err := h.db.QueryRow(t.Context(), "SELECT details FROM audit_events WHERE action = 'denylist.changed' ORDER BY seq DESC LIMIT 1").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(details["added"]) != "[1.2.3.10/32]" || fmt.Sprint(details["removed"]) != "[]" || details["entries"] != 4.0 {
		t.Fatalf("audit details %v", details)
	}
	status(t, e.do("GET", "/v1/denylist", nil, "If-None-Match", tag), http.StatusOK)
}

// A source that answers 200 with a page, or is down, keeps the last good set
// and shows why in its status, in words and without an audit row.
func TestDenylistFetchFailureKeepsTheLastGoodSet(t *testing.T) {
	h, pub, e, f := listHarness(t)
	addList(t, pub, f)
	leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })
	for _, tc := range []struct{ name, body string }{
		{"an HTML page", "<html><body>Rate limited</body></html>"},
		{"only unusable lines", "10.0.0.0/8\nhello\n"},
		{"source down", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.set(tc.body)
			before := src(t, pub, listName).Failures
			status(t, pub.do("POST", listPath(t, pub, listName, "/refresh"), nil), http.StatusNoContent)
			leadBriefly(t, h, func() bool { return src(t, pub, listName).Failures > before })
			if s := src(t, pub, listName); s.LastError == "" || s.Entries != 3 {
				t.Fatalf("status %+v", s)
			}
			if got := prefixes(t, e); !slices.Equal(got, samplePrefixes) {
				t.Fatalf("prefixes %v", got)
			}
			if got := h.auditActors("denylist.changed"); len(got) != 1 {
				t.Fatalf("changes audited by %v", got)
			}
		})
	}
}

// A source is fetched when due: not again within the hour, and again after.
func TestDenylistSourceIsFetchedOnceAnHour(t *testing.T) {
	h, pub, _, f := listHarness(t)
	addList(t, pub, f)
	leadBriefly(t, h, func() bool { return src(t, pub, listName).LastSuccessAt != nil })
	first := *src(t, pub, listName).LastAttemptAt
	h.advance(30 * time.Minute)
	if err := h.s.refreshDenylists(t.Context()); err != nil {
		t.Fatal(err)
	}
	pub = h.signedIn("pub") // the session idled out
	if got := *src(t, pub, listName).LastAttemptAt; !got.Equal(first) {
		t.Fatalf("fetched again after 30 minutes: %v then %v", first, got)
	}
	h.advance(31 * time.Minute)
	if err := h.s.refreshDenylists(t.Context()); err != nil {
		t.Fatal(err)
	}
	pub = h.signedIn("pub")
	if got := *src(t, pub, listName).LastAttemptAt; !got.After(first) {
		t.Fatalf("not fetched after an hour: %v then %v", first, got)
	}
}

// A disabled or removed list leaves what edges get, each audited, and a
// repeat of the same change writes no second row.
func TestDenylistDisableAndRemoveDropTheEntries(t *testing.T) {
	h, pub, e, f := listHarness(t)
	url := addList(t, pub, f)
	path := listPath(t, pub, listName, "")
	leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })

	status(t, pub.do("PATCH", path, map[string]bool{"enabled": false}), http.StatusNoContent)
	status(t, pub.do("PATCH", path, map[string]bool{"enabled": false}), http.StatusNoContent)
	if got := prefixes(t, e); len(got) != 0 {
		t.Fatalf("disabled list served %v", got)
	}
	status(t, pub.do("PATCH", path, map[string]bool{"enabled": true}), http.StatusNoContent)
	if got := prefixes(t, e); !slices.Equal(got, samplePrefixes) {
		t.Fatalf("enabled list served %v", got)
	}
	status(t, pub.do("DELETE", path, nil), http.StatusNoContent)
	if got := prefixes(t, e); len(got) != 0 {
		t.Fatalf("removed list served %v", got)
	}
	status(t, pub.do("DELETE", path, nil), http.StatusNotFound)
	status(t, pub.do("PATCH", path, map[string]bool{"enabled": true}), http.StatusNotFound)
	status(t, pub.do("POST", path+"/refresh", nil), http.StatusNotFound)
	want := []string{"denylist.source_added " + url, "denylist.changed " + url, "denylist.source_disabled " + url, "denylist.source_enabled " + url, "denylist.source_removed " + url}
	if got := h.listActions(); !slices.Equal(got, want) {
		t.Fatalf("audit %v, want %v", got, want)
	}
}

// Each enabled list is served whole under its name, in the order added.
func TestDenylistServesEachListByName(t *testing.T) {
	h, pub, e, f := listHarness(t)
	g := newFakeRanges(t, "5.6.7.0/24\n9.9.9.9\n")
	h.trustLists(f, g)
	addList(t, pub, f)
	addNamed(t, pub, g, "other-list", "/b.txt", false)
	leadBriefly(t, h, func() bool { return src(t, pub, listName).Entries > 0 && src(t, pub, "other-list").Entries > 0 })
	got := edgeDenylist(t, e)
	if len(got.Lists) != 2 || got.Lists[0].Name != listName || got.Lists[1].Name != "other-list" ||
		!slices.Equal(got.Lists[0].Prefixes, samplePrefixes) || !slices.Equal(got.Lists[1].Prefixes, []string{"5.6.7.0/24", "9.9.9.9/32"}) {
		t.Fatalf("lists %+v", got.Lists)
	}
}

// The response has one ETag over lists and lifts: a 304 while nothing
// changed, a new one when a list is turned on, and only an edge token reads it.
func TestDenylistETagFollowsListsAndLifts(t *testing.T) {
	h, pub, e, f := listHarness(t)
	addList(t, pub, f)
	leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })
	tag := e.do("GET", "/v1/denylist", nil).Header.Get("ETag")
	status(t, e.do("GET", "/v1/denylist", nil, "If-None-Match", tag), http.StatusNotModified)
	status(t, pub.do("PATCH", listPath(t, pub, listName, ""), map[string]bool{"enabled": false}), http.StatusNoContent)
	status(t, e.do("GET", "/v1/denylist", nil, "If-None-Match", tag), http.StatusOK)
	status(t, pub.do("GET", "/v1/denylist", nil), http.StatusForbidden)
}

func report(e *client, bans ...edge.BanReport) *http.Response {
	return e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "edge-a", Bans: bans})
}

func ban(ip string, start time.Time, d time.Duration) edge.BanReport {
	return edge.BanReport{IP: ip, Rule: "trap", Host: "www.example.com", Path: "/wp-login.php", Start: start.UnixMilli(), End: start.Add(d).UnixMilli()}
}

type banBody struct {
	IP          string `json:"ip"`
	Rule        string `json:"rule"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Edge        string `json:"edge"`
	LiftPending bool   `json:"lift_pending"`
}

func bans(t *testing.T, c *client) []banBody {
	t.Helper()
	return decode[[]banBody](t, c.do("GET", "/api/bans", nil))
}

// Bans an edge reports show on the Banned IPs list while they run, newest
// first, with what tripped them; a renewal updates the row and a report that
// repeats an address in one batch counts once.
func TestReportedBansAreListedWhileTheyRun(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	now := h.now()
	status(t, report(e,
		ban("203.0.113.5", now.Add(-10*time.Minute), time.Hour),
		ban("203.0.113.5", now.Add(-time.Minute), time.Hour),
		ban("2001:db8:1:2::", now.Add(-5*time.Minute), time.Hour),
		ban("198.51.100.1", now.Add(-3*time.Hour), time.Hour), // already over
	), http.StatusOK)
	got := bans(t, pub)
	if len(got) != 2 || got[0].IP != "203.0.113.5" || got[1].IP != "2001:db8:1:2::" ||
		got[0].Rule != "trap" || got[0].Host != "www.example.com" || got[0].Path != "/wp-login.php" || got[0].Edge != "edge-a" || got[0].LiftPending {
		t.Fatalf("bans %+v", got)
	}
	h.advance(2 * time.Hour)
	if got := bans(t, h.signedIn("pub")); len(got) != 0 {
		t.Fatalf("ended bans listed: %+v", got)
	}
}

// A report no edge sends is refused whole, before anything of it is stored.
func TestBanReportsAreValidated(t *testing.T) {
	h, _, e, _ := listHarness(t)
	now := h.now()
	many := make([]edge.BanReport, edge.MaxBanReports+1)
	for i := range many {
		many[i] = ban(netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i)}).String(), now, time.Hour)
	}
	status(t, report(e, many[:edge.MaxBanReports]...), http.StatusOK)
	for _, tc := range []struct {
		name string
		bans []edge.BanReport
	}{
		{"201 bans", many},
		{"not an address", []edge.BanReport{ban("not-an-ip", now, time.Hour)}},
		{"an IPv6 address that is not its /64", []edge.BanReport{ban("2001:db8:1:2::1", now, time.Hour)}},
		{"a 4-in-6 address", []edge.BanReport{ban("::ffff:203.0.113.5", now, time.Hour)}},
		{"a path over 128 characters", []edge.BanReport{{IP: "203.0.113.5", Rule: "r", Host: "h", Path: strings.Repeat("a", 129), Start: now.UnixMilli(), End: now.UnixMilli() + 1}}},
		{"NUL in the host", []edge.BanReport{{IP: "203.0.113.5", Rule: "r", Host: "h\x00", Path: "/", Start: now.UnixMilli(), End: now.UnixMilli() + 1}}},
		{"ending before it starts", []edge.BanReport{ban("203.0.113.5", now, -time.Hour)}},
		{"lasting over a week", []edge.BanReport{ban("203.0.113.5", now, 8*24*time.Hour)}},
		{"starting in year 10000", []edge.BanReport{ban("203.0.113.5", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Hour)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status(t, report(e, tc.bans...), http.StatusUnprocessableEntity)
		})
	}
	var n int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM bans").Scan(&n); err != nil || n != edge.MaxBanReports {
		t.Fatalf("%d bans stored, %v", n, err)
	}
}

// Lifting a ban is audited with the edge's ban key (an IPv6 address lifts
// its /64), reaches edges in the denylist response, and shows as pending on
// the list until edges have applied it. A ban that starts again after the
// lift is listed as running.
func TestLiftingABanIsAuditedAndServedToEdges(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	now := h.now()
	status(t, report(e, ban("2001:db8:1:2::", now.Add(-time.Minute), time.Hour)), http.StatusOK)
	status(t, pub.do("POST", "/api/bans/lift", map[string]string{"ip": "not-an-ip"}), http.StatusUnprocessableEntity)
	status(t, pub.do("POST", "/api/bans/lift", map[string]string{"ip": "2001:db8:1:2:3:4:5:6"}), http.StatusNoContent)
	if got := h.listActions(); !slices.Equal(got, []string{"ban.lifted 2001:db8:1:2::"}) {
		t.Fatalf("audit %v", got)
	}
	got := edgeDenylist(t, e)
	if len(got.Lifts) != 1 || got.Lifts[0].IP != "2001:db8:1:2::" || got.Lifts[0].At != now.UnixMilli() {
		t.Fatalf("lifts %+v", got.Lifts)
	}
	if b := bans(t, pub); len(b) != 1 || !b[0].LiftPending {
		t.Fatalf("bans %+v", b)
	}
	// The edge starts the ban again, after the lift.
	h.advance(time.Minute)
	status(t, report(e, ban("2001:db8:1:2::", h.now(), time.Hour)), http.StatusOK)
	if b := bans(t, pub); len(b) != 1 || b[0].LiftPending {
		t.Fatalf("bans %+v", b)
	}
	// And the lift is dropped from the list on its own once applied.
	status(t, pub.do("POST", "/api/bans/lift", map[string]string{"ip": "2001:db8:1:2::"}), http.StatusNoContent)
	h.advance(banLiftShown + time.Minute)
	if b := bans(t, pub); len(b) != 0 {
		t.Fatalf("lifted ban still listed: %+v", b)
	}
}

// A report whose bans cannot be stored fails, but its traffic counts are
// kept: the edge never resends them.
func TestBanWriteFailureKeepsTheReportsStats(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	if _, err := h.owner.Exec(t.Context(), "REVOKE INSERT, UPDATE ON bans FROM "+testenv.AppRole); err != nil {
		t.Fatal(err)
	}
	rep := edge.StatsReport{Instance: "edge-a", Versions: []edge.StatsCounts{{Version: 1, Requests: 7, LatencyMS: []uint64{7}}}, Bans: []edge.BanReport{ban("203.0.113.5", h.now(), time.Hour)}}
	status(t, e.do("POST", "/v1/edge/report", rep), http.StatusInternalServerError)
	h.advance(time.Minute)
	if err := h.s.flush(t.Context(), h.now()); err != nil {
		t.Fatal(err)
	}
	if rows := decode[[]statsRow](t, pub.do("GET", "/api/stats?minutes=5", nil)); len(rows) != 1 || rows[0].Requests != 7 {
		t.Fatalf("stats %+v", rows)
	}
}

// A report from another edge, for a ban that started before a lift, arrives
// after the lift: the ban is listed as lifted, not as running. A ban that
// started after the lift stays running.
func TestLateReportOfALiftedBanIsListedAsLifted(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	now := h.now()
	status(t, report(e, ban("203.0.113.5", now.Add(-time.Minute), time.Hour)), http.StatusOK)
	status(t, pub.do("POST", "/api/bans/lift", map[string]string{"ip": "203.0.113.5"}), http.StatusNoContent)
	h.advance(time.Second)
	late := edge.StatsReport{Instance: "edge-b", Bans: []edge.BanReport{ban("203.0.113.5", now.Add(-30*time.Second), time.Hour)}}
	status(t, e.do("POST", "/v1/edge/report", late), http.StatusOK)
	// A renewal that starts after the lift on the same edge clears it.
	h.advance(time.Second)
	fresh := edge.StatsReport{Instance: "edge-c", Bans: []edge.BanReport{ban("203.0.113.5", h.now(), time.Hour)}}
	status(t, e.do("POST", "/v1/edge/report", fresh), http.StatusOK)
	got := map[string]bool{}
	for _, b := range bans(t, pub) {
		got[b.Edge] = b.LiftPending
	}
	if len(got) != 3 || !got["edge-a"] || !got["edge-b"] || got["edge-c"] {
		t.Fatalf("lift pending by edge: %v", got)
	}
}

// The lookup says which enabled lists hold an address, by name and range.
func TestDenylistLookup(t *testing.T) {
	h, pub, _, f := listHarness(t)
	addList(t, pub, f)
	leadBriefly(t, h, func() bool { return src(t, pub, listName).Entries > 0 })
	type hit struct{ Name, Prefix string }
	for ip, want := range map[string]int{"5.6.7.200": 1, "::ffff:1.2.3.4": 1, "9.9.9.9": 0} {
		if got := decode[[]hit](t, pub.do("GET", "/api/denylists/lookup?ip="+ip, nil)); len(got) != want || want == 1 && got[0].Name != listName {
			t.Fatalf("%s: %+v", ip, got)
		}
	}
	status(t, pub.do("GET", "/api/denylists/lookup?ip=nope", nil), http.StatusUnprocessableEntity)
	status(t, pub.do("PATCH", listPath(t, pub, listName, ""), map[string]bool{"enabled": false}), http.StatusNoContent)
	if got := decode[[]hit](t, pub.do("GET", "/api/denylists/lookup?ip=5.6.7.200", nil)); len(got) != 0 {
		t.Fatalf("disabled list matched: %+v", got)
	}
}

// Retention drops bans a week after they ended and lifts after a day.
func TestRetentionDropsOldBansAndLifts(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	now := h.now()
	status(t, report(e, ban("203.0.113.5", now, time.Hour)), http.StatusOK)
	status(t, pub.do("POST", "/api/bans/lift", map[string]string{"ip": "203.0.113.5"}), http.StatusNoContent)
	count := func(table string) (n int) {
		if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	h.advance(25 * time.Hour)
	if err := h.s.dropOldStats(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count("bans") != 1 || count("ban_lifts") != 0 {
		t.Fatalf("after a day: %d bans, %d lifts", count("bans"), count("ban_lifts"))
	}
	h.advance(7 * 24 * time.Hour)
	if err := h.s.dropOldStats(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count("bans") != 0 {
		t.Fatalf("%d bans after a week", count("bans"))
	}
}

// A rule is warned about for each list name it compares client.ip_lists with
// that matches no one: a name no list has, and a list that is off or not
// downloaded yet. A list that is on and fetched gets no warning. Rules of
// every phase are checked.
func TestRuleNamingAListThatMatchesNoOneWarns(t *testing.T) {
	h, pub, _, f := listHarness(t)
	c := testConfig()
	c.Schema = snapshot.IPListsSchema
	e := mustParse(`client.ip_lists in {"nosuch" "test-list" "statuscake"}`)
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "listed", Expression: e, Settings: snapshot.Settings{CORSPolicy: new("")}})
	c.RateLimitRules = append(c.RateLimitRules, snapshot.RateLimitRule{ID: "listed-limit", Expression: e, Algorithm: "sliding_window", Limit: 10, Period: snapshot.Duration(time.Minute),
		Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"})
	c.RequestHeaderRules = append(c.RequestHeaderRules, snapshot.HeaderRule{ID: "listed-header", Expression: e, Ops: []snapshot.HeaderOp{{Op: "remove", Name: "X-A"}}})
	paths := []string{
		fmt.Sprintf("config_rules[%d].expression", len(c.ConfigRules)-1),
		fmt.Sprintf("rate_limit_rules[%d].expression", len(c.RateLimitRules)-1),
		fmt.Sprintf("request_header_rules[%d].expression", len(c.RequestHeaderRules)-1),
	}
	check := func() []string {
		resp := pub.do("POST", "/api/draft/check", map[string]any{"config": c})
		out := decode[struct {
			Errors, Warnings []map[string]any
		}](t, resp)
		if len(out.Errors) != 0 {
			t.Fatalf("errors %v", out.Errors)
		}
		var msgs []string
		for _, w := range out.Warnings {
			i := slices.IndexFunc(paths, func(p string) bool { return strings.HasSuffix(fmt.Sprint(w["path"]), p) })
			if i < 0 {
				t.Fatalf("warning on %v", w["path"])
			}
			msgs = append(msgs, fmt.Sprintf("%d: %s", i, w["message"]))
		}
		return msgs
	}
	// Each rule is warned about its names in sorted order.
	each := func(names ...string) (out []string) {
		for i := range paths {
			for _, n := range names {
				out = append(out, fmt.Sprintf("%d: %s", i, n))
			}
		}
		return out
	}
	const nosuch = `names IP list "nosuch", which does not exist, so it matches no one.`
	const statuscake = `names IP list "statuscake", which is off or not downloaded yet, so it matches no one until you turn it on in IP lists.`
	const testListMissing = `names IP list "test-list", which does not exist, so it matches no one.`
	const testListOff = `names IP list "test-list", which is off or not downloaded yet, so it matches no one until you turn it on in IP lists.`
	if got, want := check(), each(nosuch, statuscake, testListMissing); !slices.Equal(got, want) {
		t.Fatalf("warnings %q, want %q", got, want)
	}
	// Added but not downloaded yet.
	addList(t, pub, f)
	if got, want := check(), each(nosuch, statuscake, testListOff); !slices.Equal(got, want) {
		t.Fatalf("warnings %q, want %q", got, want)
	}
	leadBriefly(t, h, func() bool { return src(t, pub, listName).Entries > 0 })
	if got, want := check(), each(nosuch, statuscake); !slices.Equal(got, want) {
		t.Fatalf("warnings %q, want %q", got, want)
	}
	// Downloaded, then turned off.
	status(t, pub.do("PATCH", listPath(t, pub, listName, ""), map[string]bool{"enabled": false}), http.StatusNoContent)
	if got, want := check(), each(nosuch, statuscake, testListOff); !slices.Equal(got, want) {
		t.Fatalf("warnings %q, want %q", got, want)
	}
}

// A rule reading client.denylisted always warns: with no list on and
// downloaded it matches no one, and with one on it matches provider, crawler
// and monitor lists too.
func TestRuleReadingDenylistedAlwaysWarns(t *testing.T) {
	h, pub, _, f := listHarness(t)
	c := testConfig()
	c.Schema = snapshot.IPListsSchema
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "listed", Expression: mustParse(`client.denylisted`), Settings: snapshot.Settings{CORSPolicy: new("")}})
	check := func() []string {
		out := decode[struct {
			Errors, Warnings []map[string]any
		}](t, pub.do("POST", "/api/draft/check", map[string]any{"config": c}))
		if len(out.Errors) != 0 {
			t.Fatalf("errors %v", out.Errors)
		}
		var msgs []string
		for _, w := range out.Warnings {
			msgs = append(msgs, fmt.Sprint(w["message"]))
		}
		return msgs
	}
	const warn = "reads client.denylisted, but no IP list is on and downloaded, so it matches no one. Turn one on in IP lists."
	if got := check(); !slices.Equal(got, []string{warn}) {
		t.Fatalf("warnings %q, want %q", got, warn)
	}
	addList(t, pub, f)
	leadBriefly(t, h, func() bool { return src(t, pub, listName).Entries > 0 })
	const warnOn = "reads client.denylisted, which matches every IP list that is on, including provider, crawler and monitor lists. Name the lists with client.ip_lists."
	if got := check(); !slices.Equal(got, []string{warnOn}) {
		t.Fatalf("warnings %q, want %q with a list on and fetched", got, warnOn)
	}
}

// Lists are taken in the order added and one that would pass the entry cap is
// left out of the edge response, so a rule naming it is warned that it matches
// no one, even though the list is on and downloaded.
func TestRuleNamingALeftOutListWarns(t *testing.T) {
	h, pub, _, f := listHarness(t)
	for i, l := range []struct {
		name string
		n    int
	}{{"first", edge.MaxDenylistPrefixes / 2}, {"second", edge.MaxDenylistPrefixes/2 + 1}} {
		addNamed(t, pub, f, l.name, fmt.Sprintf("/%d.txt", i), false)
		storeEntries(t, h, l.name, l.n, fmt.Sprintf("%d.0.0.0", i+1))
	}
	c := testConfig()
	c.Schema = snapshot.IPListsSchema
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "listed", Expression: mustParse(`client.ip_lists in {"first" "second"}`), Settings: snapshot.Settings{CORSPolicy: new("")}})
	out := decode[struct {
		Errors, Warnings []map[string]any
	}](t, pub.do("POST", "/api/draft/check", map[string]any{"config": c}))
	const want = `names IP list "second", which is on but left out because the lists that are on pass 500,000 entries, so it matches no one.`
	if len(out.Errors) != 0 || len(out.Warnings) != 1 || out.Warnings[0]["message"] != want {
		t.Fatalf("errors %v, warnings %v, want one: %s", out.Errors, out.Warnings, want)
	}
}

// A policy test puts a request's IP in named lists, so rules that name a list
// can be tested without the list being on or downloaded.
func TestSimulateWithIPLists(t *testing.T) {
	c := testConfig()
	c.Schema, c.Version = snapshot.IPListsSchema, 1
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "listed", Expression: mustParse(`client.ip_lists in {"aws"}`), Settings: snapshot.Settings{CORSPolicy: new("")}})
	compiled, _, issues := snapshot.Compile(c, snapshot.Deployment{})
	if len(issues) != 0 {
		t.Fatalf("issues %v", issues)
	}
	for _, tc := range []struct {
		name  string
		lists []string
		want  bool
	}{
		{"in the named list", []string{"aws", "hetzner"}, true},
		{"in another list only", []string{"hetzner"}, false},
		{"in no list", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := simulate(compiled, TestRequest{Host: "api.example.com", Path: "/", IPLists: tc.lists})
			if err != nil || slices.Contains(res.ConfigRules, "listed") != tc.want {
				t.Fatalf("rules %v, err %v", res.ConfigRules, err)
			}
		})
	}
	if _, err := simulate(compiled, TestRequest{Host: "api.example.com", Path: "/", IPLists: []string{"AWS"}}); err == nil {
		t.Fatal("a bad list name was accepted")
	}
}

func TestParseList(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		wide     bool
		want     []string
		skipped  int
		fail     bool
	}{
		{"addresses and ranges", "1.2.3.4\n5.6.7.0/24\n2001:db8::/48\n", false, []string{"1.2.3.4/32", "2001:db8::/48", "5.6.7.0/24"}, 0, false},
		{"text after a space, tab, semicolon or hash", "1.2.3.4 x\n1.2.3.5\ty\n1.2.3.6;z\n1.2.3.7#w\n", false, []string{"1.2.3.4/32", "1.2.3.5/32", "1.2.3.6/32", "1.2.3.7/32"}, 0, false},
		{"CRLF endings and no final newline", "1.2.3.4\r\n1.2.3.5", false, []string{"1.2.3.4/32", "1.2.3.5/32"}, 0, false},
		{"comments and blank lines are not skipped entries", "# a\n\n   \n; b\n1.2.3.4\n", false, []string{"1.2.3.4/32"}, 0, false},
		{"a range is masked and repeats join", "1.2.3.5/24\n1.2.3.0/24\n", false, []string{"1.2.3.0/24"}, 0, false},
		{"text order, as the audit diff compares", "1.2.3.4\n1.2.3.10\n", false, []string{"1.2.3.10/32", "1.2.3.4/32"}, 0, false},
		{"too wide and not an address are counted", "1.2.3.4\n10.0.0.0/8\n2001::/16\nhello\n1.2.3.4/33\n::ffff:1.2.3.4\n", false, []string{"1.2.3.4/32"}, 5, false},
		{"a /10 and an IPv6 /20 are skipped on a plain list", "100.64.0.0/10\n2001:db8::/20\n1.2.3.4\n", false, []string{"1.2.3.4/32"}, 2, false},
		{"a /10 and an IPv6 /20 are kept on a wide list", "100.64.0.0/10\n2001:db8::/20\n1.2.3.4\n", true, []string{"1.2.3.4/32", "100.64.0.0/10", "2001::/20"}, 0, false},
		{"a /7 and an IPv6 /15 are skipped even on a wide list", "8.0.0.0/7\n2000::/15\n1.2.3.4\n", true, []string{"1.2.3.4/32"}, 2, false},
		{"an HTML page", "<html><body>x</body></html>", false, nil, 1, true},
		{"empty", "", false, nil, 0, true},
		{"only comments", "# nothing\n", false, nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, skipped, err := parseList([]byte(tc.in), tc.wide)
			if (err != nil) != tc.fail || !slices.Equal(got, tc.want) || skipped != tc.skipped {
				t.Fatalf("got %v, skipped %d, err %v", got, skipped, err)
			}
		})
	}
}
