package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// addTyped adds a typed list as pub and returns its response status.
func addTyped(pub *client, name, entries string, wide bool) *http.Response {
	return pub.do("POST", "/api/ip-lists", map[string]any{"name": name, "entries": entries, "wide": wide})
}

// patchList sends PATCH for the list named n.
func patchList(t *testing.T, c *client, n string, in map[string]any) *http.Response {
	t.Helper()
	return c.do("PATCH", listPath(t, c, n, ""), in)
}

// listRuleConfig is a valid config whose rule compares client.ip_lists with
// list, or no list when list is "".
func listRuleConfig(list string) *snapshot.Config {
	c := testConfig()
	c.Schema = snapshot.IPListsSchema
	if list != "" {
		c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "office-only", Expression: mustParse(fmt.Sprintf(`client.ip_lists in {%q}`, list)), Settings: snapshot.Settings{CORSPolicy: new("")}})
	}
	return c
}

// An address list typed in admin has no URL, is audited with its name, is
// served to edges at once without a fetch and never reaches the refresh.
func TestTypedIPListIsAuditedAndServedWithoutAFetch(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	status(t, addTyped(pub, "office", "203.0.113.10\n198.51.100.0/24\n\n2001:db8::1\n", false), http.StatusCreated)
	if got := h.listActions(); !slices.Equal(got, []string{"ip_list.added office"}) {
		t.Fatalf("audit %v", got)
	}
	if got := edgeIPLists(t, e); len(got.Lists) != 1 || got.Lists[0].Name != "office" || !slices.Equal(got.Lists[0].Prefixes, []string{"198.51.100.0/24", "2001:db8::1/128", "203.0.113.10/32"}) {
		t.Fatalf("served %+v", got.Lists)
	}
	if s := src(t, pub, "office"); s.URL != "" || s.Entries != 3 || !s.Enabled || s.UsedBy == nil || len(s.UsedBy) != 0 {
		t.Fatalf("list %+v", s)
	}
	if err := h.s.refreshIPLists(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s := src(t, pub, "office"); s.LastAttemptAt != nil || s.Failures != 0 {
		t.Fatalf("a typed list was fetched: %+v", s)
	}
	status(t, pub.do("POST", listPath(t, pub, "office", "/refresh"), nil), http.StatusUnprocessableEntity)
}

// A typed line is a person's intent: one bad line refuses the whole list with
// its line number, and neither the list nor an audit row is saved.
func TestTypedIPListRefusesABadLineAndSavesNothing(t *testing.T) {
	for _, tc := range []struct {
		name, entries, want string
	}{
		{"host bits set", "10.1.0.1\n198.51.100.7/24\n", "line 2: 198.51.100.7/24 has host bits set; did you mean 198.51.100.0/24?"},
		{"IPv4 written as IPv6", "::ffff:1.2.3.4\n", "line 1: ::ffff:1.2.3.4 is IPv4 written as IPv6"},
		{"zone on an address", "\nfe80::1%eth0\n", "line 2: fe80::1%eth0 has a zone"},
		{"wider than allowed", "10.0.0.0/8\n", "line 1: 10.0.0.0/8 is wider than /16"},
		{"not an address", "1.2.3.4\nnope\n", `line 2: "nope" is not an IP address or CIDR range`},
		{"repeat", "1.2.3.4\n5.6.7.8\n1.2.3.4/32\n", "line 3: 1.2.3.4/32 repeats line 1"},
		{"empty", " \n\n", "needs at least one address"},
		{"over the cap", strings.Repeat("1.2.3.4\n", 1) + manyAddresses(maxTypedEntries), fmt.Sprintf("has %d entries; at most %d are allowed", maxTypedEntries+1, maxTypedEntries)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, _, _ := listHarness(t)
			resp := addTyped(pub, "office", tc.entries, false)
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("status %d: %s", resp.StatusCode, body(resp))
			}
			var problem struct{ Errors []struct{ Message string } }
			if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil || len(problem.Errors) == 0 || !strings.Contains(problem.Errors[0].Message, tc.want) {
				t.Fatalf("errors %+v, want one with %q, %v", problem.Errors, tc.want, err)
			}
			if got := h.listActions(); len(got) != 0 || len(sources(t, pub)) != 73 {
				t.Fatalf("saved something: audit %v, %d lists", got, len(sources(t, pub)))
			}
		})
	}
}

// manyAddresses is n distinct addresses, one per line, from 10.0.0.0/16 up.
func manyAddresses(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "10.%d.%d.%d\n", 1+i/65536, i/256%256, i%256)
	}
	return b.String()
}

// A list is a URL or typed addresses, never both.
func TestAddingAListWithAURLAndAddressesIsRefused(t *testing.T) {
	_, pub, _, f := listHarness(t)
	status(t, pub.do("POST", "/api/ip-lists", map[string]any{"name": "both", "url": f.srv.URL + "/list.txt", "entries": "1.2.3.4"}), http.StatusUnprocessableEntity)
	status(t, pub.do("POST", "/api/ip-lists", map[string]any{"name": "neither"}), http.StatusUnprocessableEntity)
}

// Editing the addresses of a typed list is audited in the same transaction
// with what it added and removed, moves the edge ETag and needs no publish; an
// edit that changes nothing writes nothing.
func TestEditingATypedListIsAuditedAndMovesTheETag(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	status(t, addTyped(pub, "office", "203.0.113.10\n198.51.100.7\n", false), http.StatusCreated)
	tag := e.do("GET", "/v1/ip-lists", nil).Header.Get("ETag")

	status(t, patchList(t, pub, "office", map[string]any{"entries": "198.51.100.7\n203.0.113.99\n"}), http.StatusNoContent)
	if got := prefixes(t, e); !slices.Equal(got, []string{"198.51.100.7/32", "203.0.113.99/32"}) {
		t.Fatalf("served %v", got)
	}
	status(t, e.do("GET", "/v1/ip-lists", nil, "If-None-Match", tag), http.StatusOK)
	if got := h.listActions(); !slices.Equal(got, []string{"ip_list.added office", "ip_list.updated office"}) {
		t.Fatalf("audit %v", got)
	}
	var details map[string]map[string]any
	if err := h.db.QueryRow(t.Context(), "SELECT details FROM audit_events WHERE action = 'ip_list.updated'").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if ent := details["entries"]; fmt.Sprint(ent["added"]) != "[203.0.113.99/32]" || fmt.Sprint(ent["removed"]) != "[203.0.113.10/32]" {
		t.Fatalf("audit details %v", details)
	}

	tag = e.do("GET", "/v1/ip-lists", nil).Header.Get("ETag")
	status(t, patchList(t, pub, "office", map[string]any{"entries": "203.0.113.99\n198.51.100.7"}), http.StatusNoContent)
	status(t, e.do("GET", "/v1/ip-lists", nil, "If-None-Match", tag), http.StatusNotModified)
	if got := h.listActions(); len(got) != 2 {
		t.Fatalf("an unchanged edit was audited: %v", got)
	}
}

// A bad edit of a typed list keeps the list and writes no audit row.
func TestABadEditOfATypedListChangesNothing(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	status(t, addTyped(pub, "office", "203.0.113.10\n", false), http.StatusCreated)
	status(t, patchList(t, pub, "office", map[string]any{"name": "hq", "entries": "203.0.113.0/24 \n1.2.3.4/8"}), http.StatusUnprocessableEntity)
	if got := prefixes(t, e); !slices.Equal(got, []string{"203.0.113.10/32"}) || src(t, pub, "office").Name != "office" {
		t.Fatalf("served %v after a refused edit", got)
	}
	if got := h.listActions(); len(got) != 1 {
		t.Fatalf("audit %v", got)
	}
}

// Narrowing the wide flag re-checks a typed list: an entry that is now too
// wide refuses the change instead of being dropped.
func TestNarrowingATypedListThatHoldsAWideRangeIsRefused(t *testing.T) {
	h, pub, e, _ := listHarness(t)
	status(t, addTyped(pub, "office", "10.0.0.0/8\n", true), http.StatusCreated)
	resp := patchList(t, pub, "office", map[string]any{"wide": false})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body(resp), "10.0.0.0/8 is wider than /16") {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !src(t, pub, "office").Wide || !slices.Equal(prefixes(t, e), []string{"10.0.0.0/8"}) {
		t.Fatal("the list changed")
	}
	if got := h.listActions(); len(got) != 1 {
		t.Fatalf("audit %v", got)
	}
	// Widening is always fine.
	status(t, addTyped(pub, "lab", "10.1.0.0/16\n", false), http.StatusCreated)
	status(t, patchList(t, pub, "lab", map[string]any{"wide": true}), http.StatusNoContent)
}

// A list keeps its kind: a typed list takes no URL and a downloaded list
// takes no addresses.
func TestAListKeepsItsKind(t *testing.T) {
	_, pub, _, f := listHarness(t)
	addList(t, pub, f)
	status(t, addTyped(pub, "office", "1.2.3.4", false), http.StatusCreated)
	status(t, patchList(t, pub, "office", map[string]any{"url": f.srv.URL + "/other.txt"}), http.StatusUnprocessableEntity)
	status(t, patchList(t, pub, listName, map[string]any{"entries": "1.2.3.4"}), http.StatusUnprocessableEntity)
	status(t, pub.do("PATCH", listPath(t, pub, "office", ""), map[string]any{}), http.StatusUnprocessableEntity)
}

// A new URL or width makes a downloaded list due at once, so the next check
// fetches it instead of waiting out the hour.
func TestChangingAURLOrWidthMakesTheListDueAgain(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   func(f *fakeRanges) map[string]any
	}{
		{"a new URL", func(f *fakeRanges) map[string]any { return map[string]any{"url": f.srv.URL + "/moved.txt"} }},
		{"a new width", func(*fakeRanges) map[string]any { return map[string]any{"wide": true} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, _, f := listHarness(t)
			addList(t, pub, f)
			leadBriefly(t, h, func() bool { return src(t, pub, listName).LastAttemptAt != nil })
			status(t, patchList(t, pub, listName, tc.in(f)), http.StatusNoContent)
			s := src(t, pub, listName)
			if s.LastAttemptAt != nil {
				t.Fatalf("still marked as fetched at %v", s.LastAttemptAt)
			}
			if got := h.listActions(); len(got) < 2 || got[len(got)-1] != "ip_list.updated "+s.URL {
				t.Fatalf("audit %v", got)
			}
		})
	}
	t.Run("only the name", func(t *testing.T) {
		h, pub, _, f := listHarness(t)
		addList(t, pub, f)
		leadBriefly(t, h, func() bool { return src(t, pub, listName).LastAttemptAt != nil })
		status(t, patchList(t, pub, listName, map[string]any{"name": "renamed"}), http.StatusNoContent)
		if src(t, pub, "renamed").LastAttemptAt == nil {
			t.Fatal("a rename made the list due again")
		}
	})
	t.Run("a bad URL", func(t *testing.T) {
		_, pub, _, f := listHarness(t)
		addList(t, pub, f)
		status(t, patchList(t, pub, listName, map[string]any{"url": "http://insecure.example.com/a.txt"}), http.StatusUnprocessableEntity)
	})
}

// A rename is refused while the draft, the active version or a canary
// candidate names the list, since those rules would then match no one, and
// is allowed when nothing names it.
func TestRenamingAListUsedByAConfigIsRefused(t *testing.T) {
	t.Run("nothing names it", func(t *testing.T) {
		h, pub, _, _ := listHarness(t)
		status(t, addTyped(pub, "office", "1.2.3.4", false), http.StatusCreated)
		status(t, patchList(t, pub, "office", map[string]any{"name": "hq"}), http.StatusNoContent)
		if got := h.listActions(); !slices.Equal(got, []string{"ip_list.added office", "ip_list.updated hq"}) {
			t.Fatalf("audit %v", got)
		}
	})
	t.Run("a bad name", func(t *testing.T) {
		_, pub, _, _ := listHarness(t)
		status(t, addTyped(pub, "office", "1.2.3.4", false), http.StatusCreated)
		status(t, patchList(t, pub, "office", map[string]any{"name": "Office"}), http.StatusUnprocessableEntity)
	})
	t.Run("a name in use", func(t *testing.T) {
		_, pub, _, _ := listHarness(t)
		status(t, addTyped(pub, "office", "1.2.3.4", false), http.StatusCreated)
		status(t, addTyped(pub, "hq", "5.6.7.8", false), http.StatusCreated)
		status(t, patchList(t, pub, "office", map[string]any{"name": "hq"}), http.StatusConflict)
	})
	t.Run("the draft", func(t *testing.T) {
		_, pub, _, _ := listHarness(t)
		status(t, addTyped(pub, "office", "1.2.3.4", false), http.StatusCreated)
		status(t, pub.save(`"0"`, listRuleConfig("office")), http.StatusOK)
		resp := patchList(t, pub, "office", map[string]any{"name": "hq"})
		if resp.StatusCode != http.StatusConflict || !strings.Contains(body(resp), "rule office-only (the draft)") {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if src(t, pub, "office").Name != "office" {
			t.Fatal("the list was renamed")
		}
	})
	t.Run("the active version", func(t *testing.T) {
		_, pub, _, _ := listHarness(t)
		status(t, addTyped(pub, "office", "1.2.3.4", false), http.StatusCreated)
		status(t, pub.save(`"0"`, listRuleConfig("office")), http.StatusOK)
		status(t, pub.publishDraft("v1"), http.StatusCreated)
		status(t, pub.save(pub.revision(), listRuleConfig("")), http.StatusOK)
		resp := patchList(t, pub, "office", map[string]any{"name": "hq"})
		if resp.StatusCode != http.StatusConflict || !strings.Contains(body(resp), "rule office-only (the active version)") {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("a canary candidate", func(t *testing.T) {
		_, pub, _, _ := listHarness(t)
		status(t, addTyped(pub, "office", "1.2.3.4", false), http.StatusCreated)
		status(t, pub.save(`"0"`, listRuleConfig("")), http.StatusOK)
		status(t, pub.publishDraft("v1"), http.StatusCreated)
		status(t, pub.save(pub.revision(), listRuleConfig("office")), http.StatusOK)
		status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2 on 10%", "canary_percent": 10}, "If-Match", pub.revision()), http.StatusCreated)
		status(t, pub.save(pub.revision(), listRuleConfig("")), http.StatusOK)
		resp := patchList(t, pub, "office", map[string]any{"name": "hq"})
		if resp.StatusCode != http.StatusConflict || !strings.Contains(body(resp), "rule office-only (canary version 2)") {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

// GET /api/ip-lists says which rules name each list, from the draft, the
// active version and a canary candidate.
func TestListsShowTheRulesThatUseThem(t *testing.T) {
	_, pub, _, _ := listHarness(t)
	status(t, addTyped(pub, "office", "1.2.3.4", false), http.StatusCreated)
	status(t, addTyped(pub, "lab", "5.6.7.8", false), http.StatusCreated)
	status(t, pub.save(`"0"`, listRuleConfig("office")), http.StatusOK)
	status(t, pub.publishDraft("v1"), http.StatusCreated)
	status(t, pub.save(pub.revision(), listRuleConfig("lab")), http.StatusOK)
	if got := src(t, pub, "office").UsedBy; !slices.Equal(got, []string{"rule office-only (the active version)"}) {
		t.Fatalf("office used by %v", got)
	}
	if got := src(t, pub, "lab").UsedBy; !slices.Equal(got, []string{"rule office-only (the draft)"}) {
		t.Fatalf("lab used by %v", got)
	}
	// An unchanged draft holds the active version's rule: it is named once.
	status(t, pub.save(pub.revision(), listRuleConfig("office")), http.StatusOK)
	if got := src(t, pub, "office").UsedBy; !slices.Equal(got, []string{"rule office-only (the draft, the active version)"}) {
		t.Fatalf("office used by %v", got)
	}
}

// Typed lists are served ahead of downloaded ones, so a typed allowlist is
// not the list left out when the entry cap cuts.
func TestATypedListIsKeptAheadOfDownloadedListsAtTheCap(t *testing.T) {
	h, pub, e, f := listHarness(t)
	addNamed(t, pub, f, "big", "/big.txt", false)
	storeEntries(t, h, "big", edge.MaxIPListPrefixes, "1.0.0.0")
	status(t, addTyped(pub, "office", "203.0.113.10\n", false), http.StatusCreated)
	got := edgeIPLists(t, e)
	if len(got.Lists) != 1 || got.Lists[0].Name != "office" || !slices.Equal(got.DroppedLists, []string{"big"}) {
		t.Fatalf("served %d lists, dropped %v", len(got.Lists), got.DroppedLists)
	}
}

// A typed list's addresses are readable by anyone who reads lists, and a
// downloaded list has none to show.
func TestTypedEntriesAreReadable(t *testing.T) {
	h, pub, _, f := listHarness(t)
	addList(t, pub, f)
	status(t, addTyped(pub, "office", "203.0.113.10\n198.51.100.7\n", false), http.StatusCreated)
	h.user("view", "viewer")
	v := h.signedIn("view")
	got := decode[map[string]string](t, v.do("GET", listPath(t, v, "office", "/entries"), nil))
	if got["entries"] != "198.51.100.7/32\n203.0.113.10/32" {
		t.Fatalf("entries %q", got["entries"])
	}
	status(t, v.do("GET", listPath(t, v, listName, "/entries"), nil), http.StatusNotFound)
	status(t, v.do("GET", "/api/ip-lists/0/entries", nil), http.StatusNotFound)
}

// Editing needs the list permission, which a viewer and an editor lack.
func TestEditingAListNeedsThePermission(t *testing.T) {
	h, pub, _, _ := listHarness(t)
	status(t, addTyped(pub, "office", "1.2.3.4", false), http.StatusCreated)
	for _, role := range []string{"viewer", "editor"} {
		h.user("u-"+role, role)
		c := h.signedIn("u-" + role)
		status(t, patchList(t, c, "office", map[string]any{"entries": "5.6.7.8"}), http.StatusForbidden)
		status(t, addTyped(c, "x", "5.6.7.8", false), http.StatusForbidden)
	}
	if got := h.listActions(); len(got) != 1 {
		t.Fatalf("audit %v", got)
	}
}

// auditDetails is the details of the newest audit row with action.
func auditDetails(t *testing.T, h *harness, action string) map[string]any {
	t.Helper()
	var d map[string]any
	if err := h.db.QueryRow(t.Context(), "SELECT details FROM audit_events WHERE action = $1 ORDER BY seq DESC LIMIT 1", action).Scan(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

// A typed list's first entries are in its audit row in full, since the row is
// the only record of them.
func TestAddingATypedListAuditsEveryEntry(t *testing.T) {
	h, pub, _, _ := listHarness(t)
	status(t, addTyped(pub, "office", manyAddresses(maxTypedEntries), false), http.StatusCreated)
	d := auditDetails(t, h, "ip_list.added")
	if added, _ := d["added"].([]any); len(added) != maxTypedEntries || d["entries"] != float64(maxTypedEntries) {
		t.Fatalf("audit holds %d added entries, details entries %v", len(added), d["entries"])
	}
}

// A width change that makes a typed list re-parse and a list edit both record
// the full entries added and removed.
func TestEditingATypedListAuditsTheFullDiff(t *testing.T) {
	h, pub, _, _ := listHarness(t)
	status(t, addTyped(pub, "office", manyAddresses(maxTypedEntries), false), http.StatusCreated)
	status(t, patchList(t, pub, "office", map[string]any{"entries": "203.0.113.10\n"}), http.StatusNoContent)
	ent, _ := auditDetails(t, h, "ip_list.updated")["entries"].(map[string]any)
	added, _ := ent["added"].([]any)
	removed, _ := ent["removed"].([]any)
	if len(added) != 1 || len(removed) != maxTypedEntries || ent["count"] != float64(1) {
		t.Fatalf("entries %d added, %d removed, count %v", len(added), len(removed), ent["count"])
	}
}

// A downloaded list whose URL changes stops serving the old URL's entries at
// once, and says how many it cleared; it is served again after the next download.
func TestChangingAListURLStopsServingTheOldEntries(t *testing.T) {
	h, pub, e, f := listHarness(t)
	addList(t, pub, f)
	leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })
	status(t, patchList(t, pub, listName, map[string]any{"url": f.srv.URL + "/moved.txt"}), http.StatusNoContent)
	if got := prefixes(t, e); len(got) != 0 {
		t.Fatalf("still served %v", got)
	}
	if s := src(t, pub, listName); s.Entries != 0 || s.FetchedAt != nil {
		t.Fatalf("list still has its set: %+v", s)
	}
	if d := auditDetails(t, h, "ip_list.updated"); d["entries_cleared"] != float64(len(samplePrefixes)) {
		t.Fatalf("audit details %v", d)
	}
	leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })
}

// Narrowing a downloaded list clears its set, since the stored ranges may be
// too wide now; widening keeps it, since that only adds ranges.
func TestNarrowingADownloadedListClearsItsEntriesButWideningDoesNot(t *testing.T) {
	h, pub, e, f := listHarness(t)
	addNamed(t, pub, f, listName, "/list.txt", true)
	leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })
	status(t, patchList(t, pub, listName, map[string]any{"wide": false}), http.StatusNoContent)
	if got := prefixes(t, e); len(got) != 0 {
		t.Fatalf("narrowed list still served %v", got)
	}
	leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })
	status(t, patchList(t, pub, listName, map[string]any{"wide": true}), http.StatusNoContent)
	if got := prefixes(t, e); !slices.Equal(got, samplePrefixes) {
		t.Fatalf("widened list served %v", got)
	}
}

// A rename changes the ETag, so edges holding the old one get the list under
// its new name.
func TestRenamingAListReachesEdges(t *testing.T) {
	_, pub, e, _ := listHarness(t)
	status(t, addTyped(pub, "office", "203.0.113.10\n", false), http.StatusCreated)
	tag := e.do("GET", "/v1/ip-lists", nil).Header.Get("ETag")
	status(t, patchList(t, pub, "office", map[string]any{"name": "hq"}), http.StatusNoContent)
	resp := e.do("GET", "/v1/ip-lists", nil, "If-None-Match", tag)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := decode[ipListsBody](t, resp); len(got.Lists) != 1 || got.Lists[0].Name != "hq" {
		t.Fatalf("served %+v", got.Lists)
	}
}

// A typed list's disable and removal are audited under its name.
func TestDisablingAndRemovingATypedListAreAuditedByName(t *testing.T) {
	h, pub, _, _ := listHarness(t)
	status(t, addTyped(pub, "office", "203.0.113.10\n", false), http.StatusCreated)
	status(t, patchList(t, pub, "office", map[string]any{"enabled": false}), http.StatusNoContent)
	status(t, pub.do("DELETE", listPath(t, pub, "office", ""), nil), http.StatusNoContent)
	want := []string{"ip_list.added office", "ip_list.disabled office", "ip_list.removed office"}
	if got := h.listActions(); !slices.Equal(got, want) {
		t.Fatalf("audit %v, want %v", got, want)
	}
}

// A download that started before an edit of its list's URL or width must not
// write the old data back or mark the new source as attempted, or the new
// source would wait an hour for its first fetch.
func TestADownloadStartedBeforeAnEditIsDropped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wide    bool
		in      map[string]any
		oldURLP string
	}{
		{"a new URL", false, map[string]any{"url": "https://moved.invalid/b.txt"}, "/list.txt"},
		{"a narrower width", true, map[string]any{"wide": false}, "/list.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, e, f := listHarness(t)
			oldURL := addNamed(t, pub, f, listName, tc.oldURLP, tc.wide)
			leadBriefly(t, h, func() bool { return len(prefixes(t, e)) > 0 })
			id := src(t, pub, listName).ID
			if tc.name == "a new URL" {
				tc.in["url"] = f.srv.URL + "/moved.txt"
			}
			status(t, patchList(t, pub, listName, tc.in), http.StatusNoContent)
			if err := h.s.storeIPList(t.Context(), id, oldURL, tc.wide, samplePrefixes); err != nil {
				t.Fatal(err)
			}
			if err := h.s.recordIPList(t.Context(), id, oldURL, tc.wide, 0, nil); err != nil {
				t.Fatal(err)
			}
			if got := prefixes(t, e); len(got) != 0 {
				t.Fatalf("stale download served %v", got)
			}
			if s := src(t, pub, listName); s.LastAttemptAt != nil {
				t.Fatalf("stale attempt recorded at %v", s.LastAttemptAt)
			}
		})
	}
}
