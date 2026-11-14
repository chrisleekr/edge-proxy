package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type countryView struct {
	Country   string `json:"country"`
	Requests  int64  `json:"requests"`
	Blocked   int64  `json:"blocked"`
	Estimated int64  `json:"estimated"`
}

type trafficView struct {
	From      time.Time     `json:"from"`
	To        time.Time     `json:"to"`
	Countries []countryView `json:"countries"`
	Edge      *struct {
		Lat  float64 `json:"lat"`
		Long float64 `json:"long"`
	} `json:"edge"`
}

// geo is an allowed access line from one viewer country.
func geo(country string, extra ...any) string {
	return access("GET", "api.example.com", "/", append([]any{"client.geo.country_iso_code", country}, extra...)...)
}

// traffic flushes what admin holds, then reads the map.
func (h *harness) traffic(c *client, query string) trafficView {
	h.t.Helper()
	if err := h.s.flushTraffic(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	return decode[trafficView](h.t, c.do("GET", "/api/traffic"+query, nil))
}

func wantCountries(t *testing.T, got trafficView, want ...countryView) {
	t.Helper()
	if !slices.Equal(got.Countries, want) {
		t.Fatalf("countries = %+v, want %+v", got.Countries, want)
	}
}

// Countries are summed per viewer country, largest first, in the live view
// (minute rows) and the period view (hour rows). Sampled lines count for
// their share and are marked estimated. A line's own time files it, so an
// old line is in a long period but not in the live view.
func TestTrafficIsCountedByCountry(t *testing.T) {
	old := weightDraw
	t.Cleanup(func() { weightDraw = old })
	weightDraw = func() float64 { return 0.5 } // 1/0.25 is exactly 4: the draw cannot change it
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	status(t, h.shipper().post(
		geo("US"), geo("US"), geo("US"), geo("DE"),
		geo("FR", "edge.sample_rate", 0.25),
		geo("JP", "time", h.now().Add(-2*time.Hour).Format(time.RFC3339Nano)),
	), http.StatusAccepted)

	for _, q := range []string{"?minutes=5", "?hours=1"} {
		t.Run(q, func(t *testing.T) {
			wantCountries(t, h.traffic(vera, q),
				countryView{"FR", 4, 0, 4}, countryView{"US", 3, 0, 0}, countryView{"DE", 1, 0, 0})
		})
	}
	t.Run("a line from two hours ago is in a three hour period", func(t *testing.T) {
		wantCountries(t, h.traffic(vera, "?hours=3"),
			countryView{"FR", 4, 0, 4}, countryView{"US", 3, 0, 0}, countryView{"DE", 1, 0, 0}, countryView{"JP", 1, 0, 0})
	})
	t.Run("no query is the last 24 hours", func(t *testing.T) {
		if got := h.traffic(vera, ""); len(got.Countries) != 4 {
			t.Fatalf("countries = %+v", got.Countries)
		}
	})
}

// A line with no country, or one that is not two upper-case letters or
// digits, is filed as unknown. The client address is never stored.
func TestLinesWithoutAValidCountryCountAsUnknown(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	const addr = "203.0.113.9"
	status(t, h.shipper().post(
		access("GET", "api.example.com", "/", "client.address", addr),
		geo("usa", "client.address", addr),
		geo("u1", "client.address", addr),
		geo("us", "client.address", addr),
		geo("", "client.address", addr),
		geo("US", "client.address", addr),
	), http.StatusAccepted)
	wantCountries(t, h.traffic(vera, "?minutes=5"), countryView{"unknown", 5, 0, 0}, countryView{"US", 1, 0, 0})

	rows, err := h.db.Query(t.Context(), "SELECT t::text FROM traffic_minute t UNION ALL SELECT t::text FROM traffic_hour t")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(s, addr) {
			t.Fatalf("row %q holds the client address", s)
		}
		n++
	}
	if n != 4 { // unknown and US, in each table
		t.Fatalf("rows = %d, want 4", n)
	}
}

// Anything the edge answered with a refusal counts as blocked. Allowed
// requests, log-only matches and upstream trouble do not. Lines about a
// malformed request line count for traffic but never make a route.
func TestRefusedRequestsCountAsBlocked(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	cases := []struct {
		name    string
		country string
		line    func(country string) string
		blocked int64
	}{
		{"rate limited", "AA", func(c string) string {
			return geo(c, "edge.decision", "rate_limited", "http.response.status_code", 429, "edge.rate_limit_rule", "login")
		}, 1},
		{"access rule block", "AB", func(c string) string {
			return geo(c, "edge.decision", "blocked", "http.response.status_code", 403)
		}, 1},
		{"malformed path", "AC", func(c string) string {
			return access("GET", "evil.example", "/%2e%2e/etc/passwd", "client.geo.country_iso_code", c, "edge.decision", "path", "http.response.status_code", 400)
		}, 1},
		{"malformed method", "AD", func(c string) string {
			return access("BREW", "evil.example", "/", "client.geo.country_iso_code", c, "edge.decision", "method", "http.response.status_code", 405)
		}, 1},
		{"log only would block", "AE", func(c string) string { return geo(c, "edge.decision", "would_block") }, 0},
		{"upstream error", "AF", func(c string) string {
			return geo(c, "edge.decision", "upstream_error", "http.response.status_code", 502)
		}, 0},
		{"allow", "AG", func(c string) string { return geo(c) }, 0},
		{"upstream timeout", "AH", func(c string) string {
			return geo(c, "edge.decision", "upstream_timeout", "http.response.status_code", 504)
		}, 0},
		{"upstream tls refusal", "AI", func(c string) string {
			return geo(c, "edge.decision", "upstream_tls", "http.response.status_code", 502)
		}, 0},
		// The client left before any answer, so the edge logs no status.
		{"client gone", "AJ", func(c string) string {
			return geo(c, "edge.decision", "client_gone", "http.response.status_code", 0)
		}, 0},
	}
	var lines []string
	for _, tc := range cases {
		lines = append(lines, tc.line(tc.country))
	}
	if got := decode[map[string]int](t, h.shipper().post(lines...)); got["accepted"] != 8 || got["skipped"] != 2 {
		t.Fatalf("ingest = %v", got)
	}
	got := h.traffic(vera, "?minutes=5")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := countryView{tc.country, 1, tc.blocked, 0}
			if !slices.Contains(got.Countries, want) {
				t.Fatalf("countries = %+v, want %+v", got.Countries, want)
			}
		})
	}
	for _, r := range h.routes(vera).Routes {
		if r.Host == "evil.example" {
			t.Fatalf("a malformed request made a route: %+v", r)
		}
	}
}

// A body of lines that are not access lines, such as a shipper sending
// empty objects or nulls, is skipped and adds no traffic, while the access
// lines in the same body still count.
func TestLinesThatAreNotAccessLinesAddNoTraffic(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	lines := []string{geo("US"), `{"msg":"request panic recovered","client.geo.country_iso_code":"DE"}`}
	for range 1000 {
		lines = append(lines, `{}`, `null`)
	}
	lines = append(lines, geo("US"), access("BREW", "evil.example", "/", "client.geo.country_iso_code", "FR", "edge.decision", "method", "http.response.status_code", 405))
	if got := decode[map[string]int](t, h.shipper().post(lines...)); got["accepted"] != 2 || got["skipped"] != 2002 {
		t.Fatalf("ingest = %v", got)
	}
	wantCountries(t, h.traffic(vera, "?minutes=5"), countryView{"US", 2, 0, 0}, countryView{"FR", 1, 1, 0})
}

// A line whose own time is days old, as from a shipper replaying an old
// backlog, or too far ahead is left out of traffic rather than shown as
// live. It still makes its route.
func TestLinesWithAnImplausibleTimeAddNoTraffic(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	if got := decode[map[string]int](t, h.shipper().post(
		geo("US"),
		geo("DE", "time", h.now().Add(-50*time.Hour).Format(time.RFC3339Nano)),
		geo("FR", "time", h.now().Add(10*time.Minute).Format(time.RFC3339Nano)),
	)); got["accepted"] != 3 || got["skipped"] != 0 {
		t.Fatalf("ingest = %v", got)
	}
	for _, q := range []string{"?minutes=5", "?hours=24"} {
		t.Run(q, func(t *testing.T) {
			wantCountries(t, h.traffic(vera, q), countryView{"US", 1, 0, 0})
		})
	}
}

// The live view and a period include a line only from the start of their
// first minute or hour.
func TestTrafficRangeEdges(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	ago := func(d time.Duration) string { return h.now().Add(-d).Format(time.RFC3339Nano) }
	status(t, h.shipper().post(
		geo("AA", "time", ago(4*time.Minute)),
		geo("AB", "time", ago(6*time.Minute)),
		geo("AC", "time", ago(30*time.Hour)),
	), http.StatusAccepted)
	t.Run("a line 4 minutes old is in the last 5 minutes and one 6 minutes old is not", func(t *testing.T) {
		wantCountries(t, h.traffic(vera, "?minutes=5"), countryView{"AA", 1, 0, 0})
	})
	t.Run("a line 30 hours old is not in the default 24 hours", func(t *testing.T) {
		wantCountries(t, h.traffic(vera, ""), countryView{"AA", 1, 0, 0}, countryView{"AB", 1, 0, 0})
	})
	t.Run("a line 30 hours old is in the last 31 hours", func(t *testing.T) {
		wantCountries(t, h.traffic(vera, "?hours=31"), countryView{"AA", 1, 0, 0}, countryView{"AB", 1, 0, 0}, countryView{"AC", 1, 0, 0})
	})
}

// A sampled line's weight is drawn once, so its route and its country count
// the same requests.
func TestSampledLineCountsTheSameInRoutesAndTraffic(t *testing.T) {
	old := weightDraw
	t.Cleanup(func() { weightDraw = old })
	draws := []float64{0.1, 0.9} // 1/0.4 is 2.5: the first draw rounds up to 3, a second would round down to 2
	weightDraw = func() float64 {
		d := draws[0]
		draws = draws[1:]
		return d
	}
	h, pub := published(t)
	status(t, h.shipper().post(geo("US", "edge.sample_rate", 0.4)), http.StatusAccepted)
	r := find(h.routes(pub), "GET", "api.example.com", "/")
	if r == nil || r.Requests != 3 {
		t.Fatalf("route = %+v, want 3 requests", r)
	}
	wantCountries(t, h.traffic(pub, "?minutes=5"), countryView{"US", 3, 0, 3})
}

// Past the cap on pending rows, a new country folds into one overflow row
// for its minute, so memory is bounded and the total is kept.
func TestPendingTrafficIsBounded(t *testing.T) {
	old := maxPendingTraffic
	t.Cleanup(func() { maxPendingTraffic = old })
	maxPendingTraffic = 3
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	status(t, h.shipper().post(geo("US"), geo("DE"), geo("FR"), geo("JP"), geo("BR")), http.StatusAccepted)
	wantCountries(t, h.traffic(vera, "?minutes=5"),
		countryView{"*", 2, 0, 0}, countryView{"DE", 1, 0, 0}, countryView{"FR", 1, 0, 0}, countryView{"US", 1, 0, 0})
}

// Minute rows are only for the live view, so a flush drops those older than
// two hours. Hour rows live as long as the other stats.
func TestTrafficRetention(t *testing.T) {
	h := newHarness(t)
	count := func(table string) []string {
		t.Helper()
		rows, err := h.db.Query(t.Context(), "SELECT country FROM "+table+" ORDER BY country")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var got []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			got = append(got, c)
		}
		return got
	}
	flush := func() {
		t.Helper()
		if err := h.s.flushTraffic(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	status(t, h.shipper().post(geo("US")), http.StatusAccepted)
	flush()
	h.advance(3 * time.Hour)
	status(t, h.shipper().post(geo("DE")), http.StatusAccepted)
	flush()
	if got := count("traffic_minute"); !slices.Equal(got, []string{"DE"}) {
		t.Fatalf("minute rows after 3 hours = %v", got)
	}
	if got := count("traffic_hour"); !slices.Equal(got, []string{"DE", "US"}) {
		t.Fatalf("hour rows after 3 hours = %v", got)
	}

	h.advance(time.Duration(retentionDays+1) * 24 * time.Hour)
	status(t, h.shipper().post(geo("FR")), http.StatusAccepted)
	flush()
	if err := h.s.dropOldStats(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := count("traffic_hour"); !slices.Equal(got, []string{"FR"}) {
		t.Fatalf("hour rows after retention = %v", got)
	}
}

// The map shows where visitors are, which is stats.read. The log shipper's
// token has no such permission.
func TestTrafficNeedsStatsRead(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	status(t, h.shipper().do("GET", "/api/traffic", nil), http.StatusForbidden)
	status(t, h.client().do("GET", "/api/traffic", nil), http.StatusUnauthorized)
	status(t, h.signedIn("vera").do("GET", "/api/traffic", nil), http.StatusOK)
}

// A range that is out of bounds, not a number, or given two ways is refused
// rather than guessed.
func TestTrafficQueryLimits(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	for _, q := range []string{"minutes=0", "minutes=61", "hours=0", "hours=721", "minutes=abc", "hours=abc", "minutes=5&hours=1"} {
		t.Run(q, func(t *testing.T) {
			status(t, vera.do("GET", "/api/traffic?"+q, nil), http.StatusBadRequest)
		})
	}
	for _, q := range []string{"minutes=1", "minutes=60", "hours=1", "hours=720"} {
		t.Run(q, func(t *testing.T) {
			status(t, vera.do("GET", "/api/traffic?"+q, nil), http.StatusOK)
		})
	}
}

// The edge location, set on the Traffic map page, is where the map draws
// its lines to. Each change is audited with what it replaced.
func TestTrafficReportsTheEdgeLocation(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	h.user("ada", "admin")
	vera, ada := h.signedIn("vera"), h.signedIn("ada")
	edge := func() string {
		t.Helper()
		raw := decode[map[string]json.RawMessage](t, vera.do("GET", "/api/traffic", nil))
		e, ok := raw["edge"]
		if !ok {
			t.Fatal("reply has no edge field")
		}
		return string(e)
	}
	if got := edge(); got != "null" {
		t.Fatalf("edge before any setting = %s, want null", got)
	}
	status(t, ada.do("PUT", "/api/settings/traffic-map", map[string]any{"edge": map[string]float64{"lat": 50.11, "long": 8.68}}), http.StatusNoContent)
	if got := edge(); got != `{"lat":50.11,"long":8.68}` {
		t.Fatalf("edge after set = %s", got)
	}
	status(t, ada.do("PUT", "/api/settings/traffic-map", map[string]any{"edge": nil}), http.StatusNoContent)
	if got := edge(); got != "null" {
		t.Fatalf("edge after clear = %s, want null", got)
	}

	rows, err := h.db.Query(t.Context(), "SELECT details::text FROM audit_events WHERE action = 'settings.traffic_map' ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	details, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"after":{"edge":{"lat":50.11,"long":8.68}},"before":{"edge":null}}`,
		`{"after":{"edge":null},"before":{"edge":{"lat":50.11,"long":8.68}}}`,
	}
	if len(details) != len(want) {
		t.Fatalf("audit rows = %v, want %d", details, len(want))
	}
	for i := range want {
		if !strings.Contains(strings.ReplaceAll(details[i], " ", ""), want[i]) {
			t.Fatalf("audit row %d = %s, want %s", i, details[i], want[i])
		}
	}
}

// Only settings.manage may move the map's lines. A role that just reads
// stats is refused and nothing changes or is audited.
func TestTrafficMapSettingNeedsSettingsManage(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	status(t, vera.do("PUT", "/api/settings/traffic-map", map[string]any{"edge": map[string]float64{"lat": 1, "long": 2}}), http.StatusForbidden)
	status(t, h.client().do("PUT", "/api/settings/traffic-map", map[string]any{"edge": nil}), http.StatusUnauthorized)
	raw := decode[map[string]json.RawMessage](t, vera.do("GET", "/api/traffic", nil))
	if string(raw["edge"]) != "null" {
		t.Fatalf("edge = %s, want null", raw["edge"])
	}
	if slices.ContainsFunc(h.actions(), func(a string) bool { return strings.HasPrefix(a, "settings.traffic_map") }) {
		t.Fatal("a refused change was audited")
	}
}

// A place outside the globe is refused with the field named, and nothing is saved.
func TestTrafficMapSettingRefusesPlacesOffTheGlobe(t *testing.T) {
	h := newHarness(t)
	h.user("ada", "admin")
	ada := h.signedIn("ada")
	cases := []struct {
		name  string
		edge  map[string]any
		field string
	}{
		{"latitude above 90", map[string]any{"lat": 91, "long": 0}, "edge.lat"},
		{"latitude below -90", map[string]any{"lat": -91, "long": 0}, "edge.lat"},
		{"longitude above 180", map[string]any{"lat": 0, "long": 181}, "edge.long"},
		{"longitude below -180", map[string]any{"lat": 0, "long": -181}, "edge.long"},
		{"missing longitude", map[string]any{"lat": 5}, "edge.long"},
		{"null latitude", map[string]any{"lat": nil, "long": 5}, "edge.lat"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := ada.do("PUT", "/api/settings/traffic-map", map[string]any{"edge": tc.edge})
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("status %d: %s", resp.StatusCode, body(resp))
			}
			p := decode[problem](t, resp)
			if len(p.Errors) != 1 || p.Errors[0].Path != tc.field {
				t.Fatalf("errors = %+v, want one at %s", p.Errors, tc.field)
			}
		})
	}
	raw := decode[map[string]json.RawMessage](t, ada.do("GET", "/api/traffic", nil))
	if string(raw["edge"]) != "null" {
		t.Fatalf("edge = %s, want null", raw["edge"])
	}
}

// The poles and the antimeridian are on the globe, so they are kept as given.
func TestTrafficMapSettingAcceptsTheEdgesOfTheGlobe(t *testing.T) {
	h := newHarness(t)
	h.user("ada", "admin")
	ada := h.signedIn("ada")
	for _, want := range []string{`{"lat":90,"long":-180}`, `{"lat":-90,"long":180}`} {
		t.Run(want, func(t *testing.T) {
			status(t, ada.do("PUT", "/api/settings/traffic-map", map[string]json.RawMessage{"edge": json.RawMessage(want)}), http.StatusNoContent)
			raw := decode[map[string]json.RawMessage](t, ada.do("GET", "/api/traffic", nil))
			if string(raw["edge"]) != want {
				t.Fatalf("edge = %s, want %s", raw["edge"], want)
			}
		})
	}
}
