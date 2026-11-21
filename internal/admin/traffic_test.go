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
		Name string  `json:"name"`
	} `json:"edge"`
	Series []pointView `json:"series"`
}

type pointView struct {
	At        time.Time `json:"at"`
	Requests  int64     `json:"requests"`
	Blocked   int64     `json:"blocked"`
	Estimated int64     `json:"estimated"`
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
			return geo(c, "edge.action", "rate_limited", "http.response.status_code", 429, "edge.decided_by", "login")
		}, 1},
		{"access rule block", "AB", func(c string) string {
			return geo(c, "edge.action", "blocked", "http.response.status_code", 403)
		}, 1},
		{"malformed path", "AC", func(c string) string {
			return access("GET", "evil.example", "/%2e%2e/etc/passwd", "client.geo.country_iso_code", c, "edge.action", "path", "http.response.status_code", 400)
		}, 1},
		{"malformed method", "AD", func(c string) string {
			return access("BREW", "evil.example", "/", "client.geo.country_iso_code", c, "edge.action", "method", "http.response.status_code", 405)
		}, 1},
		{"allowed with a log-only rule logged", "AE", func(c string) string { return geo(c, "edge.logged_rules", []string{"tools"}) }, 0},
		{"older edge: log-only access rule", "AK", func(c string) string {
			return oldAccess("GET", "api.example.com", "/", "client.geo.country_iso_code", c, "edge.decision", "would_block", "edge.config_rules", []string{"tools"})
		}, 0},
		{"older edge: log-only rate limit", "AL", func(c string) string {
			return oldAccess("GET", "api.example.com", "/", "client.geo.country_iso_code", c, "edge.decision", "would_limit", "edge.rate_limit_rule", "login")
		}, 0},
		{"older edge: rate limited", "AM", func(c string) string {
			return oldAccess("GET", "api.example.com", "/", "client.geo.country_iso_code", c, "edge.decision", "rate_limited", "edge.rate_limit_rule", "login", "http.response.status_code", 429)
		}, 1},
		{"upstream error", "AF", func(c string) string {
			return geo(c, "edge.action", "upstream_error", "http.response.status_code", 502)
		}, 0},
		{"allow", "AG", func(c string) string { return geo(c) }, 0},
		{"upstream timeout", "AH", func(c string) string {
			return geo(c, "edge.action", "upstream_timeout", "http.response.status_code", 504)
		}, 0},
		{"upstream tls refusal", "AI", func(c string) string {
			return geo(c, "edge.action", "upstream_tls", "http.response.status_code", 502)
		}, 0},
		// The client left before any answer, so the edge logs no status.
		{"client gone", "AJ", func(c string) string {
			return geo(c, "edge.action", "client_gone", "http.response.status_code", 0)
		}, 0},
	}
	var lines []string
	for _, tc := range cases {
		lines = append(lines, tc.line(tc.country))
	}
	if got := decode[map[string]int](t, h.shipper().post(lines...)); got["accepted"] != 11 || got["skipped"] != 2 {
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
	lines = append(lines, geo("US"), access("BREW", "evil.example", "/", "client.geo.country_iso_code", "FR", "edge.action", "method", "http.response.status_code", 405))
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
	t.Run("a window from 31 to 29 hours ago holds only the line 30 hours old and ends at its own end", func(t *testing.T) {
		at := func(d time.Duration) string { return h.now().Add(-d).UTC().Format(time.RFC3339) }
		got := h.traffic(vera, "?from="+at(31*time.Hour)+"&to="+at(29*time.Hour))
		wantCountries(t, got, countryView{"AC", 1, 0, 0})
		if want := h.now().Add(-29 * time.Hour).Truncate(time.Hour).Add(time.Hour); !got.To.Equal(want) {
			t.Fatalf("to = %v, want %v", got.To, want)
		}
	})
	t.Run("a window wholly in the future is empty and does not end before it starts", func(t *testing.T) {
		at := func(d time.Duration) string { return h.now().Add(d).UTC().Format(time.RFC3339) }
		got := h.traffic(vera, "?from="+at(2*time.Hour)+"&to="+at(3*time.Hour))
		wantCountries(t, got)
		if got.From.After(got.To) {
			t.Fatalf("from %v is after to %v", got.From, got.To)
		}
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

// Minute rows are only for recent spans, so a flush drops those older than
// three hours. Hour rows live as long as the other stats.
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
	h.advance(4 * time.Hour)
	status(t, h.shipper().post(geo("DE")), http.StatusAccepted)
	flush()
	if got := count("traffic_minute"); !slices.Equal(got, []string{"DE"}) {
		t.Fatalf("minute rows after 4 hours = %v", got)
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
	for _, q := range []string{"minutes=0", "minutes=61", "hours=0", "hours=721", "minutes=abc", "hours=abc", "minutes=5&hours=1", "minutes=5&from=2026-01-01T00:00:00Z&to=2026-01-01T01:00:00Z"} {
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

// The edge location, set on Settings, is where the map draws
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

// A picked country's series is its own rows from the table the window reads,
// oldest first: minutes live, hours in a period.
func TestTrafficSeriesListsThePickedCountry(t *testing.T) {
	old := weightDraw
	t.Cleanup(func() { weightDraw = old })
	weightDraw = func() float64 { return 0.5 }
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	at := func(d time.Duration) string { return h.now().Add(d).Format(time.RFC3339Nano) }
	status(t, h.shipper().post(
		geo("US", "time", at(-30*time.Minute)),
		geo("US", "time", at(-30*time.Minute), "edge.action", "blocked", "http.response.status_code", 403),
		geo("US", "time", at(-2*time.Minute), "edge.sample_rate", 0.25),
		geo("DE", "time", at(-2*time.Minute)),
	), http.StatusAccepted)
	minute := func(d time.Duration) time.Time { return h.now().UTC().Add(d).Truncate(time.Minute) }
	hour := func(d time.Duration) time.Time { return h.now().UTC().Add(d).Truncate(time.Hour) }

	live := h.traffic(vera, "?minutes=60&country=US").Series
	want := []pointView{{minute(-30 * time.Minute), 2, 1, 0}, {minute(-2 * time.Minute), 4, 0, 4}}
	if !slices.EqualFunc(live, want, func(a, b pointView) bool {
		return a.At.Equal(b.At) && a.Requests == b.Requests && a.Blocked == b.Blocked && a.Estimated == b.Estimated
	}) {
		t.Fatalf("live series = %+v, want %+v", live, want)
	}
	period := h.traffic(vera, "?hours=3&country=US").Series
	if len(period) == 0 || len(period) > 2 {
		t.Fatalf("period series = %+v, want one or two hours", period)
	}
	var requests int64
	for i, p := range period {
		if !p.At.Equal(hour(p.At.Sub(hour(0)))) || i > 0 && !period[i-1].At.Before(p.At) {
			t.Fatalf("period series = %+v, want oldest first, on the hour", period)
		}
		requests += p.Requests
	}
	if requests != 6 {
		t.Fatalf("period requests = %d, want 6", requests)
	}
}

// A country with no rows has an empty series; asking for none leaves the key out.
func TestTrafficSeriesIsEmptyOrAbsent(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	status(t, h.shipper().post(geo("US")), http.StatusAccepted)
	h.traffic(vera, "")
	for query, want := range map[string]string{"?country=FR": "[]", "?minutes=5&country=FR": "[]", "": ""} {
		raw := decode[map[string]json.RawMessage](t, vera.do("GET", "/api/traffic"+query, nil))
		got, has := raw["series"]
		if has != (want != "") || string(got) != want {
			t.Fatalf("%q: series = %s (present %v), want %q", query, got, has, want)
		}
	}
}

func TestTrafficCountryMustBeACode(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	for _, tc := range []struct {
		country string
		want    int
	}{
		{"br", 400}, {"BRA", 400}, {"", 400}, {"%3C%3E", 400}, {"B", 400},
		{"BR", 200}, {"B1", 200}, {"unknown", 200}, {"%2A", 200},
	} {
		t.Run(tc.country, func(t *testing.T) {
			status(t, vera.do("GET", "/api/traffic?country="+tc.country, nil), tc.want)
		})
	}
}

// The place name is trimmed, shown wherever the setting is read, and audited
// with the value before and after. Clearing the edge drops it.
func TestTrafficMapSettingKeepsATrimmedPlaceName(t *testing.T) {
	h := newHarness(t)
	h.user("ada", "admin")
	ada := h.signedIn("ada")
	put := func(edge any) {
		t.Helper()
		status(t, ada.do("PUT", "/api/settings/traffic-map", map[string]any{"edge": edge}), http.StatusNoContent)
	}
	put(map[string]any{"lat": 50.11, "long": 8.68, "name": "  Frankfurt  "})
	if got := h.traffic(ada, "").Edge; got == nil || got.Name != "Frankfurt" {
		t.Fatalf("traffic edge = %+v", got)
	}
	raw := string(decode[json.RawMessage](t, ada.do("GET", "/api/settings/traffic-map", nil)))
	if raw != `{"edge":{"lat":50.11,"long":8.68,"name":"Frankfurt"}}` {
		t.Fatalf("settings = %s", raw)
	}
	put(map[string]any{"lat": 1, "long": 2})
	var details string
	if err := h.db.QueryRow(t.Context(), "SELECT details::text FROM audit_events WHERE action = 'settings.traffic_map' ORDER BY seq DESC LIMIT 1").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details, `"name":"Frankfurt"`) || strings.Count(details, "name") != 1 {
		t.Fatalf("audit details = %s, want the old name only in before", details)
	}
	put(map[string]any{"lat": 1, "long": 2, "name": "Sydney"})
	put(nil)
	if raw := string(decode[json.RawMessage](t, ada.do("GET", "/api/settings/traffic-map", nil))); raw != `{"edge":null}` {
		t.Fatalf("settings = %s, want no edge", raw)
	}
}

func TestTrafficMapSettingRefusesBadPlaceNames(t *testing.T) {
	h := newHarness(t)
	h.user("ada", "admin")
	ada := h.signedIn("ada")
	for name, edgeName := range map[string]string{
		"61 characters":       strings.Repeat("é", 61),
		"a control character": "Frank\nfurt",
	} {
		t.Run(name, func(t *testing.T) {
			resp := ada.do("PUT", "/api/settings/traffic-map", map[string]any{"edge": map[string]any{"lat": 1, "long": 2, "name": edgeName}})
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("status %d: %s", resp.StatusCode, body(resp))
			}
			if p := decode[problem](t, resp); len(p.Errors) != 1 || p.Errors[0].Path != "edge.name" {
				t.Fatalf("errors = %+v, want one at edge.name", p.Errors)
			}
		})
	}
	status(t, ada.do("PUT", "/api/settings/traffic-map", map[string]any{"edge": map[string]any{"lat": 1, "long": 2, "name": strings.Repeat("é", 60)}}), http.StatusNoContent)
}

// Reading the setting needs config.read. Every built-in role has it, so the
// user gets a role with only stats.read.
func TestTrafficMapSettingReadNeedsConfigRead(t *testing.T) {
	h := newHarness(t)
	for _, q := range []string{"INSERT INTO roles VALUES ('stats-only')", "INSERT INTO role_permissions VALUES ('stats-only', 'stats.read')"} {
		if _, err := h.owner.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	h.user("nia", "stats-only")
	status(t, h.signedIn("nia").do("GET", "/api/settings/traffic-map", nil), http.StatusForbidden)
	status(t, h.client().do("GET", "/api/settings/traffic-map", nil), http.StatusUnauthorized)
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// A span inside the live minute rows counts exactly the minutes it
// covers, so a dragged zoom is not widened to the hour.
func TestTrafficSpanWithinTheLastHourIsCountedByTheMinute(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	start := h.now().UTC().Truncate(time.Minute).Add(-40 * time.Minute)
	at := func(m int) string {
		return start.Add(time.Duration(m)*time.Minute + 10*time.Second).Format(time.RFC3339Nano)
	}
	status(t, h.shipper().post(
		geo("AA", "time", at(9)),
		geo("AB", "time", at(10)),
		geo("AC", "time", at(14)),
		geo("AD", "time", at(15)),
	), http.StatusAccepted)
	got := h.traffic(vera, "?from="+rfc(start.Add(10*time.Minute+20*time.Second))+"&to="+rfc(start.Add(14*time.Minute+30*time.Second)))
	wantCountries(t, got, countryView{"AB", 1, 0, 0}, countryView{"AC", 1, 0, 0})
	if !got.From.Equal(start.Add(10*time.Minute)) || !got.To.Equal(start.Add(15*time.Minute)) {
		t.Fatalf("from, to = %v, %v, want the minute-rounded span", got.From, got.To)
	}
}

// Flushes write minute rows 150 minutes back, so the hour before a one-hour
// period, which starts about 121 minutes ago, is counted exactly, not widened to hours.
func TestTrafficSpanForTheHourBeforeTheLastHourIsCountedByTheMinute(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	start := h.now().UTC().Truncate(time.Minute).Add(-125 * time.Minute)
	at := func(m int) string {
		return start.Add(time.Duration(m)*time.Minute + 10*time.Second).Format(time.RFC3339Nano)
	}
	status(t, h.shipper().post(geo("AA", "time", at(-1)), geo("AB", "time", at(2)), geo("AC", "time", at(6))), http.StatusAccepted)
	got := h.traffic(vera, "?from="+rfc(start)+"&to="+rfc(start.Add(5*time.Minute)))
	wantCountries(t, got, countryView{"AB", 1, 0, 0})
	if !got.From.Equal(start) || !got.To.Equal(start.Add(5*time.Minute)) {
		t.Fatalf("from, to = %v, %v, want the exact span", got.From, got.To)
	}
}

// Minute rows are not written past 150 minutes, so a line 200 minutes old has
// none and a span around it must be read by the hour, or it counts nothing.
func TestTrafficSpanStartingBeforeTheMinuteRowsIsCountedByTheHour(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	line := h.now().UTC().Truncate(time.Minute).Add(-200 * time.Minute)
	status(t, h.shipper().post(geo("AA", "time", line.Add(10*time.Second).Format(time.RFC3339Nano))), http.StatusAccepted)
	got := h.traffic(vera, "?from="+rfc(line.Add(-5*time.Minute))+"&to="+rfc(line.Add(5*time.Minute)))
	wantCountries(t, got, countryView{"AA", 1, 0, 0})
	if !got.From.Equal(line.Add(-5 * time.Minute).Truncate(time.Hour)) {
		t.Fatalf("from = %v, want the hour holding the span start", got.From)
	}
}

// A span hours ago is rounded out to whole hours, leaving out lines just outside.
func TestTrafficSpanHoursAgoIsRoundedOutToWholeHours(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	hour := h.now().UTC().Truncate(time.Hour).Add(-5 * time.Hour)
	at := func(d time.Duration) string { return hour.Add(d).Format(time.RFC3339Nano) }
	status(t, h.shipper().post(
		geo("AA", "time", at(-time.Minute)),
		geo("AB", "time", at(5*time.Minute)),
		geo("AC", "time", at(50*time.Minute)),
		geo("AD", "time", at(61*time.Minute)),
	), http.StatusAccepted)
	got := h.traffic(vera, "?from="+rfc(hour.Add(20*time.Minute))+"&to="+rfc(hour.Add(30*time.Minute)))
	wantCountries(t, got, countryView{"AB", 1, 0, 0}, countryView{"AC", 1, 0, 0})
	if !got.From.Equal(hour) || !got.To.Equal(hour.Add(time.Hour)) {
		t.Fatalf("from, to = %v, %v, want the whole hour", got.From, got.To)
	}
}

// A span ending after now reads up to now and reports it, not the future.
func TestTrafficSpanEndingAfterNowReadsUpToNow(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	status(t, h.shipper().post(geo("AA", "time", h.now().UTC().Add(-10*time.Minute).Format(time.RFC3339Nano))), http.StatusAccepted)
	got := h.traffic(vera, "?from="+rfc(h.now().Add(-30*time.Minute))+"&to="+rfc(h.now().Add(3*time.Hour)))
	wantCountries(t, got, countryView{"AA", 1, 0, 0})
	if !got.To.Equal(h.now().UTC()) {
		t.Fatalf("to = %v, want now %v", got.To, h.now().UTC())
	}
}

// A span wholly before retention or wholly after now is empty, never inverted.
func TestTrafficSpanOutsideRetentionOrAfterNowIsEmpty(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	oldest := h.now().UTC().Truncate(time.Hour).Add(time.Hour - time.Duration(retentionDays*24)*time.Hour)
	for name, q := range map[string]string{
		"wholly before retention": "?from=" + rfc(oldest.Add(-48*time.Hour)) + "&to=" + rfc(oldest.Add(-24*time.Hour)),
		"wholly after now":        "?from=" + rfc(h.now().Add(2*time.Hour)) + "&to=" + rfc(h.now().Add(3*time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			got := h.traffic(vera, q)
			wantCountries(t, got)
			if got.From.After(got.To) {
				t.Fatalf("from %v after to %v", got.From, got.To)
			}
		})
	}
}

// The series of a picked country holds only the points inside the span.
func TestTrafficSeriesForASpanHoldsOnlyPointsInsideIt(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	start := h.now().UTC().Truncate(time.Minute).Add(-40 * time.Minute)
	at := func(m int) string { return start.Add(time.Duration(m) * time.Minute).Format(time.RFC3339Nano) }
	status(t, h.shipper().post(geo("AA", "time", at(-5)), geo("AA", "time", at(2)), geo("AA", "time", at(12))), http.StatusAccepted)
	got := h.traffic(vera, "?country=AA&from="+rfc(start)+"&to="+rfc(start.Add(10*time.Minute)))
	if len(got.Series) != 1 || !got.Series[0].At.Equal(start.Add(2*time.Minute)) {
		t.Fatalf("series = %+v, want only the point at +2m", got.Series)
	}
}

// A span that starts before retention is cut to the oldest kept hour.
func TestTrafficSpanBeforeRetentionIsClamped(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	oldest := h.now().UTC().Truncate(time.Hour).Add(time.Hour - time.Duration(retentionDays*24)*time.Hour)
	got := h.traffic(vera, "?from="+rfc(oldest.Add(-48*time.Hour))+"&to="+rfc(oldest.Add(3*time.Hour)))
	if !got.From.Equal(oldest) || !got.To.Equal(oldest.Add(3*time.Hour)) {
		t.Fatalf("from, to = %v, %v, want from clamped to %v", got.From, got.To, oldest)
	}
}

// A span with no valid shape is a client error, not an empty answer.
func TestTrafficSpanMustBeWellFormed(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	vera := h.signedIn("vera")
	a, b := rfc(h.now().Add(-5*time.Hour)), rfc(h.now().Add(-4*time.Hour))
	for name, q := range map[string]string{
		"from without to":        "from=" + a,
		"to without from":        "to=" + b,
		"from after to":          "from=" + b + "&to=" + a,
		"from equal to":          "from=" + a + "&to=" + a,
		"unparsable from":        "from=yesterday&to=" + b,
		"unparsable to":          "from=" + a + "&to=soon",
		"from and to with hours": "from=" + a + "&to=" + b + "&hours=3",
	} {
		t.Run(name, func(t *testing.T) {
			status(t, vera.do("GET", "/api/traffic?"+q, nil), http.StatusBadRequest)
		})
	}
}
