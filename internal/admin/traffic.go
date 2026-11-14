package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// Traffic by viewer country comes from the same access lines as observed
// routes, and the edge does nothing extra for it. Only counts are kept: no
// client address reaches memory or Postgres.

const (
	// liveMinutes is how far back the live view can look.
	liveMinutes = 60
	// minuteKeep is how long minute rows live. Longer than liveMinutes so a
	// late flush still lands in a minute the live view reads.
	minuteKeep = 2 * time.Hour
	// unknownCountry is for a line with no usable country.
	unknownCountry = "unknown"
)

// maxPendingTraffic bounds the (minute, country) keys held between flushes;
// a new key past it is counted under otherKey for its minute. A variable so
// tests can shorten it.
var maxPendingTraffic = 10_000

// geoPoint is a place in decimal degrees.
type geoPoint struct {
	Lat  float64 `json:"lat"`
	Long float64 `json:"long"`
}

// notBlocked are the decisions where the edge did not refuse the request.
// Anything else, including a name added later, is a refusal.
var notBlocked = map[string]bool{
	"allow": true, "would_block": true, "upstream_timeout": true, "upstream_error": true, "upstream_tls": true, "client_gone": true,
}

type trafficKey struct {
	minute  time.Time
	country string
}

// trafficCount is one country's requests within one minute.
type trafficCount struct{ requests, blocked, estimated int64 }

// trafficAggregator holds deltas until the next flush takes them. Lines of
// any age are held by their own minute; the flush decides which tables they
// reach.
type trafficAggregator struct {
	mu sync.Mutex
	m  map[trafficKey]*trafficCount
}

func newTrafficAggregator() *trafficAggregator {
	return &trafficAggregator{m: map[trafficKey]*trafficCount{}}
}

// countryOf is the line's country if it is two upper-case letters or digits.
// The value is shipper supplied, so anything else must not become a key.
func (l *accessLine) countryOf() string {
	c := l.Country
	if len(c) == 2 && all(c, func(b byte) bool { return isDigit(b) || b >= 'A' && b <= 'Z' }) {
		return c
	}
	return unknownCountry
}

// trafficLine is what traffic keeps of an access line, so a batch holds a
// few words per line until its body is read, not the whole line.
type trafficLine struct {
	minute           time.Time
	country          string
	w                int64
	blocked, sampled bool
}

// traffic is the line's record for weight w. A line whose own time is set
// but outside lateLine or more than 5 minutes ahead has none: a days-old
// backlog must not show as live traffic. A line with no time is now.
func (l *accessLine) traffic(w int64, now time.Time) (trafficLine, bool) {
	if !l.Time.IsZero() && !l.plausible(now) {
		return trafficLine{}, false
	}
	return trafficLine{l.minute(now), l.countryOf(), w, !notBlocked[l.Decision], l.sampled()}, true
}

func (a *trafficAggregator) add(t trafficLine) {
	k := trafficKey{t.minute, t.country}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m[k] == nil && len(a.m) >= maxPendingTraffic {
		k.country = otherKey // at most one more entry per minute
	}
	c := a.m[k]
	if c == nil {
		c = &trafficCount{}
		a.m[k] = c
	}
	c.requests += t.w
	if t.blocked {
		c.blocked += t.w
	}
	if t.sampled {
		c.estimated += t.w
	}
}

func (a *trafficAggregator) take() map[trafficKey]*trafficCount {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.m
	a.m = map[trafficKey]*trafficCount{}
	return m
}

// trafficRows lays counts out as the columns of an unnest insert.
type trafficRows struct {
	times                        []time.Time
	countries                    []string
	requests, blocked, estimated []int64
}

func (r *trafficRows) add(t time.Time, country string, c *trafficCount) {
	r.times, r.countries = append(r.times, t), append(r.countries, country)
	r.requests, r.blocked, r.estimated = append(r.requests, c.requests), append(r.blocked, c.blocked), append(r.estimated, c.estimated)
}

// flushTraffic adds the held deltas to Postgres. Every replica adds to the
// same rows, so none is read back. On failure the deltas are dropped:
// traffic never blocks or grows memory. Minute rows older than minuteKeep
// are deleted on every flush so they need no separate job.
func (s *Server) flushTraffic(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, flushTimeout)
	defer cancel()
	now := s.now().UTC()
	liveFrom := now.Truncate(time.Minute).Add(-(liveMinutes - 1) * time.Minute)
	var minutes, hours trafficRows
	roll := map[trafficKey]*trafficCount{}
	for k, c := range s.trafficAgg.take() {
		if !k.minute.Before(liveFrom) {
			minutes.add(k.minute, k.country, c)
		}
		hk := trafficKey{k.minute.Truncate(time.Hour), k.country}
		if roll[hk] == nil {
			roll[hk] = &trafficCount{}
		}
		roll[hk].requests += c.requests
		roll[hk].blocked += c.blocked
		roll[hk].estimated += c.estimated
	}
	for k, c := range roll {
		hours.add(k.minute, k.country, c)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, t := range []struct {
		table, col string
		rows       *trafficRows
	}{{"traffic_minute", "minute", &minutes}, {"traffic_hour", "hour", &hours}} {
		if len(t.rows.times) == 0 {
			continue
		}
		// Sorted so replicas lock rows in the same order and never deadlock.
		if _, err := tx.Exec(ctx, `INSERT INTO `+t.table+` AS t (`+t.col+`, country, requests, blocked, estimated)
			SELECT * FROM unnest($1::timestamptz[], $2::text[], $3::bigint[], $4::bigint[], $5::bigint[]) ORDER BY 1, 2
			ON CONFLICT (`+t.col+`, country) DO UPDATE SET requests = t.requests + EXCLUDED.requests,
				blocked = t.blocked + EXCLUDED.blocked, estimated = t.estimated + EXCLUDED.estimated`,
			t.rows.times, t.rows.countries, t.rows.requests, t.rows.blocked, t.rows.estimated); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, "DELETE FROM traffic_minute WHERE minute < $1", now.Add(-minuteKeep))
	return err
}

func (s *Server) trafficRoutes() {
	s.handle("GET /api/traffic", "stats.read", s.getTraffic)
	s.handle("PUT /api/settings/traffic-map", "settings.manage", s.putTrafficMap)
}

// TrafficMapSettings is what the Traffic map needs from the operator: where
// the edges are, so it can draw lines to them. Nil draws none.
type TrafficMapSettings struct {
	Edge *geoPoint `json:"edge"`
}

// trafficMapIn is the PUT body. Pointers tell a missing coordinate from 0,
// which is a real place.
type trafficMapIn struct {
	Edge *struct {
		Lat  *float64 `json:"lat"`
		Long *float64 `json:"long"`
	} `json:"edge"`
}

// settings reports a missing coordinate or a place outside the globe, else
// the settings to store.
func (in trafficMapIn) settings() (TrafficMapSettings, []expr.Issue) {
	e := in.Edge
	if e == nil {
		return TrafficMapSettings{}, nil
	}
	var errs []expr.Issue
	switch {
	case e.Lat == nil:
		errs = append(errs, expr.Issue{Path: "edge.lat", Msg: "latitude is required"})
	case *e.Lat < -90 || *e.Lat > 90:
		errs = append(errs, expr.Issue{Path: "edge.lat", Msg: "latitude must be from -90 to 90 degrees"})
	}
	switch {
	case e.Long == nil:
		errs = append(errs, expr.Issue{Path: "edge.long", Msg: "longitude is required"})
	case *e.Long < -180 || *e.Long > 180:
		errs = append(errs, expr.Issue{Path: "edge.long", Msg: "longitude must be from -180 to 180 degrees"})
	}
	if errs != nil {
		return TrafficMapSettings{}, errs
	}
	return TrafficMapSettings{Edge: &geoPoint{Lat: *e.Lat, Long: *e.Long}}, nil
}

func loadTrafficMap(ctx context.Context, q querier) (TrafficMapSettings, error) {
	var m TrafficMapSettings
	var b []byte
	err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key = 'traffic_map'").Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

func (s *Server) putTrafficMap(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in trafficMapIn
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	m, errs := in.settings()
	if errs != nil {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid traffic map settings", Errors: errs}
	}
	ctx := r.Context()
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		before, err := loadTrafficMap(ctx, tx)
		if err != nil {
			return admindb.Event{}, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('traffic_map', $1, $2)
			ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = $2`, m, s.now())
		return admindb.Event{Action: "settings.traffic_map", Details: map[string]any{"before": before, "after": m}}, err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type countryTraffic struct {
	Country   string `json:"country"`
	Requests  int64  `json:"requests"`
	Blocked   int64  `json:"blocked"`
	Estimated int64  `json:"estimated"`
}

// getTraffic sums countries over the last ?minutes= (live, 1 to 60) or
// ?hours= (a period, as for routes). With neither it is the last 24 hours.
func (s *Server) getTraffic(w http.ResponseWriter, r *http.Request, _ *principal) error {
	q := r.URL.Query()
	table, col := "traffic_hour", "hour"
	var from time.Time
	if q.Has("minutes") {
		n, err := strconv.Atoi(q.Get("minutes"))
		if err != nil || n < 1 || n > liveMinutes || q.Has("hours") {
			return fail(http.StatusBadRequest, "minutes must be 1 to 60, and not given with hours")
		}
		table, col = "traffic_minute", "minute"
		from = s.now().UTC().Truncate(time.Minute).Add(-time.Duration(n-1) * time.Minute)
	} else {
		var err error
		if from, err = s.since(r); err != nil {
			return err
		}
	}
	settings, err := loadTrafficMap(r.Context(), s.db)
	if err != nil {
		return err
	}
	rows, err := s.db.Query(r.Context(), `SELECT country, sum(requests)::bigint, sum(blocked)::bigint, sum(estimated)::bigint
		FROM `+table+` WHERE `+col+` >= $1 GROUP BY country ORDER BY 2 DESC, 1`, from)
	if err != nil {
		return err
	}
	defer rows.Close()
	out := struct {
		From      time.Time        `json:"from"`
		To        time.Time        `json:"to"`
		Countries []countryTraffic `json:"countries"`
		Edge      *geoPoint        `json:"edge"`
	}{From: from, To: s.now().UTC(), Countries: []countryTraffic{}, Edge: settings.Edge}
	for rows.Next() {
		var c countryTraffic
		if err := rows.Scan(&c.Country, &c.Requests, &c.Blocked, &c.Estimated); err != nil {
			return err
		}
		out.Countries = append(out.Countries, c)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}
