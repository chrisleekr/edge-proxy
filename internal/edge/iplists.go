package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
)

const (
	// MaxBanReports bounds the bans one stats report carries and the queue
	// that feeds it. Admin refuses a report with more.
	MaxBanReports = 200
	// MaxIPListPrefixes bounds the prefixes of one IP list response. Admin
	// cuts its list here, and an edge refuses a response with more.
	MaxIPListPrefixes = 500_000
	// maxIPListBytes bounds the body read: 500,000 prefixes of IPv6 CIDR
	// text fit well inside it.
	maxIPListBytes = 64 << 20
	ipListInterval = time.Minute
)

// newIPLists is a variable so a test can inject the refusal, which no valid
// response or simulation reaches below the real cap.
var newIPLists = expr.NewIPLists

// IPListsResponse is admin's GET /v1/ip-lists body.
type IPListsResponse struct {
	Lists []IPList  `json:"lists"`
	Lifts []BanLift `json:"lifts"`
	// Dropped names the lists admin left out whole at MaxIPListPrefixes. Older
	// edges decode "dropped" as an int, so a new name keeps both versions
	// decoding the rest of the body, ban lifts included.
	Dropped []string `json:"dropped_lists"`
}

// IPList is one enabled list: its name, as rules write it, and its ranges.
type IPList struct {
	Name     string   `json:"name"`
	Prefixes []string `json:"prefixes"` // CIDR, e.g. "1.2.3.4/32"
}

// BanLift ends any ban on IP that started before At (Unix ms).
type BanLift struct {
	IP string `json:"ip"`
	At int64  `json:"at"`
}

// BanReport is one ban an edge recorded, sent in StatsReport.Bans.
type BanReport struct {
	IP    string `json:"ip"` // the ban key: IPv4, or the IPv6 /64 network address
	Rule  string `json:"rule"`
	Host  string `json:"host"`
	Path  string `json:"path"`
	Start int64  `json:"start"` // Unix ms
	End   int64  `json:"end"`
}

// reportBan queues b for the next stats report. A full queue drops it and
// counts: reports never block or grow. b is the ban in force, not the trip
// that asked for it. Host and path are already bounded. It returns whether the
// queue took the report, so the caller marks it reported only then.
func (e *Edge) reportBan(ip netip.Addr, b ratelimit.Ban) bool {
	if e.banReports == nil {
		return false
	}
	select {
	case e.banReports <- BanReport{IP: ratelimit.BanKey(ip).String(), Rule: b.Rule, Host: b.Host, Path: b.Path, Start: b.Start, End: b.End}:
		return true
	default:
		e.m.banReportsDropped.Add(1)
		return false
	}
}

// ipListPoller keeps the edge's IP list set and ban lifts current from
// admin. Admin down, or a bad answer, keeps the current set.
type ipListPoller struct {
	p     *poller
	edge  *Edge
	every time.Duration
	etag  string
}

func (d *ipListPoller) run(ctx context.Context) {
	wait := time.Duration(0) // first poll right after start
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		guard(d.p.m, d.p.log, "ip list poller", func() { d.poll(ctx) })
		wait = jitter(d.every)
	}
}

// poll fetches once and counts and logs a failure.
func (d *ipListPoller) poll(ctx context.Context) {
	if err := d.fetch(ctx); err != nil {
		d.p.m.ipListFailures.Add(1)
		d.p.log.Warn("ip list fetch failed; keeping current set", "error", err.Error())
	}
}

func (d *ipListPoller) fetch(ctx context.Context) error {
	// AdminURL was validated at startup, so the request can't fail to build.
	u := d.p.cfg.AdminURL.JoinPath("v1", "ip-lists")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+d.p.cfg.ServiceToken)
	if d.etag != "" {
		req.Header.Set("If-None-Match", d.etag)
	}
	resp, err := d.p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("admin answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxIPListBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxIPListBytes {
		return fmt.Errorf("IP list response is over %d bytes", maxIPListBytes)
	}
	if err := d.apply(b); err != nil {
		return err
	}
	d.etag = resp.Header.Get("ETag")
	return nil
}

// apply activates one response body, or changes nothing: an edge never
// activates a list it can't fully read. Unknown fields are ignored so a
// newer admin can add some.
func (d *ipListPoller) apply(body []byte) error {
	var r IPListsResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return err
	}
	if len(r.Lists) > expr.MaxIPLists {
		return fmt.Errorf("IP list response has %d lists, limit %d", len(r.Lists), expr.MaxIPLists)
	}
	names := make([]string, len(r.Lists))
	ps := make([][]netip.Prefix, len(r.Lists))
	total := 0
	for i, l := range r.Lists {
		if !expr.ValidListName(l.Name) || slices.Contains(names[:i], l.Name) {
			return fmt.Errorf("list %d: bad or repeated name %q", i, l.Name)
		}
		if total += len(l.Prefixes); total > MaxIPListPrefixes {
			return fmt.Errorf("IP list response has over %d prefixes", MaxIPListPrefixes)
		}
		names[i], ps[i] = l.Name, make([]netip.Prefix, len(l.Prefixes))
		for j, s := range l.Prefixes {
			p, err := netip.ParsePrefix(s)
			if err != nil || p.Addr().Is4In6() {
				return fmt.Errorf("list %q prefix %d: %q is not a CIDR range", l.Name, j, s)
			}
			ps[i][j] = p
		}
	}
	ips := make([]netip.Addr, len(r.Lifts))
	for i, l := range r.Lifts {
		a, err := netip.ParseAddr(l.IP)
		if err != nil {
			return fmt.Errorf("lift %d: %w", i, err)
		}
		ips[i] = a.Unmap()
	}
	// Lifts first: they don't depend on the lists, so a set the builder
	// refuses never holds up an unban. A lift applied twice is a no-op.
	for i, l := range r.Lifts {
		d.edge.bans.Lift(ips[i], l.At)
	}
	// No list on means a nil set: requests then pay one nil check.
	var set *expr.IPLists
	if len(r.Lists) > 0 {
		var err error
		if set, err = newIPLists(names, ps); err != nil {
			return err
		}
	}
	d.edge.lists.Store(set)
	d.p.m.ipListEntries.Store(int64(total))
	return nil
}
