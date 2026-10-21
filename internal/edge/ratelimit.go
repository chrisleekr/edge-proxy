package edge

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// maxRateLimitCalls is the most step 8 checks: every site-wide rule plus the
// capped others.
const maxRateLimitCalls = snapshot.MaxSiteWide + maxMatchedRateLimit

// Bounds on per-replica rate-limit state (CLAUDE.md, bounded memory).
const maxPenalties = 100_000

// maxLocalState bounds fail_mode local state, split evenly between rules
// so a rule keyed on client-chosen values can only fill its own share.
// Tests lower it.
var maxLocalState = 100_000

// backstop is step 5: a per-IP token bucket in this replica, always on.
func (e *Edge) backstop(st *reqState) bool {
	r, tracked := st.ver.backstop.Allow(st.client.ip, st.start)
	if !tracked {
		e.m.backstopUntracked.Add(1)
	}
	if r.Allowed {
		return true
	}
	st.retry = seconds(r.Retry)
	e.reject(st, kRateLimited, reasonBackstop)
	return false
}

// rlCheck is one rule step 8 evaluates for this request.
type rlCheck struct {
	rule *ratelimit.Rule
	idx  int
	key  string
	o    ratelimit.Outcome
	// fallback is set when the key is the client IP (on_missing_key: fallback_ip).
	fallback bool
}

// rateLimit is step 8: the local penalty cache first, then one pipelined
// Valkey batch for the rest.
func (e *Edge) rateLimit(st *reqState) bool {
	v := st.ver
	var (
		buf     [maxRateLimitCalls]rlCheck
		calls   [maxRateLimitCalls]ratelimit.Call
		pending [maxRateLimitCalls]int
	)
	checks, capped, reject := st.planChecks(v, buf[:0])
	if capped {
		e.m.rulesCapped.Add(1)
	}
	if reject {
		e.reject(st, kBadRequest, reasonRateLimitKey)
		return false
	}
	// The kill switch turns every rule into action: log.
	kill := v.c.Config.KillSwitch.RateLimit
	now := st.start.UnixMilli()
	np := 0
	for k := range checks {
		c := &checks[k]
		if until := e.penalties.Until(c.key, now); until > 0 && !kill {
			e.m.penaltyHits.Add(1)
			c.o.Result = ratelimit.Result{Reset: until - now, Retry: until - now, Now: now, Blocked: until}
			continue
		}
		p := c.rule.Params
		if kill {
			p.Penalty = 0
		}
		calls[np], pending[np] = ratelimit.Call{Key: c.key, P: p}, k
		np++
	}
	if np > 0 {
		var outs [maxRateLimitCalls]ratelimit.Outcome
		e.valkeyDo(calls[:np], outs[:np])
		for k := range np {
			checks[pending[k]].o = outs[k]
		}
	}
	return e.decide(st, checks, kill, now)
}

// maxMatchedRateLimit caps non-site-wide rules per request.
const maxMatchedRateLimit = 5

// planChecks picks the rules step 8 checks, with their keys: every
// site-wide rule, then other matching rules in order, blocking rules before
// shadow ones, up to the cap. Clients can choose which rules match, so a
// rule that can't block never takes a slot from one that can: shadow rules
// come last, and a rule skipped for a missing key takes no slot. reject is
// set when a rule with on_missing_key: reject lacks a key part.
func (st *reqState) planChecks(v *version, out []rlCheck) (checks []rlCheck, capped, reject bool) {
	checks = out
	for _, i := range v.c.SiteWide {
		c, ok, rej := st.check(v, i)
		if rej {
			return checks, false, true
		}
		if ok {
			checks = append(checks, c)
		}
	}
	n := 0
	for _, shadow := range [2]bool{false, true} {
		for i, m := range v.c.RateLimitRules {
			// SiteWide comes from the normalized expression; the raw one may wrap true.
			if v.rules[i].Shadow != shadow || slices.Contains(v.c.SiteWide, i) || !m(&st.fields) {
				continue
			}
			if n == maxMatchedRateLimit {
				return checks, true, false
			}
			c, ok, rej := st.check(v, i)
			if rej {
				return checks, false, true
			}
			if ok {
				checks = append(checks, c)
				n++
			}
		}
	}
	return checks, false, false
}

// check builds rule i's key. ok is false when a key part is missing and the
// rule skips; rej when it rejects. fallback_ip keys on the client IP alone.
func (st *reqState) check(v *version, i int) (c rlCheck, ok, rej bool) {
	r := &v.rules[i]
	var buf [256]byte
	sub, ok := st.subject(r, buf[:0])
	if !ok {
		switch r.OnMissingKey {
		case ratelimit.MissingSkip:
			return c, false, false
		case ratelimit.MissingReject:
			return c, false, true
		}
		sub = ratelimit.FallbackSubject(buf[:0], st.client.ip)
	}
	return rlCheck{rule: r, idx: i, key: r.Key(sub), fallback: !ok}, true, false
}

func (e *Edge) valkeyDo(calls []ratelimit.Call, outs []ratelimit.Outcome) {
	if e.valkey == nil {
		for i := range outs {
			outs[i].Err = ratelimit.ErrNotConnected
		}
		return
	}
	e.valkey.Do(calls, outs)
}

// decide applies fail modes, shadow mode and penalties, and answers 429 if
// any blocking rule is over its limit. Rules are independent counters: every
// matched rule consumed quota, even when another one blocks.
func (e *Edge) decide(st *reqState, checks []rlCheck, kill bool, now int64) bool {
	var limited, unavailable bool
	var retry int64
	for i := range checks {
		c := &checks[i]
		rs := &st.ver.stats.rules[c.idx]
		rs.evaluated.Add(1)
		shadow := c.rule.Shadow || kill
		if c.o.Err != nil {
			rs.failed.Add(1)
			if errors.Is(c.o.Err, ratelimit.ErrBreakerOpen) {
				e.m.valkeyBreakerOpen.Add(1)
			} else {
				e.m.valkeyErrors.Add(1)
			}
			switch c.rule.FailMode {
			case ratelimit.FailOpen:
				continue
			case ratelimit.FailClosed:
				unavailable = unavailable || !shadow
				continue
			}
			p := localParams(c.rule.Params, e.store.fleet.Load())
			if kill {
				p.Penalty = 0
			}
			var tracked bool
			c.o.Result, tracked = st.ver.local[c.idx].Take(c.key, p, now)
			if !tracked {
				e.m.localUntracked.Add(1)
			}
		}
		if !shadow && st.set.rateLimitHeaders {
			st.addRateLimitHeaders(c)
		}
		if c.o.Allowed {
			continue
		}
		if shadow {
			rs.wouldLimit.Add(1)
			if sampleTop() {
				st.ver.stats.wouldTop.add(c.key, c.rule.ID, st.display(c))
			}
			continue
		}
		rs.limited.Add(1)
		if sampleTop() {
			st.ver.stats.top.add(c.key, c.rule.ID, st.display(c))
		}
		if c.o.Blocked > 0 && !e.penalties.Block(c.key, now+c.o.Blocked-c.o.Now) {
			e.m.penaltyDropped.Add(1)
		}
		if !limited {
			st.rlRule = c.rule.ID
		}
		limited = true
		retry = max(retry, c.o.Retry)
	}
	switch {
	case limited:
		st.retry = seconds(retry)
		e.reject(st, kRateLimited, reasonRateLimited)
		return false
	case unavailable:
		st.retry = 1
		e.reject(st, kUnavailable, reasonRateLimitUnavailable)
		return false
	}
	return true
}

// localParams divides a rule across the fleet for fail_mode local: each
// replica allows its share while Valkey is unavailable.
func localParams(p ratelimit.Params, n int64) ratelimit.Params {
	p.Limit = max(p.Limit/n, 1)
	if p.Burst > 0 {
		p.Burst = max(p.Burst/n, 1)
	}
	return p
}

// subject writes the rule's characteristic values. ok is false when one is
// missing: an absent header, cookie, argument, claim, country, AS number or
// locale.
func (st *reqState) subject(r *ratelimit.Rule, b []byte) (_ []byte, ok bool) {
	c := &st.client
	b = ratelimit.Subject(b)
	for _, part := range r.Parts {
		switch part.Kind {
		case ratelimit.PartIP:
			b = ratelimit.AppendIP(b, c.ip)
		case ratelimit.PartASNum:
			if !c.hasASN {
				return b, false
			}
			b = ratelimit.AppendInt(b, c.asn)
		case ratelimit.PartConstant:
		default:
			v, ok := st.partValue(part)
			if !ok {
				return b, false
			}
			b = ratelimit.AppendValue(b, v)
		}
	}
	return b, true
}

// partValue is the value of a string characteristic.
func (st *reqState) partValue(part ratelimit.Part) (string, bool) {
	f, c := &st.fields, &st.client
	switch part.Kind {
	case ratelimit.PartHeader:
		return first(f.r.Header[part.Name])
	case ratelimit.PartCookie:
		return first(f.List("http.request.cookies", part.Name))
	case ratelimit.PartQuery:
		return first(f.List("http.request.uri.args", part.Name))
	case ratelimit.PartClaim:
		return first(f.claims[part.Name])
	case ratelimit.PartHost:
		return f.host, true
	case ratelimit.PartMethod:
		return f.r.Method, true
	case ratelimit.PartCountry:
		return c.country, c.country != ""
	default: // PartLocale
		v := f.localeValue()
		return v, v != ""
	}
}

// display shows a limited subject in admin without revealing secrets:
// IPs as keyed (IPv6 by /64), client-chosen values by their
// first 4 characters. The key's hash tells subjects with one prefix apart.
func (st *reqState) display(c *rlCheck) string {
	if c.fallback {
		return displayIP(st.client.ip)
	}
	var parts []string
	for _, part := range c.rule.Parts {
		switch part.Kind {
		case ratelimit.PartIP:
			parts = append(parts, displayIP(st.client.ip))
		case ratelimit.PartASNum:
			parts = append(parts, "AS"+strconv.FormatInt(st.client.asn, 10))
		case ratelimit.PartConstant:
		case ratelimit.PartHeader, ratelimit.PartCookie, ratelimit.PartQuery, ratelimit.PartClaim:
			v, _ := st.partValue(part) // present: the key was built
			parts = append(parts, part.Name+"="+mask(v))
		default:
			v, _ := st.partValue(part)
			parts = append(parts, v)
		}
	}
	if parts == nil {
		return "all" // a constant key: one bucket for every client
	}
	return strings.Join(parts, " ")
}

func displayIP(ip netip.Addr) string {
	if ip.Is4() {
		return ip.String()
	}
	return netip.PrefixFrom(ip, 64).Masked().String()
}

// mask shows at most the first 4 characters of a value that may be a
// secret, and never more than half of it, so no value is shown in full.
// Unprintable characters show as '?': a NUL would fail admin's jsonb insert.
func mask(v string) string {
	keep := min(4, utf8.RuneCountInString(v)/2)
	var b strings.Builder
	for _, r := range v {
		if keep == 0 {
			break
		}
		if !unicode.IsPrint(r) {
			r = '?'
		}
		b.WriteRune(r)
		keep--
	}
	return b.String() + "…"
}

// first is the first value of a repeated header, cookie or argument, so a
// client can't pick a bucket by reordering duplicates.
func first(vs []string) (string, bool) {
	if len(vs) == 0 {
		return "", false
	}
	return vs[0], true
}

// addRateLimitHeaders records the IETF draft-11 RateLimit-Policy and
// RateLimit items for one enforced rule. Rule IDs are [a-z0-9_-], so %q
// writes a valid Structured Field string.
func (st *reqState) addRateLimitHeaders(c *rlCheck) {
	if st.rlPolicy == nil {
		// One allocation holds both values for the usual one or two rules.
		buf := make([]byte, 0, 256)
		st.rlPolicy, st.rlState = buf[:0:128], buf[128:128]
	} else {
		st.rlPolicy = append(st.rlPolicy, ", "...)
		st.rlState = append(st.rlState, ", "...)
	}
	p := c.rule.Params
	st.rlPolicy = strconv.AppendInt(append(strconv.AppendQuote(st.rlPolicy, c.rule.ID), ";q="...), p.Limit, 10)
	st.rlPolicy = strconv.AppendInt(append(st.rlPolicy, ";w="...), p.Period/1000, 10)
	st.rlState = strconv.AppendInt(append(strconv.AppendQuote(st.rlState, c.rule.ID), ";r="...), c.o.Remaining, 10)
	st.rlState = strconv.AppendInt(append(st.rlState, ";t="...), int64(seconds(c.o.Reset)), 10)
}

// seconds rounds milliseconds up, so a client waiting that long succeeds.
func seconds(ms int64) int { return int((ms + 999) / 1000) }
