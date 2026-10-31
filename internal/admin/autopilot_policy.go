package admin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// ruleIn is a rate-limit rule as the agent proposes it. Admin names it,
// sets its expiry and decides whether it logs or blocks.
type ruleIn struct {
	Expression   string            `json:"expression"`
	Algorithm    string            `json:"algorithm"`
	Limit        int64             `json:"limit"`
	Period       snapshot.Duration `json:"period"`
	Burst        int64             `json:"burst,omitempty"`
	Key          []string          `json:"key"`
	OnMissingKey string            `json:"on_missing_key"`
	FailMode     string            `json:"fail_mode,omitempty"`
	Penalty      snapshot.Duration `json:"penalty,omitempty"`
	DistinctOf   string            `json:"distinct_of,omitempty"`
	// CountStatuses counts upstream responses with these statuses, such as
	// failed logins, instead of requests.
	CountStatuses []string `json:"count_statuses,omitempty"`
}

// proposeIn is the propose and validate_rule input.
type proposeIn struct {
	Action    string             `json:"action"`
	Name      string             `json:"name,omitempty"`
	Rule      *ruleIn            `json:"rule,omitempty"`
	TTL       *snapshot.Duration `json:"ttl,omitempty"`
	Rationale string             `json:"rationale"`
	Evidence  json.RawMessage    `json:"evidence,omitempty"`
	// Cites is the sensor an enforce proposal narrows; its lifetime counts
	// from the sensor's.
	Cites string `json:"cites,omitempty"`
	// RuleID is the rule a retire proposal ends.
	RuleID string `json:"rule_id,omitempty"`
	// Notes are the notes, served to this run, the proposal relies on.
	Notes []int64 `json:"notes,omitempty"`
}

// sortNotes puts the cited notes in one order, so a retried proposal
// citing them in another is the same proposal.
func (in *proposeIn) sortNotes() error {
	slices.Sort(in.Notes)
	in.Notes = slices.Compact(in.Notes)
	if len(in.Notes) > 5 {
		return fail(http.StatusUnprocessableEntity, "notes cites at most 5 notes")
	}
	return nil
}

// policyCheck is one check of a proposal, kept with the proposal.
type policyCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

var ruleName = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// candidate is a proposal after the policy: the rule as it would publish,
// its ttl and shape, the checks and the reasons it is refused, if any.
type candidate struct {
	rule    snapshot.RateLimitRule
	ttl     time.Duration
	shape   [32]byte
	cited   *apRule
	target  *apRule // a retire proposal's rule
	checks  []policyCheck
	reasons []string
	// exclusions are the ids of the exclusions the rule's expression carries.
	exclusions []int64
}

func (c *candidate) check(name string, ok bool, detail string) {
	c.checks = append(c.checks, policyCheck{Name: name, OK: ok, Detail: detail})
	if !ok && !slices.Contains(c.reasons, name) {
		c.reasons = append(c.reasons, name)
	}
}

// shapeOf identifies a rule by what it matches and how it counts, so the
// same rule under another id is a duplicate.
func shapeOf(n expr.Node, key []string) [32]byte {
	b, _ := json.Marshal(n) // a parsed Node always marshals
	return sha256.Sum256(append(append(b, 0), strings.Join(key, "\x00")...))
}

// clientIPHeaders carry a client's address as CDNs and proxies send it.
var clientIPHeaders = []string{"x-forwarded-for", "forwarded", "x-real-ip", "true-client-ip", "cf-connecting-ip", "cf-connecting-ipv6",
	"cloudfront-viewer-address", "x-gclb-client-ip"}

// namesSubjects reports whether n picks clients out: any comparison on the
// client's IP, AS number, X-Forwarded-For, a client IP header or a JWT
// claim, with any operator, negated or not, or any value that is an
// address or a prefix. Autopilot rules generalize to whoever crosses a
// threshold.
// ponytail: a deployment's own client IP header under a name not listed
// here, or an address written another way (encoded, padded), still passes.
func namesSubjects(n expr.Node) bool {
	if n.IsGroup() {
		return slices.ContainsFunc(n.Rules, namesSubjects)
	}
	switch n.Field {
	case "ip.src", "ip.src.asnum", "http.request.jwt.claims", "http.x_forwarded_for":
		return true
	case "http.request.headers":
		if slices.Contains(clientIPHeaders, strings.ToLower(n.Key)) {
			return true
		}
	}
	isAddr := func(v string) bool {
		_, errA := netip.ParseAddr(v)
		_, errP := netip.ParsePrefix(v)
		return errA == nil || errP == nil
	}
	return isAddr(n.Value.One) || slices.ContainsFunc(n.Value.List, isAddr)
}

// excluded is n with what no autopilot rule may limit left out, so the
// edge checks it on every request: verified crawlers, when admin has their
// ranges, the protected networks and the active exclusions. It is fixed
// when the rule is proposed, since a rule's content never changes under
// its id.
func (s *Server) excluded(n expr.Node, set AutopilotSettings, ex []exclusion) expr.Node {
	rules := []expr.Node{n}
	if s.cfg.Deployment.VerifiedBots {
		rules = append(rules, expr.Node{Field: expr.VerifiedBotField, Operator: "is_false"})
	}
	if p, ok := protectedExclusion(set); ok {
		rules = append(rules, p)
	}
	if e, ok := exclusionNode(ex); ok {
		rules = append(rules, e)
	}
	if len(rules) == 1 {
		return n
	}
	return expr.Node{Combinator: "and", Rules: rules}
}

// protectedExclusion is the condition that leaves the protected networks
// out, when there are any.
func protectedExclusion(set AutopilotSettings) (expr.Node, bool) {
	var cidrs []string
	for _, p := range protectedPrefixes(set) {
		cidrs = append(cidrs, p.String())
	}
	return expr.Node{Field: "ip.src", Operator: "not_in", Value: expr.Value{List: cidrs, IsList: true}}, cidrs != nil
}

// ipFirst moves "ip" to the front of a key, so the first part of a
// limited subject's display is the address admin checks before enforcing.
// The order of a key's parts does not change what it counts.
func ipFirst(key []string) []string {
	i := slices.Index(key, "ip")
	if i <= 0 {
		return key
	}
	return append([]string{"ip"}, slices.Delete(slices.Clone(key), i, i+1)...)
}

// policy checks a proposal against the rule shape, the deployment, the
// live rules, the budgets and the confirmed notes it cites. It writes
// nothing.
func (s *Server) policy(ctx context.Context, q querier, set AutopilotSettings, in proposeIn, notes []apNote) (*candidate, error) {
	c := &candidate{}
	now := s.now()
	if in.Action == "retire" {
		ok := in.RuleID != ""
		if ok {
			// The model retires sensors only. An enforcing rule ends by its
			// expiry or a person, who can mark it a false positive.
			rules, err := s.loadRules(ctx, q, "id = $1 AND kind = 'sensor' AND state IN ('proposed', 'observing')", in.RuleID)
			if err != nil {
				return nil, err
			}
			if ok = len(rules) == 1; ok {
				c.target = &rules[0]
			}
		}
		c.check("not_overlay_shape", ok, "retire names a proposed or observing autopilot sensor in rule_id")
		return c, nil
	}
	// Admin adds the ap- prefix; a name carrying its own doubles it.
	shapeOK := (in.Action == "add_sensor" || in.Action == "enforce") && ruleName.MatchString(in.Name) && !strings.HasPrefix(in.Name, overlayPrefix) && in.Rule != nil
	c.ttl = time.Duration(set.DefaultTTL)
	if in.TTL != nil {
		c.ttl = time.Duration(*in.TTL)
	}
	shapeOK = shapeOK && c.ttl >= set.minRenewableTTL()
	if shapeOK && in.Cites != "" {
		rules, err := s.loadRules(ctx, q, "id = $1 AND kind = 'sensor' AND state = 'observing'", in.Cites)
		if err != nil {
			return nil, err
		}
		if shapeOK = len(rules) == 1; shapeOK {
			c.cited = &rules[0]
		}
	}
	c.check("not_overlay_shape", shapeOK, fmt.Sprintf("action add_sensor or enforce, a name of 1 to 40 of a-z, 0-9 and - not starting ap- (admin adds it), a rule, a ttl of at least %s and cites naming an observing sensor",
		set.minRenewableTTL()))
	if !shapeOK {
		return c, nil
	}
	rc := *in.Rule
	rc.Key = ipFirst(rc.Key)
	r := &rc
	n, err := expr.Parse(r.Expression)
	if err != nil {
		c.check("compile", false, "expression: "+err.Error())
		return c, nil
	}
	failMode := r.FailMode
	if failMode == "" {
		failMode = "open"
	}
	c.rule = snapshot.RateLimitRule{ID: overlayPrefix + in.Name + "-0", Expression: n, Algorithm: r.Algorithm, Limit: r.Limit, Period: r.Period, Burst: r.Burst,
		Key: r.Key, OnMissingKey: r.OnMissingKey, Action: "log", Penalty: r.Penalty, FailMode: failMode, DistinctOf: r.DistinctOf,
		CountStatuses: r.CountStatuses, ExpiresAt: now.Add(c.ttl).Truncate(time.Second)}
	c.shape = shapeOf(n, r.Key)

	c.check("site_wide", !n.IsTrue(), "an autopilot rule never matches every request")
	c.check("fail_mode", failMode == "open", "fail_mode is open: a Valkey outage never blocks traffic for an autopilot rule")
	c.check("key_needs_ip_or_jwt", slices.ContainsFunc(r.Key, func(k string) bool { return k == "ip" || strings.HasPrefix(k, "jwt_claim:") }),
		"the key includes ip or a jwt_claim, values a client can't choose")
	hostOnly := len(r.Key) > 0 && !slices.ContainsFunc(r.Key, func(k string) bool { return k != "host" })
	c.check("constant_or_host_key", !slices.Contains(r.Key, "constant") && !hostOnly, "the key is not constant or host only")
	c.check("missing_key_rejects", r.OnMissingKey != "reject", "a request without the key is never refused")
	for _, n := range notes {
		switch {
		case n.Trust != "confirmed" || n.Effect == nil:
		case n.Kind == "key_preference":
			c.check("note_key", !slices.ContainsFunc(n.Effect.Key, func(k string) bool { return !slices.Contains(r.Key, k) }),
				fmt.Sprintf("note %d asks for a key with %s", n.ID, strings.Join(n.Effect.Key, ", ")))
		case n.Kind == "collateral_risk" && n.Effect.RequireJWTClaim:
			c.check("note_jwt_key", slices.ContainsFunc(r.Key, func(k string) bool { return strings.HasPrefix(k, "jwt_claim:") }),
				fmt.Sprintf("note %d asks for a key with a jwt_claim", n.ID))
		}
	}
	c.check("ttl_over_max", c.ttl <= time.Duration(set.MaxTTL), fmt.Sprintf("ttl is at most max_ttl %s", time.Duration(set.MaxTTL)))
	if c.cited != nil {
		end := c.cited.LiveSince.Add(time.Duration(set.MaxLifetime))
		c.check("lifetime_over_max", !now.Add(c.ttl).After(end), fmt.Sprintf("the rule and the sensor it cites end by %s, max_lifetime after the sensor went live", end.UTC().Format(time.RFC3339)))
	}
	c.check("penalty_past_expiry", time.Duration(r.Penalty) <= c.ttl, "the penalty ends by the rule's expiry")
	c.check("named_subjects", !namesSubjects(n), "the rule names no IP, AS number, X-Forwarded-For or JWT claim value")
	// The checks above read the model's own expression; what it publishes
	// also leaves out what no autopilot rule may limit.
	ex, err := activeExclusions(ctx, q, now)
	if err != nil {
		return nil, err
	}
	c.rule.Expression = s.excluded(n, set, ex)
	for _, e := range ex {
		c.exclusions = append(c.exclusions, e.ID)
	}

	active, err := s.activeConfig(ctx, q)
	if err != nil {
		return nil, err
	}
	if active == nil {
		c.check("compile", false, "nothing is published yet")
		return c, nil
	}
	// A person's adopted copy carries the expression as published, with
	// its exclusions, so it is matched in that form too.
	published := shapeOf(c.rule.Expression, c.rule.Key)
	dup := false
	for _, o := range active.RateLimitRules {
		got := shapeOf(o.Expression, ipFirst(o.Key))
		dup = dup || got == c.shape || got == published
	}
	var pending []snapshot.RateLimitRule
	live, err := s.loadRules(ctx, q, "state IN ('proposed', 'observing', 'enforcing')")
	if err != nil {
		return nil, err
	}
	for _, o := range live {
		dup = dup || [32]byte(o.Shape) == c.shape
		if o.State == "proposed" {
			pending = append(pending, o.published())
		}
	}
	c.check("duplicate", !dup, "no live rule has the same expression and key")
	var suppressed bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM autopilot_rules WHERE shape_sha256 = $1 AND (state = 'rolled_back' OR outcome = 'false_positive') AND ended_at > $2)`,
		c.shape[:], now.Add(-time.Duration(set.MaxLifetime))).Scan(&suppressed); err != nil {
		return nil, err
	}
	c.check("suppressed", !suppressed, "the same rule was not rolled back or marked a false positive within max_lifetime")
	merged := *active
	merged.RateLimitRules = append(slices.Clone(baseOf(active).RateLimitRules), overlayOf(active, now)...)
	merged.RateLimitRules = append(append(merged.RateLimitRules, pending...), c.rule)
	_, _, errs := snapshot.Compile(&merged, s.cfg.Deployment)
	var msgs []string
	for _, e := range errs {
		msgs = append(msgs, joinPath(e.Path, e.Msg))
	}
	c.check("compile", errs == nil, strings.Join(msgs, "; "))
	u, err := s.autopilotUsage(ctx, q)
	if err != nil {
		return nil, err
	}
	if in.Action == "add_sensor" {
		c.check("budget_sensors", u.Sensors < set.MaxSensors, fmt.Sprintf("%d of max_sensors %d are in use", u.Sensors, set.MaxSensors))
	} else {
		c.check("budget_enforcing", u.Enforcing < set.MaxEnforcing, fmt.Sprintf("%d of max_enforcing %d are in use", u.Enforcing, set.MaxEnforcing))
	}
	return c, nil
}

// enforceCheck decides whether an observed enforce rule may block: its
// shadow counts since it went live must show the attack still running, and
// blocking it must not take too much of the fleet's traffic, a verified
// crawler or a protected subject. It returns the reason it may not, or "",
// with the numbers that decided.
func (s *Server) enforceCheck(ctx context.Context, q querier, set AutopilotSettings, ar apRule) (string, map[string]any, float64, error) {
	now := s.now()
	rows, err := s.statsWhere(ctx, q, "minute >= $1 AND minute < $2", ar.LiveSince.Truncate(time.Minute), now)
	if err != nil {
		return "", nil, 0, err
	}
	notes, err := citedNotes(ctx, q, ar.ProposalID)
	if err != nil {
		return "", nil, 0, err
	}
	maxShare := blockShare(set, notes)
	observe, err := s.observeFor(ctx, q, set, ar)
	if err != nil {
		return "", nil, 0, err
	}
	var fleet, evaluated, would, heavy, recent uint64
	// Subjects are checked only when the key starts with ip, which propose
	// puts first: the display's first part is then the address the edge
	// keyed. Later parts are client-written and never parsed.
	checkIP := len(ar.Rule.Key) > 0 && ar.Rule.Key[0] == "ip"
	var subjects []netip.Prefix
	recentFrom := now.Add(-observe)
	for _, r := range rows {
		fleet += r.Requests
		top := map[string]uint64{} // would-limit estimates per subject, summed across replicas
		for _, t := range r.TopLimited {
			if t.Rule != ar.ID {
				continue
			}
			top[t.Key] += t.WouldLimit - min(t.Err, t.WouldLimit) // at least this many
			if p, ok := subjectPrefix(t.Display); checkIP && ok && !slices.Contains(subjects, p) {
				subjects = append(subjects, p)
			}
		}
		for _, rc := range r.RateLimit {
			if rc.ID != ar.ID {
				continue
			}
			evaluated += rc.Evaluated
			would += rc.WouldLimit
			if !r.Minute.Before(recentFrom.Truncate(time.Minute)) {
				recent += rc.WouldLimit
			}
			heavy += heavyIn(rc.WouldLimit, top)
		}
	}
	// The budget is for collateral: the attackers, each a heavy share of a
	// minute, are left out over the window, as the guard leaves them out.
	collateral := withoutHeavy(would, heavy)
	share := ratio(collateral, fleet)
	// Stored for the per-rule guard, which compares limited requests with
	// heavy subjects left out, so the shadow leaves them out too.
	shadow := ratio(collateral, evaluated)
	numbers := map[string]any{"fleet_requests": fleet, "evaluated": evaluated, "would_limit": would, "collateral_would_limit": collateral, "recent_would_limit": recent,
		"share": share, "shadow_ratio": shadow, "raw_shadow_ratio": ratio(would, evaluated), "max_block_share": maxShare}
	if share > maxShare {
		return "block_share", numbers, shadow, nil
	}
	crawlers, err := s.crawlerPrefixes(ctx, q)
	if err != nil {
		return "", nil, 0, err
	}
	protected := protectedPrefixes(set)
	overlaps := func(ps []netip.Prefix, sub netip.Prefix) bool { return slices.ContainsFunc(ps, sub.Overlaps) }
	for _, sub := range subjects {
		if overlaps(crawlers, sub) {
			numbers["subject"] = sub.String()
			return "crawler_subject", numbers, shadow, nil
		}
		if overlaps(protected, sub) {
			numbers["subject"] = sub.String()
			return "protected_subject", numbers, shadow, nil
		}
	}
	if recent == 0 {
		return "attack_stopped", numbers, shadow, nil
	}
	bar, err := s.expectedBar(ctx, q, notes)
	if err != nil {
		return "", nil, 0, err
	}
	if bar != nil {
		numbers["expected_pattern"] = bar
		return "note_expected_pattern", numbers, shadow, nil
	}
	return "", numbers, shadow, nil
}

// protectedPrefixes are the protected subjects that are addresses. An AS
// number can't be matched: subjects are reported by address.
func protectedPrefixes(set AutopilotSettings) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range set.ProtectedSubjects {
		if pf, _, _ := parseSubject(p); pf.IsValid() {
			out = append(out, pf)
		}
	}
	return out
}

// subjectPrefix reads the address part a display starts with: an IPv4
// address, or an IPv6 /64 as the edge shows it.
func subjectPrefix(display string) (netip.Prefix, bool) {
	first, _, _ := strings.Cut(display, " ")
	if p, err := netip.ParsePrefix(first); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(first); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(a.Unmap()) })
}

func (s *Server) crawlerPrefixes(ctx context.Context, q querier) ([]netip.Prefix, error) {
	rows, err := q.Query(ctx, "SELECT prefixes FROM verified_bot_sets")
	if err != nil {
		return nil, err
	}
	lists, err := pgx.CollectRows(rows, pgx.RowTo[[]string])
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, list := range lists {
		for _, p := range list {
			if pf, err := netip.ParsePrefix(p); err == nil {
				out = append(out, pf)
			}
		}
	}
	return out, nil
}
