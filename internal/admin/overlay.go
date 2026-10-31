package admin

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// The overlay is autopilot's rate-limit rules, ids prefixed overlayPrefix,
// after the rules people write. It has no table of its own: the current
// overlay is the active version's, and every publish carries it over. The
// draft holds people's rules only.
const overlayPrefix = "ap-"

// maxOverlayTTL caps how far ahead an autopilot rule expires: it answers
// an attack in progress, and a person adopts it to keep it longer.
const maxOverlayTTL = 24 * time.Hour

func isOverlay(id string) bool { return strings.HasPrefix(id, overlayPrefix) }

// baseOf is c without its overlay: the rules people wrote. A config or
// header rule with the prefix comes only from a version saved before the
// prefix was reserved; it is dropped too, so no restore or copy brings it
// into a person's rules.
func baseOf(c *snapshot.Config) *snapshot.Config {
	out := *c
	out.ConfigRules = slices.DeleteFunc(slices.Clone(c.ConfigRules), func(r snapshot.ConfigRule) bool { return isOverlay(r.ID) })
	out.RateLimitRules = slices.DeleteFunc(slices.Clone(c.RateLimitRules), func(r snapshot.RateLimitRule) bool { return isOverlay(r.ID) })
	out.RequestHeaderRules = slices.DeleteFunc(slices.Clone(c.RequestHeaderRules), func(r snapshot.HeaderRule) bool { return isOverlay(r.ID) })
	return &out
}

// overlayOf is c's overlay rules still live at now, or none for a nil c.
// An expired rule no longer runs, so carrying it would only count against
// the rule limits, with no one able to delete it.
func overlayOf(c *snapshot.Config, now time.Time) []snapshot.RateLimitRule {
	out := []snapshot.RateLimitRule{}
	if c == nil {
		return out
	}
	for _, r := range c.RateLimitRules {
		if isOverlay(r.ID) && live(r, now) {
			out = append(out, r)
		}
	}
	return out
}

// merge is base with overlay after its rate-limit rules.
func merge(base *snapshot.Config, overlay []snapshot.RateLimitRule) *snapshot.Config {
	out := *base
	out.RateLimitRules = append(slices.Clone(base.RateLimitRules), overlay...)
	return &out
}

// withOverlay is base, a person's rules, merged with active's overlay. An
// adopted overlay rule leaves the overlay once its copy is in base, so the
// rule never runs twice.
func withOverlay(base, active *snapshot.Config, adopted []string, now time.Time) *snapshot.Config {
	ids := rateLimitIDSet(base)
	overlay := slices.DeleteFunc(overlayOf(active, now), func(r snapshot.RateLimitRule) bool {
		return slices.Contains(adopted, r.ID) && ids[strings.TrimPrefix(r.ID, overlayPrefix)]
	})
	return merge(base, overlay)
}

// restoreOf is what restoring target from current publishes: target's own
// rules with current's overlay. An overlay rule of target that was adopted
// later comes back while it has not expired: the restored rules drop the
// adopted copy, and the attack it answers may still be on.
func restoreOf(target, current *snapshot.Config, now time.Time) *snapshot.Config {
	base := baseOf(target)
	overlay := overlayOf(current, now)
	was, is := rateLimitIDSet(base), rateLimitIDSet(baseOf(current))
	for _, r := range overlayOf(target, now) {
		id := strings.TrimPrefix(r.ID, overlayPrefix)
		if is[id] && !was[id] && !slices.ContainsFunc(overlay, func(o snapshot.RateLimitRule) bool { return o.ID == r.ID }) {
			overlay = append(overlay, r)
		}
	}
	return merge(base, overlay)
}

// live reports whether overlay rule r still runs at now. An overlay rule
// always expires, so one without an expiry is not live; the zero time is
// before any now.
func live(r snapshot.RateLimitRule, now time.Time) bool {
	return r.ExpiresAt.After(now)
}

// rateLimitIDSet is the set of c's rate-limit rule ids. An adopted copy is a
// rate-limit rule, so only that phase can hold one.
func rateLimitIDSet(c *snapshot.Config) map[string]bool {
	ids := map[string]bool{}
	for _, r := range c.RateLimitRules {
		ids[r.ID] = true
	}
	return ids
}

// baseIDs is the set of rule ids in every phase of c.
func baseIDs(c *snapshot.Config) map[string]bool {
	ids := map[string]bool{}
	for _, r := range c.ConfigRules {
		ids[r.ID] = true
	}
	for _, r := range c.RateLimitRules {
		ids[r.ID] = true
	}
	for _, r := range c.RequestHeaderRules {
		ids[r.ID] = true
	}
	return ids
}

// reservedIDs reports each rule in c, a person's rules, whose id starts
// with the overlay prefix.
func reservedIDs(c *snapshot.Config) []expr.Issue {
	var errs []expr.Issue
	check := func(phase string, i int, id string) {
		if isOverlay(id) {
			errs = append(errs, expr.Issue{Path: fmt.Sprintf("config.%s[%d].id", phase, i), Msg: fmt.Sprintf("%q starts with %q, which is reserved for autopilot rules; rename it", id, overlayPrefix)})
		}
	}
	for i, r := range c.ConfigRules {
		check("config_rules", i, r.ID)
	}
	for i, r := range c.RateLimitRules {
		check("rate_limit_rules", i, r.ID)
	}
	for i, r := range c.RequestHeaderRules {
		check("request_header_rules", i, r.ID)
	}
	return errs
}

// activeConfig is the active version's config, or nil before the first
// publish.
func (s *Server) activeConfig(ctx context.Context, q querier) (*snapshot.Config, error) {
	av, err := activeVersion(ctx, q)
	if err != nil || av == nil {
		return nil, err
	}
	v, err := s.loadVersion(ctx, q, *av)
	if err != nil {
		return nil, err
	}
	return &v.Config, nil
}

// publishOverlay publishes rules as autopilot's overlay on the active
// version's own rules, leaving out those already expired. It runs every
// check a publish runs and moves a draft based on the active version onto
// the new one, so the person editing it needs no rebase.
func (s *Server) publishOverlay(ctx context.Context, rules []snapshot.RateLimitRule, message string) (int64, error) {
	var errs []expr.Issue
	for i, r := range rules {
		path := fmt.Sprintf("rules[%d]", i)
		if !isOverlay(r.ID) {
			errs = append(errs, expr.Issue{Path: path, Msg: fmt.Sprintf("id %q must start with %q", r.ID, overlayPrefix)})
		}
		if r.ExpiresAt.IsZero() {
			errs = append(errs, expr.Issue{Path: path, Msg: "expires_at is required: an autopilot rule always expires"})
		}
		if r.ExpiresAt.After(s.now().Add(maxOverlayTTL)) {
			errs = append(errs, expr.Issue{Path: path, Msg: "expires_at is more than 24h ahead; an autopilot rule is short-lived"})
		}
	}
	if errs != nil {
		return 0, &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid autopilot rules", Errors: errs}
	}
	var v int64
	err := dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var err error
		v, err = s.publishOverlayTx(ctx, tx, rules, message, false)
		return err
	}))
	if err != nil {
		return 0, err
	}
	s.met.published("autopilot")
	return v, nil
}

// publishOverlayTx publishes rules as the overlay in the caller's
// transaction, so autopilot's state changes commit with the version. The
// caller counts the publish once the transaction commits. removal says the
// rules are some of the live overlay's, unchanged.
func (s *Server) publishOverlayTx(ctx context.Context, tx pgx.Tx, rules []snapshot.RateLimitRule, message string, removal bool) (int64, error) {
	// The issuers the active version needs keys for were accepted when a
	// person published it; the overlay adds none.
	return s.publishTx(ctx, tx, &principal{actor: "system:autopilot"}, publishReq{keepBase: true, overlay: rules, message: message, source: "autopilot",
		override: "autopilot keeps the active version's rules, which already ran", removal: removal})
}

// adopt copies an overlay rule into the draft as a person's rule: without
// the prefix and without an expiry. The next publish of a draft holding it
// drops the overlay rule.
func (s *Server) adopt(w http.ResponseWriter, r *http.Request, p *principal) error {
	rev, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	ctx := r.Context()
	active, err := s.activeConfig(ctx, s.db)
	if err != nil {
		return err
	}
	overlay := overlayOf(active, s.now())
	i := slices.IndexFunc(overlay, func(o snapshot.RateLimitRule) bool { return o.ID == in.ID })
	if i < 0 {
		return fail(http.StatusNotFound, fmt.Sprintf("no autopilot rule %q is active", in.ID))
	}
	rule := overlay[i]
	d, err := s.loadDraft(ctx, s.db, false)
	if err == nil && d == nil {
		d, err = s.startDraft(ctx)
	}
	if err != nil {
		return err
	}
	// saveDraft refuses the save if the draft moved on since this read.
	if d.Revision != rev {
		return fail(http.StatusPreconditionFailed, fmt.Sprintf("the draft is at revision %d; reload and reapply your change", d.Revision))
	}
	rule.ID, rule.ExpiresAt = strings.TrimPrefix(rule.ID, overlayPrefix), time.Time{}
	if baseIDs(&d.Config)[rule.ID] {
		return fail(http.StatusConflict, fmt.Sprintf("the draft already has a rule %q; rename it before adopting %s", rule.ID, in.ID))
	}
	c := merge(&d.Config, []snapshot.RateLimitRule{rule})
	adopted := append(slices.Clone(d.Adopted), in.ID)
	saved, warns, results, err := s.saveDraft(ctx, p, rev, draftIn{Config: c, Tests: d.Tests, adopted: adopted}, s.keepBase(ctx), "config.adopt",
		map[string]any{"rule": in.ID, "as": rule.ID})
	if err != nil {
		return err
	}
	return s.draftSaved(w, ctx, c, saved, warns, results)
}
