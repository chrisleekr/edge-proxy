package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// overlayRule is an autopilot rule that blocks a client sending more than
// 20 requests a minute to path, until exp. It is decoded strictly from JSON,
// as edges decode a snapshot, so it also checks the shape of expires_at.
func overlayRule(t *testing.T, id, path string, exp time.Time) snapshot.RateLimitRule {
	t.Helper()
	r := snapshot.RateLimitRule{ID: id, Expression: mustParse(`http.request.uri.path eq "` + path + `"`), Algorithm: "sliding_window", Limit: 20,
		Period: snapshot.Duration(time.Minute), Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["expires_at"] = exp.UTC().Format(time.RFC3339)
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out snapshot.RateLimitRule
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode rule: %v", err)
	}
	return out
}

// overlayPublish publishes rules as autopilot's overlay and returns the new
// version.
func (h *harness) overlayPublish(message string, rules ...snapshot.RateLimitRule) int64 {
	h.t.Helper()
	v, err := h.s.publishOverlay(context.Background(), rules, message)
	if err != nil {
		h.t.Fatalf("overlay publish: %v", err)
	}
	return v
}

// version is GET /api/versions/{v}.
func (c *client) version(v int64) versionRow {
	c.h.t.Helper()
	return decode[versionRow](c.h.t, c.do("GET", fmt.Sprintf("/api/versions/%d", v), nil))
}

// draftView is GET /api/draft.
type draftView struct {
	Config      snapshot.Config
	Revision    int64
	BaseVersion *int64 `json:"base_version"`
	Overlay     []snapshot.RateLimitRule
	Adopted     []string
}

func (c *client) draft() draftView {
	c.h.t.Helper()
	return decode[draftView](c.h.t, c.do("GET", "/api/draft", nil))
}

// adoptedAndPublished publishes ap-scraper, expiring at exp, as the
// overlay (version 2), then a person adopts it and publishes (version 3),
// so version 3 holds the person's copy and no overlay.
func adoptedAndPublished(t *testing.T, h *harness, pub *client, exp time.Time) {
	t.Helper()
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", exp))
	status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": "ap-scraper"}, "If-Match", pub.revision()), 200)
	status(t, pub.publishDraft("Keep blocking the scraper"), 201)
	if got := pub.version(3); !slices.Equal(rateLimitIDs(got.Config), []string{"login", "scraper"}) {
		t.Fatalf("version 3 rules %v", rateLimitIDs(got.Config))
	}
}

// rateLimitIDs lists a config's rate-limit rule ids in order.
func rateLimitIDs(c snapshot.Config) []string {
	ids := []string{}
	for _, r := range c.RateLimitRules {
		ids = append(ids, r.ID)
	}
	return ids
}

// limitOf is the limit of the rate-limit rule id in c, or 0.
func limitOf(c snapshot.Config, id string) int64 {
	for _, r := range c.RateLimitRules {
		if r.ID == id {
			return r.Limit
		}
	}
	return 0
}

// An overlay publish puts autopilot's rules after the active version's own,
// leaving out those already expired, and runs the active version's tests.
// Someone's unpublished draft is untouched and moves onto the new version,
// so their next publish needs no rebase.
func TestOverlayPublish(t *testing.T) {
	h, pub := published(t) // version 1: login at 10 a minute
	edit := testConfig()
	edit.RateLimitRules[0].Limit = 5
	status(t, pub.save(pub.revision(), edit, adminTest), 200)
	before := pub.draft()
	v := h.overlayPublish("Autopilot: block a scraper",
		overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour)), overlayRule(t, "ap-old", "/feed", h.now().Add(-time.Minute)))
	got := pub.version(v)

	t.Run("the new version is the active base with the overlay after it", func(t *testing.T) {
		if v != 2 || got.Status != "active" || !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || limitOf(got.Config, "login") != 10 {
			t.Fatalf("version %d %s, rules %v, login limit %d", v, got.Status, rateLimitIDs(got.Config), limitOf(got.Config, "login"))
		}
	})
	t.Run("an overlay rule already expired is left out", func(t *testing.T) {
		if slices.Contains(rateLimitIDs(got.Config), "ap-old") {
			t.Fatalf("rules %v", rateLimitIDs(got.Config))
		}
	})
	t.Run("the active version's config tests run", func(t *testing.T) {
		if len(got.TestResults) != 1 || !got.TestResults[0].Pass {
			t.Fatalf("test results %+v", got.TestResults)
		}
	})
	t.Run("it is recorded as an autopilot publish", func(t *testing.T) {
		if got.Source != "autopilot" || !slices.Contains(h.actions(), "config.overlay_publish version 2") {
			t.Fatalf("source %s, audit %v", got.Source, h.actions())
		}
		h.wantMetrics(`admin_publishes_total{source="autopilot"} 1`)
	})
	t.Run("the draft is untouched and moves onto the new version", func(t *testing.T) {
		d := pub.draft()
		if d.Revision != before.Revision || limitOf(d.Config, "login") != 5 || !slices.Equal(rateLimitIDs(d.Config), []string{"login"}) || d.BaseVersion == nil || *d.BaseVersion != 2 {
			t.Fatalf("draft revision %d (was %d), rules %v, login limit %d, base %v", d.Revision, before.Revision, rateLimitIDs(d.Config), limitOf(d.Config, "login"), d.BaseVersion)
		}
	})
}

// A rule that expires needs edges that read schema 5, so an overlay
// publish waits while an older edge is live, as any publish does.
func TestOverlayPublishWaitsForSchema5Edges(t *testing.T) {
	h, pub := published(t)
	e := h.client()
	e.token = h.edgeToken(pub)
	status(t, e.do("POST", "/v1/edge/report", edge.StatsReport{Instance: "schema-4-edge", MaxSchema: 4, Deployment: h.s.cfg.Deployment.Fingerprint()}), 200)
	_, err := h.s.publishOverlay(t.Context(), []snapshot.RateLimitRule{overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))}, "Autopilot: block a scraper")
	if p, ok := errors.AsType[*problem](err); !ok || p.Status != 409 || !strings.Contains(p.Detail, "edge schema-4-edge reads config schema up to 4") {
		t.Fatalf("err %v", err)
	}
	if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 1 {
		t.Fatalf("%d versions, want 1", len(list))
	}
}

// A draft save compiles the draft with the current overlay, as the next
// publish will, so the 200 rule limit is found at save, not at publish.
func TestDraftSaveCountsOverlayRules(t *testing.T) {
	h, pub := published(t)
	h.overlayPublish("Autopilot: block two scrapers",
		overlayRule(t, "ap-search", "/search", h.now().Add(time.Hour)), overlayRule(t, "ap-feed", "/feed", h.now().Add(time.Hour)))
	cases := []struct {
		name   string
		rules  int // the draft's own rate-limit rules
		status int
	}{
		{"a draft that fits beside the overlay saves", snapshot.MaxRulesPerPhase - 2, 200},
		{"a draft the overlay would push past the limit is refused", snapshot.MaxRulesPerPhase - 1, 422},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			for i := 1; i < tc.rules; i++ {
				r := c.RateLimitRules[0]
				r.ID = fmt.Sprint("login-", i)
				c.RateLimitRules = append(c.RateLimitRules, r)
			}
			resp := pub.save(pub.revision(), c, adminTest)
			if tc.status == 200 {
				status(t, resp, 200)
				return
			}
			p := decode[problem](t, resp)
			if resp.StatusCode != 422 || !slices.ContainsFunc(p.Errors, func(e expr.Issue) bool {
				return e.Path == "config.rate_limit_rules" && strings.Contains(e.Msg, "has 201 rules; at most 200")
			}) {
				t.Fatalf("%d %+v", resp.StatusCode, p)
			}
		})
	}
}

// Rule ids starting "ap-" belong to autopilot. A person's rule using one,
// in any phase, is refused at the id field on save and on check.
func TestReservedPrefix(t *testing.T) {
	h := newHarness(t)
	h.user("ed", "editor")
	ed := h.signedIn("ed")
	withRateLimitID := testConfig()
	withRateLimitID.RateLimitRules = append(withRateLimitID.RateLimitRules, withRateLimitID.RateLimitRules[0])
	withRateLimitID.RateLimitRules[1].ID = "ap-login"
	withConfigID := testConfig()
	withConfigID.ConfigRules = append(withConfigID.ConfigRules, snapshot.ConfigRule{ID: "ap-pages", Expression: mustParse(`starts_with(http.request.uri.path, "/pages/")`),
		Settings: snapshot.Settings{BodyLimit: new(int64(1 << 20))}})
	withHeaderID := testConfig()
	withHeaderID.RequestHeaderRules = []snapshot.HeaderRule{headerRule("ap-headers")}
	hasIDError := func(errs []expr.Issue, path string) bool {
		return slices.ContainsFunc(errs, func(e expr.Issue) bool { return e.Path == path && strings.Contains(e.Msg, "ap-") })
	}
	t.Run("a rate-limit rule id is refused on save", func(t *testing.T) {
		resp := ed.save(ed.revision(), withRateLimitID)
		if p := decode[problem](t, resp); resp.StatusCode != 422 || !hasIDError(p.Errors, "config.rate_limit_rules[1].id") {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
	})
	t.Run("a config rule id is refused on save", func(t *testing.T) {
		resp := ed.save(ed.revision(), withConfigID)
		if p := decode[problem](t, resp); resp.StatusCode != 422 || !hasIDError(p.Errors, "config.config_rules[1].id") {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
	})
	t.Run("a request header rule id is refused on save", func(t *testing.T) {
		resp := ed.save(ed.revision(), withHeaderID)
		if p := decode[problem](t, resp); resp.StatusCode != 422 || !hasIDError(p.Errors, "config.request_header_rules[0].id") {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
	})
	t.Run("a rate-limit rule id is reported by check", func(t *testing.T) {
		resp := ed.do("POST", "/api/draft/check", map[string]any{"config": withRateLimitID})
		if got := decode[struct{ Errors []expr.Issue }](t, resp); resp.StatusCode != 200 || !hasIDError(got.Errors, "config.rate_limit_rules[1].id") {
			t.Fatalf("%d %+v", resp.StatusCode, got)
		}
	})
	t.Run("nothing was saved", func(t *testing.T) {
		if rev := ed.revision(); rev != `"0"` {
			t.Fatalf("draft at revision %s", rev)
		}
	})
}

// A person's publish after an overlay publish needs no rebase: the draft
// moved onto the overlay version, and the publish keeps the overlay after
// the draft's rules.
func TestPublishKeepsOverlayWithoutRebase(t *testing.T) {
	h, pub := published(t)
	edit := testConfig()
	edit.RateLimitRules[0].Limit = 5
	status(t, pub.save(pub.revision(), edit, adminTest), 200)
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour)))
	resp := pub.publishDraft("Tighten login")
	if resp.StatusCode != 201 {
		t.Fatalf("publish %d: %s", resp.StatusCode, body(resp))
	}
	v := decode[map[string]int64](t, resp)["version"]
	got := pub.version(v)
	if !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || limitOf(got.Config, "login") != 5 {
		t.Fatalf("version %d rules %v, login limit %d", v, rateLimitIDs(got.Config), limitOf(got.Config, "login"))
	}
	if d := pub.draft(); !slices.Equal(rateLimitIDs(d.Config), []string{"login"}) {
		t.Fatalf("the draft holds %v, want the person's rules only", rateLimitIDs(d.Config))
	}
}

// A revert restores the old version's own rules and keeps today's overlay:
// it undoes a person's change, not autopilot's response to an attack.
func TestRevertKeepsOverlay(t *testing.T) {
	t.Run("a person's change reverts under the overlay", func(t *testing.T) {
		h, pub := published(t) // version 1: login at 10
		edit := testConfig()
		edit.RateLimitRules[0].Limit = 5
		status(t, pub.save(pub.revision(), edit, adminTest), 200)
		status(t, pub.publishDraft("Tighten login"), 201)                                                               // version 2
		h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 3
		resp := pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "Login limit locked users out"})
		if resp.StatusCode != 201 {
			t.Fatalf("revert %d: %s", resp.StatusCode, body(resp))
		}
		got := pub.version(decode[map[string]int64](t, resp)["version"])
		if got.Source != "revert" || got.BasedOn == nil || *got.BasedOn != 1 || !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || limitOf(got.Config, "login") != 10 {
			t.Fatalf("source %s based on %v, rules %v, login limit %d", got.Source, got.BasedOn, rateLimitIDs(got.Config), limitOf(got.Config, "login"))
		}
	})
	// Reverting to before a person adopted an autopilot rule drops their
	// copy, so the autopilot rule comes back while it has not expired.
	t.Run("reverting past an adopt brings the autopilot rule back", func(t *testing.T) {
		h, pub := published(t)
		adoptedAndPublished(t, h, pub, h.now().Add(time.Hour))
		resp := pub.do("POST", "/api/versions/2/revert", map[string]string{"reason": "The adopted copy blocks too much"})
		if resp.StatusCode != 201 {
			t.Fatalf("revert %d: %s", resp.StatusCode, body(resp))
		}
		got := pub.version(decode[map[string]int64](t, resp)["version"])
		if !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) {
			t.Fatalf("rules %v", rateLimitIDs(got.Config))
		}
	})
	t.Run("an expired autopilot rule does not come back", func(t *testing.T) {
		h, pub := published(t)
		adoptedAndPublished(t, h, pub, h.now().Add(time.Minute))
		h.advance(2 * time.Minute)
		resp := pub.do("POST", "/api/versions/2/revert", map[string]string{"reason": "The adopted copy blocks too much"})
		if resp.StatusCode != 201 {
			t.Fatalf("revert %d: %s", resp.StatusCode, body(resp))
		}
		got := pub.version(decode[map[string]int64](t, resp)["version"])
		if !slices.Equal(rateLimitIDs(got.Config), []string{"login"}) {
			t.Fatalf("rules %v", rateLimitIDs(got.Config))
		}
	})
}

// The guard rolling back a person's version restores the previous rules
// and keeps the overlay, as a revert does.
func TestGuardRollbackKeepsOverlay(t *testing.T) {
	t.Run("a person's change rolls back under the overlay", func(t *testing.T) {
		h, pub := published(t)                                                                                          // version 1: login at 10
		h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 2
		edit := testConfig()
		edit.RateLimitRules[0].Limit = 5
		status(t, pub.save(pub.revision(), edit, adminTest), 200)
		status(t, pub.publishDraft("Tighten login"), 201) // version 3
		ctx := t.Context()
		subject, _ := h.s.loadVersion(ctx, h.db, 3)
		baseline, _ := h.s.loadVersion(ctx, h.db, 2)
		if err := h.s.act(ctx, defaultGuard(), subject, baseline, nil, guardOutcome{At: h.now(), Decision: "rollback"}); err != nil {
			t.Fatal(err)
		}
		got := pub.version(4)
		if got.Source != "guard_rollback" || got.Status != "active" || !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || limitOf(got.Config, "login") != 10 {
			t.Fatalf("version 4 %s %s, rules %v, login limit %d", got.Source, got.Status, rateLimitIDs(got.Config), limitOf(got.Config, "login"))
		}
		if v3 := pub.version(3); v3.Status != "rolled_back" {
			t.Fatalf("version 3 %s", v3.Status)
		}
	})
	t.Run("rolling back the publish that adopted a rule brings the autopilot rule back", func(t *testing.T) {
		h, pub := published(t)
		adoptedAndPublished(t, h, pub, h.now().Add(time.Hour))
		ctx := t.Context()
		subject, _ := h.s.loadVersion(ctx, h.db, 3)
		baseline, _ := h.s.loadVersion(ctx, h.db, 2)
		if err := h.s.act(ctx, defaultGuard(), subject, baseline, nil, guardOutcome{At: h.now(), Decision: "rollback"}); err != nil {
			t.Fatal(err)
		}
		if got := pub.version(4); got.Source != "guard_rollback" || !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) {
			t.Fatalf("version 4 %s, rules %v", got.Source, rateLimitIDs(got.Config))
		}
	})
}

// An overlay publish waits for a running canary like any publish, and
// promoting the canary stays a status change: it makes no new version.
func TestOverlayPublishWaitsForCanary(t *testing.T) {
	h, pub := published(t)
	edit := testConfig()
	edit.RateLimitRules[0].Limit = 5
	status(t, pub.save(pub.revision(), edit, adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2 on 10%", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	scraper := overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))
	t.Run("an overlay publish during a canary is refused", func(t *testing.T) {
		_, err := h.s.publishOverlay(t.Context(), []snapshot.RateLimitRule{scraper}, "Autopilot: block a scraper")
		if p, ok := errors.AsType[*problem](err); !ok || p.Status != 409 || !strings.Contains(p.Detail, "version 2 is in canary") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("promote makes no new version", func(t *testing.T) {
		h.advance(5 * time.Minute)
		h.putStats(2, 3, 400, 0, 0, []int64{400}, "[]", "[]")
		status(t, pub.do("POST", "/api/canary/promote", nil), 204)
		if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 2 || list[0].Version != 2 || list[0].Status != "active" {
			t.Fatalf("versions %+v", list)
		}
	})
	t.Run("after the canary the overlay publishes", func(t *testing.T) {
		got := pub.version(h.overlayPublish("Autopilot: block a scraper", scraper))
		if !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || limitOf(got.Config, "login") != 5 {
			t.Fatalf("rules %v, login limit %d", rateLimitIDs(got.Config), limitOf(got.Config, "login"))
		}
	})
}

// An export carries the overlay, so a bootstrap edge keeps blocking until
// the rules expire. Importing it elsewhere replaces that admin's own rules,
// keeps its overlay, and ignores the overlay rules in the file.
func TestImportKeepsOverlay(t *testing.T) {
	staging, sp := published(t)
	edit := testConfig()
	edit.RateLimitRules[0].Limit = 7
	status(t, sp.save(sp.revision(), edit, adminTest), 200)
	status(t, sp.publishDraft("Tighten login"), 201)
	staging.overlayPublish("Autopilot: block a burst", overlayRule(t, "ap-burst", "/feed", staging.now().Add(time.Hour)))
	out := decode[struct {
		Envelope map[string]json.RawMessage
		Tests    []ConfigTest
	}](t, sp.do("GET", "/api/export", nil))
	if !bytes.Contains(out.Envelope["active"], []byte(`"ap-burst"`)) {
		t.Fatalf("the export left out the overlay: %s", out.Envelope["active"])
	}

	prod, pp := published(t)
	prod.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", prod.now().Add(time.Hour)))
	resp := pp.do("POST", "/api/import", map[string]any{"config": out.Envelope["active"], "tests": out.Tests, "message": "Promote from staging"})
	if resp.StatusCode != 201 {
		t.Fatalf("import %d: %s", resp.StatusCode, body(resp))
	}
	got := pp.version(decode[map[string]int64](t, resp)["version"])
	if got.Source != "import" || !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || limitOf(got.Config, "login") != 7 {
		t.Fatalf("source %s, rules %v, login limit %d", got.Source, rateLimitIDs(got.Config), limitOf(got.Config, "login"))
	}
}

// Adopting an autopilot rule copies it into the draft as a person's rule:
// without the prefix and without an expiry. The next publish of a draft
// holding it drops the autopilot copy, so the rule never runs twice.
func TestAdopt(t *testing.T) {
	h, pub := published(t)
	h.user("vera", "viewer")
	exp := h.now().Add(time.Hour)
	h.overlayPublish("Autopilot: block scrapers", overlayRule(t, "ap-scraper", "/search", exp), overlayRule(t, "ap-burst", "/feed", exp)) // version 2
	adopt := func(c *client, id string) *http.Response {
		return c.do("POST", "/api/draft/adopt", map[string]string{"id": id}, "If-Match", c.revision())
	}

	t.Run("a viewer can't adopt", func(t *testing.T) {
		status(t, adopt(h.signedIn("vera"), "ap-scraper"), 403)
	})
	t.Run("adopting without If-Match is refused", func(t *testing.T) {
		status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": "ap-scraper"}), 428)
	})
	t.Run("adopting with a stale If-Match is refused", func(t *testing.T) {
		status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": "ap-scraper"}, "If-Match", `"99"`), 412)
	})
	t.Run("a rule not in the overlay is not found", func(t *testing.T) {
		resp := adopt(pub, "ap-missing")
		if b := body(resp); resp.StatusCode != 404 || !strings.Contains(b, "ap-missing") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("a rule in another phase with the new id is refused", func(t *testing.T) {
		c := testConfig()
		c.RequestHeaderRules = []snapshot.HeaderRule{headerRule("scraper")}
		status(t, pub.save(pub.revision(), c, adminTest), 200)
		before := pub.revision()
		resp := adopt(pub, "ap-scraper")
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, `already has a rule \"scraper\"`) {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		if after := pub.revision(); after != before {
			t.Fatalf("revision %s, want %s", after, before)
		}
	})
	t.Run("a rule whose new id the draft already uses is refused", func(t *testing.T) {
		c := testConfig()
		c.RateLimitRules = append(c.RateLimitRules, c.RateLimitRules[0])
		c.RateLimitRules[1].ID = "burst"
		status(t, pub.save(pub.revision(), c, adminTest), 200)
		resp := adopt(pub, "ap-burst")
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, "burst") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("adopting copies the rule without its prefix or expiry", func(t *testing.T) {
		status(t, adopt(pub, "ap-scraper"), 200)
		raw := decode[struct {
			Config struct {
				RateLimitRules []map[string]any `json:"rate_limit_rules"`
			}
			Adopted []string
		}](t, pub.do("GET", "/api/draft", nil))
		i := slices.IndexFunc(raw.Config.RateLimitRules, func(r map[string]any) bool { return r["id"] == "scraper" })
		if i < 0 || !slices.Equal(raw.Adopted, []string{"ap-scraper"}) {
			t.Fatalf("draft rules %v, adopted %v", raw.Config.RateLimitRules, raw.Adopted)
		}
		if _, ok := raw.Config.RateLimitRules[i]["expires_at"]; ok || raw.Config.RateLimitRules[i]["limit"] != float64(20) {
			t.Fatalf("adopted rule %v", raw.Config.RateLimitRules[i])
		}
		if !slices.Contains(h.actions(), "config.adopt draft") {
			t.Fatalf("audit %v", h.actions())
		}
	})
	t.Run("the next publish drops the adopted rule from the overlay", func(t *testing.T) {
		resp := pub.publishDraft("Keep blocking the scraper")
		if resp.StatusCode != 201 {
			t.Fatalf("publish %d: %s", resp.StatusCode, body(resp))
		}
		got := pub.version(decode[map[string]int64](t, resp)["version"])
		if !slices.Equal(rateLimitIDs(got.Config), []string{"login", "burst", "scraper", "ap-burst"}) {
			t.Fatalf("rules %v", rateLimitIDs(got.Config))
		}
		if d := pub.draft(); len(d.Adopted) != 0 || !slices.Equal(rateLimitIDs(snapshot.Config{RateLimitRules: d.Overlay}), []string{"ap-burst"}) {
			t.Fatalf("draft adopted %v, overlay %v", d.Adopted, rateLimitIDs(snapshot.Config{RateLimitRules: d.Overlay}))
		}
	})
}

// headerRule sets X-Feature on every request.
func headerRule(id string) snapshot.HeaderRule {
	return snapshot.HeaderRule{ID: id, Expression: mustParse(`true`), Ops: []snapshot.HeaderOp{{Op: "set", Name: "X-Feature", Value: "on"}}}
}

// An autopilot rule that has expired no longer runs, so a person's next
// publish leaves it out rather than carry it against the rule limits.
func TestPublishDropsExpiredOverlay(t *testing.T) {
	h, pub := published(t)
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Minute))) // version 2
	h.advance(2 * time.Minute)
	if d := pub.draft(); len(d.Overlay) != 0 {
		t.Fatalf("the draft lists expired autopilot rules %v", rateLimitIDs(snapshot.Config{RateLimitRules: d.Overlay}))
	}
	edit := testConfig()
	edit.RateLimitRules[0].Limit = 5
	status(t, pub.save(pub.revision(), edit, adminTest), 200)
	status(t, pub.publishDraft("Tighten login"), 201)
	if got := pub.version(3); !slices.Equal(rateLimitIDs(got.Config), []string{"login"}) {
		t.Fatalf("version 3 rules %v", rateLimitIDs(got.Config))
	}
}

// Config tests describe people's rules, so an autopilot rule matching a
// test's request does not fail it: not on the overlay publish, and not on
// a revert to the version that holds the test.
func TestConfigTestsIgnoreOverlayRules(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	search := ConfigTest{Name: "search is not limited", Request: TestRequest{Host: "api.example.com", Path: "/search"}, Expect: TestExpect{RateLimitRules: &[]string{}}}
	status(t, pub.save(`"0"`, testConfig(), adminTest, search), 200)
	status(t, pub.publishDraft("v1"), 201)
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 2
	resp := pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "Undo"})
	if resp.StatusCode != 201 {
		t.Fatalf("revert %d: %s", resp.StatusCode, body(resp))
	}
	got := pub.version(decode[map[string]int64](t, resp)["version"])
	if !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || len(got.TestResults) != 2 || !got.TestResults[1].Pass {
		t.Fatalf("rules %v, test results %+v", rateLimitIDs(got.Config), got.TestResults)
	}
}

// An active version published over issuers without keys does not block
// autopilot: the overlay keeps that version's rules, which already ran.
func TestOverlayPublishOverIssuerOverride(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	status(t, pub.save(`"0"`, authConfig("https://auth.example.com/jwks")), 200)
	status(t, pub.publishDraft("Protect orders", "override_reason", "IdP is down, publishing anyway"), 201)
	got := pub.version(h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))))
	if got.Status != "active" || !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || got.OverrideReason == nil ||
		*got.OverrideReason != "autopilot keeps the active version's rules, which already ran" {
		t.Fatalf("version %d %s, rules %v, override %v", got.Version, got.Status, rateLimitIDs(got.Config), got.OverrideReason)
	}
}

// Autopilot's input is checked before anything is published: every rule
// is an autopilot rule, and every one expires.
func TestOverlayPublishRefusesInvalidRules(t *testing.T) {
	h, pub := published(t)
	unnamed := overlayRule(t, "scraper", "/search", h.now().Add(time.Hour))
	forever := overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))
	forever.ExpiresAt = time.Time{}
	far := overlayRule(t, "ap-scraper", "/search", h.now().Add(25*time.Hour))
	for _, tc := range []struct {
		name string
		rule snapshot.RateLimitRule
		msg  string
	}{
		{"a rule without the autopilot prefix is refused", unnamed, `must start with "ap-"`},
		{"a rule that never expires is refused", forever, "expires_at is required"},
		{"a rule expiring more than a day ahead is refused", far, "expires_at is more than 24h ahead"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.s.publishOverlay(t.Context(), []snapshot.RateLimitRule{tc.rule}, "Autopilot: block a scraper")
			p, ok := errors.AsType[*problem](err)
			if !ok || p.Status != 422 || p.Title != "Invalid autopilot rules" || len(p.Errors) != 1 || p.Errors[0].Path != "rules[0]" || !strings.Contains(p.Errors[0].Msg, tc.msg) {
				t.Fatalf("err %v", err)
			}
			if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 1 {
				t.Fatalf("%d versions, want 1", len(list))
			}
		})
	}
}

// Only a rate-limit rule is an adopted copy. A config rule that happens to
// carry the autopilot rule's plain id leaves the autopilot rule running.
func TestAdoptedCopyIsARateLimitRule(t *testing.T) {
	h, pub := published(t)
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 2
	status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": "ap-scraper"}, "If-Match", pub.revision()), 200)
	// The person drops the adopted copy and names a config rule scraper.
	c := testConfig()
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "scraper", Expression: mustParse(`starts_with(http.request.uri.path, "/search")`),
		Settings: snapshot.Settings{BodyLimit: new(int64(1 << 20))}})
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("Search body limit"), 201)
	if got := pub.version(3); !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) {
		t.Fatalf("version 3 rules %v", rateLimitIDs(got.Config))
	}
}

// A person's own edit of an adopted copy is what publishes, and the
// autopilot copy leaves.
func TestAdoptEditPublish(t *testing.T) {
	h, pub := published(t)
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 2
	status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": "ap-scraper"}, "If-Match", pub.revision()), 200)
	d := pub.draft()
	i := slices.IndexFunc(d.Config.RateLimitRules, func(r snapshot.RateLimitRule) bool { return r.ID == "scraper" })
	if i < 0 {
		t.Fatalf("draft rules %v", rateLimitIDs(d.Config))
	}
	d.Config.RateLimitRules[i].Limit = 50
	status(t, pub.save(etag(d.Revision), &d.Config, adminTest), 200)
	status(t, pub.publishDraft("Loosen the scraper limit"), 201)
	if got := pub.version(3); !slices.Equal(rateLimitIDs(got.Config), []string{"login", "scraper"}) || limitOf(got.Config, "scraper") != 50 {
		t.Fatalf("version 3 rules %v, scraper limit %d", rateLimitIDs(got.Config), limitOf(got.Config, "scraper"))
	}
}

// Copying a version to the draft copies people's rules only: the overlay
// stays autopilot's.
func TestCopyToDraftLeavesOverlay(t *testing.T) {
	h, pub := published(t)
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 2
	status(t, pub.do("POST", "/api/versions/2/copy-to-draft", nil, "If-Match", pub.revision()), 200)
	if d := pub.draft(); !slices.Equal(rateLimitIDs(d.Config), []string{"login"}) {
		t.Fatalf("draft rules %v", rateLimitIDs(d.Config))
	}
}

// A rebase onto a version that differs only by autopilot rules shows no
// change from active and leaves the overlay out of the draft.
func TestRebaseIgnoresOverlay(t *testing.T) {
	h, pub := published(t) // version 1; the draft is based on it
	edit := testConfig()
	edit.RateLimitRules[0].Limit = 5
	status(t, pub.save(pub.revision(), edit, adminTest), 200)
	status(t, pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "Redeploy"}), 201)               // version 2
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 3
	view := decode[map[string]json.RawMessage](t, pub.do("GET", "/api/draft/rebase", nil))
	if bytes.Contains(view["active_changes"], []byte("ap-scraper")) || bytes.Contains(view["result"], []byte("ap-scraper")) {
		t.Fatalf("active changes %s, result %s", view["active_changes"], view["result"])
	}
	status(t, pub.do("POST", "/api/draft/rebase", nil, "If-Match", pub.revision()), 200)
	if d := pub.draft(); !slices.Equal(rateLimitIDs(d.Config), []string{"login"}) || limitOf(d.Config, "login") != 5 {
		t.Fatalf("draft rules %v, login limit %d", rateLimitIDs(d.Config), limitOf(d.Config, "login"))
	}
}

// The draft compared with the overlay version is what the next publish
// changes, so the overlay is not listed as removed.
func TestDiffDraftKeepsOverlay(t *testing.T) {
	h, pub := published(t)
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 2
	diff := decode[struct{ Diff Diff }](t, pub.do("GET", "/api/diff/2/draft", nil))
	if pd := diff.Diff.Phases["rate_limit_rules"]; pd != nil && slices.Contains(pd.Removed, "ap-scraper") {
		t.Fatalf("diff %+v", pd)
	}
}

// An import keeps the file's overlay out, but an "ap-" id in another phase
// is a person's rule and is refused as a save refuses it.
func TestImportRefusesReservedConfigRule(t *testing.T) {
	_, pub := published(t)
	c := testConfig()
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "ap-pages", Expression: mustParse(`starts_with(http.request.uri.path, "/pages/")`),
		Settings: snapshot.Settings{BodyLimit: new(int64(1 << 20))}})
	resp := pub.do("POST", "/api/import", map[string]any{"config": c, "tests": []ConfigTest{adminTest}, "message": "Promote from staging"})
	if p := decode[problem](t, resp); resp.StatusCode != 422 || p.Title != "Invalid config" || len(p.Errors) != 1 || p.Errors[0].Path != "config.config_rules[1].id" {
		t.Fatalf("%d %+v", resp.StatusCode, p)
	}
	if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 1 {
		t.Fatalf("%d versions, want 1", len(list))
	}
}

// A version saved before "ap-" was reserved may hold a person's header
// rule with that prefix. Reverting to it publishes without that rule.
func TestRevertDropsPreUpgradeReservedRule(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	old := testConfig()
	old.Version = 1
	old.RequestHeaderRules = []snapshot.HeaderRule{headerRule("ap-headers")}
	if _, err := h.db.Exec(t.Context(), "INSERT INTO config_versions (version, author, message, source, status, config) VALUES (1, 'user:pub', 'v1', 'manual', 'superseded', $1)", old); err != nil {
		t.Fatal(err)
	}
	status(t, pub.save(`"0"`, testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	resp := pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "Back to v1"})
	if resp.StatusCode != 201 {
		t.Fatalf("revert %d: %s", resp.StatusCode, body(resp))
	}
	if got := pub.version(decode[map[string]int64](t, resp)["version"]); len(got.Config.RequestHeaderRules) != 0 {
		t.Fatalf("header rules %+v", got.Config.RequestHeaderRules)
	}
}

// A person's rule whose expiry has passed is valid but never runs, so the
// save says so at the field.
func TestSaveWarnsOnPastExpiry(t *testing.T) {
	h, pub := published(t)
	c := testConfig()
	c.RateLimitRules[0].ExpiresAt = h.now().Add(-time.Hour)
	resp := pub.save(pub.revision(), c, adminTest)
	got := decode[struct{ Warnings []expr.Issue }](t, resp)
	if resp.StatusCode != 200 || !slices.ContainsFunc(got.Warnings, func(w expr.Issue) bool {
		return w.Path == "config.rate_limit_rules[0].expires_at" && strings.Contains(w.Msg, "is already past; the rule will not run")
	}) {
		t.Fatalf("%d %+v", resp.StatusCode, got.Warnings)
	}
}

// matchAll is a rate-limit rule with id that matches every request.
func matchAll(id string) snapshot.RateLimitRule {
	r := testConfig().RateLimitRules[0]
	r.ID, r.Expression = id, mustParse(`true`)
	return r
}

// withoutCountry redeploys admin behind a CDN that sends no viewer country.
func withoutCountry(t *testing.T, h *harness) {
	t.Helper()
	e := baseEnv("unused")
	e["CLIENT_IP_SOURCE"] = "remote_addr"
	cfg, err := LoadConfig(env(e))
	if err != nil {
		t.Fatal(err)
	}
	h.s.cfg.Deployment = cfg.Deployment
}

// A restore returns rules that already ran, so today's overlay must not
// block it. When only the overlay makes the restore invalid, it publishes
// without the overlay and the audit row says so. When the restored rules
// are invalid on their own, the error names them, not the overlay.
func TestRestoreDropsAnOverlayThatBlocksIt(t *testing.T) {
	// capsUnderAFlood publishes two rules matching every request (version
	// 2), removes them (version 3), and has autopilot add a third rule
	// matching every request (version 4): with version 2's rules that is
	// past the limit of 2. Version 2 also uses the viewer country.
	capsUnderAFlood := func(t *testing.T) (*harness, *client) {
		t.Helper()
		h, pub := published(t) // version 1
		wide := testConfig()
		wide.ConfigRules[0].Expression = mustParse(`starts_with(http.request.uri.path, "/admin/") and ip.src.country ne "XX"`)
		wide.RateLimitRules = append(wide.RateLimitRules, matchAll("all-a"), matchAll("all-b"))
		status(t, pub.save(pub.revision(), wide, adminTest), 200)
		status(t, pub.publishDraft("Cap every client"), 201) // version 2
		status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
		status(t, pub.publishDraft("Remove the caps"), 201) // version 3
		flood := overlayRule(t, "ap-flood", "/", h.now().Add(time.Hour))
		flood.Expression = mustParse(`true`)
		h.overlayPublish("Autopilot: cap a flood", flood) // version 4
		return h, pub
	}
	dropped := func(t *testing.T, h *harness, action string, v int64) {
		t.Helper()
		var dropped bool
		if err := h.db.QueryRow(t.Context(), "SELECT (details->>'overlay_dropped')::boolean FROM audit_events WHERE action = $1 AND target = $2",
			action, fmt.Sprintf("version %d", v)).Scan(&dropped); err != nil || !dropped {
			t.Fatalf("overlay_dropped %v, err %v", dropped, err)
		}
	}
	t.Run("a revert the overlay blocks publishes without it", func(t *testing.T) {
		h, pub := capsUnderAFlood(t)
		resp := pub.do("POST", "/api/versions/2/revert", map[string]string{"reason": "The caps were right"})
		if resp.StatusCode != 201 {
			t.Fatalf("revert %d: %s", resp.StatusCode, body(resp))
		}
		v := decode[map[string]int64](t, resp)["version"]
		if got := pub.version(v); !slices.Equal(rateLimitIDs(got.Config), []string{"login", "all-a", "all-b"}) {
			t.Fatalf("version %d rules %v", v, rateLimitIDs(got.Config))
		}
		dropped(t, h, "config.revert", v)
	})
	t.Run("a revert to rules that no longer fit the deployment names those rules", func(t *testing.T) {
		h, pub := capsUnderAFlood(t)
		withoutCountry(t, h)
		resp := pub.do("POST", "/api/versions/2/revert", map[string]string{"reason": "The caps were right"})
		p := decode[problem](t, resp)
		if resp.StatusCode != 422 || p.Title != "Invalid config" || len(p.Errors) != 1 || !strings.HasPrefix(p.Errors[0].Path, "config.config_rules[0].expression") {
			t.Fatalf("%d %+v", resp.StatusCode, p)
		}
	})
	// The overlay rule uses the viewer country, which a redeploy removed;
	// the rules of the version before it do not.
	t.Run("a guard rollback of a person's version the overlay blocks publishes without it", func(t *testing.T) {
		h, pub := published(t) // version 1
		geo := overlayRule(t, "ap-geo", "/search", h.now().Add(time.Hour))
		geo.Expression = mustParse(`http.request.uri.path eq "/search" and ip.src.country eq "XX"`)
		h.overlayPublish("Autopilot: block a country's scraper", geo) // version 2
		edit := testConfig()
		edit.RateLimitRules[0].Limit = 5
		status(t, pub.save(pub.revision(), edit, adminTest), 200)
		status(t, pub.publishDraft("Tighten login"), 201) // version 3, with ap-geo
		withoutCountry(t, h)
		ctx := t.Context()
		subject, _ := h.s.loadVersion(ctx, h.db, 3)
		baseline, _ := h.s.loadVersion(ctx, h.db, 2)
		if err := h.s.act(ctx, defaultGuard(), subject, baseline, nil, guardOutcome{At: h.now(), Decision: "rollback"}); err != nil {
			t.Fatal(err)
		}
		if got := pub.version(4); got.Source != "guard_rollback" || !slices.Equal(rateLimitIDs(got.Config), []string{"login"}) || limitOf(got.Config, "login") != 10 {
			t.Fatalf("version 4 %s, rules %v, login limit %d", got.Source, rateLimitIDs(got.Config), limitOf(got.Config, "login"))
		}
		dropped(t, h, "config.rollback", 4)
	})
}

// An autopilot rule's content is fixed by its id. An adoption copies the
// rule as it was, so a rule changed under the same id would be dropped by
// the adopted list. Renewing it with a later expiry is allowed.
func TestOverlayRuleContentIsFixedPerID(t *testing.T) {
	h, pub := published(t)
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 2
	t.Run("a renewal with a later expiry is published", func(t *testing.T) {
		got := pub.version(h.overlayPublish("Autopilot: keep blocking the scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(2*time.Hour))))
		if got.Version != 3 || !slices.Equal(rateLimitIDs(got.Config), []string{"login", "ap-scraper"}) || !got.Config.RateLimitRules[1].ExpiresAt.After(h.now().Add(90*time.Minute)) {
			t.Fatalf("version %d rules %v", got.Version, got.Config.RateLimitRules)
		}
	})
	t.Run("a different limit under the same id is refused", func(t *testing.T) {
		changed := overlayRule(t, "ap-scraper", "/search", h.now().Add(2*time.Hour))
		changed.Limit = 5
		_, err := h.s.publishOverlay(t.Context(), []snapshot.RateLimitRule{changed}, "Autopilot: block the scraper harder")
		p, ok := errors.AsType[*problem](err)
		if !ok || p.Status != 422 || p.Title != "Invalid autopilot rules" || len(p.Errors) != 1 || p.Errors[0].Path != "rules[0]" ||
			p.Errors[0].Msg != `id "ap-scraper" is live with other content; a changed autopilot rule needs a new id` {
			t.Fatalf("err %v", err)
		}
		if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 3 {
			t.Fatalf("%d versions, want 3", len(list))
		}
	})
}

// The draft's adopted list matches overlay rules by id until a person
// publishes. A new autopilot rule reusing an adopted id after the adopted
// one expired would be dropped by that publish, so it is refused.
func TestOverlayPublishRefusesAnAdoptedID(t *testing.T) {
	h, pub := published(t)
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Minute))) // version 2
	status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": "ap-scraper"}, "If-Match", pub.revision()), 200)
	h.advance(2 * time.Minute)
	changed := overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))
	changed.Limit = 5
	_, err := h.s.publishOverlay(t.Context(), []snapshot.RateLimitRule{changed}, "Autopilot: block the scraper again")
	p, ok := errors.AsType[*problem](err)
	if !ok || p.Status != 422 || p.Title != "Invalid autopilot rules" || len(p.Errors) != 1 || p.Errors[0].Path != "rules[0]" ||
		p.Errors[0].Msg != `id "ap-scraper" is adopted in the draft; a new autopilot rule needs a new id` {
		t.Fatalf("err %v", err)
	}
	if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 2 {
		t.Fatalf("%d versions, want 2", len(list))
	}
}

// A version published before publishes started the draft has no draft
// row. Adopting then starts the draft from the active version's rules.
func TestAdoptStartsTheDraft(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	status(t, pub.do("POST", "/api/import", map[string]any{"config": testConfig(), "tests": []ConfigTest{adminTest}, "message": "Promote from staging"}), 201)
	if _, err := h.owner.Exec(t.Context(), "DELETE FROM config_draft"); err != nil {
		t.Fatal(err)
	}
	h.overlayPublish("Autopilot: block a scraper", overlayRule(t, "ap-scraper", "/search", h.now().Add(time.Hour))) // version 2
	status(t, pub.do("POST", "/api/draft/adopt", map[string]string{"id": "ap-scraper"}, "If-Match", `"0"`), 200)
	d := pub.draft()
	if d.Revision != 1 || d.BaseVersion == nil || *d.BaseVersion != 2 || !slices.Equal(rateLimitIDs(d.Config), []string{"login", "scraper"}) || !slices.Equal(d.Adopted, []string{"ap-scraper"}) {
		t.Fatalf("draft revision %d based on %v, rules %v, adopted %v", d.Revision, d.BaseVersion, rateLimitIDs(d.Config), d.Adopted)
	}
}
