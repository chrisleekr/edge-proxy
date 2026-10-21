package admin

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

func TestCanary(t *testing.T) {
	h, pub := published(t)
	c := testConfig()
	c.RateLimitRules[0].Limit = 8
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	h.user("eve", "editor")
	status(t, h.signedIn("eve").publishDraft("v2"), 403)
	resp := pub.do("POST", "/api/publish", map[string]any{"message": "v2 on 1%", "canary_percent": 1}, "If-Match", pub.revision())
	status(t, resp, 201)

	e := h.client()
	e.token = h.edgeToken(pub)
	env := decode[snapshot.Envelope](t, e.do("GET", "/v1/snapshot", nil))
	if env.Active.Version != 1 || env.Candidate == nil || env.Candidate.Version != 2 || env.CanaryPercent != 1 || !env.CanaryExpiresAt.After(h.now()) {
		t.Fatalf("envelope %+v", env)
	}
	status(t, pub.do("POST", "/api/versions/1/revert", map[string]string{"reason": "x"}), 409)

	t.Run("a step needs its minimum time and requests", func(t *testing.T) {
		status(t, pub.do("POST", "/api/canary/step", map[string]any{"percent": 10}), 409)
		h.advance(5 * time.Minute)
		status(t, pub.do("POST", "/api/canary/step", map[string]any{"percent": 10}), 409) // no traffic yet
		h.putStats(2, 3, 400, 0, 0, []int64{400}, "[]", "[]")
		status(t, pub.do("POST", "/api/canary/step", map[string]any{"percent": 0.5}), 422)
		status(t, pub.do("POST", "/api/canary/step", map[string]any{"percent": 10}), 204)
	})
	t.Run("promote makes the candidate active", func(t *testing.T) {
		h.advance(5 * time.Minute)
		h.putStats(2, 3, 400, 0, 0, []int64{400}, "[]", "[]")
		status(t, pub.do("POST", "/api/canary/promote", nil), 204)
		env := decode[snapshot.Envelope](t, e.do("GET", "/v1/snapshot", nil))
		if env.Active.Version != 2 || env.Candidate != nil {
			t.Fatalf("envelope %+v", env)
		}
		status(t, pub.do("POST", "/api/canary/promote", nil), 409)
	})
	if got := h.actions(); !slices.Contains(got, "canary.step version 2") || !slices.Contains(got, "canary.promote version 2") {
		t.Fatalf("audit %v", got)
	}
}

func TestCanaryAbort(t *testing.T) {
	_, pub := published(t)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 5}, "If-Match", pub.revision()), 201)
	// The draft is based on the canary, which carries its changes: there is
	// nothing to rebase, and rebasing onto active would drop them.
	for _, method := range []string{"GET", "POST"} {
		resp := pub.do(method, "/api/draft/rebase", nil, "If-Match", pub.revision())
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, "nothing to rebase") {
			t.Fatalf("%s rebase during canary: %d %s", method, resp.StatusCode, b)
		}
	}
	status(t, pub.do("POST", "/api/canary/abort", map[string]string{}), 422)
	status(t, pub.do("POST", "/api/canary/abort", map[string]string{"reason": "errors on checkout"}), 204)
	if v := decode[versionRow](t, pub.do("GET", "/api/versions/2", nil)); v.Status != "rolled_back" || v.AbortReason == nil || *v.AbortReason != "errors on checkout" {
		t.Fatalf("version %+v", v)
	}
	list := decode[[]struct {
		Version     int64   `json:"version"`
		AbortReason *string `json:"abort_reason"`
	}](t, pub.do("GET", "/api/versions", nil))
	if list[0].Version != 2 || list[0].AbortReason == nil || *list[0].AbortReason != "errors on checkout" || list[1].AbortReason != nil {
		t.Fatalf("versions %+v", list)
	}
	if c := decode[map[string]*canaryRow](t, pub.do("GET", "/api/canary", nil)); c["canary"] != nil {
		t.Fatal("canary still running")
	}
	// The draft was based on the aborted candidate, so it must rebase.
	status(t, pub.publishDraft("again"), 409)
	status(t, pub.do("GET", "/api/draft/rebase", nil), 200)
}

// A canary that moves an issuer to a new JWKS URL sends the keys of both
// URLs: the active version must not verify with the new IdP's keys.
func TestCanaryMovingAnIssuerSendsBothKeySets(t *testing.T) {
	h := newHarness(t)
	h.user("pub", "admin")
	pub := h.signedIn("pub")
	idp := newFakeJWKS(t, h)
	status(t, pub.save(`"0"`, authConfig(idp.srv.URL+"/jwks")), 200)
	status(t, pub.publishDraft("v1"), 201)
	status(t, pub.save(pub.revision(), authConfig(idp.srv.URL+"/jwks-new")), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "new IdP on 5%", "canary_percent": 5}, "If-Match", pub.revision()), 201)
	e := h.client()
	e.token = h.edgeToken(pub)
	env := decode[snapshot.Envelope](t, e.do("GET", "/v1/snapshot", nil))
	var urls []string
	for _, k := range env.Keys {
		urls = append(urls, strings.TrimPrefix(k.JWKSURL, idp.srv.URL))
	}
	if !slices.Equal(urls, []string{"/jwks", "/jwks-new"}) {
		t.Fatalf("key sets for %v", urls)
	}
	if _, errs := snapshot.CompileEnvelope(&env, h.s.cfg.Deployment); errs != nil {
		t.Fatal(expr.Issues(errs))
	}
}

// With the guard turned off, admin must still renew the canary lease, or
// edges drop the candidate after 10 minutes while admin shows it running.
func TestCanaryLeaseRenewsWithGuardOff(t *testing.T) {
	h, pub := published(t)
	g := defaultGuard()
	g.Enabled = false
	status(t, pub.do("PUT", "/api/settings/guard", g), 204)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	h.advance(9 * time.Minute)
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, _ := loadCanary(t.Context(), h.db)
	if !c.ExpiresAt.After(h.now().Add(9 * time.Minute)) {
		t.Fatalf("lease ends %v, now %v", c.ExpiresAt, h.now())
	}
}

// Guard runs early in the lease leave the snapshot unchanged, so edges
// polling during a canary get 304 instead of downloading and recompiling it.
func TestCanaryLeaseRenewalKeepsSnapshotTag(t *testing.T) {
	h, pub := published(t)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	e := h.client()
	e.token = h.edgeToken(pub)
	tag := e.do("GET", "/v1/snapshot", nil).Header.Get("ETag")
	h.advance(30 * time.Second)
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	status(t, e.do("GET", "/v1/snapshot", nil, "If-None-Match", tag), 304)
	// Past half the lease the guard renews it, and edges must see the new expiry.
	h.advance(5 * time.Minute)
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	env := decode[snapshot.Envelope](t, e.do("GET", "/v1/snapshot", nil, "If-None-Match", tag))
	// Postgres keeps microseconds, so the full lease is checked to within a second.
	if !env.CanaryExpiresAt.After(h.now().Add(canaryLease - time.Second)) {
		t.Fatalf("expiry %v, now %v", env.CanaryExpiresAt, h.now())
	}
}

// With guard ticks 6 minutes apart, waiting for half the lease to pass would
// let it lapse before the next tick, so every run renews. The tick is the
// leader's, which a later settings change does not reach.
func TestCanaryLeaseRenewsEveryRunWhenGuardIsSlow(t *testing.T) {
	h, pub := published(t)
	h.s.guardEvery.Store(int64(6 * time.Minute))
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.do("POST", "/api/publish", map[string]any{"message": "v2", "canary_percent": 10}, "If-Match", pub.revision()), 201)
	h.advance(time.Minute)
	if err := h.s.runGuard(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, _ := loadCanary(t.Context(), h.db)
	if !c.ExpiresAt.After(h.now().Add(canaryLease - time.Second)) {
		t.Fatalf("lease ends %v, now %v", c.ExpiresAt, h.now())
	}
}

// Reverting to an old version can be staged through a canary.
func TestRevertWithCanary(t *testing.T) {
	h, pub := published(t)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	h.user("eve", "editor")
	eve := h.signedIn("eve")
	status(t, eve.do("POST", "/api/versions/1/revert", map[string]any{"reason": "x", "canary_percent": 5}), 403)
	status(t, pub.do("POST", "/api/versions/1/revert", map[string]any{"reason": "back to v1, staged", "canary_percent": 5}), 201)
	v := decode[versionRow](t, pub.do("GET", "/api/versions/3", nil))
	if v.Status != "canary" || v.Source != "revert" || *v.BasedOn != 1 {
		t.Fatalf("version %+v", v)
	}
}

// A client that meant a canary but sent null, as the UI once did for "5%",
// must not publish to all traffic.
func TestCanaryPercentNull(t *testing.T) {
	h, pub := published(t)
	status(t, pub.save(pub.revision(), testConfig(), adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	before := h.actions()

	t.Run("a publish with canary_percent null is refused and nothing is published", func(t *testing.T) {
		c := testConfig()
		c.RateLimitRules[0].Limit = 8
		status(t, pub.save(pub.revision(), c, adminTest), 200)
		resp := pub.do("POST", "/api/publish", map[string]any{"message": "v3 on 5%", "canary_percent": nil}, "If-Match", pub.revision())
		if resp.StatusCode != 422 || !strings.Contains(body(resp), "left out for all traffic") {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("a revert with canary_percent null is refused and nothing is published", func(t *testing.T) {
		status(t, pub.do("POST", "/api/versions/1/revert", map[string]any{"reason": "back to v1, staged", "canary_percent": nil}), 422)
	})
	if list := decode[[]versionRow](t, pub.do("GET", "/api/versions", nil)); len(list) != 2 || list[0].Version != 2 || list[0].Status != "active" {
		t.Fatalf("versions %+v", list)
	}
	if got := h.actions(); slices.ContainsFunc(got[len(before):], func(a string) bool {
		return strings.HasPrefix(a, "config.publish") || strings.HasPrefix(a, "config.revert")
	}) {
		t.Fatalf("audit %v", got[len(before):])
	}
}
