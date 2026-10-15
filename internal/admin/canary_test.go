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
	status(t, pub.do("POST", "/api/canary/abort", map[string]string{}), 422)
	status(t, pub.do("POST", "/api/canary/abort", map[string]string{"reason": "errors on checkout"}), 204)
	if v := decode[versionRow](t, pub.do("GET", "/api/versions/2", nil)); v.Status != "rolled_back" {
		t.Fatalf("status %s", v.Status)
	}
	if c := decode[map[string]*canaryRow](t, pub.do("GET", "/api/canary", nil)); c["canary"] != nil {
		t.Fatal("canary still running")
	}
	// The draft was based on the aborted candidate, so it must rebase.
	status(t, pub.publishDraft("again"), 409)
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
