package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

var (
	corpKey         = mustKey(rsa.GenerateKey(rand.Reader, 2048))
	corpKey2        = mustKey(rsa.GenerateKey(rand.Reader, 2048))
	partnerKey      = mustKey(rsa.GenerateKey(rand.Reader, 2048))
	edPub, edKey, _ = ed25519.GenerateKey(rand.Reader)
)

func mustKey(k *rsa.PrivateKey, err error) *rsa.PrivateKey {
	if err != nil {
		panic(err)
	}
	return k
}

// fakeIdP serves each issuer's JWKS over TLS, like a real IdP, and counts fetches.
type fakeIdP struct {
	srv     *httptest.Server
	mu      sync.Mutex
	bodies  map[string][]byte // by path; absent is a 500
	fetches map[string]int
	delay   time.Duration
	block   chan struct{} // when set, requests wait for it to close
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	p := &fakeIdP{bodies: map[string][]byte{}, fetches: map[string]int{}}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.fetches[r.URL.Path]++
		body, ok := p.bodies[r.URL.Path]
		delay, block := p.delay, p.block
		p.mu.Unlock()
		time.Sleep(delay)
		if block != nil {
			<-block
		}
		if !ok {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(p.srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(p.srv.Certificate())
	old := jwksRoots
	jwksRoots = roots
	t.Cleanup(func() { jwksRoots = old })
	return p
}

func (p *fakeIdP) serve(path string, keys ...map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if keys == nil {
		delete(p.bodies, path)
		return
	}
	p.bodies[path] = testenv.JWKS(keys...)
}

func (p *fakeIdP) count(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fetches[path]
}

// authConfig: /private needs a corp token, /partner a partner token, /ed an
// ed token, /optional takes a corp token if one is sent. A header rule
// copies the verified tenant claim upstream.
func authConfig(idp *fakeIdP) *snapshot.Config {
	c := testConfig(1)
	c.Auth = snapshot.Auth{
		Issuers: []snapshot.Issuer{
			{ID: "corp", Issuer: "https://auth.example.com/", Audiences: []string{"api"}, JWKSURL: idp.srv.URL + "/corp", Algorithm: "RS256"},
			{ID: "partner", Issuer: "https://partner.example.com/", Audiences: []string{"api"}, JWKSURL: idp.srv.URL + "/partner", Algorithm: "RS256"},
			{ID: "ed", Issuer: "https://ed.example.com/", Audiences: []string{"api"}, JWKSURL: idp.srv.URL + "/ed", Algorithm: "EdDSA"},
		},
		DefaultAccepted: []string{"corp"},
	}
	rule := func(id, prefix, mode string, accepted ...string) snapshot.ConfigRule {
		return snapshot.ConfigRule{ID: id, Expression: mustParse(`starts_with(http.request.uri.path, "` + prefix + `")`),
			Settings: snapshot.Settings{Auth: &snapshot.AuthSetting{Mode: mode, Accepted: accepted}}}
	}
	c.ConfigRules = append(c.ConfigRules,
		rule("private", "/private", "required"),
		rule("partner", "/partner", "required", "partner"),
		rule("ed", "/ed", "required", "ed"),
		rule("optional", "/optional", "optional"),
	)
	c.RequestHeaderRules = []snapshot.HeaderRule{{ID: "tenant", Expression: mustParse(`http.request.jwt.claims["tenant"] ne ""`),
		Ops: []snapshot.HeaderOp{{Op: "set", Name: "X-Tenant", Value: "{{jwt_claim:tenant}}"}}}}
	return c
}

// keysFetchedAt is when admin fetched its copy of the keys. It is fixed, as
// in admin, so republishing doesn't make the copy look newer.
var keysFetchedAt = time.Now().Add(-time.Hour)

// authEnvelope carries admin's copy of the corp and partner keys.
func authEnvelope(c *snapshot.Config) *snapshot.Envelope {
	e := envelope(c)
	at := keysFetchedAt
	keys := map[string][]byte{
		"corp":    testenv.JWKS(testenv.JWK("k1", &corpKey.PublicKey, nil)),
		"partner": testenv.JWKS(testenv.JWK("p1", &partnerKey.PublicKey, nil)),
	}
	for _, is := range c.Auth.Issuers {
		if k := keys[is.ID]; k != nil {
			e.Keys = append(e.Keys, snapshot.IssuerKeys{IssuerID: is.ID, JWKSURL: is.JWKSURL, FetchedAt: at, JWKS: k})
		}
	}
	return e
}

// A canary that moves an issuer to a new JWKS URL carries admin's keys for
// both URLs. Each version verifies with its own URL's keys, even while the
// IdP is down and the edge can't fetch either.
func TestCanaryMovingAnIssuerKeepsEachVersionsKeys(t *testing.T) {
	h, idp := newAuthHarness(t)
	cand := authConfig(idp)
	cand.Version = 2
	cand.Auth.Issuers[0].JWKSURL = idp.srv.URL + "/corp-new"
	e := authEnvelope(authConfig(idp))
	e.Candidate, e.CanaryPercent, e.CanaryExpiresAt = cand, 50, time.Now().Add(time.Hour)
	// Admin fetched the new URL after the old one.
	e.Keys = append(e.Keys, snapshot.IssuerKeys{IssuerID: "corp", JWKSURL: cand.Auth.Issuers[0].JWKSURL, FetchedAt: time.Now(),
		JWKS: testenv.JWKS(testenv.JWK("k2", &corpKey2.PublicKey, nil))})
	h.load(e)

	in, out := ipWithCohort(t, true, 5000), ipWithCohort(t, false, 5000)
	if readBody(t, h.do("GET", "/private/x", nil, append(bearerOf(corpToken()), "CloudFront-Viewer-Address", out+":1")...)) != "upstream ok" {
		t.Fatal("active version lost the old URL's keys")
	}
	moved := mint(jwt.SigningMethodRS256, "k2", corpKey2, corpClaims())
	if readBody(t, h.do("GET", "/private/x", nil, append(bearerOf(moved), "CloudFront-Viewer-Address", in+":1")...)) != "upstream ok" {
		t.Fatal("candidate didn't get the new URL's keys")
	}
	if idp.count("/corp")+idp.count("/corp-new") != 0 {
		t.Fatal("keys admin sent were fetched again")
	}
}

func newAuthHarness(t *testing.T) (*harness, *fakeIdP) {
	t.Helper()
	idp := newFakeIdP(t)
	h := newHarness(t, map[string]string{"JWKS_ALLOWED_HOSTS": "127.0.0.1"})
	h.load(authEnvelope(authConfig(idp)))
	return h, idp
}

func corpClaims() jwt.MapClaims {
	return jwt.MapClaims{"iss": "https://auth.example.com/", "aud": "api", "sub": "user-1", "tenant": "acme", "exp": time.Now().Add(time.Hour).Unix()}
}

func mint(method jwt.SigningMethod, kid string, key any, claims jwt.MapClaims) string {
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		panic(err)
	}
	return s
}

func corpToken() string { return mint(jwt.SigningMethodRS256, "k1", corpKey, corpClaims()) }

func bearerOf(tok string) []string { return []string{"Authorization", "Bearer " + tok} }

// unauthorized checks a 401 and its RFC 6750 challenge.
func unauthorized(t *testing.T, resp *http.Response, challenge string) {
	t.Helper()
	if got := resp.Header.Get("WWW-Authenticate"); got != challenge {
		t.Errorf("WWW-Authenticate = %q, want %q", got, challenge)
	}
	edgeError(t, resp, 401, "unauthorized")
}

func (h *harness) upstreamHeader(name string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastApp.Header.Get(name)
}

func TestValidTokenReachesUpstreamWithIdentity(t *testing.T) {
	h, _ := newAuthHarness(t)
	tok := corpToken()
	for _, want := range []authResult{authVerified, authCached} {
		if body := readBody(t, h.do("GET", "/private/orders", nil, bearerOf(tok)...)); body != "upstream ok" {
			t.Fatalf("body %q", body)
		}
		if h.upstreamHeader("X-Edge-Auth-Issuer") != "corp" || h.upstreamHeader("X-Edge-Auth-Sub") != "user-1" || h.upstreamHeader("X-Tenant") != "acme" {
			t.Fatalf("upstream headers %v", h.lastApp.Header)
		}
		if h.srv.m.auth[want].Load() != 1 {
			t.Fatalf("%s count = %d", authNames[want], h.srv.m.auth[want].Load())
		}
	}
	// The upstream still gets the token to validate itself.
	if h.upstreamHeader("Authorization") != "Bearer "+tok {
		t.Fatal("Authorization not forwarded")
	}
}

// A client can't forge the identity headers the edge sets after verifying.
func TestForgedAuthHeadersNeverReachUpstream(t *testing.T) {
	h, _ := newAuthHarness(t)
	readBody(t, h.do("GET", "/optional", nil, "X-Edge-Auth-Sub", "admin", "X-Edge-Auth-Issuer", "corp"))
	if h.upstreamHeader("X-Edge-Auth-Sub") != "" || h.upstreamHeader("X-Edge-Auth-Issuer") != "" {
		t.Fatalf("forged identity forwarded: %v", h.lastApp.Header)
	}
}

func TestMissingToken(t *testing.T) {
	h, _ := newAuthHarness(t)
	t.Run("required path answers 401 with a bare challenge", func(t *testing.T) {
		unauthorized(t, h.do("GET", "/private/x", nil), "Bearer")
	})
	t.Run("another scheme counts as no token", func(t *testing.T) {
		unauthorized(t, h.do("GET", "/private/x", nil, "Authorization", "Basic dXNlcjpwYXNz"), "Bearer")
	})
	t.Run("optional path passes without identity", func(t *testing.T) {
		if readBody(t, h.do("GET", "/optional", nil)) != "upstream ok" || h.upstreamHeader("X-Edge-Auth-Issuer") != "" {
			t.Fatal("optional request without token not passed plainly")
		}
	})
	t.Run("path without auth ignores tokens", func(t *testing.T) {
		if readBody(t, h.do("GET", "/public", nil, bearerOf("garbage")...)) != "upstream ok" || h.upstreamHeader("X-Edge-Auth-Issuer") != "" {
			t.Fatal("public request changed by a token")
		}
	})
}

func TestInvalidTokensAreRejected(t *testing.T) {
	h, _ := newAuthHarness(t)
	with := func(change func(c jwt.MapClaims)) jwt.MapClaims {
		c := corpClaims()
		change(c)
		return c
	}
	now := time.Now()
	cases := []struct {
		name, path, token string
	}{
		{"expired beyond the clock skew", "/private", mint(jwt.SigningMethodRS256, "k1", corpKey, with(func(c jwt.MapClaims) { c["exp"] = now.Add(-2 * time.Minute).Unix() }))},
		{"not valid yet", "/private", mint(jwt.SigningMethodRS256, "k1", corpKey, with(func(c jwt.MapClaims) { c["nbf"] = now.Add(2 * time.Minute).Unix() }))},
		{"no expiry", "/private", mint(jwt.SigningMethodRS256, "k1", corpKey, with(func(c jwt.MapClaims) { delete(c, "exp") }))},
		{"another audience", "/private", mint(jwt.SigningMethodRS256, "k1", corpKey, with(func(c jwt.MapClaims) { c["aud"] = "billing" }))},
		{"unknown issuer", "/private", mint(jwt.SigningMethodRS256, "k1", corpKey, with(func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com/" }))},
		{"issuer not accepted on this path", "/private", mint(jwt.SigningMethodRS256, "p1", partnerKey, with(func(c jwt.MapClaims) { c["iss"] = "https://partner.example.com/" }))},
		{"signed by another key under a known kid", "/private", mint(jwt.SigningMethodRS256, "k1", partnerKey, corpClaims())},
		// Algorithm confusion: HMAC keyed with the public key's bytes.
		{"HS256 keyed with the RSA public key", "/private", mint(jwt.SigningMethodHS256, "k1", x509.MarshalPKCS1PublicKey(&corpKey.PublicKey), corpClaims())},
		{"alg none", "/private", mint(jwt.SigningMethodNone, "k1", jwt.UnsafeAllowNoneSignatureType, corpClaims())},
		// Cross-issuer key use: partner's key and kid with corp's iss.
		{"another issuer's key", "/private", mint(jwt.SigningMethodRS256, "p1", partnerKey, corpClaims())},
		{"not a JWT", "/private", "abc.def"},
		{"over 4096 bytes", "/private", mint(jwt.SigningMethodRS256, "k1", corpKey, with(func(c jwt.MapClaims) { c["pad"] = strings.Repeat("x", maxTokenBytes) }))},
		{"invalid token on an optional path", "/optional", mint(jwt.SigningMethodRS256, "k1", corpKey, with(func(c jwt.MapClaims) { c["aud"] = "billing" }))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.lastApp = nil
			unauthorized(t, h.do("GET", tc.path, nil, bearerOf(tc.token)...), `Bearer error="invalid_token"`)
			if h.lastApp != nil {
				t.Fatal("reached the upstream")
			}
		})
	}
}

// Two Authorization headers are ambiguous: neither is trusted.
func TestTwoAuthorizationHeadersAreRejected(t *testing.T) {
	h, _ := newAuthHarness(t)
	req, _ := http.NewRequest("GET", h.front.URL+"/private/x", nil)
	req.Host = "api.example.com"
	req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:40000")
	req.Header.Add("Authorization", "Bearer "+corpToken())
	req.Header.Add("Authorization", "Bearer other")
	resp, err := h.front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized(t, resp, `Bearer error="invalid_token"`)
}

// The access log records what step 7 decided.
func TestAuthDecisionIsLogged(t *testing.T) {
	h, _ := newAuthHarness(t)
	readBody(t, h.do("GET", "/private/x", nil, bearerOf(corpToken())...))
	unauthorized(t, h.do("GET", "/private/x", nil), "Bearer")
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 2 })
	got := []any{h.logs.lines("access")[0]["edge.auth"], h.logs.lines("access")[1]["edge.auth"]}
	if !reflect.DeepEqual(got, []any{"verified", "missing"}) {
		t.Fatalf("edge.auth = %v", got)
	}
}

// The IdP rotates to a new key: the first token with its kid makes the edge
// fetch once, and tokens signed with the removed key stop verifying.
func TestKeyRotation(t *testing.T) {
	h, idp := newAuthHarness(t)
	old := corpToken()
	readBody(t, h.do("GET", "/private/x", nil, bearerOf(old)...)) // cached under the old keys

	idp.serve("/corp", testenv.JWK("k2", &corpKey2.PublicKey, nil))
	rotated := mint(jwt.SigningMethodRS256, "k2", corpKey2, corpClaims())
	if readBody(t, h.do("GET", "/private/x", nil, bearerOf(rotated)...)) != "upstream ok" || idp.count("/corp") != 1 {
		t.Fatalf("rotated token not verified after one fetch (fetches %d)", idp.count("/corp"))
	}
	unauthorized(t, h.do("GET", "/private/x", nil, bearerOf(old)...), `Bearer error="invalid_token"`)
	if idp.count("/corp") != 1 {
		t.Fatal("a second unknown kid within 30s fetched again")
	}
	// Admin's older copy can't bring the removed key back.
	h.load(authEnvelope(authConfig(idp)))
	unauthorized(t, h.do("GET", "/private/x", nil, bearerOf(old)...), `Bearer error="invalid_token"`)
	if readBody(t, h.do("GET", "/private/x", nil, bearerOf(rotated)...)) != "upstream ok" {
		t.Fatal("edge-fetched keys replaced by an older snapshot")
	}
	// A newer snapshot copy does replace them.
	e := authEnvelope(authConfig(idp))
	e.Keys[0].FetchedAt, e.Keys[0].JWKS = time.Now().Add(time.Hour), testenv.JWKS(testenv.JWK("k1", &corpKey.PublicKey, nil))
	h.load(e)
	if readBody(t, h.do("GET", "/private/x", nil, bearerOf(old)...)) != "upstream ok" {
		t.Fatal("newer snapshot keys not used")
	}
}

// Concurrent requests carrying one new kid share a single fetch.
func TestUnknownKidFetchIsShared(t *testing.T) {
	h, idp := newAuthHarness(t)
	idp.mu.Lock()
	idp.delay = 100 * time.Millisecond
	idp.mu.Unlock()
	idp.serve("/corp", testenv.JWK("k2", &corpKey2.PublicKey, nil))
	tok := mint(jwt.SigningMethodRS256, "k2", corpKey2, corpClaims())
	var wg sync.WaitGroup
	bodies := make([]string, 5)
	for i := range bodies {
		wg.Go(func() { bodies[i] = readBody(t, h.do("GET", "/private/x", nil, bearerOf(tok)...)) })
	}
	wg.Wait()
	for _, b := range bodies {
		if b != "upstream ok" {
			t.Fatalf("bodies %q", bodies)
		}
	}
	if n := idp.count("/corp"); n != 1 {
		t.Fatalf("%d fetches for one new kid", n)
	}
}

// An unknown kid waits for the fetch only up to unknownKidWait.
func TestUnknownKidWaitIsBounded(t *testing.T) {
	h, idp := newAuthHarness(t)
	old := unknownKidWait
	unknownKidWait = 50 * time.Millisecond
	t.Cleanup(func() { unknownKidWait = old })
	idp.mu.Lock()
	idp.delay = 300 * time.Millisecond
	idp.mu.Unlock()
	idp.serve("/corp", testenv.JWK("k2", &corpKey2.PublicKey, nil))
	start := time.Now()
	unauthorized(t, h.do("GET", "/private/x", nil, bearerOf(mint(jwt.SigningMethodRS256, "k2", corpKey2, corpClaims()))...), `Bearer error="invalid_token"`)
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("request waited %v", d)
	}
}

// No key was ever obtained for an issuer: its tokens pass without identity,
// so an IdP down at setup doesn't take the path down.
func TestNoKeysEverPasses(t *testing.T) {
	h, idp := newAuthHarness(t)
	old := unknownKidInterval
	unknownKidInterval = 0
	t.Cleanup(func() { unknownKidInterval = old })
	tok := mint(jwt.SigningMethodEdDSA, "e1", edKey, jwt.MapClaims{"iss": "https://ed.example.com/", "aud": "api", "sub": "u", "exp": time.Now().Add(time.Minute).Unix()})
	if readBody(t, h.do("GET", "/ed/x", nil, bearerOf(tok)...)) != "upstream ok" || h.upstreamHeader("X-Edge-Auth-Issuer") != "" {
		t.Fatal("token for an issuer without keys not passed plainly")
	}
	if h.srv.m.auth[authPassNoKeys].Load() != 1 {
		t.Fatal("pass_no_keys not counted")
	}
	// The edge tried to fetch, failed and logged it.
	keys := h.srv.store.load().active.issuers["https://ed.example.com/"].keys
	waitFor(t, func() bool { return idle(keys) && len(h.logs.lines("jwks refresh failed; keeping current keys")) == 1 })

	// Once the IdP serves keys, the issuer is enforced.
	idp.serve("/ed", testenv.JWK("e1", edPub, nil))
	readBody(t, h.do("GET", "/ed/x", nil, bearerOf(tok)...))
	waitFor(t, func() bool { return h.srv.m.jwksFetches.Load() == 1 })
	if readBody(t, h.do("GET", "/ed/x", nil, bearerOf(tok)...)) != "upstream ok" || h.upstreamHeader("X-Edge-Auth-Issuer") != "ed" {
		t.Fatal("token not verified once keys exist")
	}
	unauthorized(t, h.do("GET", "/ed/x", nil, bearerOf(mint(jwt.SigningMethodRS256, "e1", corpKey, corpClaims()))...), `Bearer error="invalid_token"`)
}

// A JWKS without a usable key is a failed fetch: current keys stay.
func TestUnusableJWKSKeepsKeys(t *testing.T) {
	h, idp := newAuthHarness(t)
	idp.serve("/corp", testenv.JWK("k2", &corpKey2.PublicKey, map[string]string{"use": "enc"}))
	unauthorized(t, h.do("GET", "/private/x", nil, bearerOf(mint(jwt.SigningMethodRS256, "k2", corpKey2, corpClaims()))...), `Bearer error="invalid_token"`)
	if h.srv.m.jwksErrors.Load() != 1 || readBody(t, h.do("GET", "/private/x", nil, bearerOf(corpToken())...)) != "upstream ok" {
		t.Fatal("unusable JWKS replaced the keys")
	}
}

// A cached token is checked against this request's accepted issuers and
// against the issuer config it was verified under.
func TestTokenCacheFollowsConfig(t *testing.T) {
	h, idp := newAuthHarness(t)
	tok := corpToken()
	readBody(t, h.do("GET", "/private/x", nil, bearerOf(tok)...))
	unauthorized(t, h.do("GET", "/partner/x", nil, bearerOf(tok)...), `Bearer error="invalid_token"`)

	// A publish that doesn't touch the issuer keeps the cache.
	c := authConfig(idp)
	c.Version = 2
	h.load(authEnvelope(c))
	readBody(t, h.do("GET", "/private/x", nil, bearerOf(tok)...))
	if h.srv.m.auth[authCached].Load() != 1 {
		t.Fatalf("cached = %d after an unrelated publish", h.srv.m.auth[authCached].Load())
	}
	// Changing the issuer's audiences re-verifies, and the token now fails.
	c = authConfig(idp)
	c.Version = 3
	c.Auth.Issuers[0].Audiences = []string{"billing"}
	h.load(authEnvelope(c))
	unauthorized(t, h.do("GET", "/private/x", nil, bearerOf(tok)...), `Bearer error="invalid_token"`)
}

// Removing an issuer drops its keys from the store.
func TestRemovedIssuerKeysAreDropped(t *testing.T) {
	h, idp := newAuthHarness(t)
	c := authConfig(idp)
	c.Version = 2
	c.Auth.Issuers = c.Auth.Issuers[:1]
	c.ConfigRules = append(c.ConfigRules[:3], c.ConfigRules[5]) // drop the partner and ed rules
	h.load(authEnvelope(c))
	if n := len(h.srv.poller.keys.entries); n != 1 {
		t.Fatalf("store holds %d issuers", n)
	}
}

func TestKillSwitchSkipsVerification(t *testing.T) {
	h, idp := newAuthHarness(t)
	c := authConfig(idp)
	c.KillSwitch.Auth = true
	h.load(authEnvelope(c))
	if readBody(t, h.do("GET", "/private/x", nil, bearerOf(corpToken())...)) != "upstream ok" || h.upstreamHeader("X-Edge-Auth-Issuer") != "" || h.upstreamHeader("X-Tenant") != "" {
		t.Fatal("kill switch did not turn verification off")
	}
}

// The background loop refreshes every issuer at start and on its interval,
// and stops when the edge does, even mid-fetch.
func TestBackgroundRefresh(t *testing.T) {
	h, idp := newAuthHarness(t)
	oldEvery, oldGap := jwksRefreshEvery, unknownKidInterval
	jwksRefreshEvery, unknownKidInterval = 20*time.Millisecond, 0
	t.Cleanup(func() { jwksRefreshEvery, unknownKidInterval = oldEvery, oldGap })
	idp.serve("/corp", testenv.JWK("k1", &corpKey.PublicKey, nil))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { h.srv.poller.keys.run(ctx); close(done) }()
	waitFor(t, func() bool { return idp.count("/corp") >= 2 && idp.count("/partner") >= 2 && idp.count("/ed") >= 2 })
	cancel()
	<-done

	before := idp.count("/corp") + idp.count("/partner") + idp.count("/ed")
	block := make(chan struct{})
	idp.mu.Lock()
	idp.block = block
	idp.mu.Unlock()
	ctx, cancel = context.WithCancel(t.Context())
	done = make(chan struct{})
	go func() { h.srv.poller.keys.run(ctx); close(done) }()
	waitFor(t, func() bool { return idp.count("/corp")+idp.count("/partner")+idp.count("/ed") > before })
	cancel()
	<-done
	close(block)
}

// Claims become string lists: arrays per element, numbers exactly as sent;
// objects and nulls have no string form.
func TestFlattenClaims(t *testing.T) {
	var mc jwt.MapClaims
	dec := json.NewDecoder(strings.NewReader(`{"sub":"u","roles":["a","b",{"x":1},2],"n":12345678901234567890,"admin":true,"obj":{"a":1},"none":null}`))
	dec.UseNumber()
	if err := dec.Decode(&mc); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"sub": {"u"}, "roles": {"a", "b", "2"}, "n": {"12345678901234567890"}, "admin": {"true"}}
	if got := flatten(mc); !reflect.DeepEqual(got, want) {
		t.Fatalf("flatten = %v", got)
	}
}

// The verified-token cache holds at most TOKEN_CACHE_SIZE tokens and sweeps
// expired ones.
func TestTokenCacheBound(t *testing.T) {
	const maxTokenCache = 1_600
	c := newTokenCache(maxTokenCache)
	now := time.Now()
	for i := range 2 * maxTokenCache {
		var h [32]byte
		h[0], h[1], h[2] = byte(i), byte(i>>8), byte(i>>16)
		c.put(h, &tokenEntry{until: now.Add(time.Duration(i%2) * time.Hour)})
	}
	n := 0
	for i := range c.shards {
		n += len(c.shards[i].m)
	}
	if n > maxTokenCache || n < maxTokenCache/2 {
		t.Fatalf("cache holds %d, bound %d", n, maxTokenCache)
	}
	c.sweep(now)
	left := 0
	for i := range c.shards {
		left += len(c.shards[i].m)
		for _, e := range c.shards[i].m {
			if !e.until.After(now) {
				t.Fatal("expired token kept")
			}
		}
	}
	if left == 0 || left == n {
		t.Fatalf("sweep left %d of %d", left, n)
	}
}

// idle reports that no fetch is running for k.
func idle(k *issuerKeys) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.inflight == nil
}
