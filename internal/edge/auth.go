package edge

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"hash/maphash"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/chrisleekr/edge-proxy/internal/jwks"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

const (
	// maxTokenBytes is Envoy jwt_authn's default jwt_max_token_size.
	maxTokenBytes = 4096
	// clockSkew is Envoy jwt_authn's default clock_skew_seconds.
	clockSkew = 60 * time.Second
	// tokenCacheTTL bounds how long a verified token skips its signature check.
	tokenCacheTTL = 10 * time.Minute
	jwksTimeout   = 5 * time.Second
)

// Variables so tests can shorten them.
var (
	jwksRefreshEvery   = 10 * time.Minute
	unknownKidInterval = 30 * time.Second
	unknownKidWait     = time.Second
	// jwksRoots is nil (the system pool) except in tests.
	jwksRoots *x509.CertPool
)

// authResult is what step 7 decided, for the access log and metrics.
type authResult uint8

const (
	authNone authResult = iota // auth is off for this request
	authVerified
	authCached
	authMissing
	authInvalid
	authPassNoKeys
	numAuthResults
)

var authNames = [numAuthResults]string{"", "verified", "cached", "missing", "invalid", "pass_no_keys"}

// keyGen numbers every key-set replacement across issuers, so a cached
// token verified with older keys never matches.
var keyGen atomic.Uint64

type keySet struct {
	set       *jwks.Set
	fetchedAt time.Time
	gen       uint64
}

// issuerKeys is one issuer's keys, shared by every snapshot that names the
// issuer with the same JWKS URL.
type issuerKeys struct {
	id, url string
	ks      *keyStore
	cur     atomic.Pointer[keySet] // nil until keys were ever obtained

	mu       sync.Mutex
	inflight chan struct{} // closed when the running fetch ends
	last     time.Time     // when the last fetch started
}

// offer installs set if it is newer than the current one. Keys are never
// cleared, only replaced by a newer good set.
func (k *issuerKeys) offer(set *jwks.Set, at time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if c := k.cur.Load(); c == nil || at.After(c.fetchedAt) {
		k.cur.Store(&keySet{set: set, fetchedAt: at, gen: keyGen.Add(1)})
	}
}

// refresh starts a fetch unless one is running or one started within
// unknownKidInterval. It returns a channel closed when the fetch ends, or
// nil when none runs. At most one fetch per issuer runs at a time.
func (k *issuerKeys) refresh(now time.Time) <-chan struct{} {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.inflight != nil {
		return k.inflight
	}
	if !k.last.IsZero() && now.Sub(k.last) < unknownKidInterval {
		return nil
	}
	k.last = now
	ch := make(chan struct{})
	k.inflight = ch
	go func() {
		defer func() {
			k.mu.Lock()
			k.inflight = nil
			k.mu.Unlock()
			close(ch)
		}()
		guard(k.ks.m, k.ks.log, "jwks", k.fetch)
	}()
	return ch
}

func (k *issuerKeys) fetch() {
	ctx, cancel := context.WithTimeout(context.Background(), jwksTimeout)
	defer cancel()
	b, err := k.ks.client.Fetch(ctx, k.url)
	var set *jwks.Set
	if err == nil {
		set, err = jwks.Parse(b)
	}
	if err != nil {
		k.ks.m.jwksErrors.Add(1)
		k.ks.log.Warn("jwks refresh failed; keeping current keys", "issuer", k.id, "error", err.Error())
		return
	}
	k.ks.m.jwksFetches.Add(1)
	k.offer(set, k.ks.now())
}

// keyStore holds keys apart from compiled config, so a snapshot swap never
// replaces newer keys the edge fetched itself.
type keyStore struct {
	client *jwks.Client
	m      *metrics
	log    *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	entries map[snapshot.KeySource]*issuerKeys
}

func newKeyStore(client *jwks.Client, m *metrics, log *slog.Logger) *keyStore {
	return &keyStore{client: client, m: m, log: log, now: time.Now, entries: map[snapshot.KeySource]*issuerKeys{}}
}

// entry returns the keys for is, first offering the snapshot's copy. Keys
// belong to a JWKS URL: when an issuer's URL changes it starts over.
func (s *keyStore) entry(is snapshot.Issuer, snap map[snapshot.KeySource]snapshot.Keys) *issuerKeys {
	id := snapshot.KeySource{IssuerID: is.ID, JWKSURL: is.JWKSURL}
	s.mu.Lock()
	k := s.entries[id]
	if k == nil {
		k = &issuerKeys{id: is.ID, url: is.JWKSURL, ks: s}
		s.entries[id] = k
	}
	s.mu.Unlock()
	if sk, ok := snap[id]; ok {
		k.offer(sk.Set, sk.FetchedAt)
	}
	return k
}

// retain drops keys no loaded version uses, so issuers removed by a
// publish don't accumulate.
func (s *keyStore) retain(ld *loaded) {
	keep := map[*issuerKeys]bool{}
	for _, v := range []*version{ld.active, ld.candidate} {
		if v != nil {
			for _, is := range v.issuers {
				keep[is.keys] = true
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, k := range s.entries {
		if !keep[k] {
			delete(s.entries, id)
		}
	}
}

// run refreshes every issuer's keys now and every jwksRefreshEvery.
func (s *keyStore) run(ctx context.Context) {
	t := time.NewTicker(jwksRefreshEvery)
	defer t.Stop()
	for {
		s.mu.Lock()
		all := make([]*issuerKeys, 0, len(s.entries))
		for _, k := range s.entries {
			all = append(all, k)
		}
		s.mu.Unlock()
		for _, k := range all {
			if ch := k.refresh(s.now()); ch != nil {
				select {
				case <-ch:
				case <-ctx.Done():
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// issuer is one configured issuer in a version. It is reused across
// versions while its config and keys are unchanged, so cached tokens stay
// valid through publishes that don't touch it.
type issuer struct {
	cfg    snapshot.Issuer
	keys   *issuerKeys
	parser *jwt.Parser
}

// compileIssuers maps each token iss to its issuer.
func compileIssuers(c *snapshot.Compiled, ks *keyStore, snap map[snapshot.KeySource]snapshot.Keys, prev *loaded) map[string]*issuer {
	out := map[string]*issuer{}
	for _, cfg := range c.Config.Auth.Issuers {
		is := &issuer{cfg: cfg, keys: ks.entry(cfg, snap)}
		if prev != nil {
			for _, pv := range []*version{prev.active, prev.candidate} {
				if pv != nil {
					if p := pv.issuers[cfg.Issuer]; p != nil && p.keys == is.keys && reflect.DeepEqual(p.cfg, cfg) {
						is = p
					}
				}
			}
		}
		if is.parser == nil {
			// Only the configured algorithm, iss and an accepted aud verify.
			// exp is required, so no token is valid forever.
			is.parser = jwt.NewParser(
				jwt.WithValidMethods([]string{cfg.Algorithm}), jwt.WithIssuer(cfg.Issuer),
				jwt.WithAudience(cfg.Audiences...), jwt.WithLeeway(clockSkew),
				jwt.WithExpirationRequired(), jwt.WithJSONNumber(),
			)
		}
		out[cfg.Issuer] = is
	}
	return out
}

// tokenEntry is a verified token. It counts only while its issuer and key
// generation are still current, so rotation or an issuer config change
// invalidates it.
type tokenEntry struct {
	iss    *issuer
	gen    uint64
	until  time.Time // min(exp + clock skew, verified + tokenCacheTTL)
	claims map[string][]string
	sub    string
}

type tokenShard struct {
	mu sync.RWMutex
	m  map[[32]byte]*tokenEntry
}

// tokenCache holds only verified tokens. When a shard is full new tokens
// are verified every time but not stored: evicting would let a flood of
// fresh tokens push out the ones real clients reuse.
type tokenCache struct {
	shards   [16]tokenShard
	perShard int
}

var tokenSeed = maphash.MakeSeed()

// newTokenCache holds up to size tokens (TOKEN_CACHE_SIZE).
func newTokenCache(size int) *tokenCache {
	c := &tokenCache{}
	c.perShard = max(size/len(c.shards), 1)
	for i := range c.shards {
		c.shards[i].m = map[[32]byte]*tokenEntry{}
	}
	return c
}

func (c *tokenCache) shard(h [32]byte) *tokenShard {
	return &c.shards[maphash.Bytes(tokenSeed, h[:])%uint64(len(c.shards))]
}

func (c *tokenCache) get(h [32]byte) *tokenEntry {
	s := c.shard(h)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[h]
}

func (c *tokenCache) put(h [32]byte, e *tokenEntry) {
	s := c.shard(h)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[h]; ok || len(s.m) < c.perShard {
		s.m[h] = e
	}
}

func (c *tokenCache) sweep(now time.Time) {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for h, e := range s.m {
			if !now.Before(e.until) {
				delete(s.m, h)
			}
		}
		s.mu.Unlock()
	}
}

// unverified reads iss and kid before the issuer is known. Nothing it
// returns is trusted beyond picking which issuer verifies the token.
var unverified = jwt.NewParser(jwt.WithJSONNumber())

// authenticate is step 7. It reports whether the request may
// continue; on false it has already answered 401.
func (e *Edge) authenticate(st *reqState, r *http.Request) bool {
	if st.set.authMode == "none" {
		return true
	}
	st.auth = e.verify(st, r)
	e.m.auth[st.auth].Add(1)
	switch st.auth {
	case authMissing:
		if st.set.authMode == "optional" {
			return true
		}
	case authInvalid:
	default:
		return true
	}
	e.reject(st, kUnauthorized, reasonAuth)
	return false
}

func (e *Edge) verify(st *reqState, r *http.Request) authResult {
	tok, present := bearer(r.Header)
	if !present {
		return authMissing
	}
	if tok == "" || len(tok) > maxTokenBytes {
		return authInvalid
	}
	now := e.now()
	h := sha256.Sum256([]byte(tok))
	if c := e.tokens.get(h); c != nil && c.iss == st.ver.issuers[c.iss.cfg.Issuer] && c.gen == c.iss.keys.cur.Load().gen && now.Before(c.until) {
		// A hit skips only the signature: this request's accepted list
		// still applies, and until already stops at exp.
		if !slices.Contains(st.set.accepted, c.iss.cfg.ID) {
			return authInvalid
		}
		st.setClaims(c.iss.cfg.ID, c.claims, c.sub)
		return authCached
	}

	t, _, err := unverified.ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		return authInvalid
	}
	iss, _ := t.Claims.(jwt.MapClaims)["iss"].(string)
	is := st.ver.issuers[iss]
	if is == nil || !slices.Contains(st.set.accepted, is.cfg.ID) {
		return authInvalid
	}
	ks := is.keys.cur.Load()
	if ks == nil {
		// No key was ever obtained: pass so an IdP outage at setup can't
		// take the site down; upstreams still validate.
		is.keys.refresh(now)
		return authPassNoKeys
	}
	kid, _ := t.Header["kid"].(string)
	key, ok := ks.set.Lookup(kid, is.cfg.Algorithm)
	if !ok {
		// An unknown kid usually means the IdP rotated keys. Only requests
		// carrying it wait, and only briefly.
		if ch := is.keys.refresh(now); ch != nil {
			timer := time.NewTimer(unknownKidWait)
			select {
			case <-ch:
			case <-timer.C:
			case <-r.Context().Done():
			}
			timer.Stop()
		}
		ks = is.keys.cur.Load()
		if key, ok = ks.set.Lookup(kid, is.cfg.Algorithm); !ok {
			return authInvalid
		}
	}
	mc := jwt.MapClaims{}
	if _, err := is.parser.ParseWithClaims(tok, mc, func(*jwt.Token) (any, error) { return key, nil }); err != nil {
		return authInvalid
	}
	exp, _ := mc.GetExpirationTime() // required by the parser, so present
	claims := flatten(mc)
	sub := ""
	if s := claims["sub"]; len(s) > 0 {
		sub = s[0]
	}
	e.tokens.put(h, &tokenEntry{iss: is, gen: ks.gen, until: minTime(exp.Add(clockSkew), now.Add(tokenCacheTTL)), claims: claims, sub: sub})
	st.setClaims(is.cfg.ID, claims, sub)
	return authVerified
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (st *reqState) setClaims(issuerID string, claims map[string][]string, sub string) {
	st.fields.claims, st.authIssuer, st.authSub = claims, issuerID, sub
}

// bearer reads an RFC 6750 §2.1 token. Another scheme counts as no token.
// More than one Authorization header is ambiguous and yields an empty
// token, which is invalid.
func bearer(h http.Header) (string, bool) {
	vs := h["Authorization"]
	switch {
	case len(vs) == 0:
		return "", false
	case len(vs) > 1:
		return "", true
	}
	v := vs[0]
	// The scheme is case-insensitive (RFC 9110 §11.1).
	if len(v) < 7 || !strings.EqualFold(v[:7], "Bearer ") {
		return "", false
	}
	return strings.TrimSpace(v[7:]), true
}

// flatten turns claims into string lists for expressions, keys and
// placeholders. Objects and nulls have no string form and are left out.
func flatten(mc jwt.MapClaims) map[string][]string {
	out := make(map[string][]string, len(mc))
	for k, v := range mc {
		if list, ok := v.([]any); ok {
			for _, x := range list {
				if s, ok := scalar(x); ok {
					out[k] = append(out[k], s)
				}
			}
		} else if s, ok := scalar(v); ok {
			out[k] = []string{s}
		}
	}
	return out
}

func scalar(v any) (string, bool) {
	switch v := v.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}
