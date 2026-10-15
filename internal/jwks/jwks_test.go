package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

var (
	rsaKey  = must(rsa.GenerateKey(rand.Reader, 2048))
	p256Key = must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	p384Key = must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	p521Key = must(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
	edPub   = must(ed25519.GenerateKey(rand.Reader))
)

func must[T any](v T, _ ...any) T { return v }

func mkJWK(kid string, pub any, extra ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	return testenv.JWK(kid, pub, m)
}

// A typical IdP set: signing keys of every supported type, which all load.
func TestParseLoadsEverySupportedKeyType(t *testing.T) {
	s, err := Parse(testenv.JWKS(
		mkJWK("rsa", &rsaKey.PublicKey, "use", "sig", "alg", "RS256"),
		mkJWK("p256", &p256Key.PublicKey),
		mkJWK("p384", &p384Key.PublicKey),
		mkJWK("p521", &p521Key.PublicKey),
		mkJWK("ed", edPub),
	))
	if err != nil || s.Len() != 5 {
		t.Fatalf("Parse = %v, %v", s, err)
	}
}

// Keys this edge can't verify with are skipped, so one odd key never
// discards an IdP's whole set.
func TestParseSkipsUnusableKeys(t *testing.T) {
	small := must(rsa.GenerateKey(rand.Reader, 1024))
	offCurve := mkJWK("off", &p256Key.PublicKey)
	offCurve["y"] = offCurve["x"]
	cases := []struct {
		name string
		key  any
	}{
		{"encryption key", mkJWK("x", &rsaKey.PublicKey, "use", "enc")},
		{"symmetric key", map[string]string{"kty": "oct", "kid": "x", "k": "c2VjcmV0"}},
		{"RSA key under 2048 bits", mkJWK("x", &small.PublicKey)},
		{"RSA key with an even exponent", mkJWK("x", &rsaKey.PublicKey, "e", "Ag")},
		{"RSA key with a padded modulus", mkJWK("x", &rsaKey.PublicKey, "n", "AAAA"+mkJWK("", &rsaKey.PublicKey)["n"])},
		{"RSA modulus that isn't base64url", mkJWK("x", &rsaKey.PublicKey, "n", "not base64!")},
		{"EC point not on the curve", offCurve},
		{"EC coordinate shorter than the curve", mkJWK("x", &p256Key.PublicKey, "x", "AQ")},
		{"EC curve the edge doesn't support", mkJWK("x", &p256Key.PublicKey, "crv", "secp256k1")},
		{"Ed448 key", mkJWK("x", edPub, "crv", "Ed448")},
		{"entry that isn't an object", "rsa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(map[string]any{"keys": []any{tc.key, mkJWK("good", edPub)}})
			s, err := Parse(b)
			if err != nil || s.Len() != 1 {
				t.Fatalf("Parse = %v, %v; want only the good key", s, err)
			}
			if _, ok := s.Lookup("good", "EdDSA"); !ok {
				t.Fatal("good key missing")
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		msg  string
	}{
		{"no usable key", testenv.JWKS(mkJWK("x", &rsaKey.PublicKey, "use", "enc")), "no usable signing key"},
		{"empty set", []byte(`{"keys":[]}`), "no usable signing key"},
		{"HTML error page", []byte(`<html>`), "jwks:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.body); err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v, want %q", err, tc.msg)
			}
		})
	}
}

// The first key with a kid is the one used; a later duplicate can't shadow it.
func TestParseKeepsFirstDuplicateKid(t *testing.T) {
	s, _ := Parse(testenv.JWKS(mkJWK("k", edPub), mkJWK("k", &rsaKey.PublicKey)))
	if _, ok := s.Lookup("k", "EdDSA"); !ok || s.Len() != 1 {
		t.Fatal("first key not kept")
	}
}

// Lookup returns a key only for the algorithm it can verify, which blocks
// algorithm confusion inside one set.
func TestLookup(t *testing.T) {
	s, err := Parse(testenv.JWKS(
		mkJWK("rsa", &rsaKey.PublicKey),
		mkJWK("rs512", &rsaKey.PublicKey, "alg", "RS512"),
		mkJWK("p256", &p256Key.PublicKey),
		mkJWK("p384", &p384Key.PublicKey),
		mkJWK("p521", &p521Key.PublicKey),
		mkJWK("ed", edPub),
	))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, kid, alg string
		ok             bool
	}{
		{"RSA key verifies RS256", "rsa", "RS256", true},
		{"RSA key verifies PS256", "rsa", "PS256", true},
		{"P-256 key verifies ES256", "p256", "ES256", true},
		{"P-384 key verifies ES384", "p384", "ES384", true},
		{"P-521 key verifies ES512", "p521", "ES512", true},
		{"Ed25519 key verifies EdDSA", "ed", "EdDSA", true},
		{"RSA key refuses ES256", "rsa", "ES256", false},
		{"P-384 key refuses ES256", "p384", "ES256", false},
		{"P-256 key refuses RS256", "p256", "RS256", false},
		{"Ed25519 key refuses RS256", "ed", "RS256", false},
		{"key pinned to RS512 refuses RS256", "rs512", "RS256", false},
		{"key pinned to RS512 verifies RS512", "rs512", "RS512", true},
		{"unknown kid", "other", "RS256", false},
		{"token without kid against several keys", "", "RS256", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := s.Lookup(tc.kid, tc.alg); ok != tc.ok {
				t.Fatalf("Lookup(%q, %q) = %v", tc.kid, tc.alg, ok)
			}
		})
	}
}

// IdPs with a single key often issue tokens without a kid.
func TestLookupWithoutKidUsesTheOnlyKey(t *testing.T) {
	s, _ := Parse(testenv.JWKS(mkJWK("k", edPub)))
	if _, ok := s.Lookup("", "EdDSA"); !ok {
		t.Fatal("single key not used for a token without kid")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(testenv.JWKS(mkJWK("rsa", &rsaKey.PublicKey), mkJWK("p256", &p256Key.PublicKey), mkJWK("ed", edPub)))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-521","x":"","y":""},{"kty":"RSA","n":"AQ","e":"AQAB"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := Parse(b)
		if err != nil {
			return
		}
		for _, alg := range []string{"RS256", "PS512", "ES256", "ES384", "ES512", "EdDSA"} {
			s.Lookup("", alg)
		}
	})
}
