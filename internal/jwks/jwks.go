// Package jwks parses JSON Web Key Sets and fetches them behind an SSRF guard.
// Admin and edge share it, so both accept exactly the same keys.
package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// MaxBytes caps a JWKS document.
const MaxBytes = 64 << 10

// minRSABits follows RFC 7518 §3.3: RS* and PS* keys MUST be 2048 bits or larger.
const minRSABits = 2048

// Set is a parsed key set: every usable signing key by kid.
type Set struct{ keys map[string]key }

type key struct {
	pub any    // *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey
	alg string // the JWK's own "alg", "" when absent
}

// Len counts the usable keys.
func (s *Set) Len() int { return len(s.keys) }

// Lookup returns the key for kid that can verify alg. A token without a kid
// matches only a set with exactly one key, so the edge never tries several.
func (s *Set) Lookup(kid, alg string) (any, bool) {
	k, ok := s.keys[kid]
	if !ok && kid == "" && len(s.keys) == 1 {
		for _, only := range s.keys {
			k, ok = only, true
		}
	}
	if !ok || (k.alg != "" && k.alg != alg) || !fits(k.pub, alg) {
		return nil, false
	}
	return k.pub, true
}

// fits reports whether pub is the key type and curve alg needs
// (RFC 7518 §3.1, RFC 8037 §3.1). This blocks algorithm confusion within one set.
func fits(pub any, alg string) bool {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		switch alg {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			return true
		}
	case *ecdsa.PublicKey:
		switch alg {
		case "ES256":
			return p.Curve == elliptic.P256()
		case "ES384":
			return p.Curve == elliptic.P384()
		case "ES512":
			return p.Curve == elliptic.P521()
		}
	case ed25519.PublicKey:
		return alg == "EdDSA"
	}
	return false
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Parse reads a JWKS (RFC 7517 §5). Keys that can't sign or that this edge
// can't use (encryption keys, other key types, malformed keys) are skipped,
// because IdPs publish them alongside signing keys. A set with no usable
// key is an error: replacing good keys with it would reject every token.
// Fetch bounds what an IdP sends. Parse doesn't recheck the size: a set
// that passed Fetch can grow when re-encoded, as JSON escaping does to & <
// and > inside a snapshot.
func Parse(b []byte) (*Set, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	s := &Set{keys: map[string]key{}}
	for _, raw := range doc.Keys {
		var j jwk
		if json.Unmarshal(raw, &j) != nil || (j.Use != "" && j.Use != "sig") {
			continue
		}
		if _, dup := s.keys[j.Kid]; dup {
			continue // the first key with a kid wins, as a reader of the set would see it
		}
		if pub, err := j.public(); err == nil {
			s.keys[j.Kid] = key{pub: pub, alg: j.Alg}
		}
	}
	if len(s.keys) == 0 {
		return nil, errors.New("jwks has no usable signing key")
	}
	return s, nil
}

var b64 = base64.RawURLEncoding

func (j *jwk) public() (any, error) {
	switch j.Kty {
	case "RSA":
		n, err1 := b64.DecodeString(j.N)
		e, err2 := b64.DecodeString(j.E)
		if err := errors.Join(err1, err2); err != nil {
			return nil, err
		}
		// RFC 7518 §6.3.1.1: n has no leading zero octet. e fits an int and
		// must be odd and above 1 for a valid RSA key.
		if len(n) == 0 || n[0] == 0 || len(e) == 0 || len(e) > 4 || e[0] == 0 {
			return nil, errors.New("bad rsa key")
		}
		ev := 0
		for _, c := range e {
			ev = ev<<8 | int(c)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ev}
		if pub.N.BitLen() < minRSABits || ev < 3 || ev%2 == 0 {
			return nil, errors.New("rsa key too small or bad exponent")
		}
		return pub, nil
	case "EC":
		curve, ok := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[j.Crv]
		if !ok {
			return nil, errors.New("unsupported curve")
		}
		x, err1 := b64.DecodeString(j.X)
		y, err2 := b64.DecodeString(j.Y)
		size := (curve.Params().BitSize + 7) / 8
		// RFC 7518 §6.2.1.2: x and y are the full coordinate size.
		if errors.Join(err1, err2) != nil || len(x) != size || len(y) != size {
			return nil, errors.New("bad ec coordinates")
		}
		// Rejects points not on the curve.
		return ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
	case "OKP":
		x, err := b64.DecodeString(j.X)
		if j.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad okp key")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, errors.New("unsupported key type")
}
