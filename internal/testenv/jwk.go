package testenv

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"maps"
	"math/big"
)

// JWK encodes a public key as a JWK (RFC 7518 §6, RFC 8037 §2), the way an
// IdP publishes it. extra adds or overrides members such as "use" or "alg".
func JWK(kid string, pub any, extra map[string]string) map[string]string {
	b64 := base64.RawURLEncoding.EncodeToString
	j := map[string]string{"kid": kid}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		j["kty"], j["n"], j["e"] = "RSA", b64(p.N.Bytes()), b64(big.NewInt(int64(p.E)).Bytes())
	case *ecdsa.PublicKey:
		size := (p.Curve.Params().BitSize + 7) / 8
		b, _ := p.Bytes() // uncompressed: 0x04 || x || y
		j["kty"], j["crv"], j["x"], j["y"] = "EC", p.Curve.Params().Name, b64(b[1:1+size]), b64(b[1+size:])
	case ed25519.PublicKey:
		j["kty"], j["crv"], j["x"] = "OKP", "Ed25519", b64(p)
	}
	maps.Copy(j, extra)
	return j
}

// JWKS encodes keys as a JWKS document.
func JWKS(keys ...map[string]string) []byte {
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return b
}
