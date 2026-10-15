package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Argon2id at OWASP's minimum (Password Storage Cheat Sheet): 19 MiB,
// 2 iterations, parallelism 1.
const (
	argonMemory  = 19 * 1024 // KiB
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// Password length bounds (NIST SP 800-63B Rev 4 §3.1.1.2): at least 15
// characters for single-factor use; at least 64 must be accepted. The upper
// bound only caps hashing work.
const (
	minPassword = 15
	maxPassword = 256
)

// argonSlots bounds hashes running at once: each holds argonMemory, and
// login runs them before authentication. Callers past the bound wait.
var argonSlots = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

// argonKey is argon2.IDKey within one of argonSlots.
func argonKey(pw string, salt []byte, t, m uint32, p uint8, n uint32) []byte {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2.IDKey([]byte(normalize(pw)), salt, t, m, p, n)
}

var b64 = base64.RawStdEncoding

// normalize applies NFKC, as SP 800-63B Rev 4 §3.1.1.2 recommends before
// hashing, so one password typed on different keyboards matches.
func normalize(s string) string { return norm.NFKC.String(s) }

// hashPassword returns a PHC-format Argon2id hash.
func hashPassword(pw string) string {
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt) // crypto/rand.Read never returns an error (Go 1.24+)
	key := argonKey(pw, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

// checkPassword verifies pw against a hash made by hashPassword, using the
// parameters stored with it so older hashes still verify.
func checkPassword(hash, pw string) bool {
	var v int
	var m, t uint32
	var p uint8
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if errors.Join(err1, err2) != nil {
		return false
	}
	got := argonKey(pw, salt, t, m, p, uint32(len(want))) //nolint:gosec // length of a 32-byte key
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified when a username doesn't exist, so an unknown user
// takes as long as a wrong password.
var dummyHash = hashPassword("dummy password for timing")

// passwordProblem says why a new password is refused, or ""
// (SP 800-63B Rev 4 §3.1.1.2): length, and the whole password against a blocklist and
// context words. No composition rules.
func passwordProblem(pw, username string, blocklist map[string]bool) string {
	n := utf8.RuneCountInString(normalize(pw))
	switch {
	case n < minPassword:
		return fmt.Sprintf("must be at least %d characters", minPassword)
	case n > maxPassword:
		return fmt.Sprintf("must be at most %d characters", maxPassword)
	}
	low := strings.ToLower(normalize(pw))
	if blocklist[low] {
		return "is a commonly used or breached password"
	}
	if strings.Contains(low, strings.ToLower(username)) {
		return "must not contain the username"
	}
	if strings.Contains(low, "edge-proxy") || strings.Contains(low, "edgeproxy") {
		return "must not contain the service name"
	}
	return ""
}
