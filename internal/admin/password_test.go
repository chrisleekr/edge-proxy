package admin

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestPasswordRules(t *testing.T) {
	block := map[string]bool{"correcthorsebatterystaple": true}
	cases := []struct {
		pw, problem string
	}{
		{strings.Repeat("a", 14), "at least 15"},
		{strings.Repeat("a", 15), ""},
		{strings.Repeat("密", 64), ""},
		{strings.Repeat("a", 257), "at most 256"},
		{"CorrectHorseBatteryStaple", "commonly used"},
		// NFKC folds fullwidth letters, so the blocklist still matches.
		{"ｃｏｒｒｅｃｔｈｏｒｓｅｂａｔｔｅｒｙｓｔａｐｌｅ", "commonly used"},
		{"my name is alice, hello", "username"},
		{"welcome to edge-proxy admin", "service name"},
	}
	for _, tc := range cases {
		if got := passwordProblem(tc.pw, "alice", block); !strings.Contains(got, tc.problem) || (tc.problem == "") != (got == "") {
			t.Errorf("passwordProblem(%q) = %q, want %q", tc.pw, got, tc.problem)
		}
	}
}

func TestPasswordHashes(t *testing.T) {
	h := hashPassword("ｐａｓｓｗｏｒｄ ｐａｓｓｗｏｒｄ")
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") || !checkPassword(h, "password password") {
		t.Fatalf("hash %s", h)
	}
	if a, b := hashPassword("same input"), hashPassword("same input"); a == b {
		t.Fatal("salt not random")
	}
	// Hashes made with other parameters still verify with their own.
	salt := []byte("saltsalt")
	old := fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=1$%s$%s", b64.EncodeToString(salt), b64.EncodeToString(argon2.IDKey([]byte("secret"), salt, 1, 64, 1, 32)))
	if !checkPassword(old, "secret") || checkPassword(old, "Secret") {
		t.Fatal("hash with other parameters not verified by its own")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA", "$argon2id$v=16$m=8,t=1,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=x$c2FsdA$aGFzaA", "$argon2id$v=19$m=8,t=1,p=1$!!$aGFzaA"} {
		if checkPassword(bad, "secret") {
			t.Errorf("accepted %q", bad)
		}
	}
}
