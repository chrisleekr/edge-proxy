package snapshot

import "strings"

// SharedKey reports whether a rate-limit key has no per-client part, so its
// bucket holds a population (a JA4, a country, the whole site) rather than one
// client. Guards leave a rule's heaviest subject out of its limited count as an
// attacker; for a shared key that subject is the whole bucket, so they judge
// the raw count instead.
func SharedKey(key []string) bool {
	for _, k := range key {
		switch kind, _, _ := strings.Cut(k, ":"); kind {
		case "ip", "jwt_claim", "header", "cookie", "query":
			return false
		}
	}
	return true
}
