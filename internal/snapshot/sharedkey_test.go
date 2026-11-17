package snapshot

import "testing"

func TestSharedKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []string
		want bool
	}{
		{"ip is per client", []string{"ip"}, false},
		{"jwt claim is per client", []string{"jwt_claim:sub"}, false},
		{"header is per client", []string{"header:x-api-key"}, false},
		{"cookie is per client", []string{"cookie:sid"}, false},
		{"query is per client", []string{"query:user"}, false},
		{"ja4 is a population", []string{"ja4"}, true},
		{"constant is a population", []string{"constant"}, true},
		{"host is a population", []string{"host"}, true},
		{"method is a population", []string{"method"}, true},
		{"country is a population", []string{"country"}, true},
		{"asnum is a population", []string{"asnum"}, true},
		{"locale is a population", []string{"locale"}, true},
		{"population parts with a per-client part", []string{"ja4", "ip"}, false},
		{"several population parts", []string{"country", "ja4"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SharedKey(tc.key); got != tc.want {
				t.Errorf("SharedKey(%v) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}
