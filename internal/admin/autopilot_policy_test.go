package admin

import "testing"

// A value list's values were chosen by a person and can't be inspected here, so an
// autopilot rule naming one is treated as picking clients out and refused.
func TestNamesSubjectsTreatsAValueListAsASubject(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"a value list of user agents", `http.user_agent contains $agents`, true},
		{"a value list inside a nested group", `ssl and (http.host eq "a.com" or http.user_agent contains $agents)`, true},
		{"the same condition with literal values", `http.user_agent contains "curl/"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := namesSubjects(mustParse(tc.src)); got != tc.want {
				t.Fatalf("namesSubjects(%s) = %v, want %v", tc.src, got, tc.want)
			}
		})
	}
}
