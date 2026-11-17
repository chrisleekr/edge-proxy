package admin

import (
	"net/netip"
	"slices"
	"testing"
)

// parseList reads a file from anywhere on the internet, so no input may
// panic, and whatever it accepts must be what an edge can parse: canonical,
// sorted as text and unique, never 4-in-6 and never wider than the list allows.
func FuzzParseList(f *testing.F) {
	for _, s := range []string{"", "1.2.3.4\n", "# c\r\n5.6.7.0/24 ; x\n2001:db8::1\n", "<html>", "::ffff:1.2.3.4", "1.2.3.4/33", "\x00\xff\n\n"} {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	f.Fuzz(func(t *testing.T, b []byte, wide bool) {
		got, _, err := parseList(b, wide)
		if err != nil {
			return
		}
		if len(got) == 0 || !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
			t.Fatalf("not sorted and unique: %q", got)
		}
		for _, s := range got {
			if p, err := netip.ParsePrefix(s); err != nil || p != p.Masked() || p.String() != s {
				t.Fatalf("%q is not canonical: %v", s, err)
			}
			min4, min6 := 16, 32
			if wide {
				min4, min6 = 8, 16
			}
			if p, _ := netip.ParsePrefix(s); p.Addr().Is4In6() || p.Addr().Is4() && p.Bits() < min4 || p.Addr().Is6() && p.Bits() < min6 {
				t.Fatalf("%q is 4-in-6 or wider than allowed with wide=%v", s, wide)
			}
		}
	})
}
