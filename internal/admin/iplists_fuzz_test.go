package admin

import (
	"net/netip"
	"slices"
	"testing"
)

// A person's typed list must never panic the parser, and whatever it accepts
// is canonical, sorted as text, unique, within the cap and parses back to the
// same prefix, so the stored text is what edges read.
func FuzzParseTyped(f *testing.F) {
	for _, s := range []string{"", "1.2.3.4\n", "10.0.0.0/8\n", "1.2.3.4/24\n", "::ffff:1.2.3.4\n", "fe80::1%eth0\n", "1.2.3.4\n1.2.3.4/32\n", " 2001:db8::/32 \r\n\n", "\x00\xff\n"} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, text string, wide bool) {
		got, issues := parseTyped(text, wide)
		if issues != nil {
			if got != nil {
				t.Fatalf("issues %v with entries %q", issues, got)
			}
			return
		}
		if len(got) == 0 || len(got) > maxTypedEntries || !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
			t.Fatalf("not sorted, unique and within the cap: %q", got)
		}
		min4, min6 := 16, 32
		if wide {
			min4, min6 = 8, 16
		}
		for _, s := range got {
			p, err := netip.ParsePrefix(s)
			if err != nil || p != p.Masked() || p.String() != s || p.Addr().Is4In6() || p.Addr().Zone() != "" || p.Addr().Is4() && p.Bits() < min4 || p.Addr().Is6() && p.Bits() < min6 {
				t.Fatalf("%q is not a canonical prefix within the width limit: %v", s, err)
			}
		}
	})
}

// parseList reads a file from anywhere on the internet, so no input may
// panic, and whatever it accepts must be what an edge can parse: canonical,
// sorted as text and unique, never 4-in-6 and never wider than the list allows.
func FuzzParseList(f *testing.F) {
	for _, s := range []string{"", "1.2.3.4\n", "# c\r\n5.6.7.0/24 ; x\n2001:db8::1\n", "<html>", "::ffff:1.2.3.4", "1.2.3.4/33", "\x00\xff\n\n", `{"creationTime":"2026-10-20T00:00:00Z","prefixes":[{"ipv4Prefix":"216.73.216.0/22"},{"ipv6Prefix":"2001:db8::/48"}]}`, `{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"},`, `["1.2.3.4",["::ffff:1.2.3.4"]]`, `{"1.2.3.4":"5.6.7.0/24"}`, `{"n":1e400}`, `["1.2.3.4"]["5.6.7.0/24"]`} {
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
