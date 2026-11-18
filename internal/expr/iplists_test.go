package expr

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func mustIPLists(t testing.TB, names []string, ps [][]netip.Prefix) *IPLists {
	t.Helper()
	set, err := NewIPLists(names, ps)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func prefixes(t testing.TB, s string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for f := range strings.FieldsSeq(s) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

// A /32 inside a /14 must report both lists, ranges in a gap report none, and
// the last address of a family has no end boundary to rely on.
func TestIPListsLookup(t *testing.T) {
	names := []string{"aws", "firehol-abusers", "hetzner"}
	set := mustIPLists(t, names, [][]netip.Prefix{
		prefixes(t, "3.4.0.0/14 255.255.255.0/24 2600:1f00::/24"),
		prefixes(t, "3.5.140.17/32 3.4.0.0/16 2600:1f18::1/128"),
		prefixes(t, "5.9.0.0/16 10.0.0.0/8 10.1.0.0/16"),
	})
	cases := []struct {
		name string
		addr string
		want []string
	}{
		{"address in a /32 nested in another list's /14 is on both", "3.5.140.17", []string{"aws", "firehol-abusers"}},
		{"address in the outer range only is on one list", "3.6.0.1", []string{"aws"}},
		{"address in two nested ranges of different lists", "3.4.9.9", []string{"aws", "firehol-abusers"}},
		{"address between two ranges is on no list", "4.0.0.1", nil},
		{"address before every range is on no list", "1.1.1.1", nil},
		{"address after the last range of a middle gap", "3.8.0.0", nil},
		{"nested ranges of one list report the name once", "10.1.2.3", []string{"hetzner"}},
		{"range ending at 255.255.255.255", "255.255.255.255", []string{"aws"}},
		{"IPv4 mapped IPv6 is looked up as IPv4", "::ffff:5.9.1.1", []string{"hetzner"}},
		{"IPv6 in a nested range", "2600:1f18::1", []string{"aws", "firehol-abusers"}},
		{"IPv6 in the outer range only", "2600:1f00::5", []string{"aws"}},
		{"IPv6 outside every range", "2001:db8::1", nil},
		{"IPv6 zone is ignored", "2600:1f00::5%eth0", []string{"aws"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := set.Lookup(netip.MustParseAddr(tc.addr)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Lookup(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
	if got := set.Lookup(netip.Addr{}); got != nil {
		t.Fatalf("invalid address = %v, want nil", got)
	}
}

func TestIPListsRangeToLastIPv6Address(t *testing.T) {
	set := mustIPLists(t, []string{"all"}, [][]netip.Prefix{prefixes(t, "ffff::/16")})
	if got := set.Lookup(netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")); !reflect.DeepEqual(got, []string{"all"}) {
		t.Fatalf("got %v", got)
	}
}

func TestNilIPListsHoldNothing(t *testing.T) {
	var set *IPLists
	if got := set.Lookup(netip.MustParseAddr("1.2.3.4")); got != nil {
		t.Fatalf("nil set = %v, want nil", got)
	}
}

// Lookups run on every request, so they must not allocate, for a hit in IPv4
// and IPv6, a hit on two names, and a miss.
func TestIPListsLookupDoesNotAllocate(t *testing.T) {
	set := mustIPLists(t, []string{"aws", "hetzner"}, [][]netip.Prefix{
		prefixes(t, "3.4.0.0/14 2600:1f00::/24"),
		prefixes(t, "3.5.140.17/32"),
	})
	cases := []struct{ name, addr string }{
		{"IPv4 hit", "3.6.0.1"},
		{"nested two-name hit", "3.5.140.17"},
		{"IPv6 hit", "2600:1f00::5"},
		{"miss", "192.0.2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := netip.MustParseAddr(tc.addr)
			if n := testing.AllocsPerRun(100, func() { set.Lookup(a) }); n != 0 {
				t.Fatalf("allocs = %v, want 0", n)
			}
		})
	}
}

// Name combinations are bounded: a set whose combinations hold more names than
// the cap is refused, and the same set under the cap is built.
func TestIPListsRefuseTooManyNameCombinations(t *testing.T) {
	names := []string{"a", "b", "c"}
	ps := [][]netip.Prefix{prefixes(t, "10.0.0.0/8 2001:db8::/32"), prefixes(t, "10.1.0.0/16 2001:db8:1::/48"), prefixes(t, "10.1.1.0/24")}
	// The combinations {a}, {a,b} and {a,b,c} hold 6 names; IPv6 reuses them.
	for _, tc := range []struct {
		name    string
		cap     int
		wantErr bool
	}{
		{"exactly at the cap", 6, false},
		{"one name over the cap", 5, true},
		{"cap reached before the last IPv4 combination", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func(old int) { maxSetNames = old }(maxSetNames)
			maxSetNames = tc.cap
			set, err := NewIPLists(names, ps)
			if (err != nil) != tc.wantErr || (set == nil) != tc.wantErr {
				t.Fatalf("set %v, err %v, wantErr %v", set, err, tc.wantErr)
			}
		})
	}
}

// A set returned by Lookup is shared, so appending to it must not change what
// another caller sees. Three names make an unclipped set have spare capacity.
func TestIPListsSetsAreCapped(t *testing.T) {
	p := prefixes(t, "10.0.0.0/8")
	set := mustIPLists(t, []string{"a", "b", "c"}, [][]netip.Prefix{p, p, p})
	addr := netip.MustParseAddr("10.1.1.1")
	first := set.Lookup(addr)
	_ = append(first, "x")
	_ = append(set.Lookup(addr), "y")
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(first, want) || cap(first) != len(first) {
		t.Fatalf("shared set changed or has spare capacity: %v cap %d", first, cap(first))
	}
}

// IP lists lookup agrees with checking every list's prefixes in turn, with
// names in list order, including nested and overlapping ranges.
func FuzzIPLists(f *testing.F) {
	f.Add("3.4.0.0/14 3.5.140.17/32|3.4.0.0/16|5.9.0.0/16", "3.5.140.17")
	f.Add("10.0.0.0/8 10.1.0.0/16 10.1.0.0/16|10.1.0.0/16 ::/0", "10.1.2.3")
	f.Add("255.255.255.0/24|255.255.255.255/32 ffff::/16|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "255.255.255.255")
	f.Add("0.0.0.0/0|1.2.3.4/32|1.2.3.0/24", "1.2.3.4")
	f.Add("2001:db8::/32 2001:db8:1::/48|2001:db8:1::5/128", "2001:db8:1::5")
	f.Fuzz(func(t *testing.T, lists, addr string) {
		var names []string
		var ps [][]netip.Prefix
		for i, group := range strings.Split(lists, "|") {
			if i >= MaxIPLists {
				break
			}
			var l []netip.Prefix
			for f := range strings.FieldsSeq(group) {
				p, err := netip.ParsePrefix(f)
				if err == nil && !p.Addr().Is4In6() {
					l = append(l, p)
				}
			}
			names = append(names, fmt.Sprintf("list-%d", i))
			ps = append(ps, l)
		}
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return
		}
		var want []string
		for i, l := range ps {
			for _, p := range l {
				if p.Contains(clientAddr(a)) {
					want = append(want, names[i])
					break
				}
			}
		}
		if got := mustIPLists(t, names, ps).Lookup(a); !reflect.DeepEqual(got, want) {
			t.Fatalf("lists %v lookup %s = %v, linear scan says %v", ps, a, got, want)
		}
	})
}

// synthIPLists is about n prefixes over 70 lists, deterministic: /24s spread
// across IPv4 with every tenth inside a wider range of another list.
func synthIPLists(n int) ([]string, [][]netip.Prefix) {
	const lists = 70
	names := make([]string, lists)
	ps := make([][]netip.Prefix, lists)
	for i := range names {
		names[i] = fmt.Sprintf("list-%d", i)
	}
	for k := range n {
		l := k % lists
		x := uint32(k) * 37
		a := netip.AddrFrom4([4]byte{byte(x >> 16), byte(x >> 8), byte(x), 0})
		bits := 24
		if k%10 == 0 {
			bits = 16
		}
		ps[l] = append(ps[l], netip.PrefixFrom(a, bits))
	}
	return names, ps
}

func BenchmarkNewIPLists(b *testing.B) {
	names, ps := synthIPLists(225_000)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NewIPLists(names, ps); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPListsLookup(b *testing.B) {
	names, ps := synthIPLists(225_000)
	set := mustIPLists(b, names, ps)
	addrs := make([]netip.Addr, 1024)
	for i := range addrs {
		x := uint32(i) * 2654435761
		addrs[i] = netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		set.Lookup(addrs[i%len(addrs)])
		i++
	}
}
