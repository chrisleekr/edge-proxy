package expr

import (
	"bytes"
	"errors"
	"net/netip"
	"sort"
)

// wildcard matches a whole value against a pattern where "*" means zero or
// more bytes and "\*" / "\\" are literals. Case folding is ASCII
// only, so it never rewrites invalid UTF-8 and doesn't allocate for values
// up to 512 bytes.
type wildcard struct {
	segs     [][]byte // literal segments between stars
	foldCase bool
}

// compileWildcard splits the pattern on unescaped stars. foldCase lowercases
// the pattern so matching can lowercase only the value.
func compileWildcard(pattern string, foldCase bool) (wildcard, error) {
	w := wildcard{foldCase: foldCase}
	var cur []byte
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '\\':
			if i+1 >= len(pattern) || (pattern[i+1] != '*' && pattern[i+1] != '\\') {
				return wildcard{}, errors.New(`in a wildcard only \* and \\ may follow a backslash`)
			}
			i++
			cur = append(cur, pattern[i])
		case '*':
			// "**" means the same as "*", so it is rejected as a likely typo.
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				return wildcard{}, errors.New(`a wildcard can't contain "**"`)
			}
			w.segs = append(w.segs, cur)
			cur = nil
		default:
			if foldCase {
				c = lowerASCII(c)
			}
			cur = append(cur, c)
		}
	}
	w.segs = append(w.segs, cur)
	return w, nil
}

// match copies the value into a stack buffer so case folding needs no
// allocation. The first segment must be a prefix, middle segments are found
// left to right, and the last must be a suffix of what remains. Leftmost
// matching is correct when "*" is the only metacharacter.
func (w wildcard) match(s string) bool {
	var buf [512]byte
	// ponytail: values over 512 bytes allocate once; raise if paths get longer.
	b := append(buf[:0], s...)
	if w.foldCase {
		for i, c := range b {
			b[i] = lowerASCII(c)
		}
	}
	if len(w.segs) == 1 {
		return bytes.Equal(b, w.segs[0])
	}
	first, last := w.segs[0], w.segs[len(w.segs)-1]
	if !bytes.HasPrefix(b, first) {
		return false
	}
	b = b[len(first):]
	for _, seg := range w.segs[1 : len(w.segs)-1] {
		i := bytes.Index(b, seg)
		if i < 0 {
			return false
		}
		b = b[i+len(seg):]
	}
	return bytes.HasSuffix(b, last)
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// ipSet answers membership for IPs and CIDR ranges in O(log n) by merging
// them into sorted, non-overlapping address ranges. Adjacent ranges are
// left separate; lookup is still correct.
type ipSet struct {
	ranges []ipRange
}

type ipRange struct{ lo, hi netip.Addr }

// newIPSet builds a set from checked literals (addresses or prefixes).
func newIPSet(items []string) ipSet {
	rs := make([]ipRange, 0, len(items))
	for _, item := range items {
		if a, err := netip.ParseAddr(item); err == nil {
			a = a.Unmap()
			rs = append(rs, ipRange{a, a})
			continue
		}
		p := netip.MustParsePrefix(item).Masked()
		// Requests are matched unmapped, so ::ffff:a.b.c.d/n must become a.b.c.d/(n-96)
		// or it could never match.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		rs = append(rs, ipRange{p.Addr(), lastAddr(p)})
	}
	// Prefixes are nested or disjoint, so after sorting by lo with the widest
	// first, any overlapping range is contained in the one before it.
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].lo != rs[j].lo {
			return rs[i].lo.Less(rs[j].lo)
		}
		return rs[j].hi.Less(rs[i].hi)
	})
	merged := rs[:0]
	for _, r := range rs {
		if n := len(merged); n > 0 && merged[n-1].lo.BitLen() == r.lo.BitLen() &&
			!merged[n-1].hi.Less(r.lo) {
			continue
		}
		merged = append(merged, r)
	}
	return ipSet{ranges: merged}
}

func (s ipSet) contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = clientAddr(a)
	// First range whose lo is greater than a; the candidate is the one before.
	i := sort.Search(len(s.ranges), func(i int) bool { return a.Less(s.ranges[i].lo) })
	if i == 0 {
		return false
	}
	r := s.ranges[i-1]
	return r.lo.BitLen() == a.BitLen() && !r.hi.Less(a)
}

// clientAddr is the form every IP comparison uses: IPv4-mapped addresses as
// IPv4, and no zone, since a zone is interface scope, not client identity.
func clientAddr(a netip.Addr) netip.Addr { return a.WithZone("").Unmap() }

// lastAddr returns the highest address in p (all host bits set).
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
