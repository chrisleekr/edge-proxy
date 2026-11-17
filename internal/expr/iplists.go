package expr

import (
	"errors"
	"net/netip"
	"slices"
	"sort"
)

// MaxIPLists bounds the lists one set holds; masks are 128 bits.
const MaxIPLists = 128

// maxSetNames bounds the names held across all name combinations. A response
// can make about a million combinations of up to MaxIPLists names each, which
// is far more memory than its prefixes suggest. A variable so a test can lower it.
var maxSetNames = 1 << 20

// IPLists answers which named lists hold an address with one binary search.
type IPLists struct {
	v4, v6 segments
	// sets are the distinct name combinations segments point at.
	sets [][]string
	// setNames counts the names across sets, against maxSetNames.
	setNames int
}

// segments are sorted, non-overlapping ranges; set[i] indexes IPLists.sets.
// Parallel slices, no per-segment slice header: about 56 bytes a segment.
type segments struct {
	lo, hi []netip.Addr
	set    []int
}

type boundary struct {
	at    netip.Addr
	list  int32
	delta int32
}

// The last address of each family, where a range with no end boundary stops.
var (
	lastV4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	lastV6 = netip.AddrFrom16([16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
)

// NewIPLists builds the set. names[i] names prefixes[i]; the caller has
// checked the names, at most MaxIPLists lists, and that no prefix is 4-in-6.
// It refuses a set whose name combinations hold over maxSetNames names.
func NewIPLists(names []string, prefixes [][]netip.Prefix) (*IPLists, error) {
	// Sized up front: growing 450,000 boundaries by appends allocates several
	// times their size.
	var n4, n6 int
	for _, ps := range prefixes {
		for _, p := range ps {
			if p.Addr().Is6() {
				n6 += 2
			} else {
				n4 += 2
			}
		}
	}
	v4, v6 := make([]boundary, 0, n4), make([]boundary, 0, n6)
	for i, ps := range prefixes {
		for _, p := range ps {
			p = p.Masked()
			b := &v4
			if p.Addr().Is6() {
				b = &v6
			}
			*b = append(*b, boundary{p.Addr(), int32(i), 1})
			// The last range of a family has no address after it, so no end.
			if end := lastAddr(p).Next(); end.IsValid() {
				*b = append(*b, boundary{end, int32(i), -1})
			}
		}
	}
	s := &IPLists{}
	index := map[[2]uint64]int{}
	s.v4 = s.sweep(v4, names, lastV4, index)
	s.v6 = s.sweep(v6, names, lastV6, index)
	if s.setNames > maxSetNames {
		return nil, errors.New("IP lists overlap into too many name combinations")
	}
	return s, nil
}

// sweep walks one family's boundaries in order, keeping how many ranges of
// each list cover the current address. Ranges of one list may nest, hence
// counts, not bits.
func (s *IPLists) sweep(bs []boundary, names []string, last netip.Addr, index map[[2]uint64]int) segments {
	slices.SortFunc(bs, func(a, b boundary) int { return a.at.Compare(b.at) })
	count := make([]int32, len(names))
	walk := func(emit func(lo, hi netip.Addr, mask [2]uint64)) {
		clear(count)
		var mask [2]uint64
		for k := 0; k < len(bs); {
			at := bs[k].at
			for ; k < len(bs) && bs[k].at == at; k++ {
				l := bs[k].list
				count[l] += bs[k].delta
				if count[l] > 0 {
					mask[l/64] |= 1 << (l % 64)
				} else {
					mask[l/64] &^= 1 << (l % 64)
				}
			}
			if mask == [2]uint64{} {
				continue
			}
			hi := last
			if k < len(bs) {
				hi = bs[k].at.Prev()
			}
			emit(at, hi, mask)
		}
	}
	// Walked twice, first to count, so the segments are allocated once at
	// their final size: sizing by boundaries and trimming allocated twice.
	n := 0
	walk(func(netip.Addr, netip.Addr, [2]uint64) { n++ })
	t := segments{lo: make([]netip.Addr, 0, n), hi: make([]netip.Addr, 0, n), set: make([]int, 0, n)}
	walk(func(lo, hi netip.Addr, mask [2]uint64) {
		t.lo, t.hi = append(t.lo, lo), append(t.hi, hi)
		t.set = append(t.set, s.setOf(mask, names, index))
	})
	return t
}

func (s *IPLists) setOf(mask [2]uint64, names []string, index map[[2]uint64]int) int {
	if i, ok := index[mask]; ok {
		return i
	}
	// Past the cap nothing more is stored; NewIPLists refuses the set.
	if s.setNames > maxSetNames {
		return 0
	}
	var n []string
	for i, name := range names {
		if mask[i/64]&(1<<(i%64)) != 0 {
			n = append(n, name)
		}
	}
	// Capped, so a caller appending can't write into a shared array.
	i := len(s.sets)
	s.setNames += len(n)
	s.sets = append(s.sets, slices.Clip(n))
	index[mask] = i
	return i
}

// Lookup returns the names of the lists holding a, in list order, or nil.
// The slice is shared: callers must not modify it.
func (s *IPLists) Lookup(a netip.Addr) []string {
	if s == nil || !a.IsValid() {
		return nil
	}
	a = clientAddr(a)
	t := &s.v4
	if a.Is6() {
		t = &s.v6
	}
	i := sort.Search(len(t.lo), func(i int) bool { return a.Less(t.lo[i]) })
	if i == 0 || t.hi[i-1].Less(a) {
		return nil
	}
	return s.sets[t.set[i-1]]
}
