package ratelimit

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

func TestLocalStore(t *testing.T) {
	once := Params{Algo: FixedWindow, Limit: 1, Period: 1000}

	t.Run("a full store lets new subjects pass untracked", func(t *testing.T) {
		l := NewLocalStore(numShards) // one subject per shard
		untracked := 0
		for i := range 10 * numShards {
			r, tracked := l.Take(fmt.Sprint("k", i), once, 0)
			if !tracked {
				untracked++
				if !r.Allowed {
					t.Fatal("untracked subject was refused")
				}
			}
		}
		if untracked == 0 || l.Len() > numShards {
			t.Fatalf("untracked=%d len=%d", untracked, l.Len())
		}
	})

	t.Run("a subject starts fresh once its state expires", func(t *testing.T) {
		l := NewLocalStore(100)
		l.Take("k", once, 0)
		if r, _ := l.Take("k", once, 10); r.Allowed {
			t.Fatal("second request in the window passed")
		}
		if r, _ := l.Take("k", once, 1000); !r.Allowed {
			t.Fatal("request after expiry was refused")
		}
	})

	t.Run("sweeping frees room for new subjects", func(t *testing.T) {
		l := NewLocalStore(numShards)
		for i := range 10 * numShards {
			l.Take(fmt.Sprint("k", i), once, 0)
		}
		l.Sweep(1000)
		if l.Len() != 0 {
			t.Fatalf("len after sweep = %d", l.Len())
		}
		if _, tracked := l.Take("new", once, 1000); !tracked {
			t.Fatal("new subject untracked after sweep")
		}
	})

	t.Run("concurrent requests for one subject never exceed the limit", func(t *testing.T) {
		l := NewLocalStore(100)
		p := Params{Algo: FixedWindow, Limit: 50, Period: 60_000}
		var allowed atomic.Int64
		var wg sync.WaitGroup
		for range 200 {
			wg.Go(func() {
				if r, _ := l.Take("k", p, 1000); r.Allowed {
					allowed.Add(1)
				}
			})
		}
		wg.Wait()
		if allowed.Load() != 50 {
			t.Fatalf("allowed %d, want 50", allowed.Load())
		}
	})
}

func TestPenalties(t *testing.T) {
	p := NewPenalties(numShards)
	p.Block("k", 5000)
	if got := p.Until("k", 1000); got != 5000 {
		t.Fatalf("until = %d", got)
	}
	if got := p.Until("k", 5000); got != 0 {
		t.Fatalf("penalty still active at its end: %d", got)
	}
	if got := p.Until("other", 1000); got != 0 {
		t.Fatalf("unknown key blocked: %d", got)
	}

	t.Run("a full cache drops new penalties and Valkey still enforces them", func(t *testing.T) {
		full := NewPenalties(numShards)
		dropped := 0
		for i := range 10 * numShards {
			if !full.Block(fmt.Sprint("k", i), 5000) {
				dropped++
			}
		}
		if dropped == 0 || full.Len() > numShards {
			t.Fatalf("dropped=%d len=%d", dropped, full.Len())
		}
		full.Sweep(5000)
		if full.Len() != 0 {
			t.Fatalf("len after sweep = %d", full.Len())
		}
	})
}

func TestBackstop(t *testing.T) {
	cfg := snapshot.Backstop{Limit: 1, Period: snapshot.Duration(time.Second), Burst: 1, MaxEntries: 1000}
	now := time.UnixMilli(1_700_000_000_000)
	cases := []struct {
		name    string
		a, b    string
		sharedB bool
	}{
		{"addresses in one IPv6 /64 share a bucket", "2001:db8::1", "2001:db8::ffff:1", true},
		{"different IPv6 /64s have their own buckets", "2001:db8::1", "2001:db8:0:1::1", false},
		{"IPv4 addresses have their own buckets", "192.0.2.1", "192.0.2.2", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := NewBackstop(cfg)
			if r, _ := b.Allow(netip.MustParseAddr(c.a), now); !r.Allowed {
				t.Fatal("first request refused")
			}
			r, _ := b.Allow(netip.MustParseAddr(c.b), now)
			if r.Allowed == c.sharedB {
				t.Fatalf("second address allowed=%v, shared bucket=%v", r.Allowed, c.sharedB)
			}
		})
	}

	t.Run("a full backstop lets new IPs pass untracked", func(t *testing.T) {
		b := NewBackstop(snapshot.Backstop{Limit: 1, Period: snapshot.Duration(time.Second), Burst: 1, MaxEntries: 1})
		untracked := 0
		for i := range 1000 {
			ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
			if r, tracked := b.Allow(ip, now); !tracked {
				untracked++
				if !r.Allowed {
					t.Fatal("untracked IP refused")
				}
			}
		}
		if untracked == 0 || b.Len() > numShards {
			t.Fatalf("untracked=%d len=%d", untracked, b.Len())
		}
		b.Sweep(now.Add(time.Second))
		if b.Len() != 0 {
			t.Fatalf("idle IPs not swept: %d", b.Len())
		}
	})
}

// Values are length-prefixed, so no two different value lists share a key.
func TestKeyValuesAreUnambiguous(t *testing.T) {
	rule := Rule{prefix: "rl:x:1:r:{"}
	a := rule.Key(AppendValue(AppendValue(nil, "ab"), "c"))
	b := rule.Key(AppendValue(AppendValue(nil, "a"), "bc"))
	if a == b {
		t.Fatal("(ab,c) and (a,bc) share a key")
	}
	if len(a) != len("rl:x:1:r:{")+22+1 {
		t.Fatalf("key length %d: %q", len(a), a)
	}
}

// Keys extracted from attacker-controlled values never panic, are bounded in
// length, and the length-prefixed subject decodes back to its values.
func FuzzKey(f *testing.F) {
	f.Add("ab", "c", "2001:db8::1")
	f.Add("", "\x00\xff", "192.0.2.1")
	f.Fuzz(func(t *testing.T, v1, v2, ip string) {
		rule := Rule{prefix: "rl:fixed_window:60000:r:{"}
		subject := AppendValue(AppendValue(nil, v1), v2)
		if a, err := netip.ParseAddr(ip); err == nil {
			subject = AppendIP(subject, a)
		}
		if k := rule.Key(subject); len(k) != len(rule.prefix)+23 {
			t.Fatalf("key length %d", len(k))
		}
		for _, want := range []string{v1, v2} {
			n, w := binary.Uvarint(subject)
			if got := string(subject[w : w+int(n)]); got != want {
				t.Fatalf("decoded %q, want %q", got, want)
			}
			subject = subject[w+int(n):]
		}
	})
}

// slot matches the Valkey Cluster spec's CRC16 and hash-tag rules.
func TestSlot(t *testing.T) {
	cases := []struct {
		key  string
		want uint16
	}{
		{"123456789", 0x31C3 % 16384}, // the spec's CRC16 test vector
		{"foo", 12182},
		{"{user1000}.following", slot("user1000")},
		{"{user1000}.followers", slot("user1000")},
		{"foo{}{bar}", slot("foo{}{bar}")}, // empty first tag: whole key
		{"foo{{bar}}zap", slot("{bar")},
		{"foo{bar}{zap}", slot("bar")},
		{"no-closing{brace", slot("no-closing{brace")},
	}
	for _, c := range cases {
		if got := slot(c.key); got != c.want {
			t.Errorf("slot(%q) = %d, want %d", c.key, got, c.want)
		}
	}
}

func TestBans(t *testing.T) {
	v4 := netip.MustParseAddr("198.51.100.7")
	live := map[string]bool{"trap": true, "day": true, "minute": true, "week": true}

	t.Run("a ban ends at its end time", func(t *testing.T) {
		b := NewBans(100)
		if _, _, ok := b.Add(v4, Ban{Rule: "trap", End: 1000}, live); !ok {
			t.Fatal("ban refused")
		}
		if got, ok := b.Get(v4, 999); !ok || got.Rule != "trap" {
			t.Fatalf("ban before the end = %v, %v", got, ok)
		}
		if _, ok := b.Get(v4, 1000); ok {
			t.Fatal("ban at the end is still active")
		}
	})

	t.Run("addresses in one IPv6 /64 share a ban and another /64 does not", func(t *testing.T) {
		b := NewBans(100)
		b.Add(netip.MustParseAddr("2001:db8:1:2::1"), Ban{Rule: "trap", End: 1000}, live)
		if _, ok := b.Get(netip.MustParseAddr("2001:db8:1:2:ffff::9"), 0); !ok {
			t.Fatal("same /64 is not banned")
		}
		if _, ok := b.Get(netip.MustParseAddr("2001:db8:1:3::1"), 0); ok {
			t.Fatal("other /64 is banned")
		}
	})

	t.Run("a full table refuses a new ban and keeps the others", func(t *testing.T) {
		b := NewBans(numShards) // one ban per shard
		refused := 0
		for i := range 10 * numShards {
			if _, _, ok := b.Add(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), Ban{Rule: "trap", End: 1000}, live); !ok {
				refused++
			}
		}
		if refused == 0 || b.Len() > numShards {
			t.Fatalf("refused=%d len=%d", refused, b.Len())
		}
	})

	t.Run("a repeat ban extends the end even in a full table", func(t *testing.T) {
		b := NewBans(numShards)
		b.Add(v4, Ban{Rule: "trap", End: 1000}, live)
		if _, _, ok := b.Add(v4, Ban{Rule: "trap", End: 5000}, live); !ok {
			t.Fatal("renewal refused")
		}
		if _, ok := b.Get(v4, 2000); !ok {
			t.Fatal("ban ended at its first end")
		}
	})

	t.Run("a shorter ban keeps the longer one and a longer ban replaces a shorter one", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "day", Start: 1, End: 9000, Path: "/a"}, live)
		if _, _, ok := b.Add(v4, Ban{Rule: "minute", Start: 5, End: 2000, Path: "/b"}, live); !ok {
			t.Fatal("shorter ban reported as refused")
		}
		if got, _ := b.Get(v4, 0); got.Rule != "day" || got.Start != 1 || got.End != 9000 || got.Path != "/a" {
			t.Fatalf("after the shorter ban: %+v", got)
		}
		b.Add(v4, Ban{Rule: "week", Start: 6, End: 20000}, live)
		if got, _ := b.Get(v4, 0); got.Rule != "week" || got.End != 20000 {
			t.Fatalf("after the longer ban: %+v", got)
		}
	})

	t.Run("a ban whose rule is no longer live is replaced by a shorter live ban", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "day", Start: 1, End: 9000}, live)
		cur, report, ok := b.Add(v4, Ban{Rule: "minute", Start: 5, End: 2000}, map[string]bool{"minute": true})
		if !ok || !report || cur.Rule != "minute" {
			t.Fatalf("cur=%+v report=%v ok=%v", cur, report, ok)
		}
		if got, _ := b.Get(v4, 0); got.Rule != "minute" || got.End != 2000 {
			t.Fatalf("after the live ban: %+v", got)
		}
	})

	t.Run("an ended ban is replaced by a shorter one", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "day", Start: 1, End: 9000}, live)
		b.Add(v4, Ban{Rule: "minute", Start: 9500, End: 9600}, live)
		if got, _ := b.Get(v4, 9500); got.Rule != "minute" {
			t.Fatalf("after the ended ban: %+v", got)
		}
	})

	t.Run("a renewal is reported once End has moved a report interval", func(t *testing.T) {
		b := NewBans(100)
		hour := int64(time.Hour / time.Millisecond)
		steps := []struct {
			name       string
			rule       string
			start      int64
			wantReport bool
		}{
			{"first ban", "trap", 0, true},
			{"renewal a second later", "trap", 1000, false},
			{"renewal just under the interval", "trap", banReportEvery - 1, false},
			{"renewal at the interval", "trap", banReportEvery, true},
			{"renewal a second after that", "trap", banReportEvery + 1000, false},
			{"another live rule with a longer ban", "day", banReportEvery + 2000, true},
		}
		for _, st := range steps {
			end := st.start + hour
			if st.rule == "day" {
				end += hour
			}
			cur, report, ok := b.Add(v4, Ban{Rule: st.rule, Start: st.start, End: end}, live)
			if !ok || report != st.wantReport || cur.End != end {
				t.Fatalf("%s: cur=%+v report=%v ok=%v", st.name, cur, report, ok)
			}
			if got, _ := b.Get(v4, st.start); got.Rule != st.rule || got.End != end {
				t.Fatalf("%s: stored %+v, want rule %s ending %d", st.name, got, st.rule, end)
			}
			if report {
				b.MarkReported(v4, cur)
			}
		}
	})

	t.Run("a report that was never marked is offered again on the next trip", func(t *testing.T) {
		b := NewBans(100)
		if _, report, _ := b.Add(v4, Ban{Rule: "trap", Start: 0, End: 3_600_000}, live); !report {
			t.Fatal("first ban not reported")
		}
		if _, report, _ := b.Add(v4, Ban{Rule: "trap", Start: 1000, End: 3_601_000}, live); !report {
			t.Fatal("renewal after a report that was not queued was not offered again")
		}
		b.MarkReported(v4, Ban{Rule: "trap", End: 3_601_000})
		if _, report, _ := b.Add(v4, Ban{Rule: "trap", Start: 2000, End: 3_602_000}, live); report {
			t.Fatal("renewal after a queued report was offered again")
		}
	})

	t.Run("marking a report never moves it backwards or onto a different ban", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "trap", Start: 0, End: 5000}, live)
		b.MarkReported(v4, Ban{Rule: "trap", End: 5000})
		b.MarkReported(v4, Ban{Rule: "trap", End: 3000}) // a slower, older report
		b.MarkReported(v4, Ban{Rule: "trap", End: 9000}) // the ban ends before this
		b.MarkReported(netip.MustParseAddr("10.9.9.9"), Ban{Rule: "trap", End: 5000})
		if got, _ := b.Get(v4, 0); got.Reported != 5000 {
			t.Fatalf("reported %d, want 5000", got.Reported)
		}
	})

	t.Run("a late report of a replaced ban does not mark the ban that replaced it", func(t *testing.T) {
		b := NewBans(100)
		both := map[string]bool{"short": true, "long": true}
		b.Add(v4, Ban{Rule: "short", Start: 0, End: 100_000}, both) // its report is still on its way to the queue
		b.Add(v4, Ban{Rule: "long", Start: 10, End: 110_000}, both) // its report was dropped
		b.MarkReported(v4, Ban{Rule: "short", End: 100_000})        // the short ban's report lands late
		if _, report, _ := b.Add(v4, Ban{Rule: "long", Start: 20, End: 120_000}, both); !report {
			t.Fatal("renewal of a ban never reported was not offered")
		}
	})

	t.Run("a late report of a lifted ban does not mark the same rule's next ban", func(t *testing.T) {
		b := NewBans(100)
		first, _, _ := b.Add(v4, Ban{Rule: "trap", Start: 0, End: 100_000}, live) // queued, not yet marked
		b.Lift(v4, 50)
		b.Add(v4, Ban{Rule: "trap", Start: 100, End: 100_100}, live) // its report was dropped
		b.MarkReported(v4, first)                                    // the first ban's mark lands late
		if _, report, _ := b.Add(v4, Ban{Rule: "trap", Start: 200, End: 100_200}, live); !report {
			t.Fatal("renewal of a ban never reported was not offered")
		}
	})

	t.Run("ban start order decides which ban is kept", func(t *testing.T) {
		tests := []struct {
			name       string
			old, x     Ban
			live       map[string]bool
			wantRule   string
			wantEnd    int64
			wantReport bool
		}{
			{"a canary ban is replaced when the client trips the stable version's trap after the canary ends", Ban{Rule: "canary-trap", Start: 0, End: 9000}, Ban{Rule: "stable-trap", Start: 5, End: 20000}, map[string]bool{"stable-trap": true}, "stable-trap", 20000, true},
			{"a request that started before the stored ban does not replace it", Ban{Rule: "short", Start: 10, End: 2000}, Ban{Rule: "long", Start: 5, End: 20000}, map[string]bool{"short": true, "long": true}, "short", 2000, false},
			{"a request that started before an ended stored ban does not replace it", Ban{Rule: "short", Start: 10, End: 20}, Ban{Rule: "long", Start: 5, End: 20000}, map[string]bool{"short": true, "long": true}, "short", 20, false},
			{"same start keeps the longest live ban", Ban{Rule: "day", Start: 5, End: 9000}, Ban{Rule: "minute", Start: 5, End: 2000}, map[string]bool{"day": true, "minute": true}, "day", 9000, false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				b := NewBans(100)
				b.Add(v4, tc.old, map[string]bool{tc.old.Rule: true})
				cur, report, ok := b.Add(v4, tc.x, tc.live)
				if !ok || report != tc.wantReport || cur.Rule != tc.wantRule || cur.End != tc.wantEnd {
					t.Fatalf("cur=%+v report=%v ok=%v", cur, report, ok)
				}
				if got, _ := b.Get(v4, 0); got.Rule != tc.wantRule || got.End != tc.wantEnd {
					t.Fatalf("stored %+v, want %s ending %d", got, tc.wantRule, tc.wantEnd)
				}
			})
		}
	})

	t.Run("a dropped report is offered again by a trip in the same millisecond", func(t *testing.T) {
		b := NewBans(100)
		x := Ban{Rule: "trap", Start: 0, End: 3_600_000}
		if _, report, _ := b.Add(v4, x, live); !report {
			t.Fatal("first ban not reported")
		}
		cur, report, _ := b.Add(v4, x, live) // queue was full: not marked
		if !report {
			t.Fatal("same-millisecond trip after a dropped report was not offered")
		}
		b.MarkReported(v4, cur)
		if _, report, _ := b.Add(v4, x, live); report {
			t.Fatal("same-millisecond trip after a queued report was offered again")
		}
	})

	t.Run("keeping a longer ban allocates nothing", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "day", Start: 1, End: 9000}, live)
		x := Ban{Rule: "minute", Start: 5, End: 2000, Host: "a.example.com", Path: "/wp-login.php"}
		if n := testing.AllocsPerRun(100, func() { b.Add(v4, x, live) }); n != 0 {
			t.Fatalf("%v allocations", n)
		}
	})

	t.Run("a kept longer ban is not reported", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "day", Start: 1, End: 9000}, live)
		cur, report, ok := b.Add(v4, Ban{Rule: "minute", Start: 5, End: 2000}, live)
		if !ok || report || cur.Rule != "day" {
			t.Fatalf("cur=%+v report=%v ok=%v", cur, report, ok)
		}
	})

	t.Run("a lift ends a ban that started before it and not one that started after", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "trap", Start: 100, End: 9000}, live)
		b.Lift(v4, 100)
		if _, ok := b.Get(v4, 0); !ok {
			t.Fatal("a ban that started at the lift was lifted")
		}
		b.Lift(v4, 101)
		if _, ok := b.Get(v4, 0); ok {
			t.Fatal("an older ban survived the lift")
		}
		b.Lift(v4, 101) // no ban: nothing to do
	})

	t.Run("sweeping drops ended bans", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "trap", End: 1000}, live)
		b.Sweep(1000)
		if b.Len() != 0 {
			t.Fatalf("len after sweep = %d", b.Len())
		}
	})

	t.Run("the stored host and path are bounded", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "trap", End: 1000, Host: strings.Repeat("h", 1000), Path: strings.Repeat("p", 1000)}, live)
		got, _ := b.Get(v4, 0)
		if len(got.Host) != maxBanHost || len(got.Path) != maxBanPath {
			t.Fatalf("host %d bytes, path %d bytes", len(got.Host), len(got.Path))
		}
	})

	t.Run("looking up a ban allocates nothing", func(t *testing.T) {
		b := NewBans(100)
		b.Add(v4, Ban{Rule: "trap", End: 1000, Host: "a.example.com", Path: "/wp-login.php"}, live)
		if n := testing.AllocsPerRun(100, func() { b.Get(v4, 0) }); n != 0 {
			t.Fatalf("%v allocations", n)
		}
	})
}
