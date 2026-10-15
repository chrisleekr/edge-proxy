package ratelimit

import (
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// step is one request at a fake time and what it must observe.
type step struct {
	at        int64 // ms
	allowed   bool
	remaining int64
	retry     int64
}

func TestAlgorithms(t *testing.T) {
	cases := []struct {
		name  string
		p     Params
		steps []step
	}{
		{"fixed window allows the limit then refuses until the window ends",
			Params{Algo: FixedWindow, Limit: 3, Period: 1000},
			[]step{{100, true, 2, 0}, {200, true, 1, 0}, {300, true, 0, 0}, {400, false, 0, 600}, {1000, true, 2, 0}}},
		{"fixed window admits up to twice the limit across a boundary",
			Params{Algo: FixedWindow, Limit: 2, Period: 1000},
			[]step{{998, true, 1, 0}, {999, true, 0, 0}, {1000, true, 1, 0}, {1001, true, 0, 0}, {1002, false, 0, 998}}},
		{"sliding window weighs the previous window by its overlap",
			// 4 in window 0. At 1500 half of them still count, so the
			// estimate is 2 and two more pass before it reaches 4.
			Params{Algo: SlidingWindow, Limit: 4, Period: 1000},
			[]step{{0, true, 3, 0}, {1, true, 2, 0}, {2, true, 1, 0}, {3, true, 0, 0}, {1500, true, 1, 0}, {1501, true, 0, 0}, {1502, false, 0, 498}}},
		{"sliding window with a full current window waits past the boundary",
			// At 1000 the previous 4 still count fully; retry = 1000 to the
			// end of window 0 plus 1000/4 for the weight to drop below 4.
			Params{Algo: SlidingWindow, Limit: 4, Period: 1000},
			[]step{{0, true, 3, 0}, {0, true, 2, 0}, {0, true, 1, 0}, {0, true, 0, 0}, {0, false, 0, 1250}}},
		{"sliding window admits nothing extra just after a boundary",
			// The previous window's weight rounds up, so a client at the
			// limit stays there as the window rolls.
			Params{Algo: SlidingWindow, Limit: 3, Period: 1000},
			[]step{{998, true, 2, 0}, {999, true, 1, 0}, {999, true, 0, 0}, {1000, false, 0, 1000}, {1001, false, 0, 999}}},
		{"sliding window forgets a window two periods old",
			Params{Algo: SlidingWindow, Limit: 1, Period: 1000},
			[]step{{0, true, 0, 0}, {2500, true, 0, 0}}},
		{"token bucket bursts then refills at limit per period",
			Params{Algo: TokenBucket, Limit: 1, Burst: 3, Period: 1000},
			[]step{{0, true, 2, 0}, {0, true, 1, 0}, {0, true, 0, 0}, {0, false, 0, 1000}, {400, false, 0, 600}, {1000, true, 0, 0}, {5000, true, 2, 0}}},
		{"token bucket ignores a clock that steps back",
			// A Valkey failover can land on a replica whose clock is behind.
			Params{Algo: TokenBucket, Limit: 1, Burst: 1, Period: 1000},
			[]step{{5000, true, 0, 0}, {4000, false, 0, 1000}, {6000, true, 0, 0}}},
		{"leaky bucket drains steadily and rejects rather than queues",
			Params{Algo: LeakyBucket, Limit: 2, Burst: 2, Period: 1000},
			[]step{{0, true, 1, 0}, {0, true, 0, 0}, {0, false, 0, 500}, {500, true, 0, 0}, {600, false, 0, 400}}},
		{"leaky bucket ignores a clock that steps back",
			Params{Algo: LeakyBucket, Limit: 1, Burst: 1, Period: 1000},
			[]step{{5000, true, 0, 0}, {4000, false, 0, 1000}}},
		{"penalty keeps the subject blocked after the window resets",
			Params{Algo: FixedWindow, Limit: 1, Period: 1000, Penalty: 5000},
			[]step{{0, true, 0, 0}, {10, false, 0, 5000}, {1000, false, 0, 4010}, {5009, false, 0, 1}, {5010, true, 0, 0}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var s State
			for i, st := range c.steps {
				r, ttl := Step(c.p, &s, st.at)
				if r.Allowed != st.allowed || r.Remaining != st.remaining || r.Retry != st.retry {
					t.Fatalf("step %d at %d: allowed=%v remaining=%d retry=%d; want %v %d %d", i, st.at, r.Allowed, r.Remaining, r.Retry, st.allowed, st.remaining, st.retry)
				}
				if (ttl < 1 && r.Blocked == 0) || r.Now != st.at {
					t.Fatalf("step %d: ttl=%d now=%d", i, ttl, r.Now)
				}
			}
		})
	}
}

// Every key outlives the state that matters, so Valkey never forgets a
// subject early, and a penalty extends it.
func TestTTLCoversState(t *testing.T) {
	cases := []struct {
		name string
		p    Params
		at   int64
		want int64
	}{
		{"fixed window lives to the window end", Params{Algo: FixedWindow, Limit: 5, Period: 60_000}, 10_000, 50_000},
		{"sliding window lives a period past the window end", Params{Algo: SlidingWindow, Limit: 5, Period: 60_000}, 10_000, 110_000},
		{"token bucket lives until it is full again", Params{Algo: TokenBucket, Limit: 1, Burst: 3, Period: 1000}, 0, 1000},
		{"leaky bucket lives until it is empty", Params{Algo: LeakyBucket, Limit: 1, Burst: 3, Period: 1000}, 0, 1000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var s State
			if _, ttl := Step(c.p, &s, c.at); ttl != c.want {
				t.Fatalf("ttl = %d, want %d", ttl, c.want)
			}
		})
	}
	t.Run("penalty extends the ttl", func(t *testing.T) {
		p := Params{Algo: FixedWindow, Limit: 1, Period: 1000, Penalty: 300_000}
		var s State
		Step(p, &s, 0)
		r, ttl := Step(p, &s, 0)
		if ttl != 300_000 || r.Blocked != 300_000 || r.Reset != 300_000 {
			t.Fatalf("ttl=%d blocked=%d reset=%d", ttl, r.Blocked, r.Reset)
		}
	})
}

// With equal parameters leaky bucket as a meter admits exactly what token
// bucket admits, for any arrival pattern.
func TestLeakyBucketAdmitsLikeTokenBucket(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		limit, burst, period := 1+rng.Int64N(20), 1+rng.Int64N(20), 1000*(1+rng.Int64N(60))
		var tok, leak State
		now := int64(1_700_000_000_000)
		for range 300 {
			now += rng.Int64N(period / limit * 2)
			a, _ := Step(Params{Algo: TokenBucket, Limit: limit, Burst: burst, Period: period}, &tok, now)
			b, _ := Step(Params{Algo: LeakyBucket, Limit: limit, Burst: burst, Period: period}, &leak, now)
			if a.Allowed != b.Allowed || a.Remaining != b.Remaining || a.Retry != b.Retry {
				t.Fatalf("limit=%d burst=%d period=%d at %d: token %+v leaky %+v", limit, burst, period, now, a, b)
			}
		}
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestCompileRules(t *testing.T) {
	rs := Compile([]snapshot.RateLimitRule{
		{ID: "login", Expression: expr.True(), Algorithm: "sliding_window", Limit: 5, Period: snapshot.Duration(60e9), Key: []string{"ip", "header:x-api-key"}, OnMissingKey: "fallback_ip", Action: "block", Penalty: snapshot.Duration(300e9), FailMode: "local"},
		{ID: "shadow", Expression: expr.True(), Algorithm: "token_bucket", Limit: 5, Burst: 9, Period: snapshot.Duration(1e9), Key: []string{"constant"}, OnMissingKey: "skip", Action: "log", Penalty: snapshot.Duration(60e9), FailMode: "open"},
	})
	login, shadow := rs[0], rs[1]
	if login.Params != (Params{Algo: SlidingWindow, Limit: 5, Period: 60_000, Penalty: 300_000}) {
		t.Fatalf("login params %+v", login.Params)
	}
	if login.Parts[1] != (Part{Kind: PartHeader, Name: "X-Api-Key"}) {
		t.Fatalf("header part not canonical: %+v", login.Parts[1])
	}
	// A shadow rule records that a penalty would start but never blocks.
	if !shadow.Shadow || shadow.Params.Penalty != 0 || shadow.Params.Burst != 9 {
		t.Fatalf("shadow %+v", shadow)
	}
	if k := login.Key(AppendIP(nil, mustAddr("192.0.2.1"))); k[:len("rl:sliding_window:60000:login:{")] != "rl:sliding_window:60000:login:{" || k[len(k)-1] != '}' {
		t.Fatalf("key %q", k)
	}
	if login.Params.Algo.String() != "sliding_window" {
		t.Fatal(login.Params.Algo.String())
	}
}

// A name validation accepts but Compile can't map would silently run as
// fixed_window or key on the client IP.
func TestCompileKnowsEveryValidatedName(t *testing.T) {
	if got := slices.Sorted(maps.Keys(algoOf)); !slices.Equal(got, slices.Sorted(slices.Values(snapshot.Algorithms))) {
		t.Errorf("algorithms %v, validation accepts %v", got, snapshot.Algorithms)
	}
	if got := slices.Sorted(maps.Keys(partKinds)); !slices.Equal(got, slices.Sorted(slices.Values(snapshot.KeyKinds))) {
		t.Errorf("key kinds %v, validation accepts %v", got, snapshot.KeyKinds)
	}
	if got := slices.Sorted(maps.Keys(onMissingOf)); !slices.Equal(got, slices.Sorted(slices.Values(snapshot.OnMissingKeys))) {
		t.Errorf("on_missing_key %v, validation accepts %v", got, snapshot.OnMissingKeys)
	}
	if got := slices.Sorted(maps.Keys(shadowOf)); !slices.Equal(got, slices.Sorted(slices.Values(snapshot.Actions))) {
		t.Errorf("actions %v, validation accepts %v", got, snapshot.Actions)
	}
	if got := slices.Sorted(maps.Keys(failModeOf)); !slices.Equal(got, slices.Sorted(slices.Values(snapshot.FailModes))) {
		t.Errorf("fail modes %v, validation accepts %v", got, snapshot.FailModes)
	}
}
