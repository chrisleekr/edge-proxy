package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

var quiet = slog.New(slog.DiscardHandler)

// mode is one way to deploy Valkey; every integration test runs on both.
type mode struct {
	name  string
	addrs func(t *testing.T) []string
}

var modes = []mode{
	{"standalone", func(t *testing.T) []string { t.Helper(); return []string{testenv.Valkey(t)} }},
	{"cluster", func(t *testing.T) []string { t.Helper(); return testenv.ValkeyCluster(t).Addrs }},
}

func connect(t *testing.T, addrs []string, timeout time.Duration) *Valkey {
	t.Helper()
	v := NewValkey(valkey.ClientOption{InitAddress: addrs}, timeout, quiet)
	if err := v.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.client.Load().Close() })
	return v
}

func rawClient(t *testing.T, addrs []string) valkey.Client {
	t.Helper()
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: addrs, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func uniqueKey(t *testing.T, tag string) string {
	t.Helper()
	return fmt.Sprintf("rl:test:%s:{%s-%d}", t.Name(), tag, time.Now().UnixNano())
}

// The Lua scripts and Step are the same algorithm: for random parameters and
// arrival times, each call's decision, the stored state and the TTL match
// the model applied at the server's own clock.
func TestLuaMatchesModel(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			addrs := m.addrs(t)
			v := connect(t, addrs, time.Second)
			raw := rawClient(t, addrs)
			for a := range numAlgos {
				if a == Distinct {
					continue // no Go model; TestDistinctEstimateTracksAnExactCount covers it
				}
				for run := range 3 {
					t.Run(fmt.Sprint(a, run), func(t *testing.T) {
						t.Parallel()
						rng := rand.New(rand.NewPCG(uint64(a), uint64(run)))
						p := Params{Algo: a, Limit: 2 + rng.Int64N(7), Period: 1000}
						if a == TokenBucket || a == LeakyBucket {
							p.Burst = 1 + rng.Int64N(8)
						}
						if run == 2 {
							p.Penalty = 500 + rng.Int64N(500)
						}
						checkAgainstModel(t, v, raw, p, uniqueKey(t, a.String()), rng, 40)
					})
				}
			}
			t.Run("largest bucket validation admits", func(t *testing.T) {
				t.Parallel()
				// One token a day, so the key lives long enough to read back.
				big := Params{Algo: TokenBucket, Limit: 1, Burst: snapshot.MaxExact / 86_400_000, Period: 86_400_000}
				checkAgainstModel(t, v, raw, big, uniqueKey(t, "big"), rand.New(rand.NewPCG(1, 1)), 20)
			})
		})
	}
}

func checkAgainstModel(t *testing.T, v *Valkey, raw valkey.Client, p Params, key string, rng *rand.Rand, steps int) {
	t.Helper()
	ctx := t.Context()
	for i := range steps {
		before := readState(t, raw, key)
		out := make([]Outcome, 1)
		v.Do([]Call{{Key: key, P: p}}, out)
		if out[0].Err != nil {
			t.Fatal(out[0].Err)
		}
		got := out[0].Result
		model := before
		want, ttl := Step(p, &model, got.Now)
		if got != want {
			t.Fatalf("%s %+v step %d: valkey %+v, model %+v (state before %+v)", key, p, i, got, want, before)
		}
		after := readState(t, raw, key)
		pttl, err := raw.Do(ctx, raw.B().Pttl().Key(key).Build()).AsInt64()
		switch {
		case err != nil:
			t.Fatal(err)
		case !after.Set || pttl == -2:
			// The key is gone. That is right only once the server's own
			// clock has reached the expiry the model predicts: got.Now +
			// ttl, or the penalty end when nothing was written. Reading
			// server time also tolerates the Docker VM's clock jumping.
			expires := got.Now + ttl
			if ttl == 0 {
				expires = got.Blocked
			}
			if now := serverNow(t, raw); now < expires {
				t.Fatalf("%s step %d: key gone at %d, model expiry %d (state %+v)", key, i, now, expires, model)
			}
		case after != model:
			t.Fatalf("%s step %d: valkey state %+v, model %+v", key, i, after, model)
		case ttl == 0 && pttl < got.Blocked-got.Now-1000:
			t.Fatalf("%s step %d: key expires %dms before its penalty ends", key, i, got.Blocked-got.Now-pttl)
		case ttl > 0 && (pttl > ttl || pttl < ttl-1000):
			t.Fatalf("%s step %d: pttl %d, model ttl %d", key, i, pttl, ttl)
		}
		// Up to half a refill interval (at most 250ms), so windows roll and
		// buckets refill.
		time.Sleep(time.Duration(rng.Int64N(min(max(p.Period/p.Limit/2, 1), 250))) * time.Millisecond)
	}
}

func serverNow(t *testing.T, raw valkey.Client) int64 {
	t.Helper()
	ts, err := raw.Do(t.Context(), raw.B().Time().Build()).AsStrSlice()
	if err != nil {
		t.Fatal(err)
	}
	sec, _ := strconv.ParseInt(ts[0], 10, 64)
	usec, _ := strconv.ParseInt(ts[1], 10, 64)
	return sec*1000 + usec/1000
}

func readState(t *testing.T, raw valkey.Client, key string) State {
	t.Helper()
	vals, err := raw.Do(t.Context(), raw.B().Hmget().Key(key).Field("a", "b", "c", "x").Build()).ToArray()
	if err != nil {
		t.Fatal(err)
	}
	var s State
	for i, f := range []*int64{&s.A, &s.B, &s.C, &s.X} {
		str, err := vals[i].ToString()
		if err != nil {
			return State{} // key absent
		}
		*f, _ = strconv.ParseInt(str, 10, 64)
		s.Set = true
	}
	return s
}

// Several edges share one quota: concurrent calls from separate clients
// admit exactly the limit.
func TestSharedQuotaAcrossEdges(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			addrs := m.addrs(t)
			edges := []*Valkey{connect(t, addrs, time.Second), connect(t, addrs, time.Second), connect(t, addrs, time.Second), connect(t, addrs, time.Second)}
			for a := range numAlgos {
				p := Params{Algo: a, Limit: 100, Burst: 100, Period: 60_000}
				if a == FixedWindow || a == SlidingWindow {
					p.Burst = 0
				}
				// A fixed window admits up to twice its limit across a
				// boundary, so the run must not span one.
				if left := p.Period - time.Now().UnixMilli()%p.Period; a == FixedWindow && left < 3000 {
					time.Sleep(time.Duration(left+50) * time.Millisecond)
				}
				key := uniqueKey(t, a.String())
				var allowed atomic.Int64
				var wg sync.WaitGroup
				for i := range 400 {
					wg.Go(func() {
						out := make([]Outcome, 1)
						// distinct counts values, so each call brings a new one.
						edges[i%len(edges)].Do([]Call{{Key: key, P: p, Bit: DistinctBit(strconv.Itoa(i))}}, out)
						if out[0].Err != nil {
							t.Error(out[0].Err)
						}
						if out[0].Allowed {
							allowed.Add(1)
						}
					})
				}
				wg.Wait()
				// Token and leaky buckets refill during the run, at most
				// a few tokens at 100 per minute. distinct estimates its
				// count, within a few values at 100.
				lo, hi := int64(100), int64(102)
				if a == Distinct {
					lo, hi = 92, 108
				}
				if n := allowed.Load(); n < lo || n > hi {
					t.Fatalf("%s: %d allowed across 4 edges, want 100", a, n)
				}
			}
		})
	}
}

// After a node restart or SCRIPT FLUSH, EVALSHA fails with NOSCRIPT; the
// batch resends that call with EVAL, which is safe because it never ran.
func TestScriptCacheLoss(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			addrs := m.addrs(t)
			v := connect(t, addrs, time.Second)
			raw := rawClient(t, addrs)
			for _, n := range raw.Nodes() {
				if err := n.Do(t.Context(), n.B().ScriptFlush().Build()).Error(); err != nil {
					t.Fatal(err)
				}
			}
			key := uniqueKey(t, "flush")
			p := Params{Algo: SlidingWindow, Limit: 2, Period: 60_000}
			calls := []Call{{Key: key, P: p}, {Key: key, P: p}, {Key: key, P: p}}
			out := make([]Outcome, 3)
			v.Do(calls, out)
			for i, want := range []bool{true, true, false} {
				if out[i].Err != nil || out[i].Allowed != want {
					t.Fatalf("call %d: %+v, want allowed=%v", i, out[i], want)
				}
			}
		})
	}
}

// Run reconnects every few seconds to keep the slot map current. A node that
// already took the scripts doesn't get them again on each reconnect.
func TestReconnectSkipsLoadedScripts(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			addrs := m.addrs(t)
			v := connect(t, addrs, time.Second)
			raw := rawClient(t, addrs)
			before := scriptLoads(t, raw)
			if err := v.Connect(t.Context()); err != nil {
				t.Fatal(err)
			}
			if after := scriptLoads(t, raw); after != before {
				t.Fatalf("reconnect sent %d SCRIPT LOAD commands, want 0", after-before)
			}
		})
	}
}

// scriptLoads sums SCRIPT LOAD calls across every node, from INFO commandstats.
func scriptLoads(t *testing.T, raw valkey.Client) int {
	t.Helper()
	total := 0
	for _, n := range raw.Nodes() {
		info, err := n.Do(t.Context(), n.B().Info().Section("commandstats").Build()).ToString()
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.Lines(info) {
			if rest, ok := strings.CutPrefix(line, "cmdstat_script|load:calls="); ok {
				calls, _, _ := strings.Cut(rest, ",")
				c, err := strconv.Atoi(calls)
				if err != nil {
					t.Fatal(err)
				}
				total += c
			}
		}
	}
	return total
}

// One failed shard affects only its keys. Calls to it fail until its breaker
// opens, then fail fast; keys on other shards are unaffected. When the node
// returns, one probe closes the breaker.
func TestFailedShardTripsOnlyItsBreaker(t *testing.T) {
	cl := testenv.ValkeyCluster(t)
	v := connect(t, cl.Addrs, 200*time.Millisecond)
	topo := v.topo.Load()
	if len(topo.nodes) != 3 {
		t.Fatalf("topology has %d nodes", len(topo.nodes))
	}
	// One key on each node.
	keys := make([]string, 3)
	for i := 0; keys[0] == "" || keys[1] == "" || keys[2] == ""; i++ {
		k := fmt.Sprintf("rl:test:shard:{%d}", i)
		if n := topo.slots[slot(k)]; keys[n] == "" {
			keys[n] = k
		}
	}
	p := Params{Algo: FixedWindow, Limit: 1_000_000, Period: 60_000}
	call := func(node int) Outcome {
		out := make([]Outcome, 1)
		v.Do([]Call{{Key: keys[node], P: p}}, out)
		return out[0]
	}

	cl.Stop(t, 1)
	stopped := true
	defer func() {
		if stopped {
			cl.Start(t, 1)
		}
	}()
	for i := range breakerFailures {
		if o := call(1); o.Err == nil || errors.Is(o.Err, ErrBreakerOpen) {
			t.Fatalf("call %d to the stopped node: %v", i, o.Err)
		}
	}
	start := time.Now()
	if o := call(1); !errors.Is(o.Err, ErrBreakerOpen) || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("breaker did not fail fast: %v after %s", o.Err, time.Since(start))
	}
	for _, n := range []int{0, 2} {
		if o := call(n); o.Err != nil || !o.Allowed {
			t.Fatalf("healthy node %d affected: %+v", n, o)
		}
	}

	cl.Start(t, 1)
	stopped = false
	time.Sleep(breakerCooldown)
	deadline := time.Now().Add(30 * time.Second)
	for {
		o := call(1)
		if o.Err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("node never recovered: %v", o.Err)
		}
		time.Sleep(breakerCooldown)
	}
	if o := call(1); o.Err != nil {
		t.Fatalf("breaker still open after a good probe: %v", o.Err)
	}
}

// An edge whose Valkey is down starts anyway: calls fail fast into each
// rule's fail_mode, and the connect loop keeps trying until shutdown.
func TestUnreachableValkey(t *testing.T) {
	v := NewValkey(valkey.ClientOption{InitAddress: []string{"127.0.0.1:1"}}, time.Second, quiet)
	out := make([]Outcome, 2)
	v.Do([]Call{{Key: "a"}, {Key: "b"}}, out)
	if !errors.Is(out[0].Err, ErrNotConnected) || !errors.Is(out[1].Err, ErrNotConnected) {
		t.Fatalf("outcomes %+v", out)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { v.Run(ctx); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
}

// Run connects, keeps the topology, and returns promptly on shutdown,
// closing the client.
func TestRunConnectsAndCloses(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			v := NewValkey(valkey.ClientOption{InitAddress: m.addrs(t)}, time.Second, quiet)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { v.Run(ctx); close(done) }()
			for v.topo.Load() == nil {
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("Run did not return after shutdown")
			}
		})
	}
}

// If the slot map can't be read on the first connect, calls fail fast into
// their fail_mode instead of crashing the request.
func TestConnectedWithoutSlotMap(t *testing.T) {
	v := NewValkey(valkey.ClientOption{InitAddress: testenv.ValkeyCluster(t).Addrs}, time.Second, quiet)
	if err := v.Connect(canceledCtx()); err == nil {
		t.Fatal("connect with a cancelled context succeeded")
	}
	t.Cleanup(func() { v.client.Load().Close() })
	out := make([]Outcome, 1)
	v.Do([]Call{{Key: uniqueKey(t, "nomap"), P: Params{Algo: FixedWindow, Limit: 1, Period: 1000}}}, out)
	if !errors.Is(out[0].Err, ErrNotConnected) {
		t.Fatalf("outcome %+v", out[0])
	}
	// The next attempt reads the map and calls work.
	if err := v.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	v.Do([]Call{{Key: uniqueKey(t, "nomap"), P: Params{Algo: FixedWindow, Limit: 1, Period: 1000}}}, out)
	if out[0].Err != nil || !out[0].Allowed {
		t.Fatalf("outcome after reconnect %+v", out[0])
	}
}

// A node that refuses SCRIPT LOAD (an ACL without it) doesn't stop the slot
// map from being read; calls still work through the EVAL fallback.
func TestScriptLoadRefused(t *testing.T) {
	addr := testenv.Valkey(t)
	raw := rawClient(t, []string{addr})
	if err := raw.Do(t.Context(), raw.B().AclSetuser().Username("noload").Rule("on", ">pw", "~*", "+@all", "-script|load").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	v := NewValkey(valkey.ClientOption{InitAddress: []string{addr}, Username: "noload", Password: "pw"}, time.Second, quiet)
	if err := v.Connect(t.Context()); err == nil {
		t.Fatal("refused SCRIPT LOAD not reported")
	}
	t.Cleanup(func() { v.client.Load().Close() })
	if v.topo.Load() == nil {
		t.Fatal("slot map not read after SCRIPT LOAD failed")
	}
	if err := raw.Do(t.Context(), raw.B().ScriptFlush().Build()).Error(); err != nil {
		t.Fatal(err)
	}
	out := make([]Outcome, 1)
	v.Do([]Call{{Key: uniqueKey(t, "noload"), P: Params{Algo: FixedWindow, Limit: 1, Period: 1000}}}, out)
	if out[0].Err != nil || !out[0].Allowed {
		t.Fatalf("outcome %+v", out[0])
	}
}

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// Shutdown can arrive mid-connect. The attempt fails and the previous
// topology stays in use. A standalone reconnect has no I/O left to interrupt
// once the scripts are loaded.
func TestConnectInterruptedByShutdown(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			v := connect(t, m.addrs(t), time.Second)
			before := v.topo.Load()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := v.Connect(ctx); m.name == "cluster" && err == nil {
				t.Fatal("connect with a cancelled context succeeded")
			}
			if err := v.refresh(ctx, v.client.Load()); m.name == "cluster" && err == nil {
				t.Fatal("refresh with a cancelled context succeeded")
			}
			if m.name == "cluster" && v.topo.Load() != before {
				t.Fatal("failed refresh replaced the topology")
			}
		})
	}
}

// One request's batch per algorithm against real Valkey: the round trip
// the request path pays.
func BenchmarkScripts(b *testing.B) {
	addr := testenv.Valkey(b)
	v := NewValkey(valkey.ClientOption{InitAddress: []string{addr}}, time.Second, quiet)
	if err := v.Connect(b.Context()); err != nil {
		b.Fatal(err)
	}
	defer v.client.Load().Close()
	for a := range numAlgos {
		b.Run(a.String(), func(b *testing.B) {
			calls := []Call{{Key: fmt.Sprintf("rl:bench:{%s-%d}", a, time.Now().UnixNano()), P: Params{Algo: a, Limit: 1 << 30, Burst: 1 << 20, Period: 1000}}}
			out := make([]Outcome, 1)
			b.ReportAllocs()
			for b.Loop() {
				v.Do(calls, out)
				if out[0].Err != nil {
					b.Fatal(out[0].Err)
				}
			}
		})
	}
}

// The distinct script's count follows an exact count of distinct values
// closely enough for limits up to snapshot.MaxDistinct: a crawler is
// refused near its limit, never far before it. Repeating a value adds
// nothing, and the window resets the count.
func TestDistinctEstimateTracksAnExactCount(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			v := connect(t, m.addrs(t), time.Second)
			key := uniqueKey(t, "distinct")
			p := Params{Algo: Distinct, Limit: snapshot.MaxDistinct, Period: 60_000}
			call := func(value string) Result {
				t.Helper()
				out := make([]Outcome, 1)
				v.Do([]Call{{Key: key, P: p, Bit: DistinctBit(value)}}, out)
				if out[0].Err != nil {
					t.Fatal(out[0].Err)
				}
				return out[0].Result
			}
			var worst float64
			for n := int64(1); n <= snapshot.MaxDistinct; n++ {
				r := call(fmt.Sprintf("/products/%d", n))
				if !r.Allowed {
					// Over 1000 means at least 10% over the exact count here.
					if n < snapshot.MaxDistinct*9/10 {
						t.Fatalf("refused at %d distinct values, limit %d", n, p.Limit)
					}
					continue
				}
				est := p.Limit - r.Remaining
				// Exact for a handful, then within 10%: linear counting's
				// standard error at 1000 values in 1024 bits is about 3%.
				if d := float64(est - n); d < -max(1, 0.1*float64(n)) || d > max(1, 0.1*float64(n)) {
					t.Fatalf("estimate %d for %d distinct values", est, n)
				} else if n >= 10 {
					worst = max(worst, max(d, -d)/float64(n))
				}
				if n == 3 {
					if again := call("/products/1"); again.Remaining != r.Remaining {
						t.Fatalf("a repeated value changed the count: remaining %d, then %d", r.Remaining, again.Remaining)
					}
				}
			}
			t.Logf("worst relative error from 10 values: %.3f", worst)

			short := Params{Algo: Distinct, Limit: 2, Period: 1000}
			key = uniqueKey(t, "window")
			for i, want := range []bool{true, true, false} {
				out := make([]Outcome, 1)
				v.Do([]Call{{Key: key, P: short, Bit: DistinctBit(fmt.Sprint(i))}}, out)
				if out[0].Err != nil || out[0].Allowed != want {
					t.Fatalf("value %d: %+v", i, out[0])
				}
			}
			time.Sleep(1100 * time.Millisecond)
			out := make([]Outcome, 1)
			v.Do([]Call{{Key: key, P: short, Bit: DistinctBit("3")}}, out)
			if out[0].Err != nil || !out[0].Allowed || out[0].Remaining != 1 {
				t.Fatalf("after the window: %+v", out[0])
			}
		})
	}
}

// A distinct subject over its limit with a penalty stays refused until the
// penalty ends, even after its window resets, and the key lives as long as
// the penalty. A call during the penalty returns early: it changes neither
// the penalty end nor the TTL.
func TestDistinctPenaltyOutlivesTheWindow(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			addrs := m.addrs(t)
			v := connect(t, addrs, time.Second)
			raw := rawClient(t, addrs)
			key := uniqueKey(t, "penalty")
			p := Params{Algo: Distinct, Limit: 1, Period: 300, Penalty: 1500}
			call := func(value string) Outcome {
				t.Helper()
				out := make([]Outcome, 1)
				v.Do([]Call{{Key: key, P: p, Bit: DistinctBit(value)}}, out)
				if out[0].Err != nil {
					t.Fatal(out[0].Err)
				}
				return out[0]
			}
			pttl := func() int64 {
				t.Helper()
				n, err := raw.Do(t.Context(), raw.B().Pttl().Key(key).Build()).AsInt64()
				if err != nil {
					t.Fatal(err)
				}
				return n
			}

			if first := call("/a"); !first.Allowed {
				t.Fatalf("first value refused: %+v", first)
			}
			over := call("/b")
			if over.Allowed || over.Blocked != over.Now+p.Penalty || over.Retry != p.Penalty {
				t.Fatalf("over the limit: %+v", over)
			}
			if ttl := pttl(); ttl <= p.Period || ttl > p.Penalty {
				t.Fatalf("PTTL %d ms, want the %d ms penalty", ttl, p.Penalty)
			}

			time.Sleep(time.Duration(p.Period+200) * time.Millisecond) // the window has reset
			before := pttl()
			during := call("/c")
			if during.Allowed || during.Blocked != over.Blocked || during.Retry != over.Blocked-during.Now {
				t.Fatalf("during the penalty after the window reset: %+v", during)
			}
			if after := pttl(); after > before {
				t.Fatalf("PTTL went from %d to %d ms: a blocked call extended the penalty", before, after)
			}

			time.Sleep(time.Duration(over.Blocked-during.Now+100) * time.Millisecond)
			if end := call("/d"); !end.Allowed {
				t.Fatalf("after the penalty: %+v", end)
			}
		})
	}
}
