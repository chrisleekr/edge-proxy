package ratelimit

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

const numShards = 64

type expiring interface{ expiry() int64 }

// table is a sharded map with a fixed capacity. A shard lock covers only a
// map operation; when a shard is full new keys are refused, never evicted
// in a way an attacker could steer.
type table[K comparable, V expiring] struct {
	shards   [numShards]shard[K, V]
	perShard int
	hash     func(K) uint64
}

type shard[K comparable, V expiring] struct {
	mu sync.RWMutex
	m  map[K]V
}

func newTable[K comparable, V expiring](maxEntries int, hash func(K) uint64) *table[K, V] {
	t := &table[K, V]{perShard: (maxEntries + numShards - 1) / numShards, hash: hash}
	for i := range t.shards {
		t.shards[i].m = map[K]V{}
	}
	return t
}

func (t *table[K, V]) shard(k K) *shard[K, V] { return &t.shards[t.hash(k)%numShards] }

func (t *table[K, V]) get(k K) (V, bool) {
	s := t.shard(k)
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[k]
	return v, ok
}

// getOrAdd returns the entry for k, adding mk() if absent. It reports false
// when k is absent and its shard is full. An entry is never replaced, even
// when expired, so concurrent requests for one subject always share it.
func (t *table[K, V]) getOrAdd(k K, mk func() V) (V, bool) {
	if v, ok := t.get(k); ok {
		return v, true
	}
	s := t.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k] // another request may have added it since get
	if !ok {
		if len(s.m) >= t.perShard {
			return v, false
		}
		v = mk()
		s.m[k] = v
	}
	return v, true
}

// put sets k unless k is new and its shard is full.
func (t *table[K, V]) put(k K, v V) bool {
	s := t.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[k]; !ok && len(s.m) >= t.perShard {
		return false
	}
	s.m[k] = v
	return true
}

// sweep drops expired entries, one shard at a time, off the request path. A
// request already holding a swept bucket finishes on it; its subject had
// expired, so it starts fresh either way.
func (t *table[K, V]) sweep(now int64) {
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for k, v := range s.m {
			if v.expiry() <= now {
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
}

func (t *table[K, V]) len() int {
	n := 0
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		n += len(s.m)
		s.mu.RUnlock()
	}
	return n
}

var seed = maphash.MakeSeed()

func hashString(k string) uint64 { return maphash.String(seed, k) }

func hashAddr(k netip.Addr) uint64 {
	b := k.As16()
	return maphash.Bytes(seed, b[:])
}

// bucket is one subject's state. It locks only itself, so requests from
// different subjects never wait on each other.
type bucket struct {
	mu  sync.Mutex
	s   State
	exp atomic.Int64
}

func (b *bucket) expiry() int64 { return b.exp.Load() }

// Local runs the algorithms in process: for fail_mode local and the backstop.
type Local[K comparable] struct{ t *table[K, *bucket] }

func newLocal[K comparable](maxEntries int, hash func(K) uint64) *Local[K] {
	return &Local[K]{t: newTable[K, *bucket](maxEntries, hash)}
}

// NewLocalStore holds per-rule state while Valkey is unavailable.
func NewLocalStore(maxEntries int) *Local[string] { return newLocal(maxEntries, hashString) }

// Take applies one request. tracked is false when the store is full; the
// caller then lets the request pass.
func (l *Local[K]) Take(k K, p Params, now int64) (r Result, tracked bool) {
	b, ok := l.t.getOrAdd(k, func() *bucket { return &bucket{} })
	if !ok {
		return Result{Allowed: true, Now: now}, false
	}
	b.mu.Lock()
	if b.exp.Load() <= now {
		b.s = State{} // new, or expired while still in the map
	}
	r, ttl := Step(p, &b.s, now)
	if ttl > 0 {
		b.exp.Store(now + ttl)
	}
	b.mu.Unlock()
	return r, true
}

// Sweep drops expired subjects.
func (l *Local[K]) Sweep(now int64) { l.t.sweep(now) }

// Len counts tracked subjects, for metrics.
func (l *Local[K]) Len() int { return l.t.len() }

type until int64

func (u until) expiry() int64 { return int64(u) }

// Penalties is each replica's copy of active penalties, so a
// blocked subject costs no Valkey call.
type Penalties struct{ t *table[string, until] }

// NewPenalties returns an empty cache holding at most maxEntries penalties.
func NewPenalties(maxEntries int) *Penalties {
	return &Penalties{t: newTable[string, until](maxEntries, hashString)}
}

// Until returns when the penalty on key ends, or 0 if none is active.
func (p *Penalties) Until(key string, now int64) int64 {
	if u, _ := p.t.get(key); int64(u) > now {
		return int64(u)
	}
	return 0
}

// Block records a penalty and reports whether it fit. When the cache is
// full it is not recorded: for a Valkey rule, Valkey still enforces it; for
// a count rule this cache is the only enforcement, so the subject is not
// refused. That is fail-open by design, and callers count the drop.
func (p *Penalties) Block(key string, end int64) bool { return p.t.put(key, until(end)) }

// Sweep drops penalties that have ended.
func (p *Penalties) Sweep(now int64) { p.t.sweep(now) }

// Len counts cached penalties, for metrics.
func (p *Penalties) Len() int { return p.t.len() }

// Backstop is the per-replica, per-IP token bucket.
type Backstop struct {
	Config snapshot.Backstop
	p      Params
	l      *Local[netip.Addr]
}

// NewBackstop returns a backstop with no IPs tracked yet.
func NewBackstop(c snapshot.Backstop) *Backstop {
	return &Backstop{
		Config: c,
		p:      Params{Algo: TokenBucket, Limit: c.Limit, Burst: c.Burst, Period: ms(c.Period)},
		l:      newLocal(c.MaxEntries, hashAddr),
	}
}

// Allow reports whether ip is under the backstop. A new IP when the table is
// full is untracked and passes: one shared overflow bucket would throttle
// innocent clients together.
func (b *Backstop) Allow(ip netip.Addr, now time.Time) (r Result, tracked bool) {
	if ip.Is6() {
		ip = netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return b.l.Take(ip, b.p, now.UnixMilli())
}

// Sweep drops IPs whose buckets have expired.
func (b *Backstop) Sweep(now time.Time) { b.l.Sweep(now.UnixMilli()) }

// Len counts tracked IPs, for metrics.
func (b *Backstop) Len() int { return b.l.Len() }
