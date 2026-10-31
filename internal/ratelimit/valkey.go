package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"
)

var (
	// ErrNotConnected means no Valkey client exists yet; the connect loop
	// keeps trying in the background.
	ErrNotConnected = errors.New("valkey not connected")
	// ErrBreakerOpen means the call's node failed repeatedly and is being
	// skipped for a cool-down.
	ErrBreakerOpen = errors.New("valkey node breaker open")
)

// Breaker tuning. Consecutive failures, rather than an error ratio over a
// window, keep the breaker to three atomics with no lock or ring buffer.
const (
	breakerFailures = 5
	breakerCooldown = time.Second
	refreshEvery    = 5 * time.Second
)

// Call is one rate-limit check for the batch.
type Call struct {
	Key string
	P   Params
	// Bit is the value's DistinctBit, for Distinct.
	Bit int64
}

// Outcome is one call's decision, or the error that sends it to the rule's
// fail_mode.
type Outcome struct {
	Result
	Err error
}

// Valkey sends each request's rate-limit calls as one pipelined batch. Calls
// are never retried: a call consumes quota, so a timeout is ambiguous.
// Redirects and NOSCRIPT are safe to resend because the
// script did not run.
type Valkey struct {
	opt     valkey.ClientOption
	timeout time.Duration
	log     *slog.Logger
	client  atomic.Pointer[client]
	topo    atomic.Pointer[topology]
	// loaded holds nodes that took every script. Only Connect uses it, and
	// Connect never runs concurrently: warm-up first, then Run.
	loaded map[string]bool
}

type client struct{ valkey.Client }

// NewValkey takes options from valkey.ParseURL (standalone, Sentinel via
// master_set, Cluster via extra addr parameters, TLS with rediss://). It
// does not connect; Connect and Run do.
func NewValkey(opt valkey.ClientOption, timeout time.Duration, log *slog.Logger) *Valkey {
	// Retrying a quota-consuming EVALSHA could spend quota twice. valkey-go
	// already retries only read-only commands; this makes it explicit.
	opt.DisableRetry = true
	opt.DisableCache = true
	return &Valkey{opt: opt, timeout: timeout, log: log}
}

// Connect makes one connection attempt, reads the slot map and loads the
// scripts on every node. It is used before ready (bounded) and by Run.
func (v *Valkey) Connect(ctx context.Context) error {
	c := v.client.Load()
	if c == nil {
		nc, err := valkey.NewClient(v.opt)
		if err != nil {
			return err
		}
		c = &client{nc}
		v.client.Store(c)
	}
	// The slot map comes first and never depends on scripts loading, so a
	// node that refuses SCRIPT LOAD can't leave breakers on a stale map.
	if err := v.refresh(ctx, c); err != nil {
		return err
	}
	// Preloading avoids the NOSCRIPT fallback's second round trip. Each node
	// is loaded once: one that loses its scripts later (failover, restart)
	// gets them back through the fallback, because EVAL caches the script.
	loaded := make(map[string]bool, len(v.loaded))
	for addr, n := range c.Nodes() {
		if !v.loaded[addr] {
			for _, s := range scripts {
				if err := n.Do(ctx, n.B().ScriptLoad().Script(s.src).Build()).Error(); err != nil {
					return fmt.Errorf("script load: %w", err)
				}
			}
		}
		loaded[addr] = true
	}
	// Only current nodes, so it stays bounded.
	v.loaded = loaded
	return nil
}

// Run connects and keeps the slot map current until ctx ends.
func (v *Valkey) Run(ctx context.Context) {
	t := time.NewTicker(refreshEvery)
	defer t.Stop()
	for {
		if err := v.Connect(ctx); err != nil && ctx.Err() == nil {
			v.log.Warn("valkey unavailable", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			if c := v.client.Load(); c != nil {
				c.Close()
			}
			return
		case <-t.C:
		}
	}
}

// Do runs calls in one pipelined batch and fills out, which has len(calls).
func (v *Valkey) Do(calls []Call, out []Outcome) {
	// Both exist once a connect attempt has read the slot map.
	c, topo := v.client.Load(), v.topo.Load()
	if c == nil || topo == nil {
		for i := range calls {
			out[i] = Outcome{Err: ErrNotConnected}
		}
		return
	}
	now := time.Now().UnixNano()
	var (
		bufCmds [8]valkey.Completed
		bufIdx  [8]int
		bufBr   [8]*breaker
	)
	cmds, idx, brs := bufCmds[:0], bufIdx[:0], bufBr[:0]
	for i, call := range calls {
		br := topo.breaker(call.Key)
		if !br.allow(now) {
			out[i] = Outcome{Err: ErrBreakerOpen}
			continue
		}
		cmds = append(cmds, evalsha(c, call))
		idx, brs = append(idx, i), append(brs, br)
	}
	if len(cmds) == 0 {
		return
	}
	// Not the request's context: a client hanging up must not count as a
	// node failure.
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()
	resps := c.DoMulti(ctx, cmds...)
	var bufRetry [8]int
	retry := bufRetry[:0]
	for k, resp := range resps {
		if verr, ok := errors.AsType[*valkey.ValkeyError](resp.Error()); ok && verr.IsNoScript() {
			retry = append(retry, k)
			continue
		}
		out[idx[k]] = parse(resp, brs[k], now)
	}
	if len(retry) == 0 {
		return
	}
	cmds = cmds[:0]
	for _, k := range retry {
		cmds = append(cmds, eval(c, calls[idx[k]]))
	}
	for j, resp := range c.DoMulti(ctx, cmds...) {
		k := retry[j]
		out[idx[k]] = parse(resp, brs[k], now)
	}
}

// args is one call's ARGV. An array, not a slice: Arg copies its arguments,
// so the array stays on the stack. Distinct takes no burst, so its bit goes
// in that place.
func args(call Call) [4]string {
	p, third := call.P, call.P.Burst
	if p.Algo == Distinct {
		third = call.Bit
	}
	return [4]string{strconv.FormatInt(p.Limit, 10), strconv.FormatInt(p.Period, 10), strconv.FormatInt(third, 10), strconv.FormatInt(p.Penalty, 10)}
}

func evalsha(c *client, call Call) valkey.Completed {
	a := args(call)
	return c.B().Evalsha().Sha1(scripts[call.P.Algo].sha).Numkeys(1).Key(call.Key).Arg(a[:]...).Build()
}

// eval sends the script source after NOSCRIPT. The source is one of the
// constant scripts above; no request data reaches it except as KEYS/ARGV.
func eval(c *client, call Call) valkey.Completed {
	a := args(call)
	return c.B().Eval().Script(scripts[call.P.Algo].src).Numkeys(1).Key(call.Key).Arg(a[:]...).Build()
}

func parse(resp valkey.ValkeyResult, br *breaker, now int64) Outcome {
	v, err := resp.AsIntSlice()
	if err != nil {
		br.failure(now)
		return Outcome{Err: err}
	}
	br.success()
	return Outcome{Allowed: v[0] == 1, Remaining: v[1], Reset: v[2], Retry: v[3], Now: v[4], Blocked: v[5]}
}

// breaker opens after breakerFailures consecutive failures, skips its node
// for breakerCooldown, then lets one probe through.
type breaker struct {
	fails     atomic.Int32
	openUntil atomic.Int64 // unix ns; 0 when closed
	probing   atomic.Bool
}

func (b *breaker) allow(now int64) bool {
	u := b.openUntil.Load()
	if u == 0 {
		return true
	}
	if now < u {
		return false
	}
	return b.probing.CompareAndSwap(false, true)
}

func (b *breaker) success() {
	b.fails.Store(0)
	b.openUntil.Store(0)
	b.probing.Store(false)
}

func (b *breaker) failure(now int64) {
	if b.probing.Load() || b.fails.Add(1) >= breakerFailures {
		b.openUntil.Store(now + int64(breakerCooldown))
		b.probing.Store(false)
	}
}

// topology maps hash slots to per-node breakers, so one failed shard
// affects only the keys on it. valkey-go keeps its own slot map private;
// this one is read with CLUSTER SLOTS off the request path.
type topology struct {
	slots [16384]uint16
	nodes []*breaker
	addrs []string
}

func (t *topology) breaker(key string) *breaker { return t.nodes[t.slots[slot(key)]] }

// refresh reads the slot map, keeping breaker state for nodes that remain.
func (v *Valkey) refresh(ctx context.Context, c *client) error {
	old := v.topo.Load()
	t := &topology{}
	if c.Mode() != valkey.ClientModeCluster {
		t.addrs = []string{"single"}
	} else {
		ranges, err := c.Do(ctx, c.B().ClusterSlots().Build()).ToArray()
		if err != nil {
			return fmt.Errorf("cluster slots: %w", err)
		}
		at := map[string]uint16{}
		// Each range is [start, end, [host, port, id], replicas...].
		for _, r := range ranges {
			f, _ := r.ToArray()
			lo, _ := f[0].AsInt64()
			hi, _ := f[1].AsInt64()
			node, _ := f[2].ToArray()
			host, _ := node[0].ToString()
			port, _ := node[1].AsInt64()
			addr := host + ":" + strconv.FormatInt(port, 10)
			n, ok := at[addr]
			if !ok {
				n = uint16(len(t.addrs)) //nolint:gosec // a cluster has at most 16384 primaries, one per slot
				at[addr] = n
				t.addrs = append(t.addrs, addr)
			}
			for s := lo; s <= hi; s++ {
				t.slots[s] = n
			}
		}
	}
	for _, a := range t.addrs {
		br := &breaker{}
		if old != nil {
			for i, oa := range old.addrs {
				if oa == a {
					br = old.nodes[i]
				}
			}
		}
		t.nodes = append(t.nodes, br)
	}
	v.topo.Store(t)
	return nil
}

// slot is the Valkey Cluster hash slot: CRC16-XMODEM of the hash tag if the
// key has a non-empty one, else of the key, mod 16384.
func slot(key string) uint16 {
	if i := strings.IndexByte(key, '{'); i >= 0 {
		if j := strings.IndexByte(key[i+1:], '}'); j > 0 {
			key = key[i+1 : i+1+j]
		}
	}
	var crc uint16
	for i := 0; i < len(key); i++ {
		crc ^= uint16(key[i]) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc % 16384
}
