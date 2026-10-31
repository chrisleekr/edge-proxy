// Package ratelimit holds the rate-limit algorithms (Lua for Valkey and the
// same arithmetic in Go for fail_mode local), key building, the Valkey batch
// with its per-node breaker, the local penalty cache and the backstop.
package ratelimit

import (
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// Algo is a rate-limit algorithm.
type Algo uint8

// Algorithms, in the order of snapshot.Algorithms.
const (
	FixedWindow Algo = iota
	SlidingWindow
	TokenBucket
	LeakyBucket
	// Distinct counts distinct values per subject in a Valkey bitmap. It
	// has no Step model: fail_mode local is refused for it.
	Distinct
	numAlgos
)

var algoNames = [numAlgos]string{"fixed_window", "sliding_window", "token_bucket", "leaky_bucket", "distinct"}

func (a Algo) String() string { return algoNames[a] }

// algoOf maps a validated algorithm name. A name missing here would run as
// FixedWindow, so a test checks it matches snapshot.Algorithms.
var algoOf = func() map[string]Algo {
	m := make(map[string]Algo, numAlgos)
	for a, n := range algoNames {
		m[n] = Algo(a)
	}
	return m
}()

func ms(d snapshot.Duration) int64 { return int64(time.Duration(d) / time.Millisecond) }

// Params are one rule's limits in whole milliseconds. snapshot.Compile keeps
// burst × period within MaxExact, so every value below stays exact in a Lua
// double.
type Params struct {
	Algo   Algo
	Limit  int64
	Burst  int64 // token_bucket and leaky_bucket
	Period int64 // ms
	// Penalty is 0 for no penalty and for shadow rules, which never block.
	Penalty int64 // ms
}

func paramsOf(r snapshot.RateLimitRule, shadow bool) Params {
	p := Params{Algo: algoOf[r.Algorithm], Limit: r.Limit, Burst: r.Burst, Period: ms(r.Period)}
	if !shadow {
		p.Penalty = ms(r.Penalty)
	}
	return p
}

// State mirrors the Valkey hash: a, b, c and x (blocked until).
//
//	fixed_window:   A window start, B count
//	sliding_window: A window start, B current count, C previous count
//	token_bucket:   A tokens × period, B last update
//	leaky_bucket:   A level × period, B last update
type State struct {
	Set     bool
	A, B, C int64
	X       int64
}

// Result is one decision. Times are milliseconds.
type Result struct {
	Allowed   bool
	Remaining int64
	Reset     int64 // until the limit fully resets
	Retry     int64 // until a request may pass; 0 when allowed
	Now       int64 // server time the decision used
	// Blocked is the penalty end in server time, 0 when none is active.
	Blocked int64
}

// Step applies one request at time now and returns the decision and the
// key's new TTL, or 0 when a penalty blocked it and nothing changed: the TTL
// set when the penalty started already covers it. It is the exact Go twin of the Lua scripts; the differential
// test against real Valkey holds them together.
func Step(p Params, s *State, now int64) (Result, int64) {
	if s.X > now {
		return Result{Reset: s.X - now, Retry: s.X - now, Now: now, Blocked: s.X}, 0
	}
	s.X = 0 // a finished penalty is forgotten, as when its key expires
	var r Result
	var ttl int64
	r.Now = now
	L, P := p.Limit, p.Period
	switch p.Algo {
	case FixedWindow:
		ws := now - now%P
		if !s.Set || s.A != ws {
			s.A, s.B = ws, 0
		}
		r.Reset = ws + P - now
		if s.B < L {
			s.B++
			r.Allowed, r.Remaining = true, L-s.B
		} else {
			r.Retry = r.Reset
		}
		ttl = r.Reset
	case SlidingWindow:
		ws := now - now%P
		switch {
		case s.Set && s.A == ws:
		case s.Set && s.A == ws-P:
			s.C, s.B = s.B, 0
		default:
			s.B, s.C = 0, 0
		}
		s.A = ws
		// Weight of the previous window in parts per million, so every
		// product stays below 2^53. The weighted count rounds up: rounding
		// down would admit one extra request just after each boundary.
		w := (P - (now - ws)) * 1_000_000 / P
		est := s.B + (s.C*w+999_999)/1_000_000
		r.Reset = ws + P - now
		if est < L {
			s.B++
			r.Allowed, r.Remaining = true, L-est-1
		} else {
			// Upper bound: at the window end the estimate is the current
			// count, so it passes then unless the current count is full;
			// then period/limit later the weight has dropped enough.
			r.Retry = r.Reset
			if s.B >= L {
				r.Retry += (P + L - 1) / L
			}
		}
		ttl = r.Reset + P
	case TokenBucket:
		capacity := p.Burst * P
		if !s.Set {
			s.A, s.B = capacity, now
		}
		el := max(now-s.B, 0)
		if need := capacity - s.A; need <= 0 || el >= (need+L-1)/L {
			s.A = capacity
		} else {
			s.A += el * L
		}
		s.B = now
		if s.A >= P {
			s.A -= P
			r.Allowed, r.Remaining = true, s.A/P
		} else {
			r.Retry = (P - s.A + L - 1) / L
		}
		r.Reset = (capacity - s.A + L - 1) / L
		ttl = r.Reset
	default: // LeakyBucket, as a meter (equivalent to GCRA)
		capacity := p.Burst * P
		if !s.Set {
			s.A, s.B = 0, now
		}
		el := max(now-s.B, 0)
		if s.A <= 0 || el >= (s.A+L-1)/L {
			s.A = 0
		} else {
			s.A -= el * L
		}
		s.B = now
		if s.A+P <= capacity {
			s.A += P
			r.Allowed, r.Remaining = true, (capacity-s.A)/P
		} else {
			r.Retry = (s.A + P - capacity + L - 1) / L
		}
		r.Reset = (s.A + L - 1) / L
		ttl = r.Reset
	}
	s.Set = true
	if !r.Allowed && p.Penalty > 0 {
		s.X = now + p.Penalty
		r.Retry = max(r.Retry, p.Penalty)
		r.Reset = max(r.Reset, p.Penalty)
		ttl = max(ttl, p.Penalty)
	}
	if s.X > now {
		r.Blocked = s.X
	}
	return r, max(ttl, 1)
}
