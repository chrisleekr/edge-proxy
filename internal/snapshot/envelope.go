package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/jwks"
)

// MaxEnvelopeBytes bounds a snapshot: an active and a candidate config,
// keys for every issuer of both, and the crawler ranges. A range is at most
// 43 characters as JSON, plus quotes and a comma.
const MaxEnvelopeBytes = 2*MaxConfigBytes + 2*MaxListLen*jwks.MaxBytes + MaxBotSources*(MaxBotSetPrefixes*46+MaxBotSourceLen+64)

// MaxBotSourceLen bounds a VERIFIED_BOT_SOURCES URL.
const MaxBotSourceLen = 2048

// BotPrefix parses one verified crawler range of the family want6 names,
// 4-in-6 refused, and returns it masked. IPv4 wider than /16 and IPv6
// wider than /32 are refused: crawler lists publish far narrower ranges,
// and a wide one would exempt whole networks of ordinary clients.
func BotPrefix(s string, want6 bool) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR range", s)
	}
	a := p.Addr()
	switch {
	case want6 && (!a.Is6() || a.Is4In6()):
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv6 range", s)
	case !want6 && !a.Is4():
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 range", s)
	case a.Is4() && p.Bits() < 16 || a.Is6() && p.Bits() < 32:
		return netip.Prefix{}, fmt.Errorf("%q is wider than /16 for IPv4 or /32 for IPv6", s)
	}
	return p.Masked(), nil
}

// Snapshot is a compiled envelope: what the edge swaps in atomically.
type Snapshot struct {
	ExportedAt time.Time
	Active     *Compiled
	// Candidate is nil outside a canary.
	Candidate *Compiled
	// CanaryBasisPoints: a request uses Candidate when its client hash
	// mod 10000 is below this.
	CanaryBasisPoints int
	CanaryExpiresAt   time.Time
	FleetSize         int
	// Keys are the parsed key sets by issuer and JWKS URL.
	Keys map[KeySource]Keys
	// Bots is every verified crawler range in one set; empty without any.
	Bots expr.IPSet
}

// KeySource is where a key set came from: one issuer at one JWKS URL.
type KeySource struct{ IssuerID, JWKSURL string }

// Keys is one issuer's parsed key set and when it was fetched.
type Keys struct {
	FetchedAt time.Time
	Set       *jwks.Set
}

// Decode reads an envelope, rejecting unknown fields, trailing data and
// anything over MaxEnvelopeBytes. It doesn't validate; CompileEnvelope does.
func Decode(r io.Reader) (*Envelope, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxEnvelopeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	if len(b) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("snapshot is larger than %d bytes", MaxEnvelopeBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var e Envelope
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode snapshot: unexpected data after the snapshot")
	}
	return &e, nil
}

// CompileEnvelope validates and compiles both configs and the canary and
// key fields. On any error it returns nil and every error found; the edge
// then keeps its current snapshot.
func CompileEnvelope(e *Envelope, d Deployment) (*Snapshot, []expr.Issue) {
	s := &Snapshot{ExportedAt: e.ExportedAt, CanaryExpiresAt: e.CanaryExpiresAt, FleetSize: e.FleetSize, Keys: map[KeySource]Keys{}}
	var errs []expr.Issue
	add := func(path, format string, args ...any) {
		errs = append(errs, expr.Issue{Path: path, Msg: fmt.Sprintf(format, args...)})
	}
	compile := func(path string, c *Config) *Compiled {
		out, _, cerrs := Compile(c, d)
		for _, is := range cerrs {
			errs = append(errs, expr.Issue{Path: joinPath(path, is.Path), Msg: is.Msg})
		}
		return out
	}

	if e.ExportedAt.IsZero() {
		add("exported_at", "is required")
	}
	if e.Active == nil {
		add("active", "is required")
	} else {
		s.Active = compile("active", e.Active)
	}

	if e.Candidate == nil {
		if e.CanaryPercent != 0 || !e.CanaryExpiresAt.IsZero() {
			add("canary_percent", "canary fields need a candidate")
		}
	} else {
		s.Candidate = compile("candidate", e.Candidate)
		// Round: 0.07 * 100 is 7.000000000000001 in float64.
		bp := math.Round(e.CanaryPercent * 100)
		if bp < 1 || bp >= 10000 || math.Abs(e.CanaryPercent*100-bp) > 1e-6 {
			add("canary_percent", "must be from 0.01 to 99.99 in steps of 0.01")
		}
		s.CanaryBasisPoints = int(bp)
		if e.CanaryExpiresAt.IsZero() {
			add("canary_expires_at", "is required during a canary")
		}
		if e.Active != nil && e.Candidate.Version <= e.Active.Version {
			add("candidate.version", "must be newer than the active version %d", e.Active.Version)
		}
	}

	if e.FleetSize < 0 {
		add("fleet_size", "must not be negative")
	}
	if len(e.Keys) > 2*MaxListLen {
		add("keys", "has %d key sets; at most %d are allowed", len(e.Keys), 2*MaxListLen)
	}
	for i, k := range e.Keys {
		p := fmt.Sprintf("keys[%d]", i)
		if !isName(k.IssuerID) {
			add(p+".issuer_id", "is not a valid issuer id")
		}
		if k.JWKSURL == "" {
			add(p+".jwks_url", "is required")
		}
		if k.FetchedAt.IsZero() {
			add(p+".fetched_at", "is required")
		}
		set, err := jwks.Parse(k.JWKS)
		if err != nil {
			add(p+".jwks", "%s", err.Error())
		}
		src := KeySource{k.IssuerID, k.JWKSURL}
		if _, dup := s.Keys[src]; dup {
			add(p, "repeats the keys of issuer %q at %s", k.IssuerID, k.JWKSURL)
		}
		s.Keys[src] = Keys{FetchedAt: k.FetchedAt, Set: set}
	}

	if len(e.VerifiedBots) > MaxBotSources {
		add("verified_bots", "has %d sources; at most %d are allowed", len(e.VerifiedBots), MaxBotSources)
	}
	var bots []netip.Prefix
	sources := map[string]bool{}
	for i, b := range e.VerifiedBots {
		p := fmt.Sprintf("verified_bots[%d]", i)
		if b.Source == "" || len(b.Source) > MaxBotSourceLen || sources[b.Source] {
			add(p+".source", "must be a unique URL of at most %d characters", MaxBotSourceLen)
		}
		sources[b.Source] = true
		if len(b.Prefixes) < 1 || len(b.Prefixes) > MaxBotSetPrefixes {
			add(p+".prefixes", "needs 1 to %d prefixes", MaxBotSetPrefixes)
		}
		for k, s := range b.Prefixes {
			pf, err := BotPrefix(s, strings.Contains(s, ":"))
			if err != nil {
				add(fmt.Sprintf("%s.prefixes[%d]", p, k), "%s", err.Error())
				continue
			}
			bots = append(bots, pf)
		}
	}
	s.Bots = expr.NewIPSet(bots)

	if errs != nil {
		return nil, errs
	}
	return s, nil
}

func joinPath(prefix, path string) string {
	if path == "" {
		return prefix
	}
	return prefix + "." + path
}
