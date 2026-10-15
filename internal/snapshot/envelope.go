package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/jwks"
)

// MaxEnvelopeBytes bounds a snapshot: an active and a candidate config plus
// keys for every issuer of both.
const MaxEnvelopeBytes = 2*MaxConfigBytes + 2*MaxListLen*jwks.MaxBytes

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
