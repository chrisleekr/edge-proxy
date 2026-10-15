package edge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// version is one compiled config plus the stats requests under it feed.
type version struct {
	c        *snapshot.Compiled
	defaults settings
	stats    *versionStats
	rules    []ratelimit.Rule
	backstop *ratelimit.Backstop
	cors     map[string]*corsPolicy
	headers  headerPlan
	locale   *localeResolver // nil when no locales are supported
	// local holds fail_mode local state per rule.
	local []*ratelimit.Local[string]
	// issuers by token iss.
	issuers map[string]*issuer
}

// sweep drops the version's expired backstop and local rate-limit state.
func (v *version) sweep(now time.Time) {
	v.backstop.Sweep(now)
	for _, l := range v.local {
		l.Sweep(now.UnixMilli())
	}
}

// newVersion prepares a compiled config for requests. The backstop keeps its
// state across snapshots unless its settings changed.
func newVersion(c *snapshot.Compiled, st *versionStats, prev *loaded, ks *keyStore, keys map[snapshot.KeySource]snapshot.Keys) *version {
	v := &version{
		c: c, defaults: defaults(c), stats: st, rules: ratelimit.Compile(c.Config.RateLimitRules),
		cors: compileCORS(c.Config.Global.CORSPolicies), headers: compileHeaders(c), locale: newLocaleResolver(c),
		issuers: compileIssuers(c, ks, keys, prev),
	}
	if prev != nil {
		for _, pv := range []*version{prev.active, prev.candidate} {
			if pv != nil && pv.backstop.Config == c.Config.Global.Backstop {
				v.backstop = pv.backstop
			}
		}
	}
	if v.backstop == nil {
		v.backstop = ratelimit.NewBackstop(c.Config.Global.Backstop)
	}
	// Local state outlives a publish, so a publish during a Valkey outage
	// can't reset the counts. Keys carry the rule's algorithm and period,
	// so a changed rule can't misread old state. With a different rule
	// count each share changes size, and state starts fresh.
	prevLocal := map[string]*ratelimit.Local[string]{}
	if prev != nil {
		for _, pv := range []*version{prev.active, prev.candidate} {
			if pv != nil && len(pv.rules) == len(v.rules) {
				for i, r := range pv.rules {
					prevLocal[r.ID] = pv.local[i]
				}
			}
		}
	}
	for _, r := range v.rules {
		l := prevLocal[r.ID]
		if l == nil {
			l = ratelimit.NewLocalStore(maxLocalState / len(v.rules))
		}
		v.local = append(v.local, l)
	}
	return v
}

// loaded is what a request pins at step 3. It is replaced whole, never
// mutated, so a request keeps one consistent view.
type loaded struct {
	snap      *snapshot.Snapshot
	active    *version
	candidate *version // nil outside a canary
	source    string   // admin, cache or bootstrap
	// bootstrapAge is set only when serving a bootstrap file.
	bootstrapAge time.Duration
}

type store struct {
	p atomic.Pointer[loaded]
	// fleet divides limits for fail_mode local. A snapshot
	// sets it and every stats report answer updates it, so edges coming
	// and going never change the snapshot itself.
	fleet atomic.Int64
}

func (s *store) load() *loaded { return s.p.Load() }

var errBootstrapTooOld = errors.New("bootstrap_too_old")

// poller keeps the store current. It never blocks requests:
// they read the store with one atomic load.
type poller struct {
	cfg    *Config
	dep    snapshot.Deployment
	client *http.Client
	store  *store
	reg    *statsRegistry
	keys   *keyStore
	m      *metrics
	log    *slog.Logger
	now    func() time.Time
	etag   string
}

// loadInitial tries each source in order until one validates and compiles.
// If all fail the edge stays not-ready; run keeps trying admin.
func (p *poller) loadInitial(ctx context.Context) {
	if p.cfg.AdminURL != nil {
		err := p.poll(ctx)
		if err == nil {
			return
		}
		p.log.Warn("snapshot from admin failed at startup", "error", err.Error())
	}
	if p.cfg.CachePath != "" {
		err := p.loadFile(p.cfg.CachePath, "cache")
		if err == nil {
			return
		}
		p.log.Warn("snapshot cache file failed", "path", p.cfg.CachePath, "error", err.Error())
	}
	if p.cfg.BootstrapPath != "" {
		err := p.loadFile(p.cfg.BootstrapPath, "bootstrap")
		if err == nil {
			return
		}
		p.log.Error("bootstrap snapshot failed", "path", p.cfg.BootstrapPath, "error", err.Error())
	}
	p.log.Error("no snapshot source succeeded; staying not ready")
}

// run polls admin until ctx ends: every PollInterval with ±20% jitter, and
// with exponential backoff (capped at 1 minute) while admin fails.
func (p *poller) run(ctx context.Context) {
	if p.cfg.AdminURL == nil {
		return
	}
	failures := 0
	for {
		t := time.NewTimer(p.delay(failures))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		var err error
		guard(p.m, p.log, "snapshot poller", func() { err = p.poll(ctx) })
		if err != nil {
			failures++
			p.m.pollErr.Add(1)
			p.log.Warn("snapshot poll failed; keeping current snapshot", "error", err.Error(), "failures", failures)
			continue
		}
		failures = 0
	}
}

func (p *poller) delay(failures int) time.Duration {
	d := p.cfg.PollInterval << min(failures, 6)
	d = min(d, time.Minute)
	// Jitter spreads the fleet so admin isn't hit by every edge at once.
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64())) //nolint:gosec // jitter needs no cryptographic randomness
}

// poll fetches the snapshot from admin. 304 means unchanged.
func (p *poller) poll(ctx context.Context) error {
	// AdminURL was validated at startup, so the request can't fail to build.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.AdminURL.JoinPath("v1", "snapshot").String(), nil)
	req.Header.Set("Authorization", "Bearer "+p.cfg.ServiceToken)
	if p.etag != "" {
		req.Header.Set("If-None-Match", p.etag)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("admin answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, snapshot.MaxEnvelopeBytes+1))
	if err != nil {
		return err
	}
	e, err := snapshot.Decode(bytes.NewReader(b))
	if err != nil {
		p.m.snapshotRejected.Add(1)
		return err
	}
	if err := p.apply(e, "admin", 0); err != nil {
		return err
	}
	p.etag = resp.Header.Get("ETag")
	p.writeCache(b)
	return nil
}

func (p *poller) loadFile(path, source string) error {
	f, err := os.Open(path) //nolint:gosec // path comes from deployment config, not from users
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	e, err := snapshot.Decode(f)
	if err != nil {
		p.m.snapshotRejected.Add(1)
		return err
	}
	var age time.Duration
	if source == "bootstrap" {
		age = p.now().Sub(e.ExportedAt)
		if age > p.cfg.BootstrapMaxAge {
			// An old policy may lack current auth or limits; serving it
			// would quietly weaken protection.
			if !p.cfg.BootstrapAllowStale {
				return fmt.Errorf("%w: exported %s ago, limit %s", errBootstrapTooOld, age.Round(time.Second), p.cfg.BootstrapMaxAge)
			}
			p.log.Error("serving a stale bootstrap snapshot because BOOTSTRAP_ALLOW_STALE=true", "age", age.Round(time.Second).String())
		}
	}
	return p.apply(e, source, age)
}

// apply validates and compiles e and swaps it in. On any error the current
// snapshot stays: an edge never activates config it can't compile.
func (p *poller) apply(e *snapshot.Envelope, source string, bootstrapAge time.Duration) error {
	s, errs := snapshot.CompileEnvelope(e, p.dep)
	if errs != nil {
		p.m.snapshotRejected.Add(1)
		return fmt.Errorf("snapshot rejected: %w", expr.Issues(errs))
	}
	ld := &loaded{snap: s, source: source, bootstrapAge: bootstrapAge}
	prev := p.store.load()
	if s.Candidate != nil {
		st := p.reg.use(s.Active, s.Candidate)
		ld.active = newVersion(s.Active, st[0], prev, p.keys, s.Keys)
		ld.candidate = newVersion(s.Candidate, st[1], prev, p.keys, s.Keys)
	} else {
		ld.active = newVersion(s.Active, p.reg.use(s.Active)[0], prev, p.keys, s.Keys)
	}
	fleet := s.FleetSize
	if fleet == 0 {
		fleet = p.cfg.ExpectedReplicas
	}
	p.store.fleet.Store(int64(fleet))
	p.store.p.Store(ld)
	p.keys.retain(ld)
	p.m.snapshotLoads.Add(1)
	p.m.snapshotVersion.Store(s.Active.Config.Version)
	p.m.bootstrapAge.Store(int64(ld.bootstrapAge / time.Second))
	p.log.Info("snapshot loaded", "source", source, "version", s.Active.Config.Version, "canary", s.Candidate != nil)
	return nil
}

// writeCache saves the snapshot for the next cold start. It writes a temp
// file and renames it, so a crash never leaves a half-written cache.
func (p *poller) writeCache(b []byte) {
	if p.cfg.CachePath == "" {
		return
	}
	tmp := p.cfg.CachePath + ".tmp"
	err := os.WriteFile(tmp, b, 0o600)
	if err == nil {
		err = os.Rename(tmp, p.cfg.CachePath)
	}
	if err != nil {
		p.log.Warn("snapshot cache write failed", "path", p.cfg.CachePath, "error", err.Error())
	}
}
