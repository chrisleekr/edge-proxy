package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// fakeAdmin serves GET /v1/snapshot like admin: bearer auth, ETag, 304.
type fakeAdmin struct {
	srv      *httptest.Server
	body     atomic.Pointer[[]byte]
	status   atomic.Int32 // non-zero forces this status
	requests atomic.Int32
	sawToken atomic.Bool
}

func newFakeAdmin(t *testing.T, e *snapshot.Envelope) *fakeAdmin {
	t.Helper()
	a := &fakeAdmin{}
	a.set(t, e)
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.requests.Add(1)
		if r.URL.Path != "/v1/snapshot" {
			http.NotFound(w, r)
			return
		}
		a.sawToken.Store(r.Header.Get("Authorization") == "Bearer t0k")
		if s := a.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		b := *a.body.Load()
		sum := sha256.Sum256(b)
		etag := `"` + hex.EncodeToString(sum[:8]) + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write(b)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAdmin) set(t *testing.T, e *snapshot.Envelope) {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	a.body.Store(&b)
}

func writeEnvelope(t *testing.T, path string, e *snapshot.Envelope) {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func pollerHarness(t *testing.T, set map[string]string) *harness {
	t.Helper()
	return newHarness(t, set)
}

func activeVersion(h *harness) int64 {
	ld := h.srv.store.load()
	if ld == nil {
		return 0
	}
	return ld.active.c.Config.Version
}

// At startup admin wins; the snapshot is cached for the next cold start.
func TestStartupFromAdmin(t *testing.T) {
	admin := newFakeAdmin(t, envelope(testConfig(3)))
	cache := filepath.Join(t.TempDir(), "cache.json")
	h := pollerHarness(t, map[string]string{"ADMIN_URL": admin.srv.URL, "EDGE_SERVICE_TOKEN": "t0k", "SNAPSHOT_CACHE_PATH": cache})
	h.srv.poller.loadInitial(t.Context())
	if activeVersion(h) != 3 || h.srv.store.load().source != "admin" || !admin.sawToken.Load() {
		t.Fatalf("version %d, token %v", activeVersion(h), admin.sawToken.Load())
	}
	e, err := snapshot.Decode(mustOpen(t, cache))
	if err != nil || e.Active.Version != 3 {
		t.Fatalf("cache file: %v %v", e, err)
	}
}

// With admin down, a cold start uses the cache file, then the bootstrap file.
func TestStartupFallbacks(t *testing.T) {
	dir := t.TempDir()
	cache, boot := filepath.Join(dir, "cache.json"), filepath.Join(dir, "boot.json")
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	set := map[string]string{"ADMIN_URL": down.URL, "EDGE_SERVICE_TOKEN": "t0k", "SNAPSHOT_CACHE_PATH": cache, "BOOTSTRAP_PATH": boot}

	writeEnvelope(t, boot, envelope(testConfig(1)))
	h := pollerHarness(t, set)
	h.srv.poller.loadInitial(t.Context())
	if activeVersion(h) != 1 || h.srv.store.load().source != "bootstrap" {
		t.Fatalf("no cache: version %d", activeVersion(h))
	}

	writeEnvelope(t, cache, envelope(testConfig(2)))
	h = pollerHarness(t, set)
	h.srv.poller.loadInitial(t.Context())
	if activeVersion(h) != 2 || h.srv.store.load().source != "cache" {
		t.Fatalf("with cache: version %d", activeVersion(h))
	}

	// A corrupt cache is skipped, not fatal.
	if err := os.WriteFile(cache, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	h = pollerHarness(t, set)
	h.srv.poller.loadInitial(t.Context())
	if activeVersion(h) != 1 || h.srv.m.snapshotRejected.Load() != 1 {
		t.Fatalf("corrupt cache: version %d", activeVersion(h))
	}
}

// An old bootstrap could lack current auth or limits, so the edge stays
// not-ready unless the emergency override is set.
func TestBootstrapAge(t *testing.T) {
	boot := filepath.Join(t.TempDir(), "boot.json")
	old := envelope(testConfig(1))
	old.ExportedAt = time.Now().Add(-8 * 24 * time.Hour)
	writeEnvelope(t, boot, old)

	h := pollerHarness(t, map[string]string{"BOOTSTRAP_PATH": boot})
	h.srv.poller.loadInitial(t.Context())
	if h.srv.ready() || !strings.Contains(h.logs.String(), "bootstrap_too_old") {
		t.Fatal("stale bootstrap served without the override")
	}

	h = pollerHarness(t, map[string]string{"BOOTSTRAP_PATH": boot, "BOOTSTRAP_ALLOW_STALE": "true"})
	h.srv.poller.loadInitial(t.Context())
	ld := h.srv.store.load()
	if !h.srv.ready() || ld.bootstrapAge < 8*24*time.Hour || h.srv.m.bootstrapAge.Load() < 8*24*3600 || len(h.logs.lines("serving a stale bootstrap snapshot because BOOTSTRAP_ALLOW_STALE=true")) != 1 {
		t.Fatal("override didn't serve the stale bootstrap loudly")
	}
}

// A bootstrap file exported while an autopilot rule was live keeps it until
// it expires. Loaded after that, the snapshot is still valid: the edge
// becomes ready and skips the expired rule.
func TestBootstrapWithExpiredRule(t *testing.T) {
	boot := filepath.Join(t.TempDir(), "boot.json")
	c := testConfig(1)
	r := rlRule("ap-scraper", "true", "sliding_window", 1, "ip")
	r.FailMode = "local"
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	expireRule(t, c, 0, time.Now().Add(-time.Minute))
	writeEnvelope(t, boot, envelope(c))

	h := pollerHarness(t, map[string]string{"BOOTSTRAP_PATH": boot})
	h.srv.poller.loadInitial(t.Context())
	if !h.srv.ready() || activeVersion(h) != 1 {
		t.Fatalf("ready %v, version %d", h.srv.ready(), activeVersion(h))
	}
	if got := h.statuses(2, "GET", "/"); !eqInts(got, 200, 200) {
		t.Fatalf("got %v, want the expired rule skipped", got)
	}
	if n := h.ruleOutcome("ap-scraper", "expired"); n != 2 {
		t.Fatalf("expired %v, want 2", n)
	}
}

// With no usable source the edge stays not-ready and says so.
func TestStartupWithNothing(t *testing.T) {
	h := pollerHarness(t, map[string]string{"BOOTSTRAP_PATH": filepath.Join(t.TempDir(), "missing.json")})
	h.srv.poller.loadInitial(t.Context())
	if h.srv.ready() || len(h.logs.lines("no snapshot source succeeded; staying not ready")) != 1 {
		t.Fatal("not-ready state not reported")
	}
}

// The poller picks up new versions, skips unchanged ones with ETag, and
// keeps serving the current snapshot through every kind of admin failure.
func TestPollerKeepsServingThroughAdminFailures(t *testing.T) {
	admin := newFakeAdmin(t, envelope(testConfig(1)))
	h := pollerHarness(t, map[string]string{"ADMIN_URL": admin.srv.URL, "EDGE_SERVICE_TOKEN": "t0k", "POLL_INTERVAL": "10ms"})
	p := h.srv.poller
	ctx := t.Context()
	if err := p.poll(ctx); err != nil || activeVersion(h) != 1 {
		t.Fatal(err)
	}
	loads := h.srv.m.snapshotLoads.Load()
	if err := p.poll(ctx); err != nil || h.srv.m.snapshotLoads.Load() != loads {
		t.Fatal("unchanged snapshot reloaded")
	}

	failures := []struct {
		name  string
		setup func()
	}{
		{"admin answers 500", func() { admin.status.Store(500) }},
		{"admin unreachable", func() { admin.srv.Listener.Close() }},
	}
	invalid := testConfig(2)
	invalid.RateLimitRules = append(invalid.RateLimitRules, snapshot.RateLimitRule{ID: "bad"})
	corrupt := []byte(`{"exported_at":`)
	for _, tc := range []struct {
		name string
		body []byte
		env  *snapshot.Envelope
	}{{"snapshot that doesn't compile", nil, envelope(invalid)}, {"truncated snapshot", corrupt, nil}} {
		if tc.env != nil {
			admin.set(t, tc.env)
		} else {
			admin.body.Store(&tc.body)
		}
		if err := p.poll(ctx); err == nil || activeVersion(h) != 1 {
			t.Fatalf("%s: err %v, version %d", tc.name, err, activeVersion(h))
		}
	}
	for _, f := range failures {
		f.setup()
		if err := p.poll(ctx); err == nil || activeVersion(h) != 1 {
			t.Fatalf("%s: version %d", f.name, activeVersion(h))
		}
	}
	if !h.srv.ready() {
		t.Fatal("admin failures made the edge not ready")
	}
}

// run applies new versions as admin publishes them, until stopped.
func TestPollerRun(t *testing.T) {
	admin := newFakeAdmin(t, envelope(testConfig(1)))
	h := pollerHarness(t, map[string]string{"ADMIN_URL": admin.srv.URL, "EDGE_SERVICE_TOKEN": "t0k", "POLL_INTERVAL": "10ms"})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { h.srv.poller.run(ctx); close(done) }()
	waitFor(t, func() bool { return activeVersion(h) == 1 })
	admin.set(t, envelope(testConfig(2)))
	waitFor(t, func() bool { return activeVersion(h) == 2 })
	admin.status.Store(503)
	waitFor(t, func() bool { return h.srv.m.pollErr.Load() > 0 })
	cancel()
	<-done
	if activeVersion(h) != 2 {
		t.Fatal("lost the snapshot")
	}
}

// Without ADMIN_URL there is nothing to poll.
func TestPollerRunWithoutAdmin(t *testing.T) {
	h := pollerHarness(t, nil)
	done := make(chan struct{})
	go func() { h.srv.poller.run(t.Context()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("run kept going without an admin URL")
	}
}

// Polling backs off while admin fails, capped at a minute, with jitter so
// the fleet doesn't poll in lockstep.
func TestPollDelay(t *testing.T) {
	p := &poller{cfg: &Config{PollInterval: 5 * time.Second}}
	for _, tc := range []struct {
		failures int
		base     time.Duration
	}{{0, 5 * time.Second}, {1, 10 * time.Second}, {3, 40 * time.Second}, {4, time.Minute}, {50, time.Minute}} {
		for range 20 {
			d := p.delay(tc.failures)
			if d < tc.base*8/10 || d > tc.base*12/10 {
				t.Fatalf("failures %d: delay %s outside ±20%% of %s", tc.failures, d, tc.base)
			}
		}
	}
}

// A cache write failure is logged; serving continues.
func TestCacheWriteFailure(t *testing.T) {
	admin := newFakeAdmin(t, envelope(testConfig(1)))
	h := pollerHarness(t, map[string]string{"ADMIN_URL": admin.srv.URL, "EDGE_SERVICE_TOKEN": "t0k", "SNAPSHOT_CACHE_PATH": filepath.Join(t.TempDir(), "no-such-dir", "cache.json")})
	if err := h.srv.poller.poll(t.Context()); err != nil || activeVersion(h) != 1 {
		t.Fatal(err)
	}
	if len(h.logs.lines("snapshot cache write failed")) != 1 {
		t.Fatal("cache failure not logged")
	}
}

// A connection that drops mid-download is an error, not a partial snapshot.
func TestAdminBodyCutOff(t *testing.T) {
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = io.WriteString(w, `{"exported_at":`)
	}))
	defer cut.Close()
	h := pollerHarness(t, map[string]string{"ADMIN_URL": cut.URL, "EDGE_SERVICE_TOKEN": "t0k"})
	if err := h.srv.poller.poll(t.Context()); err == nil || h.srv.store.load() != nil {
		t.Fatalf("err %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
