package edge

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/jwks"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
)

// sweepEvery is how often expired rate-limit state is dropped. Tests shorten it.
var sweepEvery = 10 * time.Second

// valkeyWarmup bounds the Valkey warm-up before ready, on top of the dial
// timeout.
const valkeyWarmup = 2 * time.Second

// Server is one edge replica: the public proxy, the internal port and the
// background loops.
type Server struct {
	cfg      *Config
	log      *slog.Logger
	m        *metrics
	store    *store
	edge     *Edge
	poller   *poller
	reporter *reporter
	alog     *accessLog
	draining atomic.Bool
}

// New wires a replica from deployment config. Nothing starts until Run.
func New(cfg *Config, log *slog.Logger) *Server {
	m := &metrics{}
	st := &store{}
	reg := newStatsRegistry()
	ups := map[string]*upstream{}
	for name, u := range cfg.Upstreams {
		ups[name] = &upstream{name: name, url: u, transport: newTransport(cfg)}
	}
	alog := newAccessLog(log, m, cfg.LogSampleRate, 4096)
	keys := newKeyStore(jwks.NewClient(cfg.JWKSAllowedHosts, jwksTimeout, jwksRoots), m, log)
	s := &Server{
		cfg: cfg, log: log, m: m, store: st, alog: alog,
		edge: &Edge{
			cfg: cfg, id: newIdentity(cfg), store: st, m: m, alog: alog, log: log,
			upstreams: ups, pool: newBufferPool(), now: time.Now, strip: sourceHeaders(cfg.Deployment()),
			penalties: ratelimit.NewPenalties(maxPenalties), tokens: newTokenCache(cfg.TokenCacheSize),
		},
	}
	s.edge.rp = s.edge.newReverseProxy()
	if cfg.Valkey != nil {
		// A dedicated client with its own short timeout.
		s.edge.valkey = ratelimit.NewValkey(*cfg.Valkey, cfg.ValkeyTimeout, log)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	s.poller = &poller{cfg: cfg, dep: cfg.Deployment(), client: client, store: st, reg: reg, keys: keys, m: m, log: log, now: time.Now}
	if cfg.AdminURL != nil {
		s.reporter = &reporter{
			url: cfg.AdminURL.JoinPath("v1", "edge", "report").String(), token: cfg.ServiceToken, instance: cfg.Instance, deployment: cfg.Deployment().Fingerprint(),
			interval: cfg.StatsInterval, client: client, reg: reg, store: st, m: m, log: log,
		}
	}
	return s
}

// Run serves until ctx ends, then shuts down: fail /readyz, wait
// DrainDelay so the LB stops sending, Shutdown within ShutdownTimeout, then
// cancel what remains (hijacked WebSockets, long streams).
func (s *Server) Run(ctx context.Context, public, internal net.Listener) error {
	bg, stopBg := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { s.alog.run(bg) })
	defer func() {
		stopBg()
		wg.Wait()
	}()

	errLog := slog.NewLogLogger(s.log.Handler(), slog.LevelWarn)
	in := &http.Server{Handler: s.internalMux(), ReadHeaderTimeout: s.cfg.ReadHeaderTimeout, IdleTimeout: s.cfg.IdleTimeout, ErrorLog: errLog}
	base, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	pub := &http.Server{
		Handler:           s.edge,
		ReadHeaderTimeout: s.cfg.ReadHeaderTimeout,
		IdleTimeout:       s.cfg.IdleTimeout,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes,
		// No WriteTimeout or ReadTimeout: they would cut SSE and long
		// uploads. The body read deadline is set per request instead.
		BaseContext: func(net.Listener) context.Context { return base },
		ErrorLog:    errLog,
	}
	errc := make(chan error, 2)
	go func() { errc <- in.Serve(internal) }()

	if v := s.edge.valkey; v != nil {
		// Warm the pool before ready, best effort: a failure here never
		// delays readiness beyond the dial timeout.
		warm, cancel := context.WithTimeout(ctx, valkeyWarmup)
		if err := v.Connect(warm); err != nil {
			s.log.Warn("valkey unavailable at start", "error", err.Error())
		}
		cancel()
		wg.Go(func() { v.Run(bg) })
	}
	wg.Go(func() { s.sweep(bg) })

	// Livez answers while the first snapshot loads; readyz waits for it.
	s.poller.loadInitial(ctx)
	wg.Go(func() { s.poller.run(bg) })
	wg.Go(func() { s.poller.keys.run(bg) })
	if s.reporter != nil {
		wg.Go(func() { s.reporter.run(bg) })
	}
	go func() { errc <- pub.Serve(public) }()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
		s.log.Error("server stopped unexpectedly", "error", runErr.Error())
	}

	s.draining.Store(true)
	// Give the LB time to see /readyz fail and stop sending. Skipped when a
	// listener already failed: there is no traffic to drain from it.
	if runErr == nil {
		s.log.Info("draining", "delay", s.cfg.DrainDelay.String())
		time.Sleep(s.cfg.DrainDelay)
	}
	sctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()
	if err := pub.Shutdown(sctx); err != nil {
		s.log.Warn("shutdown timed out; closing remaining connections", "error", err.Error())
	}
	// Ends hijacked connections: ReverseProxy closes the upstream side of an
	// upgrade when the request context is done.
	cancelBase()
	_ = pub.Close()
	_ = in.Close()
	s.log.Info("stopped")
	return runErr
}

// sweep drops expired rate-limit state off the request path.
func (s *Server) sweep(ctx context.Context) {
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			guard(s.m, s.log, "sweep", func() {
				s.edge.penalties.Sweep(now.UnixMilli())
				s.edge.tokens.sweep(now)
				if ld := s.store.load(); ld != nil {
					for _, v := range []*version{ld.active, ld.candidate} {
						if v != nil {
							v.sweep(now)
						}
					}
				}
			})
		}
	}
}

func (s *Server) ready() bool { return s.store.load() != nil && !s.draining.Load() }

func (s *Server) internalMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		// Readiness never reflects dependency health.
		if !s.ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "not ready\n")
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		s.m.ready.Store(s.ready())
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		s.m.writeTo(w)
	})
	return mux
}

// Main runs the edge binary: config from the environment, logs as JSON to
// out, until SIGTERM or SIGINT. It returns the process exit code.
func Main(ctx context.Context, getenv func(string) string, out io.Writer) int {
	log := slog.New(slog.NewJSONHandler(out, nil))
	cfg, err := LoadConfig(getenv)
	if err != nil {
		log.Error("invalid deployment config", "error", err.Error())
		return 2
	}
	pub, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Error("listen failed", "addr", cfg.ListenAddr, "error", err.Error())
		return 1
	}
	in, err := net.Listen("tcp", cfg.InternalAddr)
	if err != nil {
		_ = pub.Close()
		log.Error("listen failed", "addr", cfg.InternalAddr, "error", err.Error())
		return 1
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer stop()
	return exitCode(New(cfg, log).Run(ctx, pub, in))
}

// exitCode is non-zero when Run stopped because a listener failed, so the
// orchestrator restarts the replica.
func exitCode(err error) int {
	if err != nil {
		return 1
	}
	return 0
}
