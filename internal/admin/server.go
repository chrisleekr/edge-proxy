package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/jwks"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
)

// sessionCookie uses the __Host- prefix: Secure, Path=/ and no Domain, so
// no other host can set or read it.
const sessionCookie = "__Host-edge_session"

// maxBody bounds every JSON request body; configs are at most 8 MB.
const maxBody = 10 << 20

// HTTP server limits. Variables so tests can shorten them.
var (
	// readTimeout bounds a slow request body. There is no WriteTimeout:
	// audit export streams its response.
	readTimeout = 30 * time.Second
	idleTimeout = 120 * time.Second
	// flushTimeout bounds the last stats write at shutdown, so an
	// unresponsive Postgres can't hold the replica open.
	flushTimeout = 5 * time.Second
)

// Server is the admin API.
type Server struct {
	cfg *Config
	db  *pgxpool.Pool
	log *slog.Logger
	now func() time.Time
	mux *http.ServeMux

	// Login throttles.
	pairLimit, userLimit, ipLimit, overflow *ratelimit.Local[string]
	changeLimit                             *ratelimit.Local[string] // password changes, per account

	replica string // this admin instance, for its stats rows
	agg     *aggregator
	jwks    *jwks.Client
	// The leader's incremental audit verification position.
	auditSeq int64
	auditMAC []byte
	known    *knownPeers
}

// NewServer wires the API. db must connect as the runtime role.
func NewServer(cfg *Config, db *pgxpool.Pool, log *slog.Logger) *Server {
	s := &Server{
		cfg: cfg, db: db, log: log, now: time.Now, mux: http.NewServeMux(),
		pairLimit: ratelimit.NewLocalStore(100_000), userLimit: ratelimit.NewLocalStore(100_000), ipLimit: ratelimit.NewLocalStore(100_000),
		overflow: ratelimit.NewLocalStore(64), known: &knownPeers{m: map[string]time.Time{}}, changeLimit: ratelimit.NewLocalStore(100_000),
		replica: cfg.Replica, agg: &aggregator{m: map[aggKey]*minuteAgg{}}, jwks: jwks.NewClient(cfg.JWKSAllowedHosts, 5*time.Second, nil),
	}
	s.routes()
	return s
}

// Handler rejects cross-origin browser writes (CSRF) with the stdlib check,
// which reads Sec-Fetch-Site and Origin.
func (s *Server) Handler() http.Handler { return http.NewCrossOriginProtection().Handler(s.mux) }

// principal is who a request acts as.
type principal struct {
	actor    string // audit actor: "user:<name>", "token:<id>"
	userID   string // "" for edge service tokens
	username string
	perms    map[string]bool
	session  []byte // the session hash, when signed in with a cookie
}

func (p *principal) can(perm string) bool { return p.perms[perm] }

// problem is an RFC 9457 problem details response.
type problem struct {
	Status int          `json:"status"`
	Title  string       `json:"title"`
	Detail string       `json:"detail,omitempty"`
	Errors []expr.Issue `json:"errors,omitempty"`
	Tests  []TestResult `json:"test_results,omitempty"`
}

func (p *problem) Error() string { return p.Title + ": " + p.Detail }

func fail(status int, detail string) *problem {
	return &problem{Status: status, Title: http.StatusText(status), Detail: detail}
}

var (
	errUnauthenticated = fail(http.StatusUnauthorized, "sign in or send a valid token")
	errForbidden       = fail(http.StatusForbidden, "missing permission")
)

type handlerFunc func(w http.ResponseWriter, r *http.Request, p *principal) error

// handle registers an authenticated route that needs perm ("" for any
// signed-in principal).
func (s *Server) handle(pattern, perm string, h handlerFunc) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err == nil && perm != "" && !p.can(perm) {
			err = errForbidden
		}
		if err == nil {
			err = h(w, r, p)
		}
		s.writeError(w, err)
	})
}

// public registers a route that needs no principal.
func (s *Server) public(pattern string, h func(w http.ResponseWriter, r *http.Request) error) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { s.writeError(w, h(w, r)) })
}

func (s *Server) writeError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	p, ok := errors.AsType[*problem](err)
	if !ok {
		s.log.Error("admin request failed", "error", err.Error())
		p = fail(http.StatusInternalServerError, "")
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// readJSON decodes a request body strictly.
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	return decodeOne(dec, v, "invalid JSON body")
}

// decodeOne decodes exactly one JSON value, as snapshot.Decode does: data
// after it is refused, and a body over its MaxBytesReader limit gets 413.
func decodeOne(dec *json.Decoder, v any, msg string) error {
	err := dec.Decode(v)
	if err == nil {
		if _, err = dec.Token(); errors.Is(err, io.EOF) {
			return nil
		}
		if err == nil {
			err = errors.New("unexpected data after the JSON value")
		}
	}
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		return fail(http.StatusRequestEntityTooLarge, msg+": body is too large")
	}
	return fail(http.StatusBadRequest, msg+": "+err.Error())
}

// change runs fn and its audit row in one transaction: no change commits
// without its row.
func (s *Server) change(ctx context.Context, actor string, fn func(tx pgx.Tx) (admindb.Event, error)) error {
	return dbProblem(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		e, err := fn(tx)
		if err != nil {
			return err
		}
		e.Actor = actor
		return admindb.Audit(ctx, tx, s.cfg.Audit, e)
	}))
}

// dbProblem turns constraint violations into client errors: the database
// CHECKs and foreign keys are validation's last line.
func dbProblem(err error) error {
	pe, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return err
	}
	switch pe.Code {
	case "23505": // unique_violation
		return fail(http.StatusConflict, "already exists")
	case "23503": // foreign_key_violation
		return fail(http.StatusUnprocessableEntity, "refers to something that doesn't exist")
	case "23514", "22P02": // check_violation, invalid_text_representation
		return fail(http.StatusUnprocessableEntity, "invalid value: "+pe.ConstraintName)
	}
	return err
}

// newSecret returns a 256-bit random value for the client and its SHA-256
// for storage: a database leak can't be replayed.
func newSecret() (string, []byte) {
	var b [32]byte
	_, _ = rand.Read(b[:]) // never fails (Go 1.24+)
	v := base64.RawURLEncoding.EncodeToString(b[:])
	h := sha256.Sum256([]byte(v))
	return v, h[:]
}

func hashSecret(v string) []byte {
	h := sha256.Sum256([]byte(v))
	return h[:]
}

// authenticate resolves an API token or a session cookie.
func (s *Server) authenticate(r *http.Request) (*principal, error) {
	ctx := r.Context()
	now := s.now()
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return s.tokenPrincipal(ctx, hashSecret(v), now)
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, errUnauthenticated
	}
	h := hashSecret(c.Value)
	p := &principal{session: h}
	var lastSeen time.Time
	err = s.db.QueryRow(ctx, `SELECT u.id, u.username, s.last_seen_at FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > $2 AND s.last_seen_at > $3 AND NOT u.disabled`,
		h, now, now.Add(-s.cfg.SessionIdle)).Scan(&p.userID, &p.username, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	// Writing on every request would serialize a busy session on its row.
	if now.Sub(lastSeen) > time.Minute {
		if _, err := s.db.Exec(ctx, "UPDATE sessions SET last_seen_at = $1 WHERE id_hash = $2", now, h); err != nil {
			return nil, err
		}
	}
	p.actor = "user:" + p.username
	p.perms, err = s.userPerms(ctx, p.userID)
	return p, err
}

// tokenPrincipal: edge tokens may only fetch snapshots and post reports;
// user tokens get their scopes, limited to what the owner can do now.
func (s *Server) tokenPrincipal(ctx context.Context, h []byte, now time.Time) (*principal, error) {
	var id, kind string
	var userID, username *string
	var scopes []string
	err := s.db.QueryRow(ctx, `SELECT t.id, t.kind, t.user_id, u.username, t.scopes FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > $2) AND NOT coalesce(u.disabled, false)`,
		h, now).Scan(&id, &kind, &userID, &username, &scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	p := &principal{actor: "token:" + id, perms: map[string]bool{}}
	if kind == "edge" {
		p.perms[permEdge] = true
		return p, nil
	}
	p.userID, p.username = *userID, *username
	owner, err := s.userPerms(ctx, p.userID)
	for _, sc := range scopes {
		p.perms[sc] = owner[sc]
	}
	return p, err
}

// permEdge is held only by edge service tokens.
const permEdge = "edge"

func (s *Server) userPerms(ctx context.Context, userID string) (map[string]bool, error) {
	rows, err := s.db.Query(ctx, `SELECT DISTINCT p.permission FROM user_roles r JOIN role_permissions p ON p.role = r.role WHERE r.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	perms, err := pgx.CollectRows(rows, pgx.RowTo[string])
	m := map[string]bool{}
	for _, p := range perms {
		m[p] = true
	}
	return m, err
}

// peer is the client for the login throttle and audit: the TCP peer, or,
// when that is one of ADMIN_TRUSTED_PROXIES, the rightmost X-Forwarded-For
// address none of them added. Entries further left are
// client-written and never read.
func (s *Server) peer(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	a := ap.Addr().Unmap()
	xff := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	for s.trusted(a) && xff != "" {
		i := strings.LastIndexByte(xff, ',')
		next, err := netip.ParseAddr(strings.TrimSpace(xff[i+1:]))
		if err != nil {
			break // the proxy wrote something else: throttle the proxy
		}
		a, xff = next.Unmap(), xff[:max(i, 0)]
	}
	return a.String()
}

func (s *Server) trusted(a netip.Addr) bool {
	return slices.ContainsFunc(s.cfg.TrustedProxies, func(p netip.Prefix) bool { return p.Contains(a) })
}

// Serve runs the API until ctx ends.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l) }()
	go s.lead(ctx, s.cfg.DatabaseURL)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for running := true; running; {
		select {
		case err := <-errc:
			return err
		case now := <-tick.C:
			s.sweep(now)
			if err := s.flush(ctx, now); err != nil {
				s.log.Warn("stats flush", "error", err.Error())
			}
		case <-ctx.Done():
			running = false
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := srv.Shutdown(sctx)
	// After Shutdown, so reports still in flight are included. Write what
	// this replica still holds; the next minute never comes.
	fctx, cancelFlush := context.WithTimeout(context.WithoutCancel(ctx), flushTimeout)
	defer cancelFlush()
	if ferr := s.flush(fctx, s.now().Add(time.Minute)); ferr != nil {
		s.log.Warn("stats flush at shutdown", "error", ferr.Error())
	}
	if err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// sweep drops expired throttle state so the tables don't fill.
func (s *Server) sweep(now time.Time) {
	for _, l := range []*ratelimit.Local[string]{s.pairLimit, s.userLimit, s.ipLimit, s.overflow, s.changeLimit} {
		l.Sweep(now.UnixMilli())
	}
	s.known.sweep(now)
}
