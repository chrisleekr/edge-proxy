package admin

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
)

// Login throttles (SP 800-63B Rev 4 §3.2.2). Each budget is
// per 15 minutes:
//   - username and peer: 10, for guessing from one place;
//   - peer: 100, for spraying many usernames;
//   - username: 100 (NIST's cap on failures per account), for guessing
//     from many places. A peer that signed in as this user before skips
//     it, so a distributed attack can't lock the user out of their usual
//     place.
//
// Keys a full table can't track share a small overflow budget: refusing
// them would let anyone lock everyone out, allowing them would let anyone
// guess without limit. At 6 a minute it stays under the per-account cap,
// so even then no account gets more guesses than usual.
//
// Changing a password needs a session already, so its check of the current
// password has a strict per-account budget instead: a stolen session gets
// 10 guesses per 15 minutes from anywhere, and the budget can only block
// password changes, never sign-ins.
var (
	pairAttempts     = ratelimit.Params{Algo: ratelimit.TokenBucket, Limit: 10, Burst: 10, Period: (15 * time.Minute).Milliseconds()}
	peerAttempts     = ratelimit.Params{Algo: ratelimit.TokenBucket, Limit: 100, Burst: 100, Period: (15 * time.Minute).Milliseconds()}
	userAttempts     = ratelimit.Params{Algo: ratelimit.TokenBucket, Limit: 100, Burst: 100, Period: (15 * time.Minute).Milliseconds()}
	overflowAttempts = ratelimit.Params{Algo: ratelimit.TokenBucket, Limit: 6, Burst: 6, Period: time.Minute.Milliseconds()}
	changeAttempts   = pairAttempts
)

// maxUserToken caps a user token's lifetime.
const maxUserToken = 365 * 24 * time.Hour

// Peers a user signed in from are remembered this long, per replica.
const (
	knownFor      = 30 * 24 * time.Hour
	maxKnownPeers = 100_000
)

// knownPeers remembers where each user signed in successfully.
type knownPeers struct {
	mu sync.Mutex
	m  map[string]time.Time // user + "\x00" + peer -> forget after
}

func (k *knownPeers) add(user, peer string, now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.m[user+"\x00"+peer]; ok || len(k.m) < maxKnownPeers {
		k.m[user+"\x00"+peer] = now.Add(knownFor)
	}
}

func (k *knownPeers) has(user, peer string, now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return now.Before(k.m[user+"\x00"+peer])
}

func (k *knownPeers) sweep(now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for key, until := range k.m {
		if !now.Before(until) {
			delete(k.m, key)
		}
	}
}

// throttle takes one password attempt for user from peer from each budget.
func (s *Server) throttle(user, peer string) bool {
	now := s.now()
	ms := now.UnixMilli()
	take := func(l *ratelimit.Local[string], key string, p ratelimit.Params) bool {
		res, tracked := l.Take(key, p, ms)
		if !tracked {
			res, _ = s.overflow.Take("overflow", overflowAttempts, ms)
		}
		return res.Allowed
	}
	if !take(s.pairLimit, user+"\x00"+peer, pairAttempts) || !take(s.ipLimit, peer, peerAttempts) {
		return false
	}
	return s.known.has(user, peer, now) || take(s.userLimit, user, userAttempts)
}

func (s *Server) identityRoutes() {
	s.public("POST /api/auth/login", s.login)
	s.handle("POST /api/auth/logout", "", s.logout)
	s.handle("GET /api/auth/me", "", s.me)
	s.handle("POST /api/auth/password", "", s.changePassword)
	s.handle("GET /api/roles", "", s.listRoles)
	s.handle("GET /api/users", "users.manage", s.listUsers)
	s.handle("POST /api/users", "users.manage", s.createUser)
	s.handle("PUT /api/users/{id}/roles", "users.manage", s.setRoles)
	s.handle("POST /api/users/{id}/disable", "users.manage", s.disableUser)
	s.handle("GET /api/tokens", "tokens.manage", s.listTokens)
	s.handle("POST /api/tokens", "tokens.manage", s.createToken)
	s.handle("DELETE /api/tokens/{id}", "tokens.manage", s.revokeToken)
}

var (
	errLogin   = fail(http.StatusUnauthorized, "wrong username or password")
	errTooMany = fail(http.StatusTooManyRequests, "too many attempts; try again later")
)

// maxLoginBody fits a username and a maxPassword password, JSON-escaped.
// Login is unauthenticated, so it doesn't get maxBody.
const maxLoginBody = 8 << 10

func (s *Server) login(w http.ResponseWriter, r *http.Request) error {
	var in struct{ Username, Password string }
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	ctx, now := r.Context(), s.now()
	name := strings.ToLower(in.Username)
	if len(name) > 64 {
		name = name[:64] // audit stores what was tried, bounded
	}
	if !s.throttle(name, s.peer(r)) {
		return errTooMany
	}
	var userID, hash string
	err := s.db.QueryRow(ctx, `SELECT u.id, c.hash FROM users u JOIN local_credentials c ON c.user_id = u.id
		WHERE u.username = $1 AND NOT u.disabled`, name).Scan(&userID, &hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if userID == "" {
		hash = dummyHash // same work as a wrong password, so timing doesn't reveal users
	}
	if !checkPassword(hash, in.Password) || userID == "" {
		// One error for unknown user and wrong password.
		err := s.change(ctx, "anonymous", func(pgx.Tx) (admindb.Event, error) {
			return admindb.Event{Action: "auth.login.failure", Target: name, Details: map[string]string{"peer": s.peer(r)}}, nil
		})
		if err != nil {
			return err
		}
		return errLogin
	}
	token, h := newSecret()
	err = s.change(ctx, "user:"+name, func(tx pgx.Tx) (admindb.Event, error) {
		// A new session on every login: an ID planted before login is never used.
		if c, err := r.Cookie(sessionCookie); err == nil {
			if _, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = $1 WHERE id_hash = $2", now, hashSecret(c.Value)); err != nil {
				return admindb.Event{}, err
			}
		}
		_, err := tx.Exec(ctx, "INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at) VALUES ($1, $2, $3, $3, $4)",
			h, userID, now, now.Add(s.cfg.SessionMaxAge))
		return admindb.Event{Action: "auth.login.success", Target: name, Details: map[string]string{"peer": s.peer(r)}}, err
	})
	if err != nil {
		return err
	}
	s.known.add(name, s.peer(r), now)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(s.cfg.SessionMaxAge / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return writeJSON(w, http.StatusOK, map[string]string{"username": name})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, p *principal) error {
	if p.session == nil {
		return fail(http.StatusBadRequest, "not signed in with a session")
	}
	err := s.change(r.Context(), p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		_, err := tx.Exec(r.Context(), "UPDATE sessions SET revoked_at = $1 WHERE id_hash = $2", s.now(), p.session)
		return admindb.Event{Action: "auth.logout", Target: p.username}, err
	})
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, p *principal) error {
	perms := []string{}
	for k := range p.perms {
		perms = append(perms, k)
	}
	slices.Sort(perms)
	return writeJSON(w, http.StatusOK, map[string]any{"username": p.username, "permissions": perms})
}

// changePassword needs the current password and rotates the session.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct{ Current, New string }
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	if p.session == nil {
		return fail(http.StatusForbidden, "sign in with a password to change it")
	}
	// A stolen session must not be a way around the login throttle.
	// Keyed by account only; the table holds one entry per real user, so
	// it can't fill, and an untracked key would be refused.
	if res, tracked := s.changeLimit.Take(p.userID, changeAttempts, s.now().UnixMilli()); !res.Allowed || !tracked {
		return errTooMany
	}
	ctx := r.Context()
	var hash string
	if err := s.db.QueryRow(ctx, "SELECT hash FROM local_credentials WHERE user_id = $1", p.userID).Scan(&hash); err != nil {
		return err
	}
	if !checkPassword(hash, in.Current) {
		return fail(http.StatusForbidden, "current password is wrong")
	}
	if why := passwordProblem(in.New, p.username, s.cfg.Blocklist); why != "" {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid password", Errors: []expr.Issue{{Path: "new", Msg: "password " + why}}}
	}
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		_, err := tx.Exec(ctx, "UPDATE local_credentials SET hash = $1, updated_at = $2 WHERE user_id = $3", hashPassword(in.New), s.now(), p.userID)
		if err != nil {
			return admindb.Event{}, err
		}
		// Every session ends, including this one: the caller signs in again.
		_, err = tx.Exec(ctx, "UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL", s.now(), p.userID)
		return admindb.Event{Action: "auth.password.change", Target: p.username}, err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request, _ *principal) error {
	rows, err := s.db.Query(r.Context(), `SELECT r.name, coalesce(array_agg(p.permission ORDER BY p.permission) FILTER (WHERE p.permission IS NOT NULL), '{}')
		FROM roles r LEFT JOIN role_permissions p ON p.role = r.name GROUP BY r.name ORDER BY r.name`)
	if err != nil {
		return err
	}
	type role struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[role])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, list)
}

type userView struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Disabled bool      `json:"disabled"`
	Roles    []string  `json:"roles"`
	Created  time.Time `json:"created_at"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, _ *principal) error {
	rows, err := s.db.Query(r.Context(), `SELECT u.id, u.username, u.email, u.disabled, coalesce(array_agg(r.role ORDER BY r.role) FILTER (WHERE r.role IS NOT NULL), '{}'), u.created_at
		FROM users u LEFT JOIN user_roles r ON r.user_id = u.id GROUP BY u.id ORDER BY u.username`)
	if err != nil {
		return err
	}
	users, err := pgx.CollectRows(rows, pgx.RowToStructByPos[userView])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, users)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Username, Email, Password string
		Roles                     []string
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	id, err := CreateUser(r.Context(), s.db, s.cfg, s.now, p.actor, in.Username, in.Email, in.Password, in.Roles)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// CreateUser adds a local user, dated by now. The CLI uses it to create the
// first admin, so there are no default credentials.
func CreateUser(ctx context.Context, db *pgxpool.Pool, cfg *Config, now func() time.Time, actor, username, email, password string, roles []string) (string, error) {
	username = strings.ToLower(username)
	var errs []expr.Issue
	if why := passwordProblem(password, username, cfg.Blocklist); why != "" {
		errs = append(errs, expr.Issue{Path: "password", Msg: "password " + why})
	}
	if len(roles) == 0 {
		errs = append(errs, expr.Issue{Path: "roles", Msg: "needs at least one role"})
	}
	if errs != nil {
		return "", &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid user", Errors: errs}
	}
	var id string
	err := dbProblem(pgx.BeginFunc(ctx, db, func(tx pgx.Tx) (err error) {
		id, err = insertUser(ctx, tx, cfg, now, actor, username, email, password, roles)
		return err
	}))
	return id, err
}

// insertUser writes a validated user, its credential, roles and audit row,
// dated by now.
func insertUser(ctx context.Context, tx pgx.Tx, cfg *Config, now func() time.Time, actor, username, email, password string, roles []string) (string, error) {
	var id string
	if err := tx.QueryRow(ctx, "INSERT INTO users (username, email, created_at) VALUES ($1, $2, $3) RETURNING id", username, email, now()).Scan(&id); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO local_credentials (user_id, hash) VALUES ($1, $2)", id, hashPassword(password)); err != nil {
		return "", err
	}
	if err := insertRoles(ctx, tx, id, roles); err != nil {
		return "", err
	}
	return id, admindb.Audit(ctx, tx, cfg.Audit, now, admindb.Event{Actor: actor, Action: "user.create", Target: username, Details: map[string]any{"id": id, "roles": roles}})
}

func insertRoles(ctx context.Context, tx pgx.Tx, userID string, roles []string) error {
	for _, role := range roles {
		if _, err := tx.Exec(ctx, "INSERT INTO user_roles (user_id, role) VALUES ($1, $2)", userID, role); err != nil {
			return err
		}
	}
	return nil
}

// setRoles replaces a user's roles and ends their sessions, so the change
// applies at once.
func (s *Server) setRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct{ Roles []string }
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	id := r.PathValue("id")
	ctx := r.Context()
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		var name string
		var before []string
		err := tx.QueryRow(ctx, `SELECT u.username, coalesce(array_agg(r.role ORDER BY r.role) FILTER (WHERE r.role IS NOT NULL), '{}')
			FROM users u LEFT JOIN user_roles r ON r.user_id = u.id WHERE u.id = $1 GROUP BY u.id`, id).Scan(&name, &before)
		if errors.Is(err, pgx.ErrNoRows) {
			err = fail(http.StatusNotFound, "no such user")
		}
		if err != nil {
			return admindb.Event{}, err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM user_roles WHERE user_id = $1", id); err != nil {
			return admindb.Event{}, err
		}
		if err := insertRoles(ctx, tx, id, in.Roles); err != nil {
			return admindb.Event{}, err
		}
		if err := keepUserManager(ctx, tx); err != nil {
			return admindb.Event{}, err
		}
		_, err = tx.Exec(ctx, "UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL", s.now(), id)
		return admindb.Event{Action: "user.roles", Target: name, Details: map[string]any{"id": id, "before": before, "after": in.Roles}}, err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	id := r.PathValue("id")
	if id == p.userID {
		return fail(http.StatusConflict, "you can't disable your own account")
	}
	ctx := r.Context()
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		// The username is the target, as for the user's other events, so one
		// filter finds them all.
		var name string
		err := tx.QueryRow(ctx, "UPDATE users SET disabled = true WHERE id = $1 RETURNING username", id).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			err = fail(http.StatusNotFound, "no such user")
		}
		if err != nil {
			return admindb.Event{}, err
		}
		if err := keepUserManager(ctx, tx); err != nil {
			return admindb.Event{}, err
		}
		_, err = tx.Exec(ctx, "UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL", s.now(), id)
		return admindb.Event{Action: "user.disable", Target: name, Details: map[string]any{"id": id}}, err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// userAdminLock serializes role and disable changes, so two managers
// removing each other at once can't both pass keepUserManager.
const userAdminLock = 0x75736572 // "user"

// keepUserManager refuses a change that leaves no enabled user with
// users.manage: recovering from that needs the CLI.
func keepUserManager(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", userAdminLock); err != nil {
		return err
	}
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users u JOIN user_roles r ON r.user_id = u.id
		JOIN role_permissions p ON p.role = r.role WHERE NOT u.disabled AND p.permission = 'users.manage')`).Scan(&ok)
	if err == nil && !ok {
		err = fail(http.StatusConflict, "refused: no enabled user could manage users after this change")
	}
	return err
}

type tokenView struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	UserID    *string    `json:"user_id"`
	Scopes    []string   `json:"scopes"`
	Created   time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request, _ *principal) error {
	rows, err := s.db.Query(r.Context(), "SELECT id, name, kind, user_id, scopes, created_at, expires_at, revoked_at FROM api_tokens ORDER BY created_at")
	if err != nil {
		return err
	}
	tokens, err := pgx.CollectRows(rows, pgx.RowToStructByPos[tokenView])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, tokens)
}

// createToken returns the token once; only its hash is stored. A user
// token's scopes must be permissions its creator holds.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Name      string
		Kind      string
		Scopes    []string
		ExpiresIn string `json:"expires_in"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	var errs []expr.Issue
	if in.Name == "" {
		errs = append(errs, expr.Issue{Path: "name", Msg: "is required"})
	}
	switch in.Kind {
	case "edge":
		if len(in.Scopes) > 0 {
			errs = append(errs, expr.Issue{Path: "scopes", Msg: "edge tokens have fixed access"})
		}
	case "user":
		if p.userID == "" {
			errs = append(errs, expr.Issue{Path: "kind", Msg: "only a user can own a user token"})
		}
		for _, sc := range in.Scopes {
			if !p.can(sc) {
				errs = append(errs, expr.Issue{Path: "scopes", Msg: "you don't hold " + sc})
			}
		}
	default:
		errs = append(errs, expr.Issue{Path: "kind", Msg: "must be user or edge"})
	}
	var expires *time.Time
	switch d, err := time.ParseDuration(in.ExpiresIn); {
	case in.ExpiresIn == "" && in.Kind == "user":
		// A user token stands in for sessions, which end within hours, so
		// it can't live forever. Edge tokens are rotated by deployment.
		errs = append(errs, expr.Issue{Path: "expires_in", Msg: "is required for user tokens"})
	case in.ExpiresIn == "":
	case err != nil || d <= 0:
		errs = append(errs, expr.Issue{Path: "expires_in", Msg: "must be a positive Go duration"})
	case in.Kind == "user" && d > maxUserToken:
		errs = append(errs, expr.Issue{Path: "expires_in", Msg: "must be at most 8760h (365 days)"})
	default:
		t := s.now().Add(d)
		expires = &t
	}
	if errs != nil {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid token", Errors: errs}
	}
	var owner *string
	if in.Kind == "user" {
		owner = &p.userID
	}
	token, h := newSecret()
	var id string
	err := s.change(r.Context(), p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		err := tx.QueryRow(r.Context(), "INSERT INTO api_tokens (token_hash, name, kind, user_id, scopes, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
			h, in.Name, in.Kind, owner, append([]string{}, in.Scopes...), expires).Scan(&id)
		return admindb.Event{Action: "token.create", Target: id, Details: map[string]any{"name": in.Name, "kind": in.Kind, "scopes": in.Scopes}}, err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]string{"id": id, "token": token})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request, p *principal) error {
	id := r.PathValue("id")
	err := s.change(r.Context(), p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		var name string
		err := tx.QueryRow(r.Context(), "UPDATE api_tokens SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL RETURNING name", s.now(), id).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			err = fail(http.StatusNotFound, "no such active token")
		}
		return admindb.Event{Action: "token.revoke", Target: id, Details: map[string]any{"name": name}}, err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
