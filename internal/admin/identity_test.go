package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestLoginSetsAHardenedSessionCookie(t *testing.T) {
	h := newHarness(t)
	h.user("alice", "viewer")
	c := h.client()
	resp := c.do("POST", "/api/auth/login", map[string]string{"username": "Alice", "password": goodPassword})
	status(t, resp, 200)
	var ck *http.Cookie
	for _, k := range resp.Cookies() {
		if k.Name == sessionCookie {
			ck = k
		}
	}
	if ck == nil || !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" || len(ck.Value) < 43 {
		t.Fatalf("cookie %+v", ck)
	}
	me := decode[struct {
		Username    string
		Permissions []string
	}](t, c.do("GET", "/api/auth/me", nil))
	if me.Username != "alice" || !slices.Equal(me.Permissions, []string{"audit.read", "autopilot.read", "config.read", "stats.read"}) {
		t.Fatalf("me = %+v", me)
	}
	// Only the hash of the session ID is stored.
	var n int
	_ = h.db.QueryRow(t.Context(), "SELECT count(*) FROM sessions WHERE id_hash = $1", hashSecret(ck.Value)).Scan(&n)
	if n != 1 {
		t.Fatal("session hash not stored")
	}
	if got := h.actions(); !slices.Equal(got, []string{"user.create alice", "auth.login.success alice"}) {
		t.Fatalf("audit %v", got)
	}
}

// The UI links Stats, Dashboard, route detail and anomaly rows to the
// deployment's log store with the LOG_SEARCH_URL template, which it reads
// once with the signed-in user. Without it there is no template, so the UI
// shows no links. Only stats pages use it, so a principal that can't read
// stats doesn't get it.
func TestSignedInUserGetsTheLogSearchTemplate(t *testing.T) {
	const tmpl = "https://logs.example.com/search?q=status%3A{status}%20host%3A{host}&from={from_ms}&to={to_ms}"
	for _, c := range []struct {
		name   string
		set    map[string]string
		scopes []string // a user token with these scopes, or a session when nil
		want   string
	}{
		{"a stats reader gets the template", map[string]string{"LOG_SEARCH_URL": tmpl}, nil, tmpl},
		{"no template when it is unset", nil, nil, ""},
		{"a token without stats.read gets no template", map[string]string{"LOG_SEARCH_URL": tmpl}, []string{"config.read"}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarnessWith(t, c.set)
			h.user("alice", "admin")
			cl := h.signedIn("alice")
			if c.scopes != nil {
				tok := decode[map[string]string](t, cl.do("POST", "/api/tokens", map[string]any{"name": "ci", "kind": "user", "scopes": c.scopes, "expires_in": "720h"}))
				cl = h.client()
				cl.token = tok["token"]
			}
			me := decode[map[string]any](t, cl.do("GET", "/api/auth/me", nil))
			got, ok := me["log_search_url"]
			if c.want != "" && got != c.want || c.want == "" && ok {
				t.Fatalf("log_search_url = %v (present %t), want %q", got, ok, c.want)
			}
		})
	}
}

// Unknown user and wrong password look the same to the client.
func TestLoginFailuresLookAlike(t *testing.T) {
	h := newHarness(t)
	h.user("alice", "viewer")
	wrong := body(h.client().do("POST", "/api/auth/login", map[string]string{"username": "alice", "password": "not the password at all"}))
	unknown := body(h.client().do("POST", "/api/auth/login", map[string]string{"username": "nobody", "password": goodPassword}))
	if wrong != unknown || !strings.Contains(wrong, "wrong username or password") {
		t.Fatalf("wrong %q, unknown %q", wrong, unknown)
	}
	if got := h.actions(); !slices.Equal(got[1:], []string{"auth.login.failure alice", "auth.login.failure nobody"}) {
		t.Fatalf("audit %v", got)
	}
}

func TestLoginIsThrottled(t *testing.T) {
	h := newHarness(t)
	h.user("alice", "viewer")
	c := h.client()
	for range 10 {
		status(t, c.do("POST", "/api/auth/login", map[string]string{"username": "alice", "password": "guess guess guess"}), 401)
	}
	// Even the right password waits: the attempts are per username.
	status(t, c.do("POST", "/api/auth/login", map[string]string{"username": "alice", "password": goodPassword}), 429)
	h.advance(15 * time.Minute)
	status(t, c.do("POST", "/api/auth/login", map[string]string{"username": "alice", "password": goodPassword}), 200)
}

func TestLoginThrottlesOnePeerAcrossUsernames(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	for i := range 100 {
		status(t, c.do("POST", "/api/auth/login", map[string]string{"username": "user" + string(rune('a'+i%26)) + string(rune('a'+i/26)), "password": "guess guess guess"}), 401)
	}
	status(t, c.do("POST", "/api/auth/login", map[string]string{"username": "fresh", "password": "guess guess guess"}), 429)
}

func TestSessionEnds(t *testing.T) {
	h := newHarness(t)
	h.user("alice", "viewer")
	t.Run("on logout", func(t *testing.T) {
		c := h.signedIn("alice")
		status(t, c.do("POST", "/api/auth/logout", nil), 204)
		status(t, c.do("GET", "/api/auth/me", nil), 401)
	})
	t.Run("after the idle timeout", func(t *testing.T) {
		c := h.signedIn("alice")
		h.advance(29 * time.Minute)
		status(t, c.do("GET", "/api/auth/me", nil), 200)
		h.advance(31 * time.Minute)
		status(t, c.do("GET", "/api/auth/me", nil), 401)
	})
	t.Run("at the absolute limit, however active", func(t *testing.T) {
		c := h.signedIn("alice")
		for range 12 * 4 {
			status(t, c.do("GET", "/api/auth/me", nil), 200)
			h.advance(15 * time.Minute)
		}
		status(t, c.do("GET", "/api/auth/me", nil), 401)
	})
}

// A session ID set before login (fixation) is never the one used after.
func TestLoginReplacesAnExistingSession(t *testing.T) {
	h := newHarness(t)
	h.user("alice", "viewer")
	c := h.signedIn("alice")
	old := c.c.Jar.Cookies(mustURL(h.srv.URL))[0].Value
	status(t, c.do("POST", "/api/auth/login", map[string]string{"username": "alice", "password": goodPassword}), 200)
	stale := h.client()
	stale.c.Jar.SetCookies(mustURL(h.srv.URL), []*http.Cookie{{Name: sessionCookie, Value: old, Path: "/"}})
	status(t, stale.do("GET", "/api/auth/me", nil), 401)
	status(t, c.do("GET", "/api/auth/me", nil), 200)
}

func TestPermissions(t *testing.T) {
	h := newHarness(t)
	h.user("root", "admin")
	h.user("vera", "viewer")
	status(t, h.signedIn("vera").do("GET", "/api/users", nil), 403)
	status(t, h.client().do("GET", "/api/users", nil), 401)
	users := decode[[]userView](t, h.signedIn("root").do("GET", "/api/users", nil))
	if len(users) != 2 || users[0].Username != "root" || !slices.Equal(users[1].Roles, []string{"viewer"}) {
		t.Fatalf("users %+v", users)
	}
}

func TestManagingUsers(t *testing.T) {
	h := newHarness(t)
	h.user("root", "admin")
	root := h.signedIn("root")
	created := decode[map[string]string](t, root.do("POST", "/api/users", map[string]any{"username": "Ed", "password": goodPassword, "roles": []string{"viewer"}}))
	id := created["id"]
	ed := h.signedIn("ed")

	t.Run("a role change ends the user's sessions", func(t *testing.T) {
		status(t, root.do("PUT", "/api/users/"+id+"/roles", map[string]any{"roles": []string{"editor"}}), 204)
		status(t, ed.do("GET", "/api/auth/me", nil), 401)
		ed = h.signedIn("ed")
		if !slices.Contains(decode[struct{ Permissions []string }](t, ed.do("GET", "/api/auth/me", nil)).Permissions, "config.write") {
			t.Fatal("new role not applied")
		}
	})
	t.Run("disabling ends sessions and stops logins", func(t *testing.T) {
		status(t, root.do("POST", "/api/users/"+id+"/disable", nil), 204)
		status(t, ed.do("GET", "/api/auth/me", nil), 401)
		status(t, h.client().do("POST", "/api/auth/login", map[string]string{"username": "ed", "password": goodPassword}), 401)
		// The audit row names the user, so filtering by username finds it.
		rows := decode[[]struct{ Action string }](t, root.do("GET", "/api/audit?target=ed&action=user.disable", nil))
		if len(rows) != 1 {
			t.Fatalf("audit %+v", rows)
		}
	})
	cases := []struct {
		name, method, path string
		in                 any
		status             int
	}{
		{"duplicate username", "POST", "/api/users", map[string]any{"username": "ed", "password": goodPassword, "roles": []string{"viewer"}}, 409},
		{"unknown role", "POST", "/api/users", map[string]any{"username": "fay", "password": goodPassword, "roles": []string{"owner"}}, 422},
		{"no role", "POST", "/api/users", map[string]any{"username": "fay", "password": goodPassword}, 422},
		{"short password", "POST", "/api/users", map[string]any{"username": "fay", "password": "short", "roles": []string{"viewer"}}, 422},
		{"username outside the allowed characters", "POST", "/api/users", map[string]any{"username": "fay smith", "password": goodPassword, "roles": []string{"viewer"}}, 422},
		{"roles for a missing user", "PUT", "/api/users/00000000-0000-0000-0000-000000000000/roles", map[string]any{"roles": []string{"viewer"}}, 404},
		{"disabling a missing user", "POST", "/api/users/00000000-0000-0000-0000-000000000000/disable", nil, 404},
		{"malformed user id", "POST", "/api/users/42/disable", nil, 422},
		{"unknown JSON field", "POST", "/api/users", map[string]any{"username": "fay", "admin": true}, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := root.do(tc.method, tc.path, tc.in)
			if resp.Header.Get("Content-Type") != "application/problem+json" {
				t.Errorf("content type %q", resp.Header.Get("Content-Type"))
			}
			status(t, resp, tc.status)
		})
	}
}

func TestUserManagersCantLockEveryoneOut(t *testing.T) {
	h := newHarness(t)
	rootID := h.user("root", "admin")
	viewerID := h.user("vic", "viewer")
	root := h.signedIn("root")
	t.Run("disabling yourself is refused", func(t *testing.T) {
		resp := root.do("POST", "/api/users/"+rootID+"/disable", nil)
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, "can't disable your own account") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("dropping the last users.manage holder is refused", func(t *testing.T) {
		resp := root.do("PUT", "/api/users/"+rootID+"/roles", map[string]any{"roles": []string{"viewer"}})
		if b := body(resp); resp.StatusCode != 409 || !strings.Contains(b, "no enabled user could manage users") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		status(t, root.do("GET", "/api/users", nil), 200)
	})
	t.Run("changing a user without users.manage still works", func(t *testing.T) {
		status(t, root.do("PUT", "/api/users/"+viewerID+"/roles", map[string]any{"roles": []string{"editor"}}), 204)
		root = h.signedIn("root")
	})
	t.Run("with a second manager, dropping your own users.manage works", func(t *testing.T) {
		h.user("ann", "admin")
		status(t, root.do("PUT", "/api/users/"+rootID+"/roles", map[string]any{"roles": []string{"viewer"}}), 204)
	})
	t.Run("disabling yourself is refused even with another manager", func(t *testing.T) {
		ann := h.signedIn("ann")
		status(t, ann.do("PUT", "/api/users/"+rootID+"/roles", map[string]any{"roles": []string{"admin"}}), 204)
		status(t, h.signedIn("root").do("POST", "/api/users/"+rootID+"/disable", nil), 409)
		status(t, ann.do("POST", "/api/users/"+rootID+"/disable", nil), 204)
	})
	var got []string
	for _, a := range h.actions() {
		if strings.HasPrefix(a, "user.") {
			got = append(got, a)
		}
	}
	want := []string{"user.create root", "user.create vic", "user.roles vic", "user.create ann", "user.roles root", "user.roles root", "user.disable root"}
	if !slices.Equal(got, want) {
		t.Fatalf("audit %v", got)
	}
}

func TestChangePassword(t *testing.T) {
	h := newHarness(t)
	h.user("alice", "viewer")
	c := h.signedIn("alice")
	other := h.signedIn("alice")
	status(t, c.do("POST", "/api/auth/password", map[string]string{"current": "wrong wrong wrong", "new": "a much better passphrase"}), 403)
	resp := c.do("POST", "/api/auth/password", map[string]string{"current": goodPassword, "new": "alice in wonderland 1865"})
	if b := body(resp); resp.StatusCode != 422 || !strings.Contains(b, "must not contain the username") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	status(t, c.do("POST", "/api/auth/password", map[string]string{"current": goodPassword, "new": "a much better passphrase"}), 204)
	// Every session ends; the new password works.
	status(t, other.do("GET", "/api/auth/me", nil), 401)
	status(t, c.do("GET", "/api/auth/me", nil), 401)
	status(t, h.client().do("POST", "/api/auth/login", map[string]string{"username": "alice", "password": "a much better passphrase"}), 200)
}

func TestAPITokens(t *testing.T) {
	h := newHarness(t)
	h.user("root", "admin")
	root := h.signedIn("root")
	mint := func(in map[string]any) map[string]string {
		t.Helper()
		resp := root.do("POST", "/api/tokens", in)
		if resp.StatusCode != 201 {
			t.Fatalf("%d %s", resp.StatusCode, body(resp))
		}
		return decode[map[string]string](t, resp)
	}
	t.Run("a user token gets only its scopes", func(t *testing.T) {
		tok := mint(map[string]any{"name": "ci", "kind": "user", "scopes": []string{"config.read"}, "expires_in": "720h"})
		c := h.client()
		c.token = tok["token"]
		if me := decode[struct{ Permissions []string }](t, c.do("GET", "/api/auth/me", nil)); !slices.Equal(me.Permissions, []string{"config.read"}) {
			t.Fatalf("perms %v", me.Permissions)
		}
		status(t, c.do("GET", "/api/users", nil), 403)
		status(t, root.do("DELETE", "/api/tokens/"+tok["id"], nil), 204)
		status(t, c.do("GET", "/api/auth/me", nil), 401)
		status(t, root.do("DELETE", "/api/tokens/"+tok["id"], nil), 404)
		// The revoke row carries the token's name, so a search by name finds
		// it as well as the create row.
		rows := decode[[]struct{ Action string }](t, root.do("GET", "/api/audit?mentions=%22ci%22", nil))
		if len(rows) != 2 || rows[0].Action != "token.revoke" || rows[1].Action != "token.create" {
			t.Fatalf("audit %+v", rows)
		}
	})
	t.Run("a token loses what its owner loses", func(t *testing.T) {
		h.user("pat", "admin")
		pat := h.signedIn("pat")
		resp := pat.do("POST", "/api/tokens", map[string]any{"name": "pat-ci", "kind": "user", "scopes": []string{"users.manage"}, "expires_in": "720h"})
		tok := decode[map[string]string](t, resp)
		c := h.client()
		c.token = tok["token"]
		status(t, c.do("GET", "/api/users", nil), 200)
		users := decode[[]userView](t, root.do("GET", "/api/users", nil))
		status(t, root.do("PUT", "/api/users/"+users[0].ID+"/roles", map[string]any{"roles": []string{"viewer"}}), 204)
		status(t, c.do("GET", "/api/users", nil), 403)
	})
	t.Run("an expired token stops working", func(t *testing.T) {
		tok := mint(map[string]any{"name": "short", "kind": "user", "scopes": []string{"config.read"}, "expires_in": "1h"})
		c := h.client()
		c.token = tok["token"]
		status(t, c.do("GET", "/api/auth/me", nil), 200)
		h.advance(time.Hour)
		status(t, c.do("GET", "/api/auth/me", nil), 401)
		root = h.signedIn("root") // its session idled out too
	})
	t.Run("an edge token can't use the admin API", func(t *testing.T) {
		tok := mint(map[string]any{"name": "edges", "kind": "edge"})
		c := h.client()
		c.token = tok["token"]
		status(t, c.do("GET", "/api/users", nil), 403)
		status(t, c.do("POST", "/api/auth/logout", nil), 400)
	})
	cases := []struct {
		name string
		in   map[string]any
		msg  string
	}{
		{"scope the creator doesn't hold", map[string]any{"name": "x", "kind": "user", "scopes": []string{"edge"}, "expires_in": "1h"}, "you don't hold edge"},
		{"edge token with scopes", map[string]any{"name": "x", "kind": "edge", "scopes": []string{"config.read"}}, "fixed access"},
		{"unknown kind", map[string]any{"name": "x", "kind": "service"}, "must be user or edge"},
		{"no name", map[string]any{"kind": "edge"}, "is required"},
		{"bad expiry", map[string]any{"name": "x", "kind": "edge", "expires_in": "-1h"}, "positive Go duration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := root.do("POST", "/api/tokens", tc.in)
			if b := body(resp); resp.StatusCode != 422 || !strings.Contains(b, tc.msg) {
				t.Fatalf("%d %s", resp.StatusCode, b)
			}
		})
	}
	if list := decode[[]tokenView](t, root.do("GET", "/api/tokens", nil)); len(list) != 4 {
		t.Fatalf("tokens %+v", list)
	}
	if strings.Contains(strings.Join(h.actions(), " "), "token.create") != true {
		t.Fatal("token creation not audited")
	}
}

// A page on another site can't make a signed-in browser change things.
func TestCrossSiteWritesAreRejected(t *testing.T) {
	h := newHarness(t)
	h.user("root", "admin")
	root := h.signedIn("root")
	status(t, root.do("POST", "/api/users", map[string]any{"username": "x", "password": goodPassword, "roles": []string{"admin"}}, "Sec-Fetch-Site", "cross-site"), 403)
	status(t, root.do("GET", "/api/users", nil, "Sec-Fetch-Site", "cross-site"), 200)
}

// Login runs before authentication, and each hash holds 19 MiB. A huge
// password or a burst of logins must not be able to exhaust admin's memory.
func TestLoginHashingIsBounded(t *testing.T) {
	t.Run("a password far over the limit is refused unread", func(t *testing.T) {
		h := newHarness(t)
		h.user("alice", "viewer")
		status(t, h.client().do("POST", "/api/auth/login", map[string]string{"username": "alice", "password": strings.Repeat("x", 1<<20)}), 413)
	})
	t.Run("logins past the hashing limit wait for a slot", func(t *testing.T) {
		h := newHarness(t)
		h.user("alice", "viewer")
		for range cap(argonSlots) {
			argonSlots <- struct{}{}
		}
		done := make(chan int)
		go func() { done <- h.loginFrom("203.0.113.5", "alice", goodPassword) }()
		select {
		case code := <-done:
			t.Fatalf("hashed with every slot taken: %d", code)
		case <-time.After(100 * time.Millisecond):
		}
		<-argonSlots
		if code := <-done; code != 200 {
			t.Fatalf("login after a slot freed: %d", code)
		}
		for range cap(argonSlots) - 1 {
			<-argonSlots
		}
	})
}

// Review findings on the identity commit.
func TestIdentityReviewFindings(t *testing.T) {
	t.Run("user tokens must expire within a year", func(t *testing.T) {
		h := newHarness(t)
		h.user("root", "admin")
		root := h.signedIn("root")
		for _, in := range []map[string]any{
			{"name": "forever", "kind": "user", "scopes": []string{"config.read"}},
			{"name": "too-long", "kind": "user", "scopes": []string{"config.read"}, "expires_in": "8761h"},
		} {
			resp := root.do("POST", "/api/tokens", in)
			if b := body(resp); resp.StatusCode != 422 || !strings.Contains(b, "expires_in") {
				t.Fatalf("%v: %d %s", in["name"], resp.StatusCode, b)
			}
		}
	})
	t.Run("guessing the current password is throttled", func(t *testing.T) {
		h := newHarness(t)
		h.user("alice", "viewer")
		c := h.signedIn("alice")
		for range 10 {
			status(t, c.do("POST", "/api/auth/password", map[string]string{"current": "guess guess guess", "new": "a much better passphrase"}), 403)
		}
		status(t, c.do("POST", "/api/auth/password", map[string]string{"current": goodPassword, "new": "a much better passphrase"}), 429)
	})
}

// loginFrom sends a login as if from peer, straight to the handler.
func (h *harness) loginFrom(peer, user, password string) int {
	h.t.Helper()
	return h.loginVia(peer, "", user, password)
}

// loginVia sends a login from peer carrying X-Forwarded-For xff, as a
// TLS-terminating proxy in front of admin would.
func (h *harness) loginVia(peer, xff, user, password string) int {
	h.t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": password})
	r := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(b))
	r.RemoteAddr = peer + ":40000"
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(w, r)
	return w.Code
}

// Throttling must not hand attackers a way to lock users out
// (SP 800-63B Rev 4 §3.2.2).
func TestThrottleResistsLockout(t *testing.T) {
	t.Run("guesses from one place don't lock the user out elsewhere", func(t *testing.T) {
		h := newHarness(t)
		h.user("alice", "viewer")
		for range 15 {
			h.loginFrom("198.51.100.66", "alice", "guess guess guess")
		}
		if code := h.loginFrom("203.0.113.5", "alice", goodPassword); code != 200 {
			t.Fatalf("alice from her own address: %d", code)
		}
	})
	t.Run("a distributed attack doesn't lock out a place the user signed in from", func(t *testing.T) {
		h := newHarness(t)
		h.user("alice", "viewer")
		if code := h.loginFrom("203.0.113.5", "alice", goodPassword); code != 200 {
			t.Fatal(code)
		}
		for i := range 20 { // 200 guesses: the account's budget is gone
			for range 10 {
				h.loginFrom(fmt.Sprintf("198.51.100.%d", i), "alice", "guess guess guess")
			}
		}
		if code := h.loginFrom("192.0.2.99", "alice", goodPassword); code != 429 {
			t.Fatalf("new place during the attack: %d", code)
		}
		if code := h.loginFrom("203.0.113.5", "alice", goodPassword); code != 200 {
			t.Fatalf("known place during the attack: %d", code)
		}
	})
	t.Run("a full table falls back to a small shared budget", func(t *testing.T) {
		h := newHarness(t)
		h.user("alice", "viewer")
		ms := h.now().UnixMilli()
		for i := range 200_000 {
			k := fmt.Sprintf("filler-%d", i)
			h.s.pairLimit.Take(k, pairAttempts, ms)
			h.s.userLimit.Take(k, userAttempts, ms)
			h.s.ipLimit.Take(k, peerAttempts, ms)
		}
		if code := h.loginFrom("203.0.113.5", "alice", goodPassword); code != 200 {
			t.Fatalf("first untracked login: %d", code)
		}
		for range overflowAttempts.Burst {
			h.loginFrom("198.51.100.1", "mallory", "guess guess guess")
		}
		if code := h.loginFrom("203.0.113.6", "bob", goodPassword); code != 429 {
			t.Fatalf("overflow budget not enforced: %d", code)
		}
		h.advance(16 * time.Minute)
		h.s.sweep(h.now())
		if code := h.loginFrom("203.0.113.5", "alice", goodPassword); code != 200 {
			t.Fatalf("after sweep: %d", code)
		}
	})
}

// Admin's session cookie is Secure, so it always sits behind an HTTPS
// proxy. Throttling the proxy's address would let one guesser lock out
// every user.
func TestThrottleBehindAProxy(t *testing.T) {
	const proxy = "10.0.0.5"
	t.Run("guesses through the proxy don't lock out another client", func(t *testing.T) {
		h := newHarness(t)
		h.s.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix(proxy + "/32")}
		h.user("alice", "viewer")
		for range 15 {
			h.loginVia(proxy, "198.51.100.66", "alice", "guess guess guess")
		}
		if code := h.loginVia(proxy, "203.0.113.5", "alice", goodPassword); code != 200 {
			t.Fatalf("alice from her own address: %d", code)
		}
	})
	t.Run("the client is the rightmost address the proxy didn't add", func(t *testing.T) {
		h := newHarness(t)
		h.s.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
		h.user("alice", "viewer")
		for i := range 10 { // the attacker writes its own left-hand entries
			h.loginVia(proxy, fmt.Sprintf("192.0.2.%d, 198.51.100.66, 10.0.0.9", i), "alice", "guess guess guess")
		}
		if code := h.loginVia(proxy, "198.51.100.66", "alice", goodPassword); code != 429 {
			t.Fatalf("spoofed entries escaped the throttle: %d", code)
		}
	})
	t.Run("an untrusted peer can't choose its address", func(t *testing.T) {
		h := newHarness(t)
		h.s.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix(proxy + "/32")}
		h.user("alice", "viewer")
		for i := range 10 {
			h.loginVia("198.51.100.66", fmt.Sprintf("192.0.2.%d", i), "alice", "guess guess guess")
		}
		if code := h.loginVia("198.51.100.66", "192.0.2.200", "alice", goodPassword); code != 429 {
			t.Fatalf("X-Forwarded-For from an untrusted peer was honored: %d", code)
		}
	})
	t.Run("audit records the client, not the proxy", func(t *testing.T) {
		h := newHarness(t)
		h.s.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix(proxy + "/32")}
		h.user("alice", "viewer")
		h.loginVia(proxy, "203.0.113.5", "alice", goodPassword)
		var p string
		_ = h.db.QueryRow(t.Context(), "SELECT details->>'peer' FROM audit_events WHERE action = 'auth.login.success'").Scan(&p)
		if p != "203.0.113.5" {
			t.Fatalf("audit peer %q", p)
		}
	})
}

// Under overflow no account gets more guesses than its usual budget.
func TestOverflowBudgetStaysUnderTheAccountCap(t *testing.T) {
	window := 15 * time.Minute.Milliseconds()
	if perWindow := overflowAttempts.Limit * window / overflowAttempts.Period; perWindow >= userAttempts.Limit {
		t.Fatalf("overflow allows %d per 15 minutes, account cap is %d", perWindow, userAttempts.Limit)
	}
}

// A stolen session guessing the current password from many addresses
// still gets 10 tries per 15 minutes.
func TestPasswordChangeGuessesFromManyPeers(t *testing.T) {
	h := newHarness(t)
	h.user("alice", "viewer")
	c := h.signedIn("alice")
	ck := c.c.Jar.Cookies(mustURL(h.srv.URL))[0]
	try := func(peer, current string) int {
		b, _ := json.Marshal(map[string]string{"current": current, "new": "a much better passphrase"})
		r := httptest.NewRequest("POST", "/api/auth/password", bytes.NewReader(b))
		r.RemoteAddr = peer + ":40000"
		r.AddCookie(ck)
		w := httptest.NewRecorder()
		h.s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	for i := range 10 {
		if code := try(fmt.Sprintf("198.51.100.%d", i), "guess guess guess"); code != 403 {
			t.Fatalf("guess %d: %d", i, code)
		}
	}
	if code := try("198.51.100.200", goodPassword); code != 429 {
		t.Fatalf("eleventh try: %d", code)
	}
}

// The UI offers the roles that exist, with what each allows, instead of
// knowing role names itself.
func TestListRoles(t *testing.T) {
	h := newHarness(t)
	h.user("vera", "viewer")
	roles := decode[[]struct {
		Name        string
		Permissions []string
	}](t, h.signedIn("vera").do("GET", "/api/roles", nil))
	if len(roles) != 4 || roles[0].Name != "admin" || !slices.Contains(roles[0].Permissions, "users.manage") || roles[3].Name != "viewer" || len(roles[3].Permissions) != 4 {
		t.Fatalf("roles %+v", roles)
	}
	status(t, h.client().do("GET", "/api/roles", nil), 401)
}
