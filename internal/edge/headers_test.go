package edge

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// headersConfig exercises every operation and placeholder.
func headersConfig() *snapshot.Config {
	c := testConfig(1)
	c.Global.RequestHeaders.Forward = snapshot.Forward{Mode: "denylist", Names: []string{"X-Debug"}}
	c.RequestHeaderRules = []snapshot.HeaderRule{
		{ID: "keep-ua", Expression: mustParse(`true`), Ops: []snapshot.HeaderOp{{Op: "copy", From: "User-Agent", To: "X-Original-User-Agent"}}},
		{ID: "trace", Expression: mustParse(`true`), Ops: []snapshot.HeaderOp{
			{Op: "set", Name: "X-Trace", Value: "edge {{request_id}} {{client_ip}} {{country}} {{header:x-customer}}"},
			{Op: "append", Name: "X-Hops", Value: "edge"},
			{Op: "remove", Name: "X-Debug-Token"},
			{Op: "rename", From: "X-Old", To: "X-New"},
		}},
		{ID: "orders", Expression: mustParse(`starts_with(http.request.uri.path, "/orders")`), Ops: []snapshot.HeaderOp{
			{Op: "forward", Mode: "allowlist", Names: []string{"Accept", "Authorization", "User-Agent"}},
		}},
	}
	return c
}

// Step 9 applies the forward filter, then rule operations in order, then
// edge-managed headers, which no rule can override.
func TestHeaderRules(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(headersConfig()))
	upstream := func(path string, headers ...string) http.Header {
		t.Helper()
		h.do("GET", path, nil, headers...).Body.Close()
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.lastApp.Header
	}

	got := upstream("/", "User-Agent", "ua/1", "X-Debug", "1", "X-Debug-Token", "t", "X-Old", "o", "X-Hops", "lb",
		"X-Customer", "acme", "CloudFront-Viewer-Country", "AU", "X-Request-Id", "abc")
	want := map[string][]string{
		"X-Original-User-Agent": {"ua/1"}, "X-Debug": nil, "X-Debug-Token": nil, "X-Old": nil, "X-New": {"o"},
		"X-Hops": {"lb", "edge"}, "X-Trace": {"edge " + got.Get("X-Request-Id") + " 198.51.100.7 AU acme"},
		"X-Forwarded-For": {"198.51.100.7"}, "X-Edge-Geo-Country": {"AU"},
	}
	for k, v := range want {
		if fmt.Sprint(got[k]) != fmt.Sprint(v) {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}

	t.Run("a copy with no source removes a client-sent target", func(t *testing.T) {
		got := upstream("/", "User-Agent", "", "X-Original-User-Agent", "forged")
		if v, ok := got["X-Original-User-Agent"]; ok {
			t.Fatalf("forged target kept: %q", v)
		}
	})

	t.Run("a matching rule's allowlist replaces the global filter", func(t *testing.T) {
		got := upstream("/orders/1", "Accept", "a", "Cookie", "c", "X-Customer", "acme", "User-Agent", "ua")
		for _, k := range []string{"Cookie", "X-Customer"} {
			if got.Get(k) != "" {
				t.Errorf("%s not dropped by the allowlist", k)
			}
		}
		// Operations run after the filter, and edge-managed headers last.
		if got.Get("Accept") != "a" || got.Get("X-Original-User-Agent") != "ua" || got.Get("X-Trace") == "" || got.Get("X-Forwarded-For") == "" {
			t.Errorf("upstream headers %v", got)
		}
	})

	t.Run("a WebSocket upgrade survives an allowlist", func(t *testing.T) {
		h.appHandler = func(w http.ResponseWriter, r *http.Request) {
			h.mu.Lock()
			h.lastApp = r
			h.mu.Unlock()
			echoUpgrade(w, r)
		}
		ws := dialUpgradePath(t, strings.TrimPrefix(h.front.URL, "http://"), "/orders/ws")
		ws.Close()
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.lastApp.Header.Get("Upgrade") != "echo" {
			t.Fatalf("upgrade headers dropped: %v", h.lastApp.Header)
		}
	})
}

// Config tests see the headers the upstream would get, with values from
// tokens made header-safe.
func TestSimulateUpstreamHeaders(t *testing.T) {
	c := headersConfig()
	c.Global.Locale = snapshot.Locale{Supported: []string{"en", "ko"}, Default: "en"}
	c.Auth = snapshot.Auth{Issuers: []snapshot.Issuer{{ID: "corp", Issuer: "https://id/", Audiences: []string{"api"}, JWKSURL: "https://id/jwks", Algorithm: "RS256"}}, DefaultAccepted: []string{"corp"}}
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "locale", Expression: mustParse(`true`), Settings: snapshot.Settings{Locale: new(true), Auth: &snapshot.AuthSetting{Mode: "required"}}})
	c.RequestHeaderRules = append(c.RequestHeaderRules, snapshot.HeaderRule{ID: "tenant", Expression: mustParse(`true`), Ops: []snapshot.HeaderOp{{Op: "set", Name: "X-Tenant", Value: "{{jwt_claim:tenant}} {{locale}}"}}})
	compiled, _, errs := snapshot.Compile(c, testDeployment())
	if errs != nil {
		t.Fatal(errs)
	}
	res, err := Simulate(compiled, SimRequest{Method: "GET", Host: "api.example.com", Target: "/orders/1", IP: "203.0.113.9",
		Headers: map[string][]string{"Accept": {"a"}, "Cookie": {"c"}, "Accept-Language": {"ko"}},
		// A claim can hold anything the IdP put in it, including CR/LF.
		JWTClaims: map[string][]string{"tenant": {"acme\r\nX-Injected: 1"}}})
	if err != nil {
		t.Fatal(err)
	}
	u := res.UpstreamHeaders
	if u.Get("X-Tenant") != "acmeX-Injected: 1 ko" || u.Get("Cookie") != "" || u.Get("Accept") != "a" || u.Get("X-Edge-Locale") != "ko" || u.Get("X-Trace") != "edge simulated 203.0.113.9  " {
		t.Fatalf("upstream headers %v", u)
	}
}

// headerSafe removes exactly the control characters, keeping tabs and
// obs-text bytes, against a byte-by-byte reference.
func FuzzHeaderSafe(f *testing.F) {
	f.Add("acme\r\nX-Injected: 1")
	f.Add("tab\tok\x7f\x00é")
	f.Fuzz(func(t *testing.T, s string) {
		var want []byte
		for i := 0; i < len(s); i++ {
			if c := s[i]; c == '\t' || c >= 0x20 && c != 0x7f {
				want = append(want, c)
			}
		}
		if got := headerSafe(s); got != string(want) {
			t.Fatalf("headerSafe(%q) = %q, want %q", s, got, want)
		}
	})
}

func dialUpgradePath(t *testing.T, addr, path string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: api.example.com\r\nCloudFront-Viewer-Address: 198.51.100.7:1\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	return conn
}
