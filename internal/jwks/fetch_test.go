package jwks

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

// idp serves handler over TLS on 127.0.0.1 and returns its URL and a
// client trusting its certificate with the given allowed hosts.
func idp(t *testing.T, handler http.HandlerFunc, allowed ...string) (string, *Client) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv.URL, NewClient(allowed, 2*time.Second, roots)
}

func TestFetchFromAnAllowedPrivateHost(t *testing.T) {
	body := testenv.JWKS(mkJWK("k", edPub))
	u, c := idp(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/jwks", http.StatusFound)
			return
		}
		_, _ = w.Write(body)
	}, "127.0.0.1")
	for _, path := range []string{"/jwks", "/old"} {
		b, err := c.Fetch(t.Context(), u+path)
		if err != nil || string(b) != string(body) {
			t.Fatalf("Fetch(%s) = %q, %v", path, b, err)
		}
	}
}

// A crawler range list goes through the same guard with its own size cap,
// and its errors name it as a source, not a JWKS.
func TestFetchMaxCapsOtherDocuments(t *testing.T) {
	ranges := `{"prefixes":[{"ipv4Prefix":"66.249.64.0/27"}]}`
	u, c := idp(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(ranges)) }, "127.0.0.1")
	if b, err := c.FetchMax(t.Context(), u, len(ranges)); err != nil || string(b) != ranges {
		t.Fatalf("FetchMax = %q, %v", b, err)
	}
	if _, err := c.FetchMax(t.Context(), u, len(ranges)-1); err == nil || !strings.HasPrefix(err.Error(), "source is larger than") {
		t.Fatalf("over the cap: %v", err)
	}
}

// A JWKS URL can carry a secret in its query. Errors are logged, so they
// must not repeat the URL.
func TestFetchErrorsOmitTheURL(t *testing.T) {
	c := NewClient(nil, 2*time.Second, nil)
	for _, u := range []string{"https://127.0.0.1:1/jwks?api_key=s3cret", "https://127.0.0.1:1/%zz?api_key=s3cret"} {
		if _, err := c.Fetch(t.Context(), u); err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("err = %v", err)
		}
	}
}

func TestFetchRefuses(t *testing.T) {
	u, open := idp(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			http.NotFound(w, r)
		case "/huge":
			_, _ = w.Write([]byte(strings.Repeat("x", MaxBytes+1)))
		case "/cut":
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte(`{"keys":`))
		case "/away":
			http.Redirect(w, r, "https://example.com/jwks", http.StatusFound)
		case "/plain":
			http.Redirect(w, r, "http://"+r.Host+"/jwks", http.StatusFound)
		}
	}, "127.0.0.1")
	port := must(url.Parse(u)).Port()
	guarded := NewClient(nil, 2*time.Second, nil)
	cases := []struct {
		name string
		c    *Client
		url  string
		msg  string
	}{
		{"loopback address not in JWKS_ALLOWED_HOSTS", guarded, u + "/jwks", "non-public address 127.0.0.1"},
		// The name passes any check made before the dial; the address dialed doesn't.
		{"public-looking name that resolves to loopback", guarded, "https://localhost:" + port + "/jwks", "non-public address"},
		{"cloud metadata address", guarded, "https://169.254.169.254/latest", "non-public address"},
		{"plain http", open, "http://127.0.0.1:" + port + "/jwks", "must be https"},
		{"malformed url", open, "https://127.0.0.1:" + port + "/%zz", "not a valid URL"},
		{"error status", open, u + "/missing", "status 404"},
		{"body over 64 KB", open, u + "/huge", "larger than 65536"},
		{"body cut short", open, u + "/cut", "unexpected EOF"},
		{"redirect to another host", open, u + "/away", "same https host"},
		{"redirect to http", open, u + "/plain", "same https host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.c.Fetch(t.Context(), tc.url)
			if err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v, want %q", err, tc.msg)
			}
			if guardedOut := strings.Contains(tc.msg, "non-public"); errors.Is(err, ErrNonPublic) != guardedOut {
				t.Fatalf("errors.Is(err, ErrNonPublic) = %v for %v", !guardedOut, err)
			}
		})
	}
}

// The dial check refuses every non-public address and passes public ones.
func TestGuard(t *testing.T) {
	cases := []struct {
		addr    string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"fe80::1", true},
		{"fd00::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"100.64.0.1", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"::ffff:127.0.0.1", true},
		{"64:ff9b::7f00:1", true}, // NAT64 of 127.0.0.1
		{"64:ff9b::808:808", false},
		{"8.8.8.8", false},
		{"2001:4860:4860::8888", false},
	}
	for _, tc := range cases {
		ap := netip.AddrPortFrom(netip.MustParseAddr(tc.addr), 443)
		if err := guard("tcp", ap.String(), nil); (err != nil) != tc.blocked {
			t.Errorf("guard(%s) = %v", ap, err)
		}
	}
}
