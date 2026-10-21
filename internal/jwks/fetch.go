package jwks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// Client fetches JWKS URLs that admin users entered, so every connection
// passes the SSRF guard.
type Client struct{ http *http.Client }

// NewClient builds a fetcher. allowedHosts may resolve to private addresses
// (JWKS_ALLOWED_HOSTS); roots is nil for the system pool.
func NewClient(allowedHosts []string, timeout time.Duration, roots *x509.CertPool) *Client {
	allowed := map[string]bool{}
	for _, h := range allowedHosts {
		allowed[strings.ToLower(h)] = true
	}
	tr := &http.Transport{
		// No proxy: a proxy would make the dial check see only the proxy.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: timeout}
			if host, _, _ := net.SplitHostPort(addr); !allowed[strings.ToLower(host)] {
				// Checked on the address actually dialed, so a name that
				// resolves differently between a check and the dial (DNS
				// rebinding) can't reach a private address.
				d.Control = guard
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: timeout,
	}
	return &Client{http: &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
				return errors.New("jwks redirect must stay on the same https host")
			}
			return nil
		},
	}}
}

// ErrNonPublic marks a fetch the SSRF guard refused, so callers can say so
// in words rather than as a dial error.
var ErrNonPublic = errors.New("non-public address")

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10") // shared address space, internal in many clouds
	nat64 = netip.MustParsePrefix("64:ff9b::/96")  // embeds an IPv4 address
)

func guard(_, address string, _ syscall.RawConn) error {
	// Control always gets ip:port; anything else parses to the zero
	// address, which blocked refuses.
	ap, _ := netip.ParseAddrPort(address)
	if blocked(ap.Addr()) {
		return fmt.Errorf("jwks fetch to %w %s refused", ErrNonPublic, ap.Addr())
	}
	return nil
}

// blocked covers loopback, link-local (cloud metadata), private, multicast,
// unspecified and shared addresses.
func blocked(a netip.Addr) bool {
	a = a.Unmap()
	if nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[12:]))
	}
	return !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a)
}

// Fetch GETs url and returns the body, at most MaxBytes.
func (c *Client) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		// The parse error quotes the URL, whose query may hold a secret.
		return nil, errors.New("jwks url is not a valid URL")
	}
	if req.URL.Scheme != "https" {
		return nil, errors.New("jwks url must be https")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// Do returns a *url.Error, which quotes the URL; fetch errors are
		// logged and the query may hold a secret, so keep only the cause.
		return nil, fmt.Errorf("jwks fetch: %w", errors.Unwrap(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBytes {
		return nil, fmt.Errorf("jwks is larger than %d bytes", MaxBytes)
	}
	return b, nil
}
