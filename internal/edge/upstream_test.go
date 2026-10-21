package edge

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// The upstream is a load balancer that, like an Istio gateway or an ALB,
// picks its certificate and route by TLS server name. Each Host reaches it
// named as itself, with no host list on the edge, while the connection still
// goes to UPSTREAM_URL. A name it has no certificate for fails as a 502.
func TestHTTPSUpstreamIsNamedByTheRequestHost(t *testing.T) {
	served := []string{"api.example.com", "shop.example.com"}
	cert, roots := selfSigned(t, served...)
	lb := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.ServerName+" "+r.Host)
	}))
	lb.TLS = &tls.Config{GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if slices.Contains(served, hi.ServerName) {
			return &cert, nil
		}
		return nil, fmt.Errorf("no listener for %q", hi.ServerName)
	}}
	lb.StartTLS()
	t.Cleanup(lb.Close)
	old := upstreamRoots
	upstreamRoots = roots
	t.Cleanup(func() { upstreamRoots = old })

	h := newHarness(t, map[string]string{"UPSTREAM_URL": lb.URL})
	h.load(envelope(testConfig(1)))
	for _, host := range served {
		if body := readBody(t, h.do("GET", "/", nil, "Host", host)); body != host+" "+host {
			t.Errorf("Host %s: load balancer saw %q, want server name and Host %s", host, body, host)
		}
	}
	edgeError(t, h.do("GET", "/", nil, "Host", "other.example.com"), 502, "bad_gateway")
}

// A client can send any Host. One the load balancer has no certificate for
// is a 502 counted as upstream_tls, with no warn line per request, whether
// the load balancer refuses the name or presents a certificate without it.
func TestHTTPSUpstreamWithoutACertificateForTheHostIsNotLogged(t *testing.T) {
	cert, roots := selfSigned(t, "api.example.com")
	old := upstreamRoots
	upstreamRoots = roots
	t.Cleanup(func() { upstreamRoots = old })
	for name, getCert := range map[string]func(*tls.ClientHelloInfo) (*tls.Certificate, error){
		"refuses the name": func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hi.ServerName == "api.example.com" {
				return &cert, nil
			}
			return nil, fmt.Errorf("no listener for %q", hi.ServerName)
		},
		"presents another name": func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
	} {
		t.Run(name, func(t *testing.T) {
			lb := httptest.NewUnstartedServer(http.NotFoundHandler())
			lb.TLS = &tls.Config{GetCertificate: getCert}
			lb.StartTLS()
			t.Cleanup(lb.Close)
			h := newHarness(t, map[string]string{"UPSTREAM_URL": lb.URL})
			h.load(envelope(testConfig(1)))
			edgeError(t, h.do("GET", "/", nil, "Host", "other.example.com"), 502, "bad_gateway")
			if got := h.srv.m.rejected[reasonUpstreamTLS].Load(); got != 1 {
				t.Errorf("upstream_tls counted %d times, want 1", got)
			}
			if strings.Contains(h.logs.String(), "upstream request failed") {
				t.Error("a client-chosen Host produced a warn line")
			}
		})
	}
}

// HTTP/1.0 allows a request with no Host. Over HTTPS the edge then names the
// upstream by its own host, as an http upstream is reached, so the load
// balancer answers it rather than the edge failing it as a 502.
func TestHTTPSUpstreamNamesItselfForARequestWithoutHost(t *testing.T) {
	cert, roots := selfSigned(t, "localhost")
	lb := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.ServerName+" Host="+r.Host)
	}))
	lb.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	lb.StartTLS()
	t.Cleanup(lb.Close)
	old := upstreamRoots
	upstreamRoots = roots
	t.Cleanup(func() { upstreamRoots = old })
	_, port, _ := net.SplitHostPort(lb.Listener.Addr().String())

	h := newHarness(t, map[string]string{"UPSTREAM_URL": "https://localhost:" + port})
	h.load(envelope(testConfig(1)))
	conn, err := net.Dial("tcp", h.front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.0\r\nCloudFront-Viewer-Address: 198.51.100.7:1\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Go's client sends the URL's host when Host is empty.
	if body := readBody(t, resp); resp.StatusCode != 200 || body != "localhost Host=localhost:"+port {
		t.Fatalf("status %d, body %q; want 200 from the load balancer named localhost", resp.StatusCode, body)
	}
}

// selfSigned is a certificate for names that is also its own trust root.
func selfSigned(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
