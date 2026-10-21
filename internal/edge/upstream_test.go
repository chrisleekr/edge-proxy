package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
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
