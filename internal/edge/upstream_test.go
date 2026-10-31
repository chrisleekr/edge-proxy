package edge

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
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
	"unicode/utf8"
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
// is a 502 counted as upstream_tls, with the error on its access line and
// no warn line per request, whether the load balancer refuses the name or
// presents a certificate without it.
func TestHTTPSUpstreamWithoutACertificateForTheHostLogsTheTLSErrorOnTheAccessLineOnly(t *testing.T) {
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
			waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
			if strings.Contains(h.logs.String(), `"level":"WARN"`) {
				t.Error("a client-chosen Host produced a warn line")
			}
			line := h.logs.lines("access")[0]
			if msg, _ := line["edge.upstream_error"].(string); line["edge.decision"] != "upstream_tls" || !strings.Contains(msg, "tls") || line["edge.upstream_error_kind"] != "tls" {
				t.Errorf("access line %v, want the TLS error with kind tls", line)
			}
		})
	}
}

// The certificate error names the Host, which the client picks, so the
// logged message is cut to 512 bytes however long the Host is.
func TestUpstreamErrorOnTheAccessLineIsBounded(t *testing.T) {
	cert, roots := selfSigned(t, "api.example.com")
	old := upstreamRoots
	upstreamRoots = roots
	t.Cleanup(func() { upstreamRoots = old })
	lb := httptest.NewUnstartedServer(http.NotFoundHandler())
	lb.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	lb.StartTLS()
	t.Cleanup(lb.Close)
	h := newHarness(t, map[string]string{"UPSTREAM_URL": lb.URL})
	h.load(envelope(testConfig(1)))
	host := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.com"
	host = strings.Repeat(host+".", 4) + "example.com"
	edgeError(t, h.do("GET", "/", nil, "Host", host), 502, "bad_gateway")
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
	msg, _ := h.logs.lines("access")[0]["edge.upstream_error"].(string)
	if len(msg) != maxUpstreamError || !strings.Contains(msg, "certificate is valid for api.example.com") {
		t.Fatalf("edge.upstream_error is %d bytes, want the certificate error cut to %d: %q", len(msg), maxUpstreamError, msg)
	}

	// A CA name can be UTF-8. The load balancer's certificate comes from a
	// CA the edge trusts only under another key with the same name, as
	// after a CA rotation, so the error quotes the name. The cut never
	// splits a character, whichever byte the 512th falls on.
	for _, name := range []string{strings.Repeat("Ü", 200), "x" + strings.Repeat("Ü", 200)} {
		t.Run(fmt.Sprintf("a %d-byte CA name", len(name)), func(t *testing.T) {
			signer := testCA(t, name)
			trusted := testCA(t, name)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"api.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, &key.PublicKey, signer.key)
			if err != nil {
				t.Fatal(err)
			}
			pool := x509.NewCertPool()
			pool.AddCert(trusted.cert)
			upstreamRoots = pool
			lb := httptest.NewUnstartedServer(http.NotFoundHandler())
			lb.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			lb.StartTLS()
			t.Cleanup(lb.Close)
			h := newHarness(t, map[string]string{"UPSTREAM_URL": lb.URL})
			h.load(envelope(testConfig(1)))
			edgeError(t, h.do("GET", "/", nil), 502, "bad_gateway")
			waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
			msg, _ := h.logs.lines("access")[0]["edge.upstream_error"].(string)
			// JSON shows a split character as U+FFFD.
			if len(msg) < maxUpstreamError-1 || len(msg) > maxUpstreamError || strings.ContainsRune(msg, utf8.RuneError) || !strings.Contains(msg, "candidate authority certificate \""+name[:3]) {
				t.Fatalf("edge.upstream_error is %d bytes: %q", len(msg), msg)
			}
		})
	}
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// testCA is a self-signed CA named name, with its own key.
func testCA(t *testing.T, name string) ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca{cert, key}
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

// Each way the upstream can fail is a 502 whose access line names the
// error and its kind, so an operator can tell a stopped upstream from a
// name that no longer resolves without a separate warn line per request.
// The 502 counts as the edge's own answer, apart from upstream 502s.
func TestUpstreamFailureKinds(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		upstream   func(t *testing.T) map[string]string
		fail       func(h *harness)
	}{
		{name: "a closed port fails as refused", kind: "refused", fail: func(h *harness) { h.app.Close() }},
		{name: "a connection the upstream aborts fails as reset", kind: "reset", upstream: abortingUpstream},
		{name: "a name that does not resolve fails as dns", kind: "dns", fail: unresolvableUpstream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var set map[string]string
			if tc.upstream != nil {
				set = tc.upstream(t)
			}
			h := newHarness(t, set)
			h.load(envelope(testConfig(1)))
			if tc.fail != nil {
				tc.fail(h)
			}
			edgeError(t, h.do("GET", "/", nil), 502, "bad_gateway")
			waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
			line := h.logs.lines("access")[0]
			if line["edge.decision"] != "upstream_error" {
				t.Fatalf("decision %v, want upstream_error", line["edge.decision"])
			}
			if msg, _ := line["edge.upstream_error"].(string); msg == "" || len(msg) > 512 {
				t.Errorf("edge.upstream_error = %q, want the error message, at most 512 bytes", msg)
			}
			if line["edge.upstream_error_kind"] != tc.kind {
				t.Errorf("edge.upstream_error_kind = %v, want %s", line["edge.upstream_error_kind"], tc.kind)
			}
			if strings.Contains(h.logs.String(), `"level":"WARN"`) {
				t.Error("the failure also wrote a separate warn line")
			}
			if got := statusCodes(t, h.srv.store.load().active.stats.counts()); fmt.Sprint(got) != fmt.Sprint(map[string]map[string]uint64{"edge": {"502": 1}}) {
				t.Errorf("status codes %v, want one edge 502", got)
			}
		})
	}
}

// Each upstream failure is counted once by cause in the version's report,
// so admin can show exact counts for a stopped upstream or a name that no
// longer resolves. The access line names the same cause.
func TestUpstreamFailuresAreCountedByCause(t *testing.T) {
	for _, tc := range []struct {
		name, cause, kind string
		status            int
		upstream          func(t *testing.T) map[string]string
		fail              func(h *harness)
		send              func(t *testing.T, h *harness) *http.Response
	}{
		{name: "a closed port counts as refused", cause: "refused", status: 502, kind: "bad_gateway", fail: func(h *harness) { h.app.Close() }},
		{name: "a connection the upstream aborts counts as reset", cause: "reset", status: 502, kind: "bad_gateway", upstream: abortingUpstream},
		{name: "a name that does not resolve counts as dns", cause: "dns", status: 502, kind: "bad_gateway", fail: unresolvableUpstream},
		{name: "a Host the load balancer has no certificate for counts as tls", cause: "tls", status: 502, kind: "bad_gateway", upstream: func(t *testing.T) map[string]string {
			t.Helper()
			cert, roots := selfSigned(t, "api.example.com")
			old := upstreamRoots
			upstreamRoots = roots
			t.Cleanup(func() { upstreamRoots = old })
			lb := httptest.NewUnstartedServer(http.NotFoundHandler())
			lb.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			lb.StartTLS()
			t.Cleanup(lb.Close)
			return map[string]string{"UPSTREAM_URL": lb.URL}
		}, send: func(_ *testing.T, h *harness) *http.Response {
			return h.do("GET", "/", nil, "Host", "other.example.com")
		}},
		{name: "headers later than the route's upstream timeout count as timeout", cause: "timeout", status: 504, kind: "gateway_timeout",
			fail: func(h *harness) { h.appHandler = func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() } },
			send: func(_ *testing.T, h *harness) *http.Response { return h.do("GET", "/admin/slow", nil) }},
		{name: "a switch to a protocol the client did not ask for counts as other", cause: "other", status: 502, kind: "bad_gateway",
			fail: func(h *harness) {
				h.appHandler = func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Connection", "Upgrade")
					w.Header().Set("Upgrade", "something-else")
					w.WriteHeader(http.StatusSwitchingProtocols)
				}
			},
			send: func(t *testing.T, h *harness) *http.Response {
				t.Helper()
				resp, _, _ := raw(t, h.front.Listener.Addr().String(), wsHandshake)
				return resp
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var set map[string]string
			if tc.upstream != nil {
				set = tc.upstream(t)
			}
			h := newHarness(t, set)
			h.load(envelope(testConfig(1)))
			if tc.fail != nil {
				tc.fail(h)
			}
			var resp *http.Response
			if tc.send != nil {
				resp = tc.send(t, h)
			} else {
				resp = h.do("GET", "/", nil)
			}
			edgeError(t, resp, tc.status, tc.kind)
			waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
			if got := h.logs.lines("access")[0]["edge.upstream_error_kind"]; got != tc.cause {
				t.Errorf("edge.upstream_error_kind = %v, want %s", got, tc.cause)
			}
			if got := upstreamErrors(t, h.srv.poller.reg.deltas()[0]); fmt.Sprint(got) != fmt.Sprint(map[string]uint64{tc.cause: 1}) {
				t.Errorf("upstream_errors %v, want %s: 1", got, tc.cause)
			}
		})
	}
}

// upstreamErrors is the upstream_errors object of c as reports send it.
func upstreamErrors(t *testing.T, c StatsCounts) map[string]uint64 {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		UpstreamErrors map[string]uint64 `json:"upstream_errors"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m.UpstreamErrors
}

// An upstream that sends a header line Go can't parse fails as a 502.
// Go's error quotes the whole line, which can hold a cookie, so the access
// line keeps the cause and drops the quoted line.
func TestMalformedUpstreamHeaderIsLoggedWithoutItsValue(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = http.ReadRequest(bufio.NewReader(c))
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nSet-Cookie: session=secret-session-token\x01\r\nContent-Length: 0\r\n\r\n")
			_ = c.Close()
		}
	}()
	h := newHarness(t, map[string]string{"UPSTREAM_URL": "http://" + ln.Addr().String()})
	h.load(envelope(testConfig(1)))
	edgeError(t, h.do("GET", "/", nil), 502, "bad_gateway")
	waitFor(t, func() bool { return len(h.logs.lines("access")) == 1 })
	line := h.logs.lines("access")[0]
	msg, _ := line["edge.upstream_error"].(string)
	if line["edge.decision"] != "upstream_error" || !strings.Contains(msg, "malformed MIME header line") {
		t.Fatalf("access line %v, want the malformed header cause", line)
	}
	if strings.Contains(h.logs.String(), "secret-session-token") {
		t.Fatalf("the upstream's cookie was logged: %q", msg)
	}
}

// unresolvableUpstream points the edge's transport at a name whose lookup
// fails, with no DNS server reached.
func unresolvableUpstream(h *harness) {
	tr := newTransport(h.srv.cfg)
	d := &net.Dialer{Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("no DNS server reachable")
	}}}
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, "upstream.invalid:80")
	}
	h.srv.edge.rp.Transport = tr
}

// abortingUpstream reads each request, then resets the connection.
func abortingUpstream(t *testing.T) map[string]string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = http.ReadRequest(bufio.NewReader(c))
			_ = c.(*net.TCPConn).SetLinger(0) // close sends RST
			_ = c.Close()
		}
	}()
	return map[string]string{"UPSTREAM_URL": "http://" + ln.Addr().String()}
}
