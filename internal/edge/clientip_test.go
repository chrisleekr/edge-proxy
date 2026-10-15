package edge

import (
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func identityFor(t testing.TB, set map[string]string) *identity {
	t.Helper()
	e := cloudfrontEnv()
	maps.Copy(e, set)
	c, err := LoadConfig(env(e))
	if err != nil {
		t.Fatal(err)
	}
	return newIdentity(c)
}

func cdnRequest(peer string, headers ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	r.RemoteAddr = peer
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Add(headers[i], headers[i+1])
	}
	return r
}

// The real client and viewer fields come from CDN headers, and only when the
// TCP peer is a trusted proxy. Anything ambiguous is a 400, never a guess.
func TestIdentify(t *testing.T) {
	cf := identityFor(t, nil)
	cases := []struct {
		name string
		id   *identity
		r    *http.Request
		want netip.Addr
		err  error
	}{
		{"CloudFront IPv4 with port", cf, cdnRequest("10.1.2.3:5000", "CloudFront-Viewer-Address", "198.51.100.10:46532"), netip.MustParseAddr("198.51.100.10"), nil},
		{"CloudFront IPv6 without brackets", cf, cdnRequest("10.1.2.3:5000", "CloudFront-Viewer-Address", "2001:db8::1:443"), netip.MustParseAddr("2001:db8::1"), nil},
		{"CloudFront IPv6 with brackets", cf, cdnRequest("10.1.2.3:5000", "CloudFront-Viewer-Address", "[2001:db8::1]:443"), netip.MustParseAddr("2001:db8::1"), nil},
		{"IPv4-mapped IPv6 becomes IPv4", cf, cdnRequest("10.1.2.3:5000", "CloudFront-Viewer-Address", "[::ffff:198.51.100.7]:1"), netip.MustParseAddr("198.51.100.7"), nil},
		{"trusted peer that is IPv4-mapped", cf, cdnRequest("[::ffff:10.1.2.3]:5000", "CloudFront-Viewer-Address", "198.51.100.10:1"), netip.MustParseAddr("198.51.100.10"), nil},
		{"peer outside TRUSTED_PROXIES", cf, cdnRequest("203.0.113.9:5000", "CloudFront-Viewer-Address", "198.51.100.10:1"), netip.Addr{}, errUntrustedPeer},
		{"peer address that isn't ip:port", cf, cdnRequest("pipe", "CloudFront-Viewer-Address", "198.51.100.10:1"), netip.Addr{}, errUntrustedPeer},
		{"missing client IP header", cf, cdnRequest("10.1.2.3:5000"), netip.Addr{}, errClientIPHeader},
		{"client IP header sent twice", cf, cdnRequest("10.1.2.3:5000", "CloudFront-Viewer-Address", "198.51.100.10:1", "CloudFront-Viewer-Address", "203.0.113.1:1"), netip.Addr{}, errClientIPHeader},
		{"port missing where one is expected", cf, cdnRequest("10.1.2.3:5000", "CloudFront-Viewer-Address", "198.51.100.10"), netip.Addr{}, errClientIPHeader},
		{"port that isn't a number", cf, cdnRequest("10.1.2.3:5000", "CloudFront-Viewer-Address", "198.51.100.10:http"), netip.Addr{}, errClientIPHeader},
		{"bracketed address that doesn't parse", cf, cdnRequest("10.1.2.3:5000", "CloudFront-Viewer-Address", "[2001:db8::g]:1"), netip.Addr{}, errClientIPHeader},
		{"zoned address", cf, cdnRequest("10.1.2.3:5000", "CloudFront-Viewer-Address", "[fe80::1%eth0]:1"), netip.Addr{}, errClientIPHeader},
		{"zoned address without brackets", identityFor(t, map[string]string{"CLIENT_IP_SOURCE": "cloudflare"}), cdnRequest("10.1.2.3:5000", "CF-Connecting-IP", "fe80::1%eth0"), netip.Addr{}, errClientIPHeader},
		{"Cloudflare plain IP", identityFor(t, map[string]string{"CLIENT_IP_SOURCE": "cloudflare"}), cdnRequest("10.0.0.1:1", "CF-Connecting-IP", " 2001:db8::5 "), netip.MustParseAddr("2001:db8::5"), nil},
		{"remote_addr uses the TCP peer", identityFor(t, map[string]string{"CLIENT_IP_SOURCE": "remote_addr", "TRUSTED_PROXIES": ""}), cdnRequest("203.0.113.9:5000", "CloudFront-Viewer-Address", "1.1.1.1:1"), netip.MustParseAddr("203.0.113.9"), nil},
		{"XFF skips trusted hops from the right", identityFor(t, map[string]string{"CLIENT_IP_SOURCE": "xff"}), cdnRequest("10.0.0.1:1", "X-Forwarded-For", "1.1.1.1, 198.51.100.4", "X-Forwarded-For", "10.9.9.9"), netip.MustParseAddr("198.51.100.4"), nil},
		{"XFF where every hop is trusted uses the leftmost", identityFor(t, map[string]string{"CLIENT_IP_SOURCE": "xff"}), cdnRequest("10.0.0.1:1", "X-Forwarded-For", "10.1.1.1, 10.2.2.2"), netip.MustParseAddr("10.1.1.1"), nil},
		{"XFF with garbage", identityFor(t, map[string]string{"CLIENT_IP_SOURCE": "xff"}), cdnRequest("10.0.0.1:1", "X-Forwarded-For", "1.1.1.1, unknown"), netip.Addr{}, errClientIPHeader},
		{"XFF missing", identityFor(t, map[string]string{"CLIENT_IP_SOURCE": "xff"}), cdnRequest("10.0.0.1:1"), netip.Addr{}, errClientIPHeader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.id.identify(tc.r)
			if !errors.Is(err, tc.err) || c.ip != tc.want {
				t.Fatalf("identify = %v, %v; want %v, %v", c.ip, err, tc.want, tc.err)
			}
		})
	}
}

// The ingress secret is checked for every request, and two values can be
// live at once so it can be rotated without downtime.
func TestIngressSecret(t *testing.T) {
	id := identityFor(t, map[string]string{"INGRESS_SECRET_HEADER": "X-Origin-Secret", "INGRESS_SECRET_VALUES": "old-secret,new-secret"})
	for _, v := range []string{"old-secret", "new-secret"} {
		if _, err := id.identify(cdnRequest("10.0.0.1:1", "X-Origin-Secret", v, "CloudFront-Viewer-Address", "1.2.3.4:1")); err != nil {
			t.Errorf("secret %q rejected: %v", v, err)
		}
	}
	for _, v := range []string{"", "new-secre", "new-secretX"} {
		if _, err := id.identify(cdnRequest("10.0.0.1:1", "X-Origin-Secret", v, "CloudFront-Viewer-Address", "1.2.3.4:1")); !errors.Is(err, errIngressSecret) {
			t.Errorf("secret %q accepted: %v", v, err)
		}
	}
}

// Viewer fields are normalized the way rules expect them; a
// malformed value is absent rather than an error.
func TestViewerFields(t *testing.T) {
	id := identityFor(t, map[string]string{"VIEWER_HEADERS": "ip.src.continent=X-Continent,client_cert.verified=X-Cert"})
	c, err := id.identify(cdnRequest("10.0.0.1:1", "CloudFront-Viewer-Address", "1.2.3.4:1",
		"CloudFront-Viewer-Country", " au", "X-Continent", "oc", "CloudFront-Viewer-ASN", "64500",
		"CloudFront-Forwarded-Proto", "HTTPS", "CloudFront-Viewer-Http-Version", "2.0", "X-Cert", "True"))
	if err != nil {
		t.Fatal(err)
	}
	if c.country != "AU" || c.continent != "OC" || !c.hasASN || c.asn != 64500 || !c.ssl || c.version != "2.0" || !c.certVerified {
		t.Fatalf("viewer = %+v", c)
	}
	bad, _ := id.identify(cdnRequest("10.0.0.1:1", "CloudFront-Viewer-Address", "1.2.3.4:1",
		"CloudFront-Viewer-Country", "Australia", "CloudFront-Viewer-ASN", "-1", "CloudFront-Forwarded-Proto", "http", "X-Cert", "SUCCESS"))
	if bad.country != "" || bad.hasASN || bad.ssl || bad.certVerified {
		t.Fatalf("malformed viewer values were used: %+v", bad)
	}
}

// Whatever a CDN or attacker puts in the client-IP header, parsing never
// panics, and an accepted address is always clean: no zone, never mapped.
func FuzzParseClientIP(f *testing.F) {
	for _, s := range []string{"198.51.100.10:46532", "2001:db8::1:443", "[2001:db8::1]:443", "[::ffff:1.2.3.4]:1", "1.2.3.4", "[fe80::1%eth0]:1", ":", "[", "1.2.3.4:99999"} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, v string, withPort bool) {
		a, ok := parseClientIP(v, withPort)
		if !ok {
			return
		}
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() {
			t.Fatalf("parseClientIP(%q, %v) = %v", v, withPort, a)
		}
		if !withPort && strings.Contains(v, "]") {
			t.Fatalf("bracketed form accepted without a port: %q", v)
		}
	})
}

// Everything left of the hops the proxies added is client-written, up to
// MAX_HEADER_BYTES of it. The walk reads from the right and allocates
// nothing, so a long header costs no more than a short one.
func TestXFFWalkAllocatesNothing(t *testing.T) {
	id := identityFor(t, map[string]string{"CLIENT_IP_SOURCE": "xff"})
	vals := []string{strings.Repeat("1,", 30000) + "198.51.100.4, 10.0.0.2"}
	if a, err := id.fromXFF(vals); err != nil || a != netip.MustParseAddr("198.51.100.4") {
		t.Fatalf("client %v, %v", a, err)
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = id.fromXFF(vals) }); n != 0 {
		t.Fatalf("%v allocations per walk", n)
	}
}

// xffReference splits every hop first, then walks: obviously right, but its
// cost grows with the whole header.
func xffReference(id *identity, vals []string) (netip.Addr, error) {
	var hops []string
	for _, v := range vals {
		hops = append(hops, strings.Split(v, ",")...)
	}
	var client netip.Addr
	for _, hop := range slices.Backward(hops) {
		a, ok := parseClientIP(strings.TrimSpace(hop), false)
		if !ok {
			return netip.Addr{}, errClientIPHeader
		}
		client = a
		if !id.isTrusted(a) {
			break
		}
	}
	if !client.IsValid() {
		return netip.Addr{}, errClientIPHeader
	}
	return client, nil
}

// The allocation-free walk picks the same client as the reference for any
// X-Forwarded-For lines; "\n" separates repeated header lines.
func FuzzXFF(f *testing.F) {
	for _, s := range []string{"1.1.1.1, 198.51.100.4\n10.9.9.9", "10.1.1.1, 10.2.2.2", "1.1.1.1, unknown", "", ",", "10.0.0.1,", " , 10.0.0.1", "2001:db8::1,10.0.0.1\n\n10.0.0.2"} {
		f.Add(s)
	}
	id := identityFor(f, map[string]string{"CLIENT_IP_SOURCE": "xff"})
	f.Fuzz(func(t *testing.T, s string) {
		vals := strings.Split(s, "\n")
		got, err := id.fromXFF(vals)
		want, werr := xffReference(id, vals)
		if got != want || (err == nil) != (werr == nil) {
			t.Fatalf("fromXFF(%q) = %v, %v; reference %v, %v", vals, got, err, want, werr)
		}
	})
}
