package edge

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// client is what step 2 learns about the client.
type client struct {
	ip netip.Addr
	// trusted means the TCP peer is a trusted proxy.
	trusted bool

	country, continent, version string
	asn                         int64
	hasASN                      bool
	ssl, certVerified           bool
}

// Reasons step 2 rejects a request. Each is a 400 with the bad_request template.
var (
	errUntrustedPeer  = errors.New("peer is not a trusted proxy")
	errIngressSecret  = errors.New("ingress secret missing or wrong")
	errClientIPHeader = errors.New("client IP header missing, repeated or unparseable")
)

// identity is the client-IP and viewer setup, resolved once from Config.
type identity struct {
	kind     string
	header   string // canonical
	withPort bool
	trusted  []netip.Prefix

	secretHeader string
	secrets      [][]byte

	country, continent, asn, ssl, version, cert string // viewer headers, canonical
}

func newIdentity(c *Config) *identity {
	h := http.CanonicalHeaderKey
	id := &identity{
		kind: c.ClientIP.Kind, header: h(c.ClientIP.Header), withPort: c.ClientIP.WithPort,
		trusted:      c.TrustedProxies,
		secretHeader: h(c.IngressSecretHeader),
		country:      h(c.Viewer["ip.src.country"]),
		continent:    h(c.Viewer["ip.src.continent"]),
		asn:          h(c.Viewer["ip.src.asnum"]),
		ssl:          h(c.Viewer["ssl"]),
		version:      h(c.Viewer["http.request.version"]),
		cert:         h(c.Viewer["client_cert.verified"]),
	}
	for _, s := range c.IngressSecrets {
		id.secrets = append(id.secrets, []byte(s))
	}
	return id
}

func (id *identity) isTrusted(a netip.Addr) bool {
	for _, p := range id.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// identify runs step 2's trust checks and reads the client IP and viewer fields.
func (id *identity) identify(r *http.Request) (client, error) {
	var c client
	// net/http sets RemoteAddr to ip:port for TCP listeners; anything else
	// parses to an invalid address, which no prefix contains: untrusted.
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	pa := clean(peer.Addr())
	c.trusted = id.isTrusted(pa)

	if id.secretHeader != "" && !id.secretOK(r.Header.Get(id.secretHeader)) {
		return c, errIngressSecret
	}
	if id.kind == "remote_addr" {
		c.ip = pa
		return c, nil
	}
	// Headers from anyone else could be spoofed (control 2).
	if !c.trusted {
		return c, errUntrustedPeer
	}
	var err error
	if id.kind == "xff" {
		c.ip, err = id.fromXFF(r.Header.Values("X-Forwarded-For"))
	} else {
		c.ip, err = id.fromHeader(r.Header.Values(id.header))
	}
	if err != nil {
		return c, err
	}
	id.viewer(r.Header, &c)
	return c, nil
}

// secretOK compares in constant time against every configured value, so
// rotation can run old and new values side by side.
func (id *identity) secretOK(got string) bool {
	ok := 0
	for _, s := range id.secrets {
		ok |= subtle.ConstantTimeCompare([]byte(got), s)
	}
	return ok == 1
}

func (id *identity) fromHeader(vals []string) (netip.Addr, error) {
	// Two values mean something upstream of the CDN added one: ambiguous.
	if len(vals) != 1 {
		return netip.Addr{}, errClientIPHeader
	}
	a, ok := parseClientIP(strings.TrimSpace(vals[0]), id.withPort)
	if !ok {
		return netip.Addr{}, errClientIPHeader
	}
	return a, nil
}

// parseClientIP reads "ip" or "ip:port". Bracketed IPv6 uses the brackets;
// otherwise the port follows the last colon. AWS doesn't document whether
// CloudFront brackets IPv6, so both forms are accepted.
func parseClientIP(v string, withPort bool) (netip.Addr, bool) {
	if withPort {
		if strings.HasPrefix(v, "[") {
			ap, err := netip.ParseAddrPort(v)
			if err != nil || ap.Addr().Zone() != "" {
				return netip.Addr{}, false
			}
			return clean(ap.Addr()), true
		}
		i := strings.LastIndexByte(v, ':')
		if i < 0 {
			return netip.Addr{}, false
		}
		if _, err := strconv.ParseUint(v[i+1:], 10, 16); err != nil {
			return netip.Addr{}, false
		}
		v = v[:i]
	}
	a, err := netip.ParseAddr(v)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return clean(a), true
}

// fromXFF walks X-Forwarded-For right to left past trusted proxies. The first
// untrusted address is the client; if every hop is trusted, the leftmost is.
// It slices from the right without splitting: hops left of the client are
// client-written and never read, so their length costs nothing.
func (id *identity) fromXFF(vals []string) (netip.Addr, error) {
	var client netip.Addr
	for _, v := range slices.Backward(vals) {
		for {
			j := strings.LastIndexByte(v, ',')
			a, ok := parseClientIP(strings.TrimSpace(v[j+1:]), false)
			if !ok {
				return netip.Addr{}, errClientIPHeader
			}
			client = a
			if !id.isTrusted(a) {
				return client, nil
			}
			if j < 0 {
				break
			}
			v = v[:j]
		}
	}
	if !client.IsValid() {
		return netip.Addr{}, errClientIPHeader
	}
	return client, nil
}

// viewer reads trusted viewer fields. A malformed value counts as absent:
// it can't be matched on, and the request still goes through (P1).
func (id *identity) viewer(h http.Header, c *client) {
	if id.country != "" {
		c.country = isoCode(h.Get(id.country))
	}
	if id.continent != "" {
		c.continent = isoCode(h.Get(id.continent))
	}
	// An absent header skips parsing: ParseInt("") allocates its error.
	if v := h.Get(id.asn); id.asn != "" && v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			c.asn, c.hasASN = n, true
		}
	}
	if id.ssl != "" {
		c.ssl = strings.EqualFold(h.Get(id.ssl), "https")
	}
	if id.version != "" {
		c.version = h.Get(id.version)
	}
	if id.cert != "" {
		c.certVerified = strings.EqualFold(h.Get(id.cert), "true")
	}
}

// isoCode returns a two-character code in uppercase, or "".
func isoCode(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if len(v) != 2 || !isAlnum(v[0]) || !isAlnum(v[1]) {
		return ""
	}
	return v
}

func isAlnum(c byte) bool { return 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' }

// clean is the canonical client address: IPv4-mapped as IPv4, no zone.
func clean(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }
