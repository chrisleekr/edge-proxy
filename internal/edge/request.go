package edge

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// fields implements expr.Request for one request. Values that cost work to
// extract (query args, cookies, the full URI) are computed on first use only.
type fields struct {
	r    *http.Request
	c    *client
	path string // normalized
	host string // lowercase, no port
	// loc resolves edge.locale on first read; nil when the
	// request's locale setting is off.
	loc       *localeResolver
	locale    string
	localeSet bool
	// claims holds verified JWT claims as strings; nil without a verified token.
	claims map[string][]string
	// bots is the snapshot's verified crawler ranges.
	bots    *expr.IPSet
	signals uint16

	args url.Values
	// cookies are sorted by name, in request order within a name, so one
	// name's values are a contiguous run of cookieVals.
	cookies                   []*http.Cookie
	cookieVals                []string
	uri, fullURI, cookie, xff string
	parsed                    uint8 // bit set of what has been parsed
}

const (
	parsedArgs uint8 = 1 << iota
	parsedCookies
	parsedURI
	parsedFullURI
	parsedCookie
	parsedXFF
	parsedSignals
)

// once returns *v, computing it on the first call for bit. Every rule in
// every phase reads the same fields, so each value is built once.
func (f *fields) once(bit uint8, v *string, build func(*fields) string) string {
	if f.parsed&bit == 0 {
		*v = build(f)
		f.parsed |= bit
	}
	return *v
}

func newFields(r *http.Request, c *client, path string) fields {
	return fields{r: r, c: c, path: path, host: hostOnly(r.Host)}
}

// hostOnly lowercases the host and drops any port, IPv6 brackets and a
// trailing dot.
func hostOnly(h string) string {
	// Most hosts have no port; SplitHostPort would allocate an error for them.
	if strings.Contains(h, ":") {
		if hp, _, err := net.SplitHostPort(h); err == nil {
			h = hp
		}
	}
	// A trailing dot names the same DNS host (an absolute name).
	return strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"), "."))
}

func (f *fields) String(name string) string {
	r := f.r
	switch name {
	case "http.request.full_uri":
		return f.once(parsedFullURI, &f.fullURI, buildFullURI)
	case "http.request.uri":
		return f.once(parsedURI, &f.uri, func(f *fields) string { return f.r.URL.RequestURI() })
	case "http.request.uri.path":
		return f.path
	case "http.request.uri.query":
		return r.URL.RawQuery
	case "http.host":
		return f.host
	case "http.request.method":
		return r.Method
	case "http.cookie":
		return f.once(parsedCookie, &f.cookie, func(f *fields) string { return strings.Join(f.r.Header.Values("Cookie"), "; ") })
	// The server canonicalizes header names, so a map read skips the
	// canonicalization Header.Get repeats for every rule.
	case "http.referer":
		v, _ := first(r.Header["Referer"])
		return v
	case "http.user_agent":
		v, _ := first(r.Header["User-Agent"])
		return v
	case "http.x_forwarded_for":
		return f.once(parsedXFF, &f.xff, func(f *fields) string { return strings.Join(f.r.Header.Values("X-Forwarded-For"), ", ") })
	case "ip.src.country":
		return f.c.country
	case "ip.src.continent":
		return f.c.continent
	case "http.request.version":
		return f.c.version
	case "tls.client.ja4":
		return f.c.ja4
	case "tls.client.ja3":
		return f.c.ja3
	default: // edge.locale; expr only passes string fields
		return f.localeValue()
	}
}

func buildFullURI(f *fields) string {
	scheme := "http"
	if f.c.ssl {
		scheme = "https"
	}
	host := f.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal, as a URI writes it
	}
	return scheme + "://" + host + f.String("http.request.uri")
}

// localeValue is the request's locale, resolved once; "" when locale is off.
func (f *fields) localeValue() string {
	if !f.localeSet && f.loc != nil {
		f.locale = f.loc.resolve(f.r.Header.Get("Accept-Language"))
	}
	f.localeSet = true
	return f.locale
}

func (f *fields) List(name, key string) []string {
	switch name {
	case "http.request.headers":
		// key is canonical (expr canonicalizes at compile time): a map read.
		return f.r.Header[key]
	case "http.request.uri.args":
		if f.parsed&parsedArgs == 0 {
			// ParseQuery skips malformed pairs, as Rewrite drops them from the
			// forwarded query, so rules see what the upstream sees.
			f.args, _ = url.ParseQuery(f.r.URL.RawQuery)
			f.parsed |= parsedArgs
		}
		return f.args[key]
	case "http.request.cookies":
		if f.parsed&parsedCookies == 0 {
			f.cookies = f.r.Cookies()
			slices.SortStableFunc(f.cookies, func(a, b *http.Cookie) int { return strings.Compare(a.Name, b.Name) })
			f.cookieVals = make([]string, len(f.cookies))
			for i, c := range f.cookies {
				f.cookieVals[i] = c.Value
			}
			f.parsed |= parsedCookies
		}
		i, _ := slices.BinarySearchFunc(f.cookies, key, func(c *http.Cookie, k string) int { return strings.Compare(c.Name, k) })
		j := i
		for j < len(f.cookies) && f.cookies[j].Name == key {
			j++
		}
		// Capped, so a caller appending can't overwrite the next name's values.
		return f.cookieVals[i:j:j]
	case expr.SignalsField:
		return signalLists[f.signalBits()]
	default: // http.request.jwt.claims; expr only passes list fields
		return f.claims[key]
	}
}

// signalBits computes the request's client signals on first use: only
// requests a rule reads them for pay for them.
func (f *fields) signalBits() uint16 {
	if f.parsed&parsedSignals == 0 {
		f.signals = signalsOf(f.r.Header, f.c)
		f.parsed |= parsedSignals
	}
	return f.signals
}

func (f *fields) IP(string) netip.Addr { return f.c.ip }

func (f *fields) Int(string) (int64, bool) { return f.c.asn, f.c.hasASN }

func (f *fields) Bool(name string) bool {
	switch name {
	case "ssl":
		return f.c.ssl
	case "client.verified_bot":
		// No ranges loaded means no verified crawler: an exemption fails closed.
		return f.bots != nil && f.bots.Contains(f.c.ip)
	}
	return f.c.certVerified
}
