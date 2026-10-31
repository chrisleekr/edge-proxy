package edge

import (
	"bufio"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// Paths that upstreams interpret differently are rejected; everything else
// is matched in normalized form so encodings can't bypass a rule.
func TestMatchPath(t *testing.T) {
	cases := []struct {
		target, want string
		err          error
	}{
		{"/v1/orders", "/v1/orders", nil},
		{"/%61dmin/users", "/admin/users", nil},
		{"//admin//users/", "/admin/users/", nil},
		{"/a/./b/.", "/a/b", nil},
		{"/a/..b/c..", "/a/..b/c..", nil},
		// A ".." segment resolved here but not upstream (Express mounts,
		// many Node routers) would match /public while /admin serves it.
		// Browsers and RFC 3986 clients remove dot-segments before sending.
		{"/admin/x/../../public/y", "", errAmbiguousPath},
		{"/admin/%2e%2e/public", "", errAmbiguousPath},
		{"/admin/..", "", errAmbiguousPath},
		{"/../../etc", "", errAmbiguousPath},
		{"/", "/", nil},
		{"/caf%C3%A9", "/café", nil},
		// Path parameters are dropped for matching: Tomcat and Spring route
		// /admin;jsessionid=1 to /admin.
		{"/admin;jsessionid=1", "/admin", nil},
		{"/a;x=1/b;y/", "/a/b/", nil},
		{"/;x/admin", "/admin", nil},
		// A segment that is a dot-segment only after its parameter is
		// dropped is a plain name to nginx, Express or Go upstreams, so
		// /admin/secret/..;x would match as /admin there but route under
		// /admin/secret upstream.
		{"/admin/secret/..;x", "", errAmbiguousPath},
		{"/admin/secret/.;x/y", "", errAmbiguousPath},
		{"/admin/secret/..%3Bx", "", errAmbiguousPath},
		// %2F stays inside its segment, as a gateway that keeps escaped
		// slashes routes it: GitLab reads group%2Fproject as one project.
		{"/api/v4/projects/group%2Fproject/members", "/api/v4/projects/group%2Fproject/members", nil},
		{"/api/v4/projects/1/repository/files/docs%2fREAD%4DE.md", "/api/v4/projects/1/repository/files/docs%2FREADME.md", nil},
		// Go's EscapedPath re-encodes when the raw path has a character like
		// { or |, which would hide the encoded slash; RawPath keeps it.
		{"/a%2Fb{", "/a%2Fb{", nil},
		// A gateway that decodes %2F (nginx) resolves these into another prefix.
		{"/admin%2F..%2Fsecret|", "", errAmbiguousPath},
		{"/public/..%2Fadmin", "", errAmbiguousPath},
		{"/public/.%2Fadmin", "", errAmbiguousPath},
		{"/public/%2e%2e%2Fadmin", "", errAmbiguousPath},
		// A gateway that strips ";x" sees "..", as dropParams does below.
		{"/public%2F..;x/admin", "", errAmbiguousPath},
		{"/public%2F..%3Bx/admin", "", errAmbiguousPath},
		// Dots inside a name are not dot-segments.
		{"/files/a..b%2Fc", "/files/a..b%2Fc", nil},
		// %2F only in the userinfo of an absolute-form target: the path has
		// none, so it is matched as usual.
		{"http://u%2Fx@h/admin", "/admin", nil},
		// Overlong UTF-8 for "/" decodes to invalid UTF-8; some servers read it as "/".
		{"/%c0%afadmin", "", errAmbiguousPath},
		{"/a%2Fb", "/a%2Fb", nil},
		{"/a%2fb", "/a%2Fb", nil},
		{"/a%5Cb", "", errAmbiguousPath},
		{"/a%00b", "", errAmbiguousPath},
		{"*", "", errBadPath},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			r := rawTarget(t, tc.target)
			got, err := matchPath(r)
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("matchPath = %q, %v; want %q, %v", got, err, tc.want, tc.err)
			}
		})
	}
	// A raw backslash in the request line reaches Path undecoded.
	r := rawTarget(t, `/a\b`)
	if _, err := matchPath(r); !errors.Is(err, errAmbiguousPath) {
		t.Fatalf("raw backslash: %v", err)
	}
}

// Rule matching sees a canonical path: absolute, no "//", "." or "..", and
// normalizing twice changes nothing.
func FuzzMatchPath(f *testing.F) {
	for _, s := range []string{"/a/../b", "//x//", "/%2e%2e/", "/a%2Fb", "/./", "/a/b/../../../c/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, target string) {
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader("GET " + target + " HTTP/1.1\r\nHost: h\r\n\r\n")))
		if err != nil || !strings.HasPrefix(target, "/") {
			return
		}
		p, err := matchPath(r)
		if err != nil {
			return
		}
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, "/./") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
			t.Fatalf("matchPath(%q) = %q is not canonical", target, p)
		}
		again, err := matchPath(rawTarget(t, (&url.URL{Path: p}).EscapedPath()))
		if err != nil || again != p {
			t.Fatalf("normalizing %q again gave %q, %v", p, again, err)
		}
	})
}

// rawTarget parses a request line the way the server does, so the raw
// target reaches matchPath unchanged.
func rawTarget(t *testing.T, target string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader("GET " + target + " HTTP/1.1\r\nHost: h\r\n\r\n")))
	if err != nil {
		t.Fatalf("server would reject %q: %v", target, err)
	}
	return r
}

func TestCheckMethod(t *testing.T) {
	for _, m := range []string{"GET", "POST", "M-SEARCH", "PROPFIND"} {
		if checkMethod(m) != nil {
			t.Errorf("%s rejected", m)
		}
	}
	for _, m := range []string{"post", "Get"} {
		if !errors.Is(checkMethod(m), errMethodCase) {
			t.Errorf("%s accepted", m)
		}
	}
}

// Every field in the expression schema is extracted from the request, so a
// field added to the schema without extraction code fails here.
func TestFieldsCoverTheSchema(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://API.Example.com:8443/v1/%61dmin?a=1&a=2&b=%zz&c=3", nil)
	r.Header.Add("X-Api-Key", "k1")
	r.Header.Add("X-Api-Key", "k2")
	r.Header.Add("Cookie", "sid=s1; theme=dark")
	r.Header.Add("Cookie", "sid=s2")
	r.Header.Set("Referer", "https://ref.example.com/")
	r.Header.Set("User-Agent", "curl/8")
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	c := client{ip: netip.MustParseAddr("198.51.100.1"), country: "AU", continent: "OC", version: "2.0", asn: 64500, hasASN: true, ssl: true, certVerified: true,
		ja4: chromeJA4, ja3: chromeJA3}
	f := newFields(r, &c, "/v1/admin")
	bots := expr.NewIPSet([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
	f.bots = &bots
	f.locale = "ko"
	f.claims = map[string][]string{"sub": {"u1"}}

	strs := map[string]string{
		"http.request.full_uri":  "https://api.example.com/v1/%61dmin?a=1&a=2&b=%zz&c=3",
		"http.request.uri":       "/v1/%61dmin?a=1&a=2&b=%zz&c=3",
		"http.request.uri.path":  "/v1/admin",
		"http.request.uri.query": "a=1&a=2&b=%zz&c=3",
		"http.host":              "api.example.com",
		"http.request.method":    "POST",
		"http.cookie":            "sid=s1; theme=dark; sid=s2",
		"http.referer":           "https://ref.example.com/",
		"http.user_agent":        "curl/8",
		"http.x_forwarded_for":   "1.1.1.1, 2.2.2.2",
		"ip.src.country":         "AU",
		"ip.src.continent":       "OC",
		"http.request.version":   "2.0",
		"tls.client.ja4":         chromeJA4,
		"tls.client.ja3":         chromeJA3,
		"edge.locale":            "ko",
	}
	lists := map[string]struct {
		key  string
		want []string
	}{
		"http.request.uri.args":   {"a", []string{"1", "2"}},
		"http.request.headers":    {"X-Api-Key", []string{"k1", "k2"}},
		"http.request.cookies":    {"sid", []string{"s1", "s2"}},
		"http.request.jwt.claims": {"sub", []string{"u1"}},
		expr.SignalsField:         {"", []string{"ua_tool"}},
	}
	for _, fd := range expr.Fields {
		switch fd.Type {
		case expr.TypeString:
			want, ok := strs[fd.Name]
			if !ok {
				t.Errorf("no test value for string field %s", fd.Name)
			}
			if got := f.String(fd.Name); got != want {
				t.Errorf("%s = %q, want %q", fd.Name, got, want)
			}
		case expr.TypeStringList:
			l, ok := lists[fd.Name]
			if !ok {
				t.Errorf("no test value for list field %s", fd.Name)
			}
			// Twice: the second read comes from the parsed cache.
			for range 2 {
				if got := f.List(fd.Name, l.key); !reflect.DeepEqual(got, l.want) {
					t.Errorf("%s[%s] = %q, want %q", fd.Name, l.key, got, l.want)
				}
			}
		case expr.TypeIP:
			if f.IP(fd.Name) != c.ip {
				t.Errorf("%s wrong", fd.Name)
			}
		case expr.TypeInt:
			if n, ok := f.Int(fd.Name); !ok || n != 64500 {
				t.Errorf("%s = %d %v", fd.Name, n, ok)
			}
		case expr.TypeBool:
			if !f.Bool(fd.Name) {
				t.Errorf("%s false", fd.Name)
			}
		}
	}
	// The malformed pair b=%zz is skipped, as Rewrite drops it upstream.
	if got := f.List("http.request.uri.args", "b"); got != nil {
		t.Errorf("malformed arg visible to rules: %q", got)
	}
	plain := client{}
	g := newFields(httptest.NewRequest(http.MethodGet, "http://[2001:db8::1]/", nil), &plain, "/")
	if g.host != "2001:db8::1" || g.String("http.request.full_uri") != "http://[2001:db8::1]/" || g.Bool("ssl") || g.Bool("client_cert.verified") || g.Bool("client.verified_bot") {
		t.Errorf("plain request fields wrong: host %q", g.host)
	}
}

// A trailing dot names the same DNS host, so rules and routing must treat
// api.example.com. as api.example.com.
func TestHostOnly(t *testing.T) {
	cases := map[string]string{
		"API.example.com":      "api.example.com",
		"api.example.com.":     "api.example.com",
		"api.example.com.:443": "api.example.com",
		"[2001:DB8::1]:8443":   "2001:db8::1",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

// With 200 rules per phase reading cookies by name, User-Agent or Referer,
// a read after the first must cost no allocation.
func TestCookieAndHeaderFieldsAllocateOnce(t *testing.T) {
	r := httptest.NewRequest("GET", "http://api.example.com/", nil)
	r.Header.Add("Cookie", "theme=dark; sid=s1; _ga=x")
	r.Header.Add("Cookie", "sid=s2")
	r.Header.Set("User-Agent", "ua/1")
	r.Header.Set("Referer", "https://a.example/")
	f := newFields(r, &client{}, "/")
	read := func() {
		f.List("http.request.cookies", "sid")
		f.List("http.request.cookies", "missing")
		f.String("http.user_agent")
		f.String("http.referer")
	}
	read()
	if got := f.List("http.request.cookies", "sid"); !slices.Equal(got, []string{"s1", "s2"}) {
		t.Fatalf("sid = %q, want both values in request order", got)
	}
	if got := f.List("http.request.cookies", "missing"); len(got) != 0 {
		t.Fatalf("missing = %q", got)
	}
	if n := testing.AllocsPerRun(100, read); n != 0 {
		t.Fatalf("%v allocations per read after the first", n)
	}
}

// The sorted cookie lookup returns what a linear scan of the request's
// cookies returns, in the same order, for any Cookie headers and name.
func FuzzCookieLookup(f *testing.F) {
	f.Add("sid=s1; theme=dark", "sid=s2", "sid")
	f.Add("a=1; a=2; b=3", "", "a")
	f.Add("x=1", "y=2; x=3", "z")
	f.Add("=v; =w", "", "")
	f.Fuzz(func(t *testing.T, h1, h2, key string) {
		r := httptest.NewRequest("GET", "http://h/", nil)
		r.Header.Add("Cookie", h1)
		r.Header.Add("Cookie", h2)
		var want []string
		for _, c := range r.Cookies() {
			if c.Name == key {
				want = append(want, c.Value)
			}
		}
		fl := newFields(r, &client{}, "/")
		if got := fl.List("http.request.cookies", key); !slices.Equal(got, want) {
			t.Fatalf("%q: got %q, want %q", key, got, want)
		}
	})
}

// With 200 rules per phase reading the raw URI or joined headers, each must
// be built once per request, not once per rule.
func TestRawFieldsAreBuiltOncePerRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "http://api.example.com/v1/items?page=2", nil)
	r.Header.Add("Cookie", "a=1")
	r.Header.Add("Cookie", "b=2")
	r.Header.Add("X-Forwarded-For", "198.51.100.1")
	r.Header.Add("X-Forwarded-For", "203.0.113.9")
	f := newFields(r, &client{ssl: true}, "/v1/items")
	want := map[string]string{
		"http.request.full_uri": "https://api.example.com/v1/items?page=2",
		"http.request.uri":      "/v1/items?page=2",
		"http.cookie":           "a=1; b=2",
		"http.x_forwarded_for":  "198.51.100.1, 203.0.113.9",
	}
	for name, v := range want {
		if got := f.String(name); got != v {
			t.Fatalf("%s = %q, want %q", name, got, v)
		}
	}
	n := testing.AllocsPerRun(100, func() {
		for name := range want {
			f.String(name)
		}
	})
	if n != 0 {
		t.Fatalf("%v allocations per read after the first", n)
	}
}

// Every proxied body and edge response takes a buffer from the pool; the
// round trip must not allocate.
func TestBufferPoolRoundTripAllocatesNothing(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items at random under -race")
	}
	p := newBufferPool()
	p.Put(p.Get())
	if n := testing.AllocsPerRun(100, func() { p.Put(p.Get()) }); n != 0 {
		t.Fatalf("%v allocations per round trip", n)
	}
}

// Whatever path a client sends, the escaped form decodes to the same path
// and Go sends it as is, so the upstream routes what the edge matched.
func FuzzEscapeRaw(f *testing.F) {
	for _, s := range []string{"/admin%2F..%2Fsecret|", "/a%2fb{}", "/caf\xc3\xa9", `/a"b<c>`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		decoded, err := url.PathUnescape(raw)
		if err != nil {
			return // the server rejects it before the edge sees it
		}
		esc := escapeRaw(raw)
		if again, err := url.PathUnescape(esc); err != nil || again != decoded {
			t.Fatalf("escapeRaw(%q) = %q decodes to %q, %v; want %q", raw, esc, again, err, decoded)
		}
		if got := (&url.URL{Path: decoded, RawPath: esc}).EscapedPath(); got != esc {
			t.Fatalf("Go would send %q, not %q", got, esc)
		}
	})
}
