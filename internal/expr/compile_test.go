package expr

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// fakeReq is a request with fixed field values. Absent fields return zero values.
type fakeReq struct {
	str   map[string]string
	lists map[string][]string // "field|key"
	ip    netip.Addr
	ints  map[string]int64
	bools map[string]bool
}

func (r *fakeReq) String(f string) string     { return r.str[f] }
func (r *fakeReq) List(f, k string) []string  { return r.lists[f+"|"+k] }
func (r *fakeReq) IP(string) netip.Addr       { return r.ip }
func (r *fakeReq) Bool(f string) bool         { return r.bools[f] }
func (r *fakeReq) Int(f string) (int64, bool) { n, ok := r.ints[f]; return n, ok }

var testEnv = Env{Phase: PhaseRateLimit, ViewerAvailable: allViewer, AllowRegex: true}

func mustCompile(t testing.TB, src string) Matcher {
	t.Helper()
	n, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	m, is := Compile(n, testEnv)
	if is != nil {
		t.Fatalf("Compile(%q): %v", src, Issues(is))
	}
	return m
}

// A typical API request, matched against the rules operators write.
func TestCompiledRulesMatchRequests(t *testing.T) {
	req := &fakeReq{
		str: map[string]string{
			"http.host":             "api.example.com",
			"http.request.uri.path": "/v1/Users/42",
			"http.user_agent":       "curl/8.9",
			"http.request.method":   "POST",
			"http.request.version":  "2.0",
		},
		lists: map[string][]string{
			"http.request.headers|X-Api-Key": {"k1", "k2"},
		},
		ip:    netip.MustParseAddr("::ffff:10.1.2.3"),
		ints:  map[string]int64{"ip.src.asnum": 64500},
		bools: map[string]bool{"ssl": true},
	}
	cases := []struct {
		src  string
		want bool
	}{
		{`true`, true},
		{`not true`, false},
		{`http.host eq "api.example.com"`, true},
		{`http.host ne "api.example.com"`, false},
		{`http.host contains "example"`, true},
		{`not http.host contains "example"`, false},
		{`starts_with(http.request.uri.path, "/v1/")`, true},
		{`ends_with(http.request.uri.path, "/42")`, true},
		{`not ends_with(http.request.uri.path, "/42")`, false},
		{`http.host wildcard "*.EXAMPLE.com"`, true},
		{`http.request.uri.path wildcard "/V1/USERS/*"`, true},
		{`http.request.uri.path strict wildcard "/v1/users/*"`, false},
		{`http.request.uri.path strict wildcard "/v1/*/42"`, true},
		{`http.user_agent matches "^curl/"`, true},
		{`http.request.method in {"GET" "POST"}`, true},
		{`not http.request.method in {"GET" "HEAD"}`, true},
		{`http.request.headers["X-Api-Key"] eq "k2"`, true},
		{`http.request.headers["x-api-key"] eq "k3"`, false},
		{`not http.request.headers["x-api-key"] contains "k"`, false},
		{`http.request.headers["x-missing"] eq ""`, false},
		{`ip.src eq 10.1.2.3`, true},
		{`ip.src eq 10.1.2.4`, false},
		{`ip.src in {10.0.0.0/8}`, true},
		{`not ip.src in {192.0.2.0/24 2001:db8::/32}`, true},
		{`ip.src in {::ffff:10.0.0.0/104}`, true},
		{`not ip.src in {::ffff:10.0.0.0/104}`, false},
		{`ip.src.asnum eq 64500`, true},
		{`ip.src.asnum in {64500 64501}`, true},
		{`ip.src.asnum in {1}`, false},
		{`ip.src.asnum gt 64499`, true},
		{`ip.src.asnum ge 64501`, false},
		{`ip.src.asnum lt 64501`, true},
		{`ip.src.asnum le 64499`, false},
		{`ssl`, true},
		{`client_cert.verified`, false},
		{`ssl and http.request.method eq "GET"`, false},
		{`http.request.method eq "GET" or ssl`, true},
		{`http.request.method eq "GET" or not ssl`, false},
		{`not (http.request.method eq "GET" or not ssl)`, true},
		{`ssl and (http.request.method eq "GET" or ip.src.asnum eq 64500)`, true},
		// Version literals saved in the CDN's spelling match the edge's form.
		{`http.request.version eq "HTTP/2"`, true},
		{`http.request.version ne "HTTP/2"`, false},
		{`http.request.version in {"HTTP/1.1" "2"}`, true},
		{`not http.request.version in {"HTTP/1.1" "HTTP/3"}`, true},
		{`http.request.version eq "h2"`, false},
		{`starts_with(http.request.version, "2")`, true},
		{`not starts_with(http.request.version, "HTTP/2")`, false},
		{`http.request.version contains "HTTP/1.1"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.src, func(t *testing.T) {
			if got := mustCompile(t, tc.src)(req); got != tc.want {
				t.Fatalf("match = %v, want %v", got, tc.want)
			}
		})
	}
}

// A field the edge could not extract (no client IP, no ASN) never matches a
// positive rule, so a missing value can't trigger a limit by accident.
func TestAbsentValuesDoNotMatch(t *testing.T) {
	empty := &fakeReq{}
	for _, src := range []string{
		`ip.src eq 10.0.0.1`,
		`ip.src in {0.0.0.0/0 ::/0}`,
		`ip.src.asnum eq 0`,
		`ip.src.asnum in {0}`,
		`ip.src.asnum le 0`,
		`http.request.headers["a"] contains ""`,
	} {
		if mustCompile(t, src)(empty) {
			t.Errorf("%s matched an empty request", src)
		}
	}
}

// An IPv6 zone is local interface scope, not part of the client's identity,
// so "in" and "eq" both ignore it rather than disagreeing.
func TestZonedClientIPMatchesItsAddress(t *testing.T) {
	req := &fakeReq{ip: netip.MustParseAddr("fe80::1%eth0")}
	for _, src := range []string{`ip.src eq fe80::1`, `ip.src in {fe80::/10}`, `ip.src in {::/0}`} {
		if !mustCompile(t, src)(req) {
			t.Errorf("%s did not match fe80::1%%eth0", src)
		}
	}
}

// Wildcards anchor at both ends; "*" spans any run, including empty.
func TestWildcardMatching(t *testing.T) {
	cases := []struct {
		pat, s string
		fold   bool
		want   bool
	}{
		{"exact", "exact", false, true},
		{"exact", "exactly", false, false},
		{"/api/*", "/api/", false, true},
		{"/api/*", "/web/x", false, false},
		{"*.js", "/a/b.js", false, true},
		{"*.js", "/a/b.jsx", false, false},
		{"/a/*/b/*/c", "/a/x/b/y/c", false, true},
		{"/a/*/b/*/c", "/a/x/y/c", false, false},
		{"*ab*ab", "ab", false, false},
		{"*", "", false, true},
		{"a*", "a", false, true},
		{"*/É*", "/é", true, false},
		{`a\*b`, "a*b", false, true},
		{`a\*b`, "axb", false, false},
		{`a\\*`, `a\zzz`, false, true},
		{"*.EXAMPLE.com", "www.example.COM", true, true},
		{"*.EXAMPLE.com", "www.example.COM", false, false},
	}
	for _, tc := range cases {
		w, err := compileWildcard(tc.pat, tc.fold)
		if err != nil {
			t.Fatalf("compileWildcard(%q): %v", tc.pat, err)
		}
		if got := w.match(tc.s); got != tc.want {
			t.Errorf("%q fold=%v match %q = %v, want %v", tc.pat, tc.fold, tc.s, got, tc.want)
		}
	}
	for _, bad := range []string{`a\`, `a\b`, "a**b"} {
		if _, err := compileWildcard(bad, false); err == nil {
			t.Errorf("compileWildcard(%q) accepted a bad escape", bad)
		}
	}
}

// Overlapping and adjacent CIDR lists collapse into ranges; IPv4 and IPv6 never
// match each other, and IPv4-mapped IPv6 is treated as IPv4.
func TestIPSetMembership(t *testing.T) {
	s := newIPSet([]string{"11.0.0.0", "11.0.0.0/8", "10.0.0.0/8", "10.1.0.0/16", "10.255.0.0/16", "11.0.0.0/8", "12.0.0.0/8", "192.0.2.7", "::ffff:198.51.100.1", "2001:db8::/32"})
	in := []string{"10.0.0.0", "10.200.1.1", "11.255.255.255", "12.0.0.1", "192.0.2.7", "198.51.100.1", "2001:db8::1"}
	out := []string{"9.255.255.255", "13.0.0.0", "192.0.2.8", "0.0.0.0", "::", "::a00:1", "2001:db9::", "ffff::"}
	for _, a := range in {
		if !s.contains(netip.MustParseAddr(a)) {
			t.Errorf("%s not in set", a)
		}
	}
	for _, a := range out {
		if s.contains(netip.MustParseAddr(a)) {
			t.Errorf("%s in set", a)
		}
	}
	if s.contains(netip.Addr{}) {
		t.Error("invalid address in set")
	}
	// 10/8 absorbs 10.1/16 and 10.255/16, and 11/8 absorbs 11.0.0.0 whichever
	// way the sort orders them.
	if len(s.ranges) != 6 {
		t.Errorf("got %d ranges, want 6", len(s.ranges))
	}
}

// Text typed in the editor and the AST the builder saves always agree: any
// expression that parses renders to text that parses back to the same tree.
func FuzzParseRenderRoundTrip(f *testing.F) {
	for _, s := range []string{
		`true`, `ssl and (http.host eq "a" or not ip.src in {10.0.0.0/8})`,
		`not starts_with(http.request.uri.path, "/x\"y")`, `http.request.headers["A"] strict wildcard "\\*"`,
		`ip.src.asnum ge 1 or not (ssl and true)`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		n, err := Parse(src)
		if err != nil {
			return
		}
		text := Render(n)
		// Quoting can push text past the limit; Check rejects those ASTs.
		if len(text) > MaxTextLen {
			return
		}
		again, err := Parse(text)
		if err != nil {
			t.Fatalf("Parse(Render(%q)) = %q: %v", src, text, err)
		}
		if !reflect.DeepEqual(again, n) {
			t.Fatalf("round trip of %q changed the AST via %q", src, text)
		}
	})
}

// Matching runs on every request, so no operator may allocate. Values are
// realistic lengths, below the wildcard's 512-byte stack buffer.
func TestMatchingDoesNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items under -race; scripts/ci/test.sh checks this in its non-race run")
	}
	req := &fakeReq{
		str:   map[string]string{"http.host": "api.example.com", "http.request.uri.path": "/V1/Users/42", "http.user_agent": "Mozilla/5.0 (X11; Linux x86_64)", "http.request.method": "GET"},
		lists: map[string][]string{"http.request.headers|X-Api-Key": {"k1"}},
		ip:    netip.MustParseAddr("2001:db8::1"),
		ints:  map[string]int64{"ip.src.asnum": 64500},
		bools: map[string]bool{"ssl": true},
	}
	for _, src := range []string{
		`http.host eq "api.example.com"`,
		`http.host in {"a.com" "api.example.com"}`,
		`http.user_agent contains "Linux"`,
		`not starts_with(http.request.uri.path, "/v2/")`,
		`ends_with(http.request.uri.path, "/42")`,
		`http.request.uri.path wildcard "/v1/users/*"`,
		`http.request.uri.path strict wildcard "/V1/*"`,
		`http.user_agent matches "Linux x86_\\d+"`,
		`http.request.headers["x-api-key"] eq "k1"`,
		`ip.src eq 2001:db8::1`,
		`ip.src in {10.0.0.0/8 2001:db8::/32}`,
		`ip.src.asnum in {64500 64501}`,
		`ip.src.asnum ge 64500`,
		`ssl and not http.request.method eq "POST"`,
	} {
		m := mustCompile(t, src)
		if n := testing.AllocsPerRun(100, func() { m(req) }); n != 0 {
			t.Errorf("%s: %v allocations per match", src, n)
		}
	}
}

// Matching cost for a snapshot at the design limit: 200 rules of 32 conditions,
// none of which match, so every condition is evaluated.
func BenchmarkMatch200Rules(b *testing.B) {
	ms := make([]Matcher, 200)
	for i := range ms {
		g := Node{Combinator: "and"}
		for j := range MaxConditions {
			g.Rules = append(g.Rules, rule("http.request.uri.path", "ne", fmt.Sprintf("/p/%d/%d", i, j)))
		}
		g.Rules[MaxConditions-1] = rule("http.host", "eq", "nomatch")
		m, err := Compile(g, testEnv)
		if err != nil {
			b.Fatal(err)
		}
		ms[i] = m
	}
	req := &fakeReq{str: map[string]string{"http.request.uri.path": "/x", "http.host": "a"}}
	b.ReportAllocs()
	for b.Loop() {
		for _, m := range ms {
			if m(req) {
				b.Fatal("matched")
			}
		}
	}
}

// A realistic rate_limit phase: 20 rules mixing host, path, method, header and
// a 200-range IP list, with short-circuiting doing its normal work.
func BenchmarkMatchRealistic(b *testing.B) {
	cidrs := make([]string, 200)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	var ms []Matcher
	for i := range 20 {
		srcs := []string{
			fmt.Sprintf(`http.host eq "api%d.example.com" and starts_with(http.request.uri.path, "/v1/")`, i),
			fmt.Sprintf(`http.request.method in {"POST" "PUT"} and http.request.uri.path wildcard "/v1/r%d/*"`, i),
			`http.request.headers["x-api-key"] eq "" or ip.src in {` + strings.Join(cidrs, " ") + `}`,
			fmt.Sprintf(`not ssl or http.user_agent contains "bot%d"`, i),
		}
		ms = append(ms, mustCompile(b, srcs[i%len(srcs)]))
	}
	req := &fakeReq{
		str:   map[string]string{"http.host": "api7.example.com", "http.request.uri.path": "/v1/orders/42", "http.request.method": "POST", "http.user_agent": "Mozilla/5.0"},
		lists: map[string][]string{"http.request.headers|X-Api-Key": {"k"}},
		ip:    netip.MustParseAddr("192.0.2.1"),
		bools: map[string]bool{"ssl": true},
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, m := range ms {
			m(req)
		}
	}
}

// Compiling happens once per snapshot, off the request path; B/op shows the
// memory one worst-case rule set (200 rules x 32 conditions) costs to build.
func BenchmarkCompileWorst(b *testing.B) {
	ns := make([]Node, 200)
	for i := range ns {
		g := Node{Combinator: "and"}
		for j := range MaxConditions {
			g.Rules = append(g.Rules, rule("http.request.uri.path", "wildcard", fmt.Sprintf("/p/%d/*/%d", i, j)))
		}
		ns[i] = g
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, n := range ns {
			if _, err := Compile(n, testEnv); err != nil {
				b.Fatal(err)
			}
		}
	}
}
