package expr

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// A rule saved from the builder arrives as JSON. Whatever the JSON, the edge
// must not panic: a panic while compiling a snapshot would stop the edge from
// loading config, and a panic while matching would fail live requests.
// Anything Check accepts must also compile, survive storage unchanged, show
// the same text in the UI, and match without panicking.
func FuzzBuilderAST(f *testing.F) {
	for _, s := range []string{
		`{"combinator":"and","rules":[]}`,
		`{"combinator":"or","not":true,"rules":[{"field":"http.request.headers","key":"X-A","operator":"eq","value":"k"},{"field":"ip.src","operator":"in","value":["10.0.0.0/8","::ffff:1.2.3.0/120"]}]}`,
		`{"combinator":"and","rules":[{"field":"http.request.uri.path","operator":"wildcard","value":"/A/*\\*"},{"combinator":"or","rules":[{"field":"ssl","operator":"is_true"}]}]}`,
		`{"field":"ip.src.asnum","operator":"ge","value":"64500"}`,
		`{"field":"http.user_agent","operator":"matches","value":"^curl/"}`,
		`{"field":"client.signals","operator":"in","value":["ua_tool","browser_tls_mismatch"]}`,
		`{"field":"tls.client.ja4","operator":"eq","value":"t13d1516h2_8daaf6152771_02713d6af862"}`,
	} {
		f.Add([]byte(s), "/A/b", "10.1.2.3")
	}
	env := Env{Phase: PhaseRateLimit, ViewerAvailable: allViewer, AllowRegex: true}
	f.Fuzz(func(t *testing.T, data []byte, val, ip string) {
		var n Node
		if json.Unmarshal(data, &n) != nil {
			return
		}
		m, compileErr := Compile(n, env)
		if checkErr := Check(n, env); checkErr != nil {
			if compileErr == nil {
				t.Fatalf("Compile accepted what Check rejected: %v", checkErr)
			}
			return
		}
		if compileErr != nil {
			t.Fatalf("Check accepted what Compile rejected: %v", compileErr)
		}

		stored, err := json.Marshal(n)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var loaded Node
		if err := json.Unmarshal(stored, &loaded); err != nil {
			t.Fatalf("stored JSON doesn't load: %v", err)
		}
		if Render(loaded) != Render(n) {
			t.Fatalf("storage changed the rule: %q became %q", Render(n), Render(loaded))
		}

		text := Render(n)
		parsed, err := Parse(text)
		if err != nil {
			t.Fatalf("UI text %q doesn't parse: %v", text, err)
		}
		if !reflect.DeepEqual(parsed, Normalize(n)) {
			t.Fatalf("UI text %q parses to a different rule", text)
		}

		addr, _ := netip.ParseAddr(ip)
		reqs := []*fakeReq{{}, anyReq(val, addr)}
		for _, r := range reqs {
			m(r)
		}
	})
}

// anyReq sets every field to v so each compiled condition sees a value.
func anyReq(v string, ip netip.Addr) *fakeReq {
	r := &fakeReq{str: map[string]string{}, lists: map[string][]string{}, ip: ip, ints: map[string]int64{}, bools: map[string]bool{}}
	for _, f := range Fields {
		r.str[f.Name] = v
		r.ints[f.Name] = int64(len(v))
		r.bools[f.Name] = len(v)%2 == 0
	}
	return r
}

// The wildcard matcher agrees with an independent implementation built on
// RE2, for every pattern the checker accepts and every request value.
func FuzzWildcardMatchesRegexp(f *testing.F) {
	f.Add("/api/*/users/*", "/api/v1/users/42", false)
	f.Add("*.EXAMPLE.com", "www.example.COM", true)
	f.Add(`a\*b*`, "a*bc", false)
	f.Add("*ab*ab", "abab", false)
	f.Fuzz(func(t *testing.T, pattern, s string, fold bool) {
		w, err := compileWildcard(pattern, fold)
		if err != nil || !utf8.ValidString(pattern) {
			return
		}
		// RE2 reads text as UTF-8 and would see U+FFFD where the matcher sees
		// raw bytes; compare only where both see the same thing.
		if !utf8.ValidString(s) || strings.ContainsRune(pattern, utf8.RuneError) {
			return
		}
		quoted := make([]string, len(w.segs))
		for i, seg := range w.segs {
			quoted[i] = regexp.QuoteMeta(string(seg))
		}
		re := regexp.MustCompile(`^(?s:` + strings.Join(quoted, ".*") + `)$`)
		subject := s
		if fold {
			subject = asciiLower(s)
		}
		if got, want := w.match(s), re.MatchString(subject); got != want {
			t.Fatalf("wildcard %q fold=%v on %q = %v, regexp says %v", pattern, fold, s, got, want)
		}
	})
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		b[i] = lowerASCII(c)
	}
	return string(b)
}

// IP set lookup agrees with checking every listed address and range in turn.
func FuzzIPSetMatchesLinearScan(f *testing.F) {
	f.Add("10.0.0.0/8 10.1.0.0/16 11.0.0.0 ::ffff:10.0.0.0/104 2001:db8::/32", "10.1.2.3")
	f.Add("0.0.0.0/0 ::/0", "::ffff:1.2.3.4")
	f.Add("192.0.2.7 192.0.2.7/32 192.0.2.0/31", "192.0.2.1")
	f.Fuzz(func(t *testing.T, list, addr string) {
		var items []string
		for item := range strings.FieldsSeq(list) {
			if literalProblem(FieldDef{Type: TypeIP}, OpDef{Name: "in"}, item, true) == "" {
				items = append(items, item)
			}
		}
		a, err := netip.ParseAddr(addr)
		if err != nil || len(items) == 0 {
			return
		}
		want := false
		for _, item := range items {
			want = want || linearContains(item, a)
		}
		if got := newIPSet(items).contains(a); got != want {
			t.Fatalf("set %v contains %s = %v, linear scan says %v", items, a, got, want)
		}
	})
}

func linearContains(item string, a netip.Addr) bool {
	a = a.WithZone("").Unmap()
	if x, err := netip.ParseAddr(item); err == nil {
		return x.Unmap() == a
	}
	p := netip.MustParsePrefix(item)
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Contains(a)
}

// ja4Pattern is the JA4 grammar as a regular expression: obviously right,
// too slow and allocating for the request path.
var ja4Pattern = regexp.MustCompile(`^[tqd](1[0-3]|s[23]|d[1-3]|00)[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

var ja3Pattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// The hand-written fingerprint checks accept exactly what the grammar's
// regular expressions accept, for any header value a CDN or client sends.
func FuzzJA4(f *testing.F) {
	for _, s := range []string{"t13d1516h2_8daaf6152771_02713d6af862", "q13i0310h3_55b375c5d22e_cd85d2d88918", "d00d0000000_000000000000_000000000000",
		"t12d1209h1_8daaf6152771_02713d6af862", "ts3d1516h2_8daaf6152771_02713d6af862", "t14d1516h2_8daaf6152771_02713d6af862",
		"e7d705a3286e19ea42f587b344ee6865", "", "t13d1516h2_8DAAF6152771_02713d6af862", "t13d1516h2",
		// One malformed part each: protocol, version, SNI, counts, ALPN.
		"x13d1516h2_8daaf6152771_02713d6af862", "t19d1516h2_8daaf6152771_02713d6af862", "ts4d1516h2_8daaf6152771_02713d6af862", "td4d1516h2_8daaf6152771_02713d6af862", "t01d1516h2_8daaf6152771_02713d6af862",
		"tx3d1516h2_8daaf6152771_02713d6af862", "t13x1516h2_8daaf6152771_02713d6af862", "t13d15a6h2_8daaf6152771_02713d6af862", "t13d1516h!_8daaf6152771_02713d6af862", "t13d1516H2_8daaf6152771_02713d6af862"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := ValidJA4(s), ja4Pattern.MatchString(s); got != want {
			t.Fatalf("ValidJA4(%q) = %v, grammar says %v", s, got, want)
		}
		if got, want := ValidJA3(s), ja3Pattern.MatchString(s); got != want {
			t.Fatalf("ValidJA3(%q) = %v, grammar says %v", s, got, want)
		}
	})
}
