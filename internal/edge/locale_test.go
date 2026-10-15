package edge

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// edge.locale is resolved once per request from Accept-Language with the
// snapshot's matcher, and sent upstream when the locale setting is on.
func TestLocale(t *testing.T) {
	h := newHarness(t, nil)
	c := testConfig(1)
	c.Global.Locale = snapshot.Locale{Supported: []string{"en", "ko", "zh-Hant"}, Default: "en"}
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "locale", Expression: mustParse(`not starts_with(http.request.uri.path, "/raw")`), Settings: snapshot.Settings{Locale: new(true)}})
	c.RequestHeaderRules = []snapshot.HeaderRule{
		{ID: "korean", Expression: mustParse(`edge.locale eq "ko"`), Ops: []snapshot.HeaderOp{{Op: "set", Name: "X-Korean", Value: "{{locale}}"}}},
	}
	h.load(envelope(c))
	cases := []struct {
		name, path, accept, want string
	}{
		{"a supported language with a region", "/", "ko-KR,ko;q=0.9,en;q=0.5", "ko"},
		{"a region that implies a script", "/", "zh-TW", "zh-Hant"},
		{"q-values decide", "/", "en;q=0.2, ko;q=0.8", "ko"},
		{"an unsupported language gets the default", "/", "fr-FR", "en"},
		{"no header gets the default", "/", "", "en"},
		{"a header over 256 bytes gets the default", "/", "ko," + strings.Repeat("x", 300), "en"},
		{"a malformed header gets the default", "/", "!!!", "en"},
		{"locale off sends nothing", "/raw", "ko", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hs []string
			if tc.accept != "" {
				hs = []string{"Accept-Language", tc.accept}
			}
			h.do("GET", tc.path, nil, append(hs, "X-Edge-Locale", "forged")...).Body.Close()
			h.mu.Lock()
			defer h.mu.Unlock()
			if got := h.lastApp.Header.Get("X-Edge-Locale"); got != tc.want {
				t.Fatalf("X-Edge-Locale %q, want %q", got, tc.want)
			}
			if korean := h.lastApp.Header.Get("X-Korean"); (korean == "ko") != (tc.want == "ko") {
				t.Fatalf("rule on edge.locale: X-Korean %q", korean)
			}
		})
	}
}

// The locale cache answers repeats with one map read and never grows past
// its bound: new strings are matched but not stored.
func TestLocaleCache(t *testing.T) {
	c := testConfig(1)
	c.Global.Locale = snapshot.Locale{Supported: []string{"en", "ko"}, Default: "en", OutputHeader: "X-Edge-Lang"}
	compiled, _, errs := snapshot.Compile(c, testDeployment())
	if errs != nil {
		t.Fatal(errs)
	}
	l := newLocaleResolver(compiled)
	if l.header != "X-Edge-Lang" {
		t.Fatalf("output header %q", l.header)
	}
	if n := testing.AllocsPerRun(100, func() { l.resolve("ko-KR") }); n != 0 {
		t.Fatalf("cache hit allocates %v times", n)
	}
	for i := range 2 * maxLocaleCache {
		if got := l.resolve(fmt.Sprintf("ko;q=0.%d", i%9+1) + strings.Repeat(" ", i%50) + fmt.Sprint(",x-", i)); got != "ko" {
			t.Fatalf("matched %q", got)
		}
	}
	n := 0
	for i := range l.cache {
		n += len(l.cache[i].m)
	}
	if n > maxLocaleCache {
		t.Fatalf("cache holds %d entries, bound %d", n, maxLocaleCache)
	}
}
