package snapshot

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// allowlistOf returns n distinct, non-overlapping entries that each pass
// validation: IPv4 /24s and IPv6 /48s alternating.
func allowlistOf(n int) []string {
	out := make([]string, n)
	for i := range out {
		if i%2 == 0 {
			out[i] = fmt.Sprintf("100.64.%d.0/24", i/2)
		} else {
			out[i] = fmt.Sprintf("2001:db8:%x::/48", i/2)
		}
	}
	return out
}

func compileAllowlist(t *testing.T, entries ...string) *Compiled {
	t.Helper()
	c := validConfig()
	c.Global.ClientAllowlist = entries
	out, _, errs := Compile(c, testDeployment)
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	return out
}

// The allowlist came with schema 6. A policy of any schema may set it, and
// then needs edges that read schema 6, so admin holds the publish until every
// live edge does. Without it, or with an empty list, a config needs only its
// own schema.
func TestClientAllowlistNeedsSchema6Edges(t *testing.T) {
	set := func(entries ...any) func(m map[string]any) {
		return func(m map[string]any) { m["global"].(map[string]any)["client_allowlist"] = entries }
	}
	schema5 := validConfig()
	schema5.Schema = 5
	schema6 := validConfig()
	schema6.Schema = 6
	cases := []struct {
		name   string
		config *Config
		patch  func(m map[string]any)
		want   int
	}{
		{"schema 5 policy without it", schema5, nil, 5},
		{"schema 5 policy with an empty list", schema5, set(), 5},
		{"schema 5 policy with a trusted client", schema5, set("203.0.113.7"), 6},
		{"schema 1 policy with a trusted client", olderConfig(1), set("203.0.113.7"), 6},
		{"schema 6 policy with a trusted client", schema6, set("203.0.113.7"), 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, errs := compileJSON(t, tc.config, testDeployment, tc.patch)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got.NeedsSchema != tc.want {
				t.Fatalf("needs schema %d, want %d", got.NeedsSchema, tc.want)
			}
		})
	}
}

// A policy with no trusted clients encodes with no client_allowlist key, so
// an edge that reads an older schema decodes it strictly.
func TestEmptyClientAllowlistIsLeftOut(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		want    bool
	}{
		{"absent", nil, false},
		{"empty", []string{}, false},
		{"one trusted client", []string{"203.0.113.7"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Global.ClientAllowlist = tc.entries
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(b), `"client_allowlist"`); got != tc.want {
				t.Fatalf("key present %v, want %v", got, tc.want)
			}
		})
	}
}

// One mistake gives one error, so the UI shows one message beside the entry.
func TestClientAllowlistReportsEachProblemOnce(t *testing.T) {
	cases := []struct {
		name    string
		entries []string
		path    string
	}{
		{"address written twice", []string{"203.0.113.7", "203.0.113.7"}, "global.client_allowlist[1]"},
		{"more than 100 entries", allowlistOf(MaxListLen + 1), "global.client_allowlist"},
		{"address inside a range", []string{"198.51.100.0/24", "198.51.100.9"}, "global.client_allowlist[1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Global.ClientAllowlist = tc.entries
			_, _, errs := Compile(c, testDeployment)
			if len(errs) != 1 || errs[0].Path != tc.path {
				t.Fatalf("want one error at %q, got %v", tc.path, expr.Issues(errs))
			}
		})
	}
}

// An entry matches by its own prefix length: an exact IPv6 address is not
// its /64, a range stops at its edge, and an entry written as a mapped IPv6
// address matches the IPv4 client. The entry comes back as written.
func TestClientAllowlistMatchesByPrefixLength(t *testing.T) {
	c := compileAllowlist(t, "203.0.113.7", "198.51.100.0/24", "2001:db8:f00::/48", "2001:db8:1::5", "::ffff:192.0.2.9")
	for _, tc := range []struct{ name, ip, want string }{
		{"exact IPv4 address", "203.0.113.7", "203.0.113.7"},
		{"next IPv4 address", "203.0.113.8", ""},
		{"first address of a range", "198.51.100.0", "198.51.100.0/24"},
		{"last address of a range", "198.51.100.255", "198.51.100.0/24"},
		{"address after a range", "198.51.101.0", ""},
		{"address inside an IPv6 range", "2001:db8:f00:ffff::1", "2001:db8:f00::/48"},
		{"address after an IPv6 range", "2001:db8:f01::1", ""},
		{"exact IPv6 address", "2001:db8:1::5", "2001:db8:1::5"},
		{"neighbour of an exact IPv6 address in its /64", "2001:db8:1::6", ""},
		{"IPv4 client for an entry written as mapped IPv6", "192.0.2.9", "::ffff:192.0.2.9"},
		{"no address", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ip netip.Addr
			if tc.ip != "" {
				ip = netip.MustParseAddr(tc.ip)
			}
			if got := c.AllowedClient(ip); got != tc.want {
				t.Fatalf("AllowedClient(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
	if got := compileAllowlist(t).AllowedClient(netip.MustParseAddr("203.0.113.7")); got != "" {
		t.Fatalf("empty allowlist matched %q", got)
	}
}

// The match runs on every request, hit or miss, so it allocates nothing.
func TestClientAllowlistMatchAllocatesNothing(t *testing.T) {
	c := compileAllowlist(t, allowlistOf(MaxListLen)...)
	hit, miss := netip.MustParseAddr("100.64.49.7"), netip.MustParseAddr("203.0.113.7")
	if c.AllowedClient(hit) == "" || c.AllowedClient(miss) != "" {
		t.Fatal("setup: hit must match and miss must not")
	}
	if n := testing.AllocsPerRun(100, func() { c.AllowedClient(hit); c.AllowedClient(miss) }); n != 0 {
		t.Fatalf("%v allocations per match", n)
	}
}

// Anything validation accepts compiles to a list whose entries never
// overlap, so every entry's first address resolves to that entry.
func FuzzClientAllowlist(f *testing.F) {
	f.Add("203.0.113.7", "198.51.100.0/24", "2001:db8:f00::/48")
	f.Add("203.0.113.7", "::ffff:203.0.113.7", "")
	f.Add("198.51.100.0/25", "198.51.100.0/24", "10.0.0.0/8")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		cfg := validConfig()
		cfg.Global.ClientAllowlist = []string{a, b, c}
		out, _, errs := Compile(cfg, testDeployment)
		if out == nil {
			if errs == nil {
				t.Fatal("no snapshot and no errors")
			}
			return
		}
		for _, entry := range cfg.Global.ClientAllowlist {
			addr, err := netip.ParseAddr(entry)
			if err != nil {
				p, perr := netip.ParsePrefix(entry)
				if perr != nil {
					t.Fatalf("compiled entry %q is neither an address nor a prefix", entry)
				}
				addr = p.Addr()
			}
			if got := out.AllowedClient(addr.Unmap()); got != entry {
				t.Fatalf("first address of %q resolved to %q", entry, got)
			}
		}
	})
}

// The browser floor came with schema 7. A policy of any schema may set it
// and then needs edges that read schema 7. A rule naming browser_outdated is
// accepted once the floor is set and compiles the floors the edge reads.
func TestBrowserFloorNeedsSchema7Edges(t *testing.T) {
	older := validConfig()
	older.Schema = 6
	cases := []struct {
		name   string
		config *Config
		floor  map[string]int
		want   int
	}{
		{"schema 6 policy without a floor", older, nil, 6},
		{"schema 6 policy with an empty floor", older, map[string]int{}, 6},
		{"schema 6 policy with a floor", older, map[string]int{"chromium": 130}, 7},
		{"schema 1 policy with a floor", olderConfig(1), map[string]int{"chromium": 130}, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := *tc.config
			c.Global.BrowserFloor = tc.floor
			got, _, errs := Compile(&c, testDeployment)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got.NeedsSchema != tc.want {
				t.Fatalf("needs schema %d, want %d", got.NeedsSchema, tc.want)
			}
		})
	}
}

func TestBrowserFloorCompilesAndAcceptsTheSignal(t *testing.T) {
	c := validConfig()
	c.Global.BrowserFloor = map[string]int{"chromium": 130, "firefox": 128}
	c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "stale", Expression: mustParse(`client.signals eq "browser_outdated"`), Settings: Settings{BodyLimit: new(int64(1))}})
	got, _, errs := Compile(c, testDeployment)
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	if got.ChromiumFloor != 130 || got.FirefoxFloor != 128 {
		t.Fatalf("floors %d and %d", got.ChromiumFloor, got.FirefoxFloor)
	}
}

// A ban came with schema 9. A policy of any schema may set it and then needs
// edges that read schema 9.
func TestBanNeedsSchema9Edges(t *testing.T) {
	older := validConfig()
	older.Schema = 8
	cases := []struct {
		name   string
		config *Config
		ban    *Duration
		want   int
	}{
		{"schema 8 policy without a ban", older, nil, 8},
		{"schema 8 policy with a ban", older, new(dur("10m")), 9},
		{"schema 1 policy with a ban", olderConfig(1), new(dur("10m")), 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := *tc.config
			c.ConfigRules = append(slices.Clone(c.ConfigRules), ConfigRule{ID: "trap", Expression: mustParse(`starts_with(http.request.uri.path, "/wp-")`), Settings: Settings{Block: new("block"), Ban: tc.ban}})
			got, _, errs := Compile(&c, testDeployment)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got.NeedsSchema != tc.want {
				t.Fatalf("needs schema %d, want %d", got.NeedsSchema, tc.want)
			}
		})
	}
}

// client.denylisted came with schema 10 and client.ip_lists with schema 11. A
// policy of any schema may read either and then needs edges that read it.
func TestIPListsFieldNeedsSchema11Edges(t *testing.T) {
	older := validConfig()
	older.Schema = 9
	cases := []struct {
		name   string
		config *Config
		expr   string
		want   int
	}{
		{"schema 9 policy without the field", older, `starts_with(http.request.uri.path, "/wp-")`, 9},
		{"schema 9 policy reading the field", older, `client.ip_lists in {"aws"} and not ssl`, 11},
		{"schema 1 policy reading the field", olderConfig(1), `client.ip_lists in {"aws" "azure"}`, 11},
		{"schema 9 policy reading client.denylisted", older, `client.denylisted and not ssl`, 10},
		{"schema 1 policy reading client.denylisted", olderConfig(1), `client.denylisted`, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := *tc.config
			c.ConfigRules = append(slices.Clone(c.ConfigRules), ConfigRule{ID: "listed", Expression: mustParse(tc.expr), Settings: Settings{Block: new("block")}})
			got, _, errs := Compile(&c, testDeployment)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got.NeedsSchema != tc.want {
				t.Fatalf("needs schema %d, want %d", got.NeedsSchema, tc.want)
			}
		})
	}
}

// Admin warns about names rules compare client.ip_lists with, so every phase
// counts, the same name is listed once, and other fields add nothing.
func TestIPListNames(t *testing.T) {
	c := validConfig()
	c.ConfigRules = append(slices.Clone(c.ConfigRules),
		ConfigRule{ID: "a", Expression: mustParse(`client.ip_lists in {"aws" "azure"}`), Settings: Settings{Block: new("block")}},
		ConfigRule{ID: "b", Expression: mustParse(`not client.ip_lists in {"statuscake"} and client.ip_lists eq "aws"`), Settings: Settings{Block: new("log")}},
		ConfigRule{ID: "c", Expression: mustParse(`client.signals eq "ua_tool"`), Settings: Settings{Block: new("log")}})
	c.RateLimitRules = append(slices.Clone(c.RateLimitRules),
		RateLimitRule{ID: "rl-listed", Expression: mustParse(`client.ip_lists in {"hetzner"}`), Algorithm: "fixed_window", Limit: 10, Period: dur("1m"), Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"})
	c.RequestHeaderRules = append(slices.Clone(c.RequestHeaderRules),
		HeaderRule{ID: "hdr-listed", Expression: mustParse(`client.ip_lists eq "firehol"`), Ops: []HeaderOp{{Op: "remove", Name: "X-Debug-Token"}}})
	got := IPListNames(c)
	if want := []string{"aws", "azure", "firehol", "hetzner", "statuscake"}; !slices.Equal(got, want) {
		t.Fatalf("IPListNames = %v, want %v", got, want)
	}
	if got := IPListNames(validConfig()); len(got) != 0 {
		t.Fatalf("config without the field = %v", got)
	}
}
