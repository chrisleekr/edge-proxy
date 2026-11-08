package snapshot

import (
	"encoding/json"
	"fmt"
	"net/netip"
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
		{"schema 6 policy with a trusted client", validConfig(), set("203.0.113.7"), 6},
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
