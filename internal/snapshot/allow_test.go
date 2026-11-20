package snapshot

import (
	"slices"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

func addAllow(c *Config, src string, block *string) {
	c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "office", Expression: mustParse(src), Settings: Settings{Allow: true, Block: block}})
}

func TestCompileAcceptsAllowOnAClientsIdentity(t *testing.T) {
	bots := testDeployment
	bots.VerifiedBots = true
	cases := []struct {
		name string
		src  string
	}{
		{"client on an IP list", `client.ip_lists in {"office"}`},
		{"client on one IP list", `client.ip_lists eq "office"`},
		{"client IP in an IPv4 /24", `ip.src in {198.51.100.0/24}`},
		{"client IP in an IPv6 /48", `ip.src in {2001:db8:1::/48}`},
		{"IP list and a too wide IP range", `client.ip_lists in {"office"} and ip.src in {10.0.0.0/8}`},
		{"IP in parentheses and a path", `(ip.src eq 203.0.113.7) and starts_with(http.request.uri.path, "/admin")`},
		{"IP list in an and subgroup and a host", `(client.ip_lists in {"office"} and ssl) and http.host eq "a.com"`},
		{"client IP equals an address", `ip.src eq 203.0.113.7`},
		{"verified crawler", `client.verified_bot`},
		{"IP list and a path", `client.ip_lists in {"office"} and starts_with(http.request.uri.path, "/admin")`},
		{"a path and an IP, in either order", `starts_with(http.request.uri.path, "/admin") and ip.src eq 203.0.113.7`},
		{"one of two hosts and an IP", `(http.host eq "a.com" or http.host eq "b.com") and ip.src eq 203.0.113.7`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			addAllow(c, tc.src, nil)
			if _, _, errs := Compile(c, bots); errs != nil {
				t.Fatal(expr.Issues(errs))
			}
		})
	}
}

func TestCompileRejectsAllow(t *testing.T) {
	const subject = `an always-allow rule must require the client IP, an IP list or a verified crawler`
	wide := func(val, reason string) string {
		return "an always-allow rule's client IP " + val + " " + reason + ": put wider networks in an IP list and use client.ip_lists"
	}
	rule := func(src string) func(c *Config) { return func(c *Config) { addAllow(c, src, nil) } }
	runRejects(t, []rejectCase{
		{"allow together with block", func(c *Config) { addAllow(c, `ip.src eq 203.0.113.7`, new("block")) }, nil, "config_rules[3].settings.allow", "can't be set with block"},
		{"allow together with log only", func(c *Config) { addAllow(c, `ip.src eq 203.0.113.7`, new("log")) }, nil, "config_rules[3].settings.allow", "can't be set with block"},
		{"allow on a header only", rule(`http.request.headers["x-bypass"] eq "1"`), nil, "config_rules[3].expression", subject},
		{"allow on a user agent only", rule(`http.user_agent contains "internal"`), nil, "config_rules[3].expression", subject},
		{"allow on every request", func(c *Config) { addAllow(c, `true`, nil) }, nil, "config_rules[3].expression", subject},
		{"allow on an IP or a header", rule(`ip.src eq 203.0.113.7 or http.request.headers["x-bypass"] eq "1"`), nil, "config_rules[3].expression", subject},
		{"allow on a client that is not on an IP", rule(`ip.src ne 203.0.113.7`), nil, "config_rules[3].expression", subject},
		{"allow on a client not in an IP range", rule(`not ip.src in {10.0.0.0/8}`), nil, "config_rules[3].expression", subject},
		{"allow on a client not on an IP list", rule(`not client.ip_lists in {"office"}`), nil, "config_rules[3].expression", subject},
		{"allow on a country", rule(`ip.src.country eq "AU"`), nil, "config_rules[3].expression", subject},
		{"allow on a verified crawler negated", rule(`not client.verified_bot`), func() *Deployment { d := testDeployment; d.VerifiedBots = true; return &d }(), "config_rules[3].expression", subject},
		{"allow on every client by range", rule(`ip.src in {0.0.0.0/0 ::/0}`), nil, "config_rules[3].expression", wide("0.0.0.0/0", "is wider than /24 for IPv4 or /48 for IPv6")},
		{"allow on a /8", rule(`ip.src in {10.0.0.0/8}`), nil, "config_rules[3].expression", wide("10.0.0.0/8", "is wider than /24 for IPv4 or /48 for IPv6")},
		{"allow on a range with host bits set", rule(`ip.src in {198.51.100.7/24}`), nil, "config_rules[3].expression", "an always-allow rule's client IP 198.51.100.7/24 has host bits set; write 198.51.100.0/24 for the whole range or 198.51.100.7 for the one address"},
		{"allow on an or whose branch has the IP", rule(`(ip.src eq 203.0.113.7 and ssl) or ssl`), nil, "config_rules[3].expression", subject},
	})
}

// An allow rule is a setting: it needs no other setting, and edges that
// predate it would ignore it, so it needs schema 12.
func TestAllowNeedsSchema12Edges(t *testing.T) {
	older := validConfig()
	older.Schema = 9
	c := *older
	c.ConfigRules = slices.Clone(c.ConfigRules)
	addAllow(&c, `client.ip_lists in {"office"}`, nil)
	got, _, errs := Compile(&c, testDeployment)
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	if got.NeedsSchema != AllowSchema {
		t.Fatalf("needs schema %d, want %d", got.NeedsSchema, AllowSchema)
	}
}
