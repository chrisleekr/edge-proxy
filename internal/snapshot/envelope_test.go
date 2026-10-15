package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/jwks"
)

// Valid but suspicious configs save, with a warning on the rule.
func TestCompileWarns(t *testing.T) {
	cases := []struct {
		name   string
		change func(c *Config)
		path   string
		msg    string
	}{
		{"allowlist dropping auth headers", func(c *Config) {
			c.RequestHeaderRules[2].Ops[0].Names = []string{"Accept"}
		}, "request_header_rules[2].ops[0].names", "allowlist drops Authorization"},
		{"copy from a header a forward filter drops", func(c *Config) {
			c.RequestHeaderRules[2].Ops[0].Names = []string{"Authorization", "Content-Type", "Accept", "Cookie", "X-Old"}
		}, "request_header_rules[0].ops[0].from", "User-Agent can be dropped by a forward filter first"},
		{"rename from a header the global denylist drops", func(c *Config) {
			c.Global.RequestHeaders.Forward = Forward{Mode: "denylist", Names: []string{"x-old"}}
		}, "request_header_rules[1].ops[3].from", "X-Old can be dropped"},
		{"rule overwritten by a later catch-all", func(c *Config) {
			c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: "catch-all", Expression: expr.True(), Settings: Settings{
				Auth: &AuthSetting{Mode: "none"}, CORSPolicy: new(""), Upstream: new("web"), UpstreamTimeout: new(dur("5s")),
			}})
		}, "config_rules[0]", "every setting is overwritten"},
		{"host that is two things at once", func(c *Config) {
			c.ConfigRules[0].Expression = mustParse(`http.host eq "a.example.com" and (ssl or http.host eq "b.example.com" and http.host eq "c.example.com")`)
		}, "config_rules[0].expression", "can never all be true"},
		{"limit skipped by sending a header", func(c *Config) {
			c.RateLimitRules[1].Expression = mustParse(`http.request.uri.path eq "/v1/login" and http.request.headers["x-internal"] ne "1"`)
		}, "rate_limit_rules[1].expression", "client-controlled http.request.headers"},
		{"limit skipped through a negated group", func(c *Config) {
			c.RateLimitRules[1].Expression = mustParse(`http.request.uri.path eq "/v1/login" and not (http.user_agent contains "monitor" or ssl)`)
		}, "rate_limit_rules[1].expression", "client-controlled http.user_agent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.change(c)
			out, warns, errs := Compile(c, testDeployment)
			if out == nil {
				t.Fatalf("a warning blocked the save: %v", expr.Issues(errs))
			}
			for _, w := range warns {
				if w.Path == tc.path && strings.Contains(w.Msg, tc.msg) {
					return
				}
			}
			t.Fatalf("no warning at %q mentioning %q; got %v", tc.path, tc.msg, expr.Issues(warns))
		})
	}
}

// testJWKS holds the Ed25519 public key from RFC 8037 Appendix A.2.
const testJWKS = `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`

func validEnvelope() *Envelope {
	cand := validConfig()
	cand.Version = 8
	return &Envelope{
		ExportedAt:      time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		Active:          validConfig(),
		Candidate:       cand,
		CanaryPercent:   0.07,
		CanaryExpiresAt: time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC),
		FleetSize:       6,
		Keys: []IssuerKeys{{IssuerID: "corp", JWKSURL: "https://idp.example.com/jwks",
			FetchedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), JWKS: json.RawMessage(testJWKS)}},
	}
}

// A key set fetched at the 64 KB cap still loads after admin's JSON
// encoding escapes its & < and > to \u0026 and the like, six bytes each.
func TestEnvelopeKeysAtTheFetchCap(t *testing.T) {
	e := validEnvelope()
	pad := jwks.MaxBytes - len(testJWKS) - len(`,"x":""`)
	full := testJWKS[:len(testJWKS)-1] + `,"x":"` + strings.Repeat("&", pad) + `"}`
	e.Keys[0].JWKS = json.RawMessage(full)
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`\u0026`)) || len(full) != jwks.MaxBytes {
		t.Fatalf("test setup: %d bytes, escaped %v", len(full), bytes.Contains(b, []byte(`\u0026`)))
	}
	d, err := Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, errs := CompileEnvelope(d, testDeployment); errs != nil {
		t.Fatal(expr.Issues(errs))
	}
}

// Admin is upgraded before edges, and re-encodes stored versions with its
// own types; edges not yet upgraded decode strictly. So a schema 1 envelope
// must encode exactly as it always has: a field added later must be omitted
// when unset (omitempty or omitzero) and need a higher schema when set.
// Never regenerate testdata/schema1-envelope.json to make this pass.
func TestSchema1EncodingNeverChanges(t *testing.T) {
	b, err := os.ReadFile("testdata/schema1-envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	e, err := Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, errs := CompileEnvelope(e, testDeployment); errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	got, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := json.Compact(&want, b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("a schema 1 envelope encodes differently, so edges not yet upgraded would reject it:\n got %s\nwant %s", got, want.Bytes())
	}
}

// What admin serves decodes and compiles on the edge, canary included.
// 0.07% needs rounding: 0.07 * 100 is not exactly 7 in float64.
func TestEnvelopeRoundTrip(t *testing.T) {
	b, err := json.Marshal(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	e, err := Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	s, errs := CompileEnvelope(e, testDeployment)
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	if s.Active == nil || s.Candidate == nil || s.CanaryBasisPoints != 7 || s.FleetSize != 6 || s.Keys[KeySource{"corp", "https://idp.example.com/jwks"}].Set.Len() != 1 {
		t.Fatalf("snapshot = %+v", s)
	}

	e.Candidate, e.CanaryPercent, e.CanaryExpiresAt = nil, 0, time.Time{}
	if s, errs := CompileEnvelope(e, testDeployment); errs != nil || s.Candidate != nil {
		t.Fatalf("no-canary snapshot: %v", expr.Issues(errs))
	}
}

// A broken snapshot is rejected whole, so the edge keeps the one it has.
func TestCompileEnvelopeRejects(t *testing.T) {
	cases := []struct {
		name   string
		change func(e *Envelope)
		path   string
		msg    string
	}{
		{"no export time", func(e *Envelope) { e.ExportedAt = time.Time{} }, "exported_at", "is required"},
		{"no active config", func(e *Envelope) { e.Active = nil }, "active", "is required"},
		{"error inside the active config", func(e *Envelope) { e.Active.RateLimitRules[1].Limit = 0 }, "active.rate_limit_rules[1].limit", "must be 1 to"},
		{"error at the root of the candidate", func(e *Envelope) { e.Candidate.Schema = 9 }, "candidate.schema", "not supported"},
		{"candidate over 8 MB", func(e *Envelope) { addHugeHeaderRules(e.Candidate) }, "candidate", "bytes as JSON"},
		{"canary percent without a candidate", func(e *Envelope) { e.Candidate = nil }, "canary_percent", "need a candidate"},
		{"canary expiry without a candidate", func(e *Envelope) { e.Candidate, e.CanaryPercent = nil, 0 }, "canary_percent", "need a candidate"},
		{"canary of 0%", func(e *Envelope) { e.CanaryPercent = 0 }, "canary_percent", "0.01 to 99.99"},
		{"canary of 100%", func(e *Envelope) { e.CanaryPercent = 100 }, "canary_percent", "0.01 to 99.99"},
		{"canary finer than 0.01%", func(e *Envelope) { e.CanaryPercent = 1.005 }, "canary_percent", "steps of 0.01"},
		{"canary without an expiry", func(e *Envelope) { e.CanaryExpiresAt = time.Time{} }, "canary_expires_at", "required during a canary"},
		{"candidate older than active", func(e *Envelope) { e.Candidate.Version = 7 }, "candidate.version", "newer than the active version 7"},
		{"negative fleet size", func(e *Envelope) { e.FleetSize = -1 }, "fleet_size", "not be negative"},
		{"keys for more issuers than both configs can have", func(e *Envelope) {
			for i := range 2 * MaxListLen {
				k := e.Keys[0]
				k.IssuerID = fmt.Sprintf("i%d", i)
				e.Keys = append(e.Keys, k)
			}
		}, "keys", "at most 200"},
		{"keys under a bad issuer id", func(e *Envelope) { e.Keys[0].IssuerID = "Corp" }, "keys[0].issuer_id", "not a valid issuer id"},
		{"keys with no JWKS URL", func(e *Envelope) { e.Keys[0].JWKSURL = "" }, "keys[0].jwks_url", "is required"},
		{"one issuer and URL twice", func(e *Envelope) { e.Keys = append(e.Keys, e.Keys[0]) }, "keys[1]", `repeats the keys of issuer "corp"`},
		{"keys with no fetch time", func(e *Envelope) { e.Keys[0].FetchedAt = time.Time{} }, "keys[0].fetched_at", "is required"},
		{"keys with no usable signing key", func(e *Envelope) {
			e.Keys[0].JWKS = json.RawMessage(`{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`)
		}, "keys[0].jwks", "no usable signing key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnvelope()
			tc.change(e)
			s, errs := CompileEnvelope(e, testDeployment)
			if s != nil {
				t.Fatal("compiled a broken snapshot")
			}
			for _, is := range errs {
				if is.Path == tc.path && strings.Contains(is.Msg, tc.msg) {
					return
				}
			}
			t.Fatalf("no error at %q mentioning %q; got %v", tc.path, tc.msg, expr.Issues(errs))
		})
	}
}

// Malformed input never reaches the validator: typos in field names, trailing
// garbage and oversized bodies are rejected while decoding.
func TestDecodeRejects(t *testing.T) {
	good, err := json.Marshal(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, body, msg string
	}{
		{"unknown top-level field", `{"exported_at":"2026-10-01T00:00:00Z","activ":{}}`, `unknown field "activ"`},
		{"unknown field in a rule", strings.Replace(string(good), `"on_missing_key"`, `"on_missing"`, 1), `unknown field "on_missing"`},
		{"trailing data", string(good) + ` {}`, "unexpected data after the snapshot"},
		{"duration as a number", strings.Replace(string(good), `"period":"1m0s"`, `"period":60`, 1), "duration must be a string"},
		{"duration that doesn't parse", strings.Replace(string(good), `"period":"1m0s"`, `"period":"1 minute"`, 1), "invalid duration"},
		{"not JSON", `<html>`, "invalid character"},
		{"larger than the cap", `"` + strings.Repeat("a", MaxEnvelopeBytes) + `"`, "larger than"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("Decode error = %v, want mention of %q", err, tc.msg)
			}
		})
	}
	// A dropped connection mid-download is an error, not a partial snapshot.
	wantErr := errors.New("connection reset")
	if _, err := Decode(iotest.ErrReader(wantErr)); !errors.Is(err, wantErr) {
		t.Fatalf("Decode error = %v, want %v", err, wantErr)
	}
}

// Template placeholders are split once; literal text with single braces,
// such as JSON, is left alone.
func TestTemplateRender(t *testing.T) {
	tpl, err := parseTemplate(`{"a":{{x}},"b":"{{y:z}}"}tail`)
	if err != nil {
		t.Fatal(err)
	}
	got := tpl.Render([]byte("> "), func(p Placeholder) string { return p.Name + "=" + p.Arg })
	if string(got) != `> {"a":x=,"b":"y=z"}tail` {
		t.Fatalf("Render = %s", got)
	}
	if ps := tpl.Placeholders(); len(ps) != 2 || ps[1] != (Placeholder{"y", "z"}) {
		t.Fatalf("Placeholders = %v", ps)
	}
	empty, _ := parseTemplate("")
	if len(empty.Render(nil, nil)) != 0 {
		t.Fatal("empty template rendered text")
	}
}
