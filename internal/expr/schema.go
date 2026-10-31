package expr

import "slices"

// Type is a field's value type.
type Type int

// Field value types. The zero Type is invalid.
const (
	TypeString Type = iota + 1
	TypeStringList
	TypeIP
	TypeInt
	TypeBool
)

var typeNames = [...]string{TypeString: "string", TypeStringList: "string_list", TypeIP: "ip", TypeInt: "int", TypeBool: "bool"}

// MarshalText names the type for the admin schema API.
func (t Type) MarshalText() ([]byte, error) { return []byte(typeNames[t]), nil }

// Phase is where in the request path a rule runs.
type Phase string

// Rule phases, in the order the edge runs them.
const (
	PhaseConfig         Phase = "config"
	PhaseRateLimit      Phase = "rate_limit"
	PhaseRequestHeaders Phase = "request_headers"
)

// Source says where a field's value comes from.
type Source int

// Field sources. The zero Source is invalid.
const (
	SourceRequest Source = iota + 1
	// SourceViewer fields come only from trusted CDN headers and are
	// unavailable unless the deployment configures a source for them.
	SourceViewer
	SourceClientIP
	SourceLocale
	SourceJWT
	// SourceEdge fields are computed by the edge from the request and the
	// snapshot, in every phase.
	SourceEdge
)

// FieldDef describes one field the language can reference.
type FieldDef struct {
	Name   string // expression name, e.g. "http.host"
	Label  string // UI name, e.g. "Hostname"
	Type   Type
	Keyed  bool // needs a key, e.g. http.request.headers["name"]
	Source Source
	// LowerKey lowercases keys (header names are case-insensitive).
	LowerKey bool
	// TokenKey means keys are RFC 9110 tokens (header and cookie names);
	// any other key can never match.
	TokenKey bool
	// TokenValue means values are RFC 9110 tokens (request methods).
	TokenValue bool
	// Slash means values start with "/": the edge rejects any other path.
	Slash bool
	// Case is the letter case the edge delivers the value in, so the checker
	// can reject case-sensitive comparisons that can never match.
	Case Case
	// Exact means values are names compared whole: only eq, ne, in and
	// not_in apply.
	Exact bool
}

// Case is the letter case of a field's values.
type Case int

// Letter cases. CaseAny means values may arrive in any case.
const (
	CaseAny Case = iota
	CaseLower
	CaseUpper
)

// Fields is the complete field list. Order is the UI order.
var Fields = []FieldDef{
	{Name: "http.request.full_uri", Label: "URI Full", Type: TypeString, Source: SourceRequest},
	{Name: "http.request.uri", Label: "URI", Type: TypeString, Source: SourceRequest},
	{Name: "http.request.uri.path", Label: "URI Path", Type: TypeString, Source: SourceRequest, Slash: true},
	{Name: "http.request.uri.query", Label: "URI Query String", Type: TypeString, Source: SourceRequest},
	{Name: "http.request.uri.args", Label: "URI Query Argument", Type: TypeStringList, Keyed: true, Source: SourceRequest},
	{Name: "http.host", Label: "Hostname", Type: TypeString, Source: SourceRequest, Case: CaseLower},
	{Name: "http.request.method", Label: "Request Method", Type: TypeString, Source: SourceRequest, TokenValue: true, Case: CaseUpper},
	{Name: "http.request.headers", Label: "Header", Type: TypeStringList, Keyed: true, LowerKey: true, TokenKey: true, Source: SourceRequest},
	{Name: "http.cookie", Label: "Cookie", Type: TypeString, Source: SourceRequest},
	{Name: "http.request.cookies", Label: "Cookie (named)", Type: TypeStringList, Keyed: true, TokenKey: true, Source: SourceRequest},
	{Name: "http.referer", Label: "Referer", Type: TypeString, Source: SourceRequest},
	{Name: "http.user_agent", Label: "User Agent", Type: TypeString, Source: SourceRequest},
	{Name: "http.x_forwarded_for", Label: "X-Forwarded-For", Type: TypeString, Source: SourceRequest},
	{Name: "ip.src", Label: "IP Source Address", Type: TypeIP, Source: SourceClientIP},
	{Name: "ip.src.country", Label: "Country", Type: TypeString, Source: SourceViewer, Case: CaseUpper},
	{Name: "ip.src.continent", Label: "Continent", Type: TypeString, Source: SourceViewer, Case: CaseUpper},
	{Name: "ip.src.asnum", Label: "AS Num", Type: TypeInt, Source: SourceViewer},
	{Name: "ssl", Label: "SSL/HTTPS", Type: TypeBool, Source: SourceViewer},
	{Name: "http.request.version", Label: "HTTP Version", Type: TypeString, Source: SourceViewer},
	{Name: "client_cert.verified", Label: "Client Certificate Verified", Type: TypeBool, Source: SourceViewer},
	{Name: "tls.client.ja4", Label: "JA4 Fingerprint", Type: TypeString, Source: SourceViewer},
	{Name: "tls.client.ja3", Label: "JA3 Fingerprint", Type: TypeString, Source: SourceViewer},
	{Name: SignalsField, Label: "Client Signals", Type: TypeStringList, Source: SourceEdge, Exact: true},
	{Name: VerifiedBotField, Label: "Verified Crawler", Type: TypeBool, Source: SourceEdge},
	{Name: "edge.locale", Label: "Locale", Type: TypeString, Source: SourceLocale},
	{Name: "http.request.jwt.claims", Label: "JWT claim", Type: TypeStringList, Keyed: true, Source: SourceJWT},
}

// SignalsField is the edge-computed list of client signals.
const SignalsField = "client.signals"

// VerifiedBotField is true for an address in the crawler ranges admin
// fetches from VERIFIED_BOT_SOURCES.
const VerifiedBotField = "client.verified_bot"

// SignalDef is one client.signals name. Needs lists the viewer fields it
// reads: without a source for each, it can never fire.
type SignalDef struct {
	Name  string   `json:"name"`
	Needs []string `json:"needs,omitempty"`
}

// Signals lists every client.signals name in the edge's bit order. Browsers
// send Sec-Fetch-* and client hints only in secure contexts, and negotiate
// HTTP/2 only over TLS, so those signals need ssl.
var Signals = []SignalDef{
	{Name: "ua_missing"},
	{Name: "ua_tool"},
	{Name: "ua_headless"},
	{Name: "browser_no_accept_language"},
	{Name: "browser_no_sec_fetch", Needs: []string{"ssl"}},
	{Name: "chromium_no_client_hints", Needs: []string{"ssl"}},
	{Name: "client_hints_mismatch", Needs: []string{"ssl"}},
	{Name: "browser_http1", Needs: []string{"ssl", "http.request.version"}},
	{Name: "browser_tls_mismatch", Needs: []string{"tls.client.ja4"}},
}

var fieldsByName = func() map[string]FieldDef {
	m := make(map[string]FieldDef, len(Fields))
	for _, f := range Fields {
		m[f.Name] = f
	}
	return m
}()

// LookupField returns the definition for name.
func LookupField(name string) (FieldDef, bool) {
	f, ok := fieldsByName[name]
	return f, ok
}

// InPhase reports whether the field's value exists when phase runs.
// The config phase runs before JWT verification and locale resolution.
func (f FieldDef) InPhase(p Phase) bool {
	if p == PhaseConfig {
		return f.Source != SourceJWT && f.Source != SourceLocale
	}
	return true
}

// OpDef describes one operator.
type OpDef struct {
	Name  string `json:"name"`  // AST name
	Label string `json:"label"` // UI name
	// Negates is the positive operator this one negates, or "".
	Negates string `json:"negates,omitempty"`
	List    bool   `json:"list"`     // takes a list value
	NoValue bool   `json:"no_value"` // takes no value (bool operators)
	Types   []Type `json:"types"`
}

var stringTypes = []Type{TypeString, TypeStringList}

// Operators is the complete operator list. Order is the UI order.
var Operators = []OpDef{
	{Name: "eq", Label: "equals", Types: []Type{TypeString, TypeStringList, TypeIP, TypeInt}},
	{Name: "ne", Label: "does not equal", Negates: "eq", Types: []Type{TypeString, TypeStringList, TypeIP, TypeInt}},
	{Name: "contains", Label: "contains", Types: stringTypes},
	{Name: "not_contains", Label: "does not contain", Negates: "contains", Types: stringTypes},
	{Name: "starts_with", Label: "starts with", Types: stringTypes},
	{Name: "not_starts_with", Label: "does not start with", Negates: "starts_with", Types: stringTypes},
	{Name: "ends_with", Label: "ends with", Types: stringTypes},
	{Name: "not_ends_with", Label: "does not end with", Negates: "ends_with", Types: stringTypes},
	{Name: "wildcard", Label: "wildcard", Types: stringTypes},
	{Name: "strict_wildcard", Label: "strict wildcard", Types: stringTypes},
	{Name: "in", Label: "is in", List: true, Types: []Type{TypeString, TypeStringList, TypeIP, TypeInt}},
	{Name: "not_in", Label: "is not in", Negates: "in", List: true, Types: []Type{TypeString, TypeStringList, TypeIP, TypeInt}},
	{Name: "matches", Label: "matches regex", Types: stringTypes},
	{Name: "gt", Label: "greater than", Types: []Type{TypeInt}},
	{Name: "ge", Label: "greater than or equal", Types: []Type{TypeInt}},
	{Name: "lt", Label: "less than", Types: []Type{TypeInt}},
	{Name: "le", Label: "less than or equal", Types: []Type{TypeInt}},
	{Name: "is_true", Label: "is true", NoValue: true, Types: []Type{TypeBool}},
	{Name: "is_false", Label: "is false", Negates: "is_true", NoValue: true, Types: []Type{TypeBool}},
}

var opsByName = func() map[string]OpDef {
	m := make(map[string]OpDef, len(Operators))
	for _, o := range Operators {
		m[o.Name] = o
	}
	return m
}()

// negatedOf maps a positive operator to its negated form, e.g. "eq" -> "ne".
var negatedOf = func() map[string]string {
	m := map[string]string{}
	for _, o := range Operators {
		if o.Negates != "" {
			m[o.Negates] = o.Name
		}
	}
	return m
}()

// LookupOp returns the definition for name.
func LookupOp(name string) (OpDef, bool) {
	o, ok := opsByName[name]
	return o, ok
}

func (o OpDef) accepts(t Type) bool {
	return slices.Contains(o.Types, t)
}

// Limits bound the cost of one expression on the request path.
const (
	MaxTextLen    = 4000
	MaxConditions = 32
	MaxRegexLen   = 1024
	MaxDepth      = 8
)
