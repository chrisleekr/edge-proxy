package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/language"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// Deployment is what validation needs from deployment config (env and
// flags). Admin users can't edit any of it.
type Deployment struct {
	// ViewerFields are the viewer fields with a configured trusted source,
	// e.g. "ip.src.country".
	ViewerFields []string
	// SourceHeaders are the client-IP, viewer and ingress secret headers.
	// The edge strips them, so rules can neither read nor set them.
	SourceHeaders []string
	// AllowRegex enables the "matches" operator.
	AllowRegex bool
	// VerifiedBots allows client.verified_bot. Admin sets it when
	// VERIFIED_BOT_SOURCES is set; edges always do, since their ranges come
	// with the snapshot and an edge must not refuse a config admin accepted.
	VerifiedBots bool
}

// Fingerprint identifies d. Edges report theirs, and admin refuses to
// publish while a live edge's differs from its own: every edge would reject
// a config validated against another deployment.
func (d Deployment) Fingerprint() string {
	sorted := func(xs []string, fold bool) []string {
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			if fold {
				x = strings.ToLower(x)
			}
			out = append(out, x)
		}
		slices.Sort(out)
		return out
	}
	// VerifiedBots is left out: edges always set it, so it never differs between edges.
	b, _ := json.Marshal([]any{sorted(d.ViewerFields, false), sorted(d.SourceHeaders, true), d.AllowRegex}) // strings and a bool
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// Compiled is a validated config ready for the request path. Slices are
// parallel to the rule lists in Config.
type Compiled struct {
	Config *Config
	// Deployment is what the config was validated against. Config tests
	// read the source headers from it, which the edge strips.
	Deployment     Deployment
	ConfigRules    []expr.Matcher
	RateLimitRules []expr.Matcher
	// SiteWide holds the indexes of rate-limit rules whose expression is
	// true; they are always evaluated.
	SiteWide    []int
	HeaderRules []expr.Matcher
	// HeaderValues[i][k] is the parsed value of rule i, op k (set and append).
	HeaderValues [][]Template
	Responses    map[string]Template
	// Locale is nil when no locales are supported.
	Locale language.Matcher
	// NeedsSchema is the lowest schema an edge must read to load this
	// config: its own, or higher when it sets a field added later.
	NeedsSchema int
	// Counts[i] holds the statuses rate-limit rule i counts; empty for a
	// rule that counts requests.
	Counts []StatusSet
}

// StatusSet is a set of HTTP statuses from 100 to 499, as bits.
type StatusSet [7]uint64

func (s *StatusSet) add(lo, hi int) {
	for c := lo; c <= hi; c++ {
		s[(c-100)/64] |= 1 << ((c - 100) % 64)
	}
}

// Has reports whether code is in the set.
func (s *StatusSet) Has(code int) bool {
	return code >= 100 && code < 500 && s[(code-100)/64]&(1<<((code-100)%64)) != 0
}

// Limits on one config.
const (
	// A build reads every config schema from MinSchema to SupportedSchema,
	// so an edge upgraded first still loads versions saved under older
	// schemas. Raising MinSchema needs admin to upgrade stored versions.
	MinSchema       = 1
	SupportedSchema = 5
	// MaxInflightSchema is the first schema whose edges read
	// global.max_inflight. A config of any schema may set it; admin then
	// publishes it only once every live edge reads that schema.
	MaxInflightSchema = 3
	// BotSchema is the first schema whose edges read the bot detection
	// fields, settings and rule options. A config of any schema may use
	// them; admin then waits for edges that read this schema.
	BotSchema = 4
	// ExpiresSchema is the first schema whose edges read a rate-limit
	// rule's expires_at. A config of any schema may set it; admin then
	// waits for edges that read this schema.
	ExpiresSchema = 5
	// MaxDistinct bounds a distinct rule's limit: the 1024-bit estimate
	// drifts beyond it.
	MaxDistinct = 1000
	// MaxBotSources bounds VERIFIED_BOT_SOURCES and MaxBotSetPrefixes each
	// source's ranges, so the snapshot stays bounded.
	MaxBotSources     = 16
	MaxBotSetPrefixes = 2000
	MaxConfigBytes    = 8 << 20
	MaxRulesPerPhase  = 200
	MaxSiteWide       = 2
	MaxKeyParts       = 5
	// MaxListLen bounds every other list and map: origins, header names,
	// issuers, audiences, locales, templates, policies, ops.
	MaxListLen      = 100
	MaxBodyTemplate = 32 << 10
	MaxHeaderValue  = 4096
	MaxNameArg      = 256
	// MaxNameLen bounds rule and issuer IDs, and template and CORS policy names.
	MaxNameLen     = 64
	MaxCount       = 1_000_000_000
	MaxBackstopIPs = 10_000_000
	MaxInflight    = 1_000_000
	MaxRulePeriod  = 24 * time.Hour
	// MaxExact bounds burst × period in ms for token and leaky buckets,
	// leaving headroom under 2^53 for the scripts' intermediate sums.
	MaxExact         = 1 << 51
	MaxServerTimeout = time.Hour
)

// statusOf is the status each response kind must use.
var statusOf = map[string]int{
	"bad_request":       400,
	"unauthorized":      401,
	"payload_too_large": 413,
	"rate_limited":      429,
	"bad_gateway":       502,
	"unavailable":       503,
	"overloaded":        503,
	"gateway_timeout":   504,
	"forbidden":         403,
}

// ContentTypes are the content types a response template may use.
var ContentTypes = []string{"application/json", "application/problem+json", "text/html; charset=utf-8", "text/plain; charset=utf-8"}

// ResponseStatuses returns each response kind and the status it must use.
// The edge keeps its own kind table; its tests check the two agree.
func ResponseStatuses() map[string]int { return maps.Clone(statusOf) }

// Algorithms are the rate-limit algorithms validation accepts. ratelimit
// keeps its enum in agreement, checked by its tests.
var Algorithms = []string{"fixed_window", "sliding_window", "token_bucket", "leaky_bucket", "distinct"}

// KeyKinds are the rate-limit key characteristics validation accepts.
// header, cookie, query and jwt_claim take a name; the rest take none.
// ratelimit keeps its part table in agreement, checked by its tests.
var KeyKinds = []string{"ip", "header", "cookie", "query", "jwt_claim", "host", "method", "country", "asnum", "ja4", "locale", "constant"}

// NamedKeyKinds are the KeyKinds written kind:name.
var NamedKeyKinds = []string{"header", "cookie", "query", "jwt_claim"}

// The other names validation accepts, in the order its errors list them.
// Each consumer's tests check it handles every one, so a name added here
// can't fall through to some other behavior.
var (
	OnMissingKeys = []string{"skip", "fallback_ip", "reject"}
	Actions       = []string{"block", "log"}
	BlockModes    = []string{"block", "log"}
	// DistinctOfKinds are what distinct counts; query takes a name.
	DistinctOfKinds  = []string{"path", "query", "ip", "asnum", "ja4"}
	FailModes        = []string{"open", "closed", "local"}
	AuthModes        = []string{"none", "optional", "required"}
	ForwardModes     = []string{"all", "allowlist", "denylist"}
	HeaderOps        = []string{"set", "append", "remove", "copy", "rename", "forward"}
	PlaceholderNames = []string{"header", "client_ip", "jwt_claim", "country", "locale", "request_id"}
)

// orList writes names as "a, b or c".
func orList(names []string) string {
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// JWTAlgorithms are the asymmetric algorithms golang-jwt v5 verifies. HMAC
// is excluded: the key would have to be a shared secret in the snapshot.
var JWTAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// reserved are request headers no rule may target. Lowercase.
var reserved = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true,
	"connection": true, "keep-alive": true, "proxy-connection": true,
	"proxy-authenticate": true, "proxy-authorization": true, "te": true,
	"trailer": true, "upgrade": true, "forwarded": true, "x-request-id": true,
}

// Reserved reports a header the edge or the HTTP framing manages, which no
// rule may target. The edge's forward filter always keeps these.
func Reserved(name string) bool { return reserved[strings.ToLower(name)] }

// traceHeaders carry W3C trace context, which the edge always forwards and,
// with tracing on, replaces with its own span's. Rules naming them only get
// a warning: rejecting them would stop an edge loading a snapshot that
// already does.
var traceHeaders = map[string]bool{"traceparent": true, "tracestate": true}

// TraceHeader reports a W3C trace context header. The edge's forward filter
// always keeps these.
func TraceHeader(name string) bool { return traceHeaders[strings.ToLower(name)] }

// clientControlled fields can be set to anything by the client, so rules
// must not rely on them to exclude traffic or to switch a block off.
var clientControlled = map[string]bool{
	"http.request.headers": true, "http.request.cookies": true, "http.cookie": true,
	"http.request.uri.args": true, "http.request.uri.query": true,
	"http.x_forwarded_for": true, "http.user_agent": true, "http.referer": true,
	// A client picks its own ClientHello and request headers, which the
	// fingerprints and signals are computed from.
	"tls.client.ja4": true, "tls.client.ja3": true, expr.SignalsField: true,
}

// botFields came with BotSchema.
var botFields = []string{"tls.client.ja4", "tls.client.ja3", expr.SignalsField, expr.VerifiedBotField}

// usesBotFeatures reports whether a stored config uses anything added in
// BotSchema, before upgrade adds its own forbidden template.
func usesBotFeatures(c *Config) bool {
	_, forbidden := c.Global.Defaults.Responses["forbidden"]
	if c.KillSwitch.Block || forbidden {
		return true
	}
	for _, r := range c.ConfigRules {
		if _, ok := r.Settings.Responses["forbidden"]; ok || r.Settings.Block != nil {
			return true
		}
	}
	for _, r := range c.RateLimitRules {
		if len(r.CountStatuses) > 0 || r.Algorithm == "distinct" || r.DistinctOf != "" ||
			slices.ContainsFunc(r.Key, func(k string) bool { return strings.HasPrefix(k, "ja4") }) {
			return true
		}
	}
	return slices.ContainsFunc(botFields, func(f string) bool { return ReadsField(c, f) })
}

// Compile validates c against d and builds the request-path structures. It
// is the only validation path: admin runs it on every save and publish, the
// edge before activation. It returns the compiled config, or nil and every
// error found. Warnings are returned either way.
func Compile(c *Config, d Deployment) (*Compiled, []expr.Issue, []expr.Issue) {
	schema1 := c.Schema == 1
	needs := c.Schema
	if usesBotFeatures(c) {
		needs = max(needs, BotSchema)
	}
	if slices.ContainsFunc(c.RateLimitRules, func(r RateLimitRule) bool { return !r.ExpiresAt.IsZero() }) {
		needs = max(needs, ExpiresSchema)
	}
	templates := len(c.Global.Responses)
	c = upgrade(c)
	v := &validator{
		d: d, c: c, schema1: schema1, addedTemplates: len(c.Global.Responses) - templates,
		out:     &Compiled{Config: c, Deployment: d, Responses: map[string]Template{}, NeedsSchema: needs},
		viewer:  setOf(d.ViewerFields, caseSensitive),
		sources: setOf(d.SourceHeaders, foldCase),
		issuers: map[string]bool{},
		locales: map[string]bool{},
		ruleIDs: map[string]bool{},
	}
	v.config()
	if len(v.errs) > 0 {
		return nil, v.warns, v.errs
	}
	return v.out, v.warns, nil
}

// CheckExpression validates one expression as Compile would for a rule in
// phase of c, so the admin rule builder and save can't disagree. It reads
// only c's supported locales.
func CheckExpression(n expr.Node, phase expr.Phase, c *Config, d Deployment) (errs, warns []expr.Issue) {
	v := &validator{d: d, c: c, viewer: setOf(d.ViewerFields, caseSensitive), sources: setOf(d.SourceHeaders, foldCase), locales: setOf(c.Global.Locale.Supported, caseSensitive)}
	v.expression("", n, phase)
	trim := func(is []expr.Issue) []expr.Issue {
		for i := range is {
			is[i].Path = strings.TrimPrefix(is[i].Path, ".")
		}
		return is
	}
	return trim(v.errs), trim(v.warns)
}

type validator struct {
	d                         Deployment
	c                         *Config
	out                       *Compiled
	errs, warns               []expr.Issue
	viewer, sources           map[string]bool
	issuers, locales, ruleIDs map[string]bool
	siteWideIP                bool
	// schema1 is set when the stored config predates schema 2.
	schema1 bool
	// addedTemplates is the forbidden template upgrade added, which the
	// template count allows for: an older config at the cap must still load.
	addedTemplates int
}

func (v *validator) err(path, format string, args ...any) {
	v.errs = append(v.errs, expr.Issue{Path: path, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) warn(path, format string, args ...any) {
	v.warns = append(v.warns, expr.Issue{Path: path, Msg: fmt.Sprintf(format, args...)})
}

// upgrade returns c as the current schema reads it. c itself is not
// changed: admin serves stored versions as they were saved, so edges not yet
// upgraded still read them.
//
// Schema 1 routed each request to a named upstream and answered 421
// "misdirected" when none applied; schema 2 forwards everything to the one
// upstream, so that response kind is dropped. A schema 1 rule that set
// "upstream" fails to decode instead, because its routing can't be kept.
//
// Schemas before BotSchema had no forbidden kind, so a forbidden template
// is added: the one named forbidden if it has status 403, else an HTML
// template under the first free name.
func upgrade(c *Config) *Config {
	if c.Schema < MinSchema || c.Schema >= BotSchema {
		return c
	}
	// u shares c's maps and slices; change only the fields cloned here.
	u := *c
	u.Global.Defaults.Responses = maps.Clone(c.Global.Defaults.Responses)
	if u.Global.Defaults.Responses == nil {
		u.Global.Defaults.Responses = map[string]string{}
	}
	if c.Schema == 1 {
		u.Schema = 2
		delete(u.Global.Defaults.Responses, "misdirected")
		u.ConfigRules = slices.Clone(c.ConfigRules)
		for i := range u.ConfigRules {
			u.ConfigRules[i].Settings.Responses = maps.Clone(c.ConfigRules[i].Settings.Responses)
			delete(u.ConfigRules[i].Settings.Responses, "misdirected")
		}
	}
	if _, ok := u.Global.Defaults.Responses["forbidden"]; !ok {
		name := "forbidden"
		if r, ok := c.Global.Responses[name]; !ok || r.Status != 403 {
			for i := 1; ; i++ {
				if _, taken := c.Global.Responses[name]; !taken {
					break
				}
				name = "forbidden_html"
				if i > 1 {
					name = fmt.Sprintf("forbidden_html_%d", i)
				}
			}
			u.Global.Responses = maps.Clone(c.Global.Responses)
			if u.Global.Responses == nil {
				u.Global.Responses = map[string]Response{}
			}
			u.Global.Responses[name] = forbiddenHTML
		}
		u.Global.Defaults.Responses["forbidden"] = name
	}
	return &u
}

// forbiddenHTML is the default forbidden template: a block usually refuses
// a page request, and a browser shows HTML.
var forbiddenHTML = Response{Status: 403, ContentType: "text/html; charset=utf-8",
	Body: `<!doctype html><html lang="en"><meta charset="utf-8"><title>Forbidden</title><h1>Forbidden</h1><p>This request was refused. Request ID: {{request_id}}</p></html>`}

func (v *validator) config() {
	c := v.c
	if c.Schema < MinSchema || c.Schema > SupportedSchema {
		v.err("schema", "schema %d is not supported; this build reads schemas %d to %d", c.Schema, MinSchema, SupportedSchema)
	}
	if c.Version < 1 {
		v.err("version", "must be at least 1")
	}
	// Marshaling a decoded Config can't fail: every type in it marshals.
	if b, _ := json.Marshal(c); len(b) > MaxConfigBytes {
		v.err("", "config is %d bytes as JSON; at most %d are allowed", len(b), MaxConfigBytes)
	}
	v.global()
	v.auth()
	v.configRules()
	v.unused()
	v.rateLimitRules()
	v.headerRules()
}

func (v *validator) global() {
	g := v.c.Global
	b := g.Backstop
	v.count("global.backstop.limit", b.Limit)
	v.period("global.backstop.period", b.Period, time.Hour)
	v.count("global.backstop.burst", b.Burst)
	if b.MaxEntries < 1 || b.MaxEntries > MaxBackstopIPs {
		v.err("global.backstop.max_entries", "must be 1 to %s", thousands(MaxBackstopIPs))
	}
	if g.MaxInflight < 0 || g.MaxInflight > MaxInflight {
		v.err("global.max_inflight", "must be 1 to %s, or left out to keep each edge's own limit", thousands(MaxInflight))
	}
	if g.MaxInflight > 0 {
		v.out.NeedsSchema = max(v.out.NeedsSchema, MaxInflightSchema)
	}

	v.templates(g.Responses)
	d := g.Defaults
	if d.BodyLimit < 1 {
		v.err("global.defaults.body_limit", "must be at least 1 byte")
	}
	v.timeout("global.defaults.body_read_timeout", d.BodyReadTimeout)
	v.timeout("global.defaults.upstream_timeout", d.UpstreamTimeout)
	v.responseMap("global.defaults.responses", d.Responses)
	for _, kind := range slices.Sorted(maps.Keys(statusOf)) {
		if _, ok := d.Responses[kind]; !ok {
			v.err("global.defaults.responses", "needs a template for %q; the edge can send it on any request", kind)
		}
	}

	v.cors(g.CORSPolicies)
	v.locale(g.Locale, d.Locale)
	v.forward("global.request_headers.forward", g.RequestHeaders.Forward)
}

func (v *validator) templates(rs map[string]Response) {
	if len(rs) > MaxListLen+v.addedTemplates {
		v.err("global.responses", "has %d templates; at most %d are allowed", len(rs), MaxListLen)
	}
	samples := map[string]string{"retry_after": "1", "request_id": "r1", "status": "429"}
	for _, name := range slices.Sorted(maps.Keys(rs)) {
		r := rs[name]
		p := fmt.Sprintf("global.responses[%q]", name)
		v.name(p, name)
		if r.Status < 400 || r.Status > 599 {
			v.err(p+".status", "must be 400 to 599")
		}
		if !slices.Contains(ContentTypes, r.ContentType) {
			v.err(p+".content_type", "must be one of %s", strings.Join(ContentTypes, ", "))
		}
		if len(r.Body) > MaxBodyTemplate {
			v.err(p+".body", "is %d bytes; at most %d are allowed", len(r.Body), MaxBodyTemplate)
		}
		t, err := parseTemplate(r.Body)
		if err != nil {
			v.err(p+".body", "%v", err)
			continue
		}
		bad := false
		for _, ph := range t.Placeholders() {
			if _, ok := samples[ph.Name]; !ok || ph.Arg != "" {
				v.err(p+".body", "unknown placeholder {{%s}}; use {{retry_after}}, {{request_id}} or {{status}}", ph.Name)
				bad = true
			}
		}
		if !bad && strings.HasSuffix(r.ContentType, "json") {
			if out := t.Render(nil, func(ph Placeholder) string { return samples[ph.Name] }); !json.Valid(out) {
				v.err(p+".body", "is not valid JSON after filling placeholders with sample values")
			}
		}
		v.out.Responses[name] = t
	}
}

// responseMap checks a kind -> template map, used by defaults and rules.
func (v *validator) responseMap(path string, m map[string]string) {
	for _, kind := range slices.Sorted(maps.Keys(m)) {
		status, ok := statusOf[kind]
		if !ok {
			v.err(path, "unknown response kind %q", kind)
			continue
		}
		r, ok := v.c.Global.Responses[m[kind]]
		switch {
		case !ok:
			v.err(path, "%s uses template %q, which doesn't exist", kind, m[kind])
		case r.Status != status:
			v.err(path, "%s needs a template with status %d; %q has %d", kind, status, m[kind], r.Status)
		}
	}
}

func (v *validator) cors(ps map[string]CORSPolicy) {
	if len(ps) > MaxListLen {
		v.err("global.cors_policies", "has %d policies; at most %d are allowed", len(ps), MaxListLen)
	}
	for _, name := range slices.Sorted(maps.Keys(ps)) {
		cp := ps[name]
		p := fmt.Sprintf("global.cors_policies[%q]", name)
		v.name(p, name)
		if len(cp.Origins) == 0 {
			v.err(p+".origins", "needs at least one origin")
		}
		v.list(p+".origins", cp.Origins, caseSensitive, func(o string) string {
			if o == "*" {
				if cp.Credentials {
					return `"*" can't be used with credentials (Fetch standard)`
				}
				return ""
			}
			return originProblem(o)
		})
		v.list(p+".methods", cp.Methods, caseSensitive, func(m string) string {
			if !expr.IsToken(m) || strings.ToUpper(m) != m {
				return "must be an uppercase method name"
			}
			return ""
		})
		headerList := func(h string) string {
			if h == "*" && cp.Credentials {
				return `"*" can't be used with credentials (Fetch standard)`
			}
			if h != "*" && !expr.IsToken(h) {
				return "is not a valid header name; use letters, digits and -, such as x-request-id"
			}
			return ""
		}
		v.list(p+".request_headers", cp.RequestHeaders, foldCase, headerList)
		v.list(p+".exposed_headers", cp.ExposedHeaders, foldCase, headerList)
		if cp.MaxAge != 0 {
			v.period(p+".max_age", cp.MaxAge, 24*time.Hour)
		}
	}
}

// originProblem checks a serialized origin: scheme://host[:port], lowercase,
// nothing else, because browsers send exactly that form.
func originProblem(o string) string {
	u, err := url.Parse(o)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(o, "?") || strings.HasSuffix(o, "#") {
		return "must be an origin such as https://app.example.com"
	}
	if strings.ToLower(o) != o {
		return "must be lowercase; browsers send origins in lowercase"
	}
	return ""
}

func (v *validator) locale(l Locale, defaultOn bool) {
	if len(l.Supported) == 0 {
		if l.Default != "" || l.OutputHeader != "" || defaultOn {
			v.err("global.locale.supported", "needs at least one locale when locale is used")
		}
		return
	}
	var tags []language.Tag
	v.list("global.locale.supported", l.Supported, caseSensitive, func(s string) string {
		t, err := language.Parse(s)
		if err != nil {
			return "is not a BCP 47 language tag"
		}
		if t.String() != s {
			return fmt.Sprintf("must be written in canonical form %q", t.String())
		}
		tags = append(tags, t)
		v.locales[s] = true
		return ""
	})
	if !v.locales[l.Default] {
		v.err("global.locale.default", "must be one of the supported locales")
	}
	if l.OutputHeader != "" && (!expr.IsToken(l.OutputHeader) || !strings.HasPrefix(strings.ToLower(l.OutputHeader), "x-edge-")) {
		v.err("global.locale.output_header", "must be a header name starting with X-Edge-, so clients can't send it")
	}
	v.out.Locale = language.NewMatcher(tags)
}

func (v *validator) forward(path string, f Forward) {
	if !slices.Contains(ForwardModes, f.Mode) {
		v.err(path+".mode", "must be %s", orList(ForwardModes))
		return
	}
	if f.Mode == "all" {
		if len(f.Names) > 0 {
			v.err(path+".names", "must be empty when mode is all")
		}
		return
	}
	if len(f.Names) == 0 {
		v.err(path+".names", "needs at least one header name")
	}
	v.list(path+".names", f.Names, foldCase, v.targetProblem)
	for i, n := range f.Names {
		if TraceHeader(n) {
			v.warn(fmt.Sprintf("%s.names[%d]", path, i), "%s is always forwarded, so listing it has no effect; with tracing off, a remove op drops it", http.CanonicalHeaderKey(n))
		}
	}
	if f.Mode == "allowlist" {
		for _, h := range []string{"Authorization", "Cookie", "Content-Type"} {
			if !slices.ContainsFunc(f.Names, func(n string) bool { return strings.EqualFold(n, h) }) {
				v.warn(path+".names", "allowlist drops %s", h)
			}
		}
	}
}

func (v *validator) auth() {
	a := v.c.Auth
	if len(a.Issuers) > MaxListLen {
		v.err("auth.issuers", "has %d issuers; at most %d are allowed", len(a.Issuers), MaxListLen)
	}
	iss := map[string]bool{}
	for i, is := range a.Issuers {
		p := fmt.Sprintf("auth.issuers[%d]", i)
		v.name(p+".id", is.ID)
		if v.issuers[is.ID] {
			v.err(p+".id", "duplicate issuer id %q", is.ID)
		}
		v.issuers[is.ID] = true
		if is.Issuer == "" || len(is.Issuer) > MaxNameArg || expr.HasControl(is.Issuer) {
			v.err(p+".issuer", "must be 1 to %d characters with no control characters", MaxNameArg)
		}
		// The token's iss picks the issuer, so two issuers can't share one.
		if iss[is.Issuer] {
			v.err(p+".issuer", "another issuer already uses %q", is.Issuer)
		}
		iss[is.Issuer] = true
		if len(is.Audiences) == 0 {
			v.err(p+".audiences", "needs at least one audience")
		}
		v.list(p+".audiences", is.Audiences, caseSensitive, func(s string) string {
			if s == "" || len(s) > MaxNameArg || expr.HasControl(s) {
				return fmt.Sprintf("must be 1 to %d characters with no control characters", MaxNameArg)
			}
			return ""
		})
		if u, err := url.Parse(is.JWKSURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			v.err(p+".jwks_url", "must be an https URL with a host and no credentials or fragment")
		}
		if !slices.Contains(JWTAlgorithms, is.Algorithm) {
			v.err(p+".algorithm", "must be one of %s", strings.Join(JWTAlgorithms, ", "))
		}
	}
	v.issuerList("auth.default_accepted", a.DefaultAccepted)
}

func (v *validator) issuerList(path string, ids []string) {
	v.list(path, ids, caseSensitive, func(id string) string {
		if !v.issuers[id] {
			return fmt.Sprintf("issuer %q doesn't exist", id)
		}
		return ""
	})
}

func (v *validator) configRules() {
	rs := v.c.ConfigRules
	v.ruleCount("config_rules", len(rs))
	v.out.ConfigRules = make([]expr.Matcher, len(rs))
	blockedEarlier := false
	for i, r := range rs {
		p := fmt.Sprintf("config_rules[%d]", i)
		v.ruleID(p, r.ID)
		v.out.ConfigRules[i] = v.expression(p, r.Expression, expr.PhaseConfig)
		v.settings(p+".settings", r.Settings)
		switch {
		case r.Settings.Block == nil:
		case *r.Settings.Block == "block":
			v.spoofableExclusion(p, r.Expression)
			blockedEarlier = true
		case *r.Settings.Block == "log" && blockedEarlier:
			v.spoofableLogBlock(p, r.Expression)
		}
	}
	// A rule whose every setting a later "true" rule sets again never has an effect.
	for i, r := range rs {
		later := map[string]bool{}
		for _, l := range rs[i+1:] {
			if expr.Normalize(l.Expression).IsTrue() {
				for _, n := range settingNames(l.Settings) {
					later[n] = true
				}
			}
		}
		names := settingNames(r.Settings)
		if len(names) > 0 && !slices.ContainsFunc(names, func(n string) bool { return !later[n] }) {
			v.warn(fmt.Sprintf("config_rules[%d]", i), "every setting is overwritten by a later rule that matches all requests")
		}
	}
}

// unused warns about a CORS policy, issuer or template nothing refers to:
// it saves and publishes but changes no response.
func (v *validator) unused() {
	c := v.c
	cors, issuers, templates := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, id := range c.Auth.DefaultAccepted {
		issuers[id] = true
	}
	for _, name := range c.Global.Defaults.Responses {
		templates[name] = true
	}
	for _, r := range c.ConfigRules {
		s := r.Settings
		if s.CORSPolicy != nil {
			cors[*s.CORSPolicy] = true
		}
		if s.Auth != nil {
			for _, id := range s.Auth.Accepted {
				issuers[id] = true
			}
		}
		for _, name := range s.Responses {
			templates[name] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Global.CORSPolicies)) {
		if !cors[name] {
			v.warn(fmt.Sprintf("global.cors_policies[%q]", name), `no config rule selects it, so it has no effect; set "cors_policy": %q in a config rule's settings`, name)
		}
	}
	for i, is := range c.Auth.Issuers {
		if !issuers[is.ID] {
			v.warn(fmt.Sprintf("auth.issuers[%d]", i), `no config rule accepts it and it is not in default_accepted, so no request accepts its tokens; add %q to either`, is.ID)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Global.Responses)) {
		if !templates[name] {
			v.warn(fmt.Sprintf("global.responses[%q]", name), "nothing sends it; name it in global.defaults.responses or in a config rule's responses")
		}
	}
}

func settingNames(s Settings) []string {
	var ns []string
	add := func(set bool, n string) {
		if set {
			ns = append(ns, n)
		}
	}
	add(s.Auth != nil, "auth")
	add(s.CORSPolicy != nil, "cors_policy")
	add(s.Locale != nil, "locale")
	for _, k := range slices.Sorted(maps.Keys(s.Responses)) {
		ns = append(ns, "responses."+k)
	}
	add(s.BodyLimit != nil, "body_limit")
	add(s.UpstreamTimeout != nil, "upstream_timeout")
	add(s.RateLimitHeaders != nil, "ratelimit_headers")
	add(s.Block != nil, "block")
	return ns
}

func (v *validator) settings(p string, s Settings) {
	if len(settingNames(s)) == 0 {
		v.err(p, "sets nothing; add at least one setting")
	}
	if a := s.Auth; a != nil {
		switch {
		case !slices.Contains(AuthModes, a.Mode):
			v.err(p+".auth.mode", "must be %s", orList(AuthModes))
		case a.Mode == "none":
			if len(a.Accepted) > 0 {
				v.err(p+".auth.accepted", "must be empty when mode is none")
			}
		case len(a.Accepted) == 0 && len(v.c.Auth.DefaultAccepted) == 0:
			v.err(p+".auth.accepted", "no issuers are accepted: set accepted or auth.default_accepted")
		}
		v.issuerList(p+".auth.accepted", a.Accepted)
	}
	if s.CORSPolicy != nil && *s.CORSPolicy != "" {
		if _, ok := v.c.Global.CORSPolicies[*s.CORSPolicy]; !ok {
			v.err(p+".cors_policy", "CORS policy %q doesn't exist", *s.CORSPolicy)
		}
	}
	if s.Locale != nil && *s.Locale && len(v.c.Global.Locale.Supported) == 0 {
		v.err(p+".locale", "locale is not configured in global.locale")
	}
	v.responseMap(p+".responses", s.Responses)
	if s.BodyLimit != nil && *s.BodyLimit < 1 {
		v.err(p+".body_limit", "must be at least 1 byte")
	}
	if s.UpstreamTimeout != nil {
		v.timeout(p+".upstream_timeout", *s.UpstreamTimeout)
	}
	if s.Block != nil && !slices.Contains(BlockModes, *s.Block) {
		v.err(p+".block", "must be %s", orList(BlockModes))
	}
}

func (v *validator) rateLimitRules() {
	rs := v.c.RateLimitRules
	v.ruleCount("rate_limit_rules", len(rs))
	v.out.RateLimitRules = make([]expr.Matcher, len(rs))
	v.out.Counts = make([]StatusSet, len(rs))
	for i, r := range rs {
		// Count rules take no Valkey slot, so they are not site-wide rules,
		// and only a rule counting every request is an ip partner.
		if expr.Normalize(r.Expression).IsTrue() && len(r.CountStatuses) == 0 {
			v.out.SiteWide = append(v.out.SiteWide, i)
			v.siteWideIP = v.siteWideIP || r.Algorithm != "distinct" && slices.Contains(r.Key, "ip")
		}
	}
	if len(v.out.SiteWide) > MaxSiteWide {
		v.err("rate_limit_rules", "has %d rules matching all requests; at most %d are allowed", len(v.out.SiteWide), MaxSiteWide)
	}
	for i, r := range rs {
		p := fmt.Sprintf("rate_limit_rules[%d]", i)
		v.ruleID(p, r.ID)
		v.out.RateLimitRules[i] = v.expression(p, r.Expression, expr.PhaseRateLimit)
		v.spoofableExclusion(p, r.Expression)
		if !slices.Contains(Algorithms, r.Algorithm) {
			v.err(p+".algorithm", "must be one of %s", strings.Join(Algorithms, ", "))
		}
		v.count(p+".limit", r.Limit)
		v.period(p+".period", r.Period, MaxRulePeriod)
		v.distinct(p, r)
		if len(r.CountStatuses) > 0 {
			v.out.Counts[i] = v.countStatuses(p, r)
		}
		if r.Algorithm == "token_bucket" || r.Algorithm == "leaky_bucket" {
			v.count(p+".burst", r.Burst)
			// Valkey's Lua numbers are doubles; the bucket scripts work in
			// burst × period milliseconds and must stay exact.
			if ms := int64(time.Duration(r.Period) / time.Millisecond); ms > 0 && r.Burst > MaxExact/ms {
				v.err(p+".burst", "burst × period is too large: at most %d per %s", MaxExact/ms, time.Duration(r.Period))
			}
		} else if r.Burst != 0 {
			v.err(p+".burst", "applies only to token_bucket and leaky_bucket")
		}
		v.key(p+".key", r.Key)
		if !slices.Contains(OnMissingKeys, r.OnMissingKey) {
			v.err(p+".on_missing_key", "must be %s", orList(OnMissingKeys))
		}
		if !slices.Contains(Actions, r.Action) {
			v.err(p+".action", "must be %s", orList(Actions))
		}
		if r.Penalty != 0 {
			v.period(p+".penalty", r.Penalty, MaxRulePeriod)
		}
		if !slices.Contains(FailModes, r.FailMode) {
			v.err(p+".fail_mode", "must be %s", orList(FailModes))
		}
	}
}

// key checks rate-limit key characteristics.
func (v *validator) key(p string, parts []string) {
	if len(parts) < 1 || len(parts) > MaxKeyParts {
		v.err(p, "needs 1 to %d characteristics", MaxKeyParts)
		return
	}
	attacker, partner := false, false
	v.list(p, parts, caseSensitive, func(k string) string {
		kind, arg, hasArg := strings.Cut(k, ":")
		if !slices.Contains(KeyKinds, kind) {
			return "must be ip, header:<n>, cookie:<n>, query:<n>, jwt_claim:<n>, host, method, country, asnum, ja4, locale or constant"
		}
		switch kind {
		case "ip", "jwt_claim":
			partner = true
		case "header", "cookie", "query", "host", "method", "ja4":
			// Any uppercase token is a valid method, and the edge forwards
			// any Host to the one upstream, so clients choose both. A client
			// picks its own ClientHello, and many real users share one JA4.
			attacker = true
		}
		switch kind {
		case "header", "cookie":
			if !expr.IsToken(arg) {
				return fmt.Sprintf("%s needs a valid name, e.g. %s:x-api-key", kind, kind)
			}
			if kind == "header" {
				if msg := v.managedProblem(arg); msg != "" {
					return msg
				}
			}
		case "query", "jwt_claim":
			if arg == "" || len(arg) > MaxNameArg || expr.HasControl(arg) || !utf8.ValidString(arg) {
				return fmt.Sprintf("%s needs a name of 1 to %d characters, e.g. %s:user_id", kind, MaxNameArg, kind)
			}
		default:
			if hasArg {
				return fmt.Sprintf("%s takes no name", kind)
			}
		}
		switch {
		case kind == "country" && !v.viewer["ip.src.country"], kind == "asnum" && !v.viewer["ip.src.asnum"], kind == "ja4" && !v.viewer["tls.client.ja4"]:
			return fmt.Sprintf("%s has no trusted source configured in this deployment", kind)
		case kind == "locale" && len(v.locales) == 0:
			return "locale is not configured in global.locale"
		case kind == "constant" && len(parts) > 1:
			return "constant can't be combined with other characteristics"
		}
		return ""
	})
	// Clients rotate header, cookie and query values to get fresh buckets.
	if attacker && !partner && !v.siteWideIP {
		v.err(p, "keys only on client-controlled values; add ip or jwt_claim, or add a rule matching all requests keyed on ip")
	}
}

func (v *validator) headerRules() {
	rs := v.c.RequestHeaderRules
	v.ruleCount("request_header_rules", len(rs))
	v.out.HeaderRules = make([]expr.Matcher, len(rs))
	v.out.HeaderValues = make([][]Template, len(rs))
	for i, r := range rs {
		p := fmt.Sprintf("request_header_rules[%d]", i)
		v.ruleID(p, r.ID)
		v.out.HeaderRules[i] = v.expression(p, r.Expression, expr.PhaseRequestHeaders)
		if len(r.Ops) < 1 || len(r.Ops) > MaxListLen {
			v.err(p+".ops", "needs 1 to %d operations", MaxListLen)
		}
		v.out.HeaderValues[i] = make([]Template, len(r.Ops))
		for k, op := range r.Ops {
			v.out.HeaderValues[i][k] = v.op(fmt.Sprintf("%s.ops[%d]", p, k), op)
		}
	}
	// Copy and rename read the forwarded headers, after the forward filter.
	// Which filter applies depends on the request, so any that can drop
	// the source is worth a warning.
	filters := []Forward{v.c.Global.RequestHeaders.Forward}
	for _, r := range rs {
		for _, op := range r.Ops {
			if op.Op == "forward" {
				filters = append(filters, Forward{Mode: op.Mode, Names: op.Names})
			}
		}
	}
	for i, r := range rs {
		for k, op := range r.Ops {
			if (op.Op == "copy" || op.Op == "rename") && slices.ContainsFunc(filters, func(f Forward) bool { return drops(f, op.From) }) {
				v.warn(fmt.Sprintf("request_header_rules[%d].ops[%d].from", i, k), "%s can be dropped by a forward filter first; the copy then removes %s", http.CanonicalHeaderKey(op.From), http.CanonicalHeaderKey(op.To))
			}
		}
	}
}

func drops(f Forward, name string) bool {
	listed := slices.ContainsFunc(f.Names, func(n string) bool { return strings.EqualFold(n, name) })
	return f.Mode == "allowlist" && !listed || f.Mode == "denylist" && listed
}

func (v *validator) op(p string, op HeaderOp) Template {
	// used lists the fields this op takes; any other field set is an error.
	var used []string
	var t Template
	if !slices.Contains(HeaderOps, op.Op) {
		v.err(p+".op", "must be %s", orList(HeaderOps))
		return t
	}
	switch op.Op {
	case "set", "append":
		used = []string{"name", "value"}
		v.target(p+".name", op.Name)
		t = v.headerValue(p+".value", op.Value)
	case "remove":
		used = []string{"name"}
		v.target(p+".name", op.Name)
	case "copy", "rename":
		used = []string{"from", "to"}
		v.target(p+".from", op.From)
		v.target(p+".to", op.To)
	case "forward":
		used = []string{"mode", "names"}
		v.forward(p, Forward{Mode: op.Mode, Names: op.Names})
	}
	set := map[string]bool{"name": op.Name != "", "value": op.Value != "", "from": op.From != "", "to": op.To != "", "mode": op.Mode != "", "names": op.Names != nil}
	for _, f := range slices.Sorted(maps.Keys(set)) {
		if set[f] && !slices.Contains(used, f) {
			v.err(p+"."+f, "doesn't apply to %s", op.Op)
		}
	}
	return t
}

func (v *validator) target(p, name string) {
	if msg := v.targetProblem(name); msg != "" {
		v.err(p, "%s", msg)
	} else if TraceHeader(name) {
		v.warn(p, "%s is trace context: with tracing on, the edge replaces it with its own span's", http.CanonicalHeaderKey(name))
	}
}

// targetProblem rejects invalid header names and those managedProblem rejects.
func (v *validator) targetProblem(name string) string {
	if !expr.IsToken(name) {
		return fmt.Sprintf("%q is not a valid header name; use letters, digits and -, such as x-tenant", name)
	}
	return v.managedProblem(name)
}

// managedProblem rejects header names no rule may read or write, on every
// path that names a header (ops, placeholders, keys, expressions): the edge
// manages, strips or frames them. Reading matters too: a client
// can forge X-Edge-* before the edge replaces it, and source headers can
// carry the ingress secret.
func (v *validator) managedProblem(name string) string {
	l := strings.ToLower(name)
	if reserved[l] || v.sources[l] || strings.HasPrefix(l, "x-edge-") || strings.HasPrefix(l, "x-forwarded-") {
		return fmt.Sprintf("%s is managed by the edge and can't be used in rules", http.CanonicalHeaderKey(name))
	}
	return ""
}

func (v *validator) headerValue(p, s string) Template {
	// CR or LF in a value would split the header; other controls are invalid (RFC 9110 §5.5).
	if len(s) > MaxHeaderValue || expr.HasControl(s) || !utf8.ValidString(s) {
		v.err(p, "must be at most %d bytes of valid UTF-8 with no control characters", MaxHeaderValue)
		return Template{}
	}
	t, err := parseTemplate(s)
	if err != nil {
		v.err(p, "%v", err)
		return t
	}
	for _, ph := range t.Placeholders() {
		if msg := v.placeholderProblem(ph); msg != "" {
			v.err(p, "{{%s}}: %s", ph.Name, msg)
		}
	}
	return t
}

func (v *validator) placeholderProblem(ph Placeholder) string {
	if !slices.Contains(PlaceholderNames, ph.Name) {
		return "unknown placeholder; use " + orList(PlaceholderNames)
	}
	switch ph.Name {
	case "header":
		if !expr.IsToken(ph.Arg) {
			return "needs a header name, e.g. {{header:user-agent}}"
		}
		return v.managedProblem(ph.Arg)
	case "jwt_claim":
		if ph.Arg == "" || len(ph.Arg) > MaxNameArg {
			return "needs a claim name, e.g. {{jwt_claim:sub}}"
		}
		return ""
	}
	switch {
	case ph.Arg != "":
		return "takes no name"
	case ph.Name == "country" && !v.viewer["ip.src.country"]:
		return "country has no trusted source configured in this deployment"
	case ph.Name == "locale" && len(v.locales) == 0:
		return "locale is not configured in global.locale"
	}
	return ""
}

// expression compiles n for phase. It rejects edge-managed headers and
// locales the edge never produces, and warns on the raw URI fields, which
// an encoded path slips past.
func (v *validator) expression(p string, n expr.Node, phase expr.Phase) expr.Matcher {
	available := func(f string) bool { return v.viewer[f] || f == expr.VerifiedBotField && v.d.VerifiedBots }
	env := expr.Env{Phase: phase, ViewerAvailable: available, AllowRegex: v.d.AllowRegex, RelativePaths: v.schema1}
	m, issues := expr.Compile(n, env)
	for _, is := range issues {
		v.errs = append(v.errs, expr.Issue{Path: p + "." + is.Path, Msg: is.Msg})
	}
	// Schema 1 accepted a path without its leading "/"; refusing it now
	// would stop an upgraded edge loading the version it serves.
	if m != nil && v.schema1 {
		env.RelativePaths = false
		for _, is := range expr.Check(n, env) {
			v.warn(p+"."+is.Path, "%s", is.Msg)
		}
	}
	rawWarned := false
	walk(n, false, func(r expr.Node, _ bool) {
		if !rawWarned && (r.Field == "http.request.uri" || r.Field == "http.request.full_uri") {
			v.warn(p+".expression", "%s is not normalized, so an encoded path such as /%%61dmin can slip past it; match on http.request.uri.path or http.request.uri.args instead", r.Field)
			rawWarned = true
		}
		if r.Field == "http.request.headers" && expr.IsToken(r.Key) {
			if msg := v.managedProblem(r.Key); msg != "" {
				v.err(p+".expression", "%s", msg)
			}
		}
		if r.Field == "http.request.version" {
			v.httpVersion(p, r)
			return
		}
		if r.Field != "edge.locale" {
			return
		}
		if len(v.locales) == 0 {
			v.err(p+".expression", "uses edge.locale, but locale is not configured in global.locale")
			return
		}
		if r.Operator != "eq" && r.Operator != "ne" && r.Operator != "in" && r.Operator != "not_in" {
			return
		}
		vals := r.Value.List
		if !r.Value.IsList {
			vals = []string{r.Value.One}
		}
		// "" is the value when locale is off for the request.
		for _, val := range vals {
			if val != "" && !v.locales[val] {
				v.err(p+".expression", "edge.locale is never %q; supported locales are %s", val, strings.Join(v.c.Global.Locale.Supported, ", "))
			}
		}
	})
	if unsatisfiable(expr.Normalize(n)) {
		v.warn(p+".expression", "contains conditions that can never all be true")
	}
	return m
}

// httpVersion warns on an exact HTTP version the edge never produces. A
// literal the edge maps, such as "HTTP/2", is compiled as its mapped form,
// and "" is the value when the version is absent. It is not an error:
// versions published before the edge normalised the version must still load.
func (v *validator) httpVersion(p string, r expr.Node) {
	if r.Operator != "eq" && r.Operator != "ne" && r.Operator != "in" && r.Operator != "not_in" {
		return
	}
	vals := r.Value.List
	if !r.Value.IsList {
		vals = []string{r.Value.One}
	}
	for _, val := range vals {
		if val != "" && expr.HTTPVersion(val) == "" {
			v.warn(p+".expression", "http.request.version is never %q; the edge writes it as %s", val, strings.Join(httpVersions, ", "))
		}
	}
}

// httpVersions are the values the edge normalises every viewer source to.
var httpVersions = []string{"1.0", "1.1", "2.0", "3.0"}

func (v *validator) spoofableExclusion(p string, n expr.Node) {
	warned := false
	walk(n, false, func(r expr.Node, neg bool) {
		op, _ := expr.LookupOp(r.Operator)
		if !warned && clientControlled[r.Field] && neg != (op.Negates != "") {
			v.warn(p+".expression", "excludes traffic using client-controlled %s; clients can set it to skip this rule. Exclude by ip.src or a verified claim", r.Field)
			warned = true
		}
	})
}

// spoofableLogBlock warns on a block: log rule, after a block: block rule,
// that matches on a client-controlled field: a later rule's block setting
// wins, so a client that sets the value turns the earlier refusal into a log.
func (v *validator) spoofableLogBlock(p string, n expr.Node) {
	warned := false
	walk(n, false, func(r expr.Node, neg bool) {
		op, _ := expr.LookupOp(r.Operator)
		if !warned && clientControlled[r.Field] && neg == (op.Negates != "") {
			v.warn(p+".expression", "sets block to log for requests matching client-controlled %s; clients can set it to turn an earlier block rule off. Match by ip.src or a verified claim", r.Field)
			warned = true
		}
	})
}

// walk calls f for every rule in n with whether an odd number of group
// negations encloses it.
func walk(n expr.Node, neg bool, f func(r expr.Node, neg bool)) {
	if !n.IsGroup() {
		f(n, neg)
		return
	}
	for _, c := range n.Rules {
		walk(c, neg != n.Not, f)
	}
}

// unsatisfiable finds an "and" group requiring one single-valued field to
// equal two different values.
func unsatisfiable(n expr.Node) bool {
	if !n.IsGroup() {
		return false
	}
	if n.Combinator == "and" && !n.Not {
		seen := map[string]string{}
		for _, r := range n.Rules {
			if r.IsGroup() || r.Operator != "eq" || r.Key != "" {
				continue
			}
			if prev, ok := seen[r.Field]; ok && prev != r.Value.One {
				return true
			}
			seen[r.Field] = r.Value.One
		}
	}
	return slices.ContainsFunc(n.Rules, unsatisfiable)
}

// Shared field checks.

func (v *validator) ruleCount(p string, n int) {
	if n > MaxRulesPerPhase {
		v.err(p, "has %d rules; at most %d are allowed", n, MaxRulesPerPhase)
	}
}

// ruleID requires IDs unique across all phases: rate-limit keys and stats use them.
func (v *validator) ruleID(p, id string) {
	v.name(p+".id", id)
	if v.ruleIDs[id] {
		v.err(p+".id", "duplicate rule id %q", id)
	}
	v.ruleIDs[id] = true
}

func (v *validator) name(p, s string) {
	if !isName(s) {
		v.err(p, "%q must be 1 to %d lowercase letters, digits, - or _, starting with a letter or digit", s, MaxNameLen)
	}
}

func (v *validator) count(p string, n int64) {
	if n < 1 || n > MaxCount {
		v.err(p, "must be 1 to %s", thousands(MaxCount))
	}
}

// period requires whole seconds: rate-limit keys and windows use seconds.
func (v *validator) period(p string, d Duration, maxD time.Duration) {
	t := time.Duration(d)
	if t < time.Second || t > maxD || t%time.Second != 0 {
		v.err(p, "must be whole seconds from 1s to %s", maxD)
	}
}

func (v *validator) timeout(p string, d Duration) {
	if t := time.Duration(d); t < time.Second || t > MaxServerTimeout {
		v.err(p, "must be from 1s to %s", MaxServerTimeout)
	}
}

// list checks length and duplicates, then each item. foldCase makes "X-A"
// and "x-a" duplicates, for header names.
// Case handling for list and setOf: header names compare case-insensitively.
const (
	caseSensitive = false
	foldCase      = true
)

func (v *validator) list(p string, items []string, fold bool, problem func(string) string) {
	if len(items) > MaxListLen {
		v.err(p, "has %d items; at most %d are allowed", len(items), MaxListLen)
	}
	seen := map[string]bool{}
	for i, s := range items {
		ip := fmt.Sprintf("%s[%d]", p, i)
		k := s
		if fold {
			k = strings.ToLower(s)
		}
		if seen[k] {
			v.err(ip, "duplicate %q", s)
		}
		seen[k] = true
		if msg := problem(s); msg != "" {
			v.err(ip, "%s", msg)
		}
	}
}

func setOf(items []string, fold bool) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		if fold {
			s = strings.ToLower(s)
		}
		m[s] = true
	}
	return m
}

func isName(s string) bool {
	if s == "" || len(s) > MaxNameLen || s[0] == '-' || s[0] == '_' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte("abcdefghijklmnopqrstuvwxyz0123456789-_", s[i]) < 0 {
			return false
		}
	}
	return true
}

// thousands writes a positive n with comma separators, as the admin UI
// shows numbers, so a limit reads 1,000,000,000 rather than 1000000000.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// distinct checks the distinct algorithm's options. Its state is a bitmap
// per subject in Valkey: a local copy per subject would outgrow the bounded
// store, so fail_mode local is refused.
func (v *validator) distinct(p string, r RateLimitRule) {
	if r.Algorithm != "distinct" {
		if r.DistinctOf != "" {
			v.err(p+".distinct_of", "applies only to the distinct algorithm")
		}
		return
	}
	if r.Limit > MaxDistinct {
		v.err(p+".limit", "must be at most %s for distinct: the estimate drifts beyond it", thousands(MaxDistinct))
	}
	if r.FailMode == "local" {
		v.err(p+".fail_mode", "local can't be used with distinct; use open or closed")
	}
	kind, arg, hasArg := strings.Cut(r.DistinctOf, ":")
	switch {
	case !slices.Contains(DistinctOfKinds, kind):
		v.err(p+".distinct_of", "must be path, query:<name>, ip, asnum or ja4")
	case kind == "query":
		if arg == "" || len(arg) > MaxNameArg || expr.HasControl(arg) || !utf8.ValidString(arg) {
			v.err(p+".distinct_of", "query needs a name of 1 to %d characters, e.g. query:id", MaxNameArg)
		}
	case hasArg:
		v.err(p+".distinct_of", "%s takes no name", kind)
	case kind == "asnum" && !v.viewer["ip.src.asnum"], kind == "ja4" && !v.viewer["tls.client.ja4"]:
		v.err(p+".distinct_of", "%s has no trusted source configured in this deployment", kind)
	}
}

// countStatuses checks a count rule's statuses. A 5xx is usually the
// upstream's fault: counting it would block every active client during an
// outage and lock real users out after recovery.
func (v *validator) countStatuses(p string, r RateLimitRule) StatusSet {
	var set StatusSet
	if r.Algorithm == "distinct" {
		v.err(p+".count_statuses", "can't be used with the distinct algorithm")
	}
	if r.FailMode != "open" {
		v.warn(p+".fail_mode", "has no effect: a rule with count_statuses counts in each edge's memory and never calls Valkey")
	}
	v.list(p+".count_statuses", r.CountStatuses, caseSensitive, func(s string) string {
		lo, hi, ok := statusRange(s)
		switch {
		case !ok:
			return `must be a status from 100 to 499 or a class from 1xx to 4xx, such as "404" or "4xx"`
		case lo >= 500:
			return "5xx can't be counted: a 5xx is usually the upstream's fault, and counting it would lock clients out after an outage"
		}
		set.add(lo, hi)
		return ""
	})
	return set
}

// statusRange reads "404" or "4xx" as the statuses it names.
func statusRange(s string) (lo, hi int, ok bool) {
	if len(s) != 3 || s[0] < '1' || s[0] > '5' {
		return 0, 0, false
	}
	if s[1:] == "xx" {
		lo = int(s[0]-'0') * 100
		return lo, lo + 99, true
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, false
	}
	return n, n, true
}

// ReadsField reports whether any rule of c reads field. Admin ships the
// verified crawler ranges only to a snapshot whose configs read them.
func ReadsField(c *Config, field string) bool {
	found := false
	f := func(r expr.Node, _ bool) { found = found || r.Field == field }
	for _, r := range c.ConfigRules {
		walk(r.Expression, false, f)
	}
	for _, r := range c.RateLimitRules {
		walk(r.Expression, false, f)
	}
	for _, r := range c.RequestHeaderRules {
		walk(r.Expression, false, f)
	}
	return found
}
