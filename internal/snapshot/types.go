// Package snapshot defines the published policy, decodes it
// strictly, and validates and compiles it. Admin and edge share this package,
// so a config admin accepts is exactly a config the edge can run.
package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// Envelope is what GET /v1/snapshot returns, and the cache and bootstrap file format.
type Envelope struct {
	ExportedAt time.Time `json:"exported_at"`
	Active     *Config   `json:"active"`
	// Candidate is present only during a canary.
	Candidate       *Config      `json:"candidate,omitempty"`
	CanaryPercent   float64      `json:"canary_percent,omitempty"`
	CanaryExpiresAt time.Time    `json:"canary_expires_at,omitzero"`
	FleetSize       int          `json:"fleet_size"`
	Keys            []IssuerKeys `json:"keys,omitempty"`
	// VerifiedBots are the crawler ranges admin fetched, present only while
	// the active or candidate config reads client.verified_bot: schema 3
	// edges decode strictly and would reject the field.
	VerifiedBots []BotSet `json:"verified_bots,omitempty"`
}

// BotSet is the latest good range list from one VERIFIED_BOT_SOURCES URL.
type BotSet struct {
	Source   string   `json:"source"`
	Prefixes []string `json:"prefixes"`
}

// IssuerKeys is the latest good JWKS admin fetched from one issuer's JWKS
// URL. Keys belong to the URL: a canary that moves an issuer to a new URL
// carries one entry for each, so the active version never gets the new
// IdP's keys. The edge keeps whichever copy has the newest FetchedAt.
type IssuerKeys struct {
	IssuerID  string          `json:"issuer_id"`
	JWKSURL   string          `json:"jwks_url"`
	FetchedAt time.Time       `json:"fetched_at"`
	JWKS      json.RawMessage `json:"jwks"`
}

// Config is one policy version.
type Config struct {
	Schema             int             `json:"schema"`
	Version            int64           `json:"version"`
	KillSwitch         KillSwitch      `json:"kill_switch"`
	Global             Global          `json:"global"`
	Auth               Auth            `json:"auth"`
	ConfigRules        []ConfigRule    `json:"config_rules"`
	RateLimitRules     []RateLimitRule `json:"rate_limit_rules"`
	RequestHeaderRules []HeaderRule    `json:"request_header_rules"`
}

// KillSwitch disables enforcement without editing rules.
type KillSwitch struct {
	RateLimit bool `json:"rate_limit"`
	Auth      bool `json:"auth"`
	// Block makes every block setting act as log. Added in schema 4.
	Block bool `json:"block,omitempty"`
}

// Global holds settings that apply to every request unless a rule overrides them.
type Global struct {
	Backstop       Backstop              `json:"backstop"`
	Defaults       Defaults              `json:"defaults"`
	CORSPolicies   map[string]CORSPolicy `json:"cors_policies"`
	Responses      map[string]Response   `json:"responses"`
	Locale         Locale                `json:"locale"`
	RequestHeaders RequestHeaders        `json:"request_headers"`
	// MaxInflight lowers every edge's cap on concurrent ordinary requests;
	// 0 leaves each edge's own. It can't raise the cap: that comes from the
	// edge's memory. Added in schema 3, omitted when unset.
	MaxInflight int `json:"max_inflight,omitempty"`
}

// Backstop is the per-replica, per-IP token bucket.
type Backstop struct {
	Limit      int64    `json:"limit"`
	Period     Duration `json:"period"`
	Burst      int64    `json:"burst"`
	MaxEntries int      `json:"max_entries"`
}

// Defaults apply when no config rule sets a value.
type Defaults struct {
	Locale          bool     `json:"locale"`
	BodyLimit       int64    `json:"body_limit"`
	BodyReadTimeout Duration `json:"body_read_timeout"`
	UpstreamTimeout Duration `json:"upstream_timeout"`
	// Responses maps every response kind to a template name.
	Responses map[string]string `json:"responses"`
}

// CORSPolicy is a named CORS policy that config rules select.
type CORSPolicy struct {
	Origins        []string `json:"origins"`
	Methods        []string `json:"methods"`
	RequestHeaders []string `json:"request_headers"`
	ExposedHeaders []string `json:"exposed_headers"`
	Credentials    bool     `json:"credentials"`
	MaxAge         Duration `json:"max_age"`
}

// Response is a template for an edge-generated response.
type Response struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

// Locale configures Accept-Language matching.
type Locale struct {
	Supported    []string `json:"supported"`
	Default      string   `json:"default"`
	OutputHeader string   `json:"output_header"`
}

// RequestHeaders holds the default handling of client request headers.
type RequestHeaders struct {
	Forward Forward `json:"forward"`
}

// Forward filters which client headers reach the upstream.
type Forward struct {
	Mode  string   `json:"mode"` // all | allowlist | denylist
	Names []string `json:"names,omitempty"`
}

// Auth lists the trusted JWT issuers. DefaultAccepted names the issuers a
// rule accepts when it lists none of its own.
type Auth struct {
	Issuers         []Issuer `json:"issuers"`
	DefaultAccepted []string `json:"default_accepted"`
}

// Issuer is one JWT issuer the edge verifies tokens from.
type Issuer struct {
	ID        string   `json:"id"`
	Issuer    string   `json:"issuer"`
	Audiences []string `json:"audiences"`
	JWKSURL   string   `json:"jwks_url"`
	Algorithm string   `json:"algorithm"`
}

// ConfigRule sets request settings when its expression matches.
type ConfigRule struct {
	ID         string    `json:"id"`
	Expression expr.Node `json:"expression"`
	Settings   Settings  `json:"settings"`
}

// Settings are the config-phase settings. Nil means "not set by this rule".
type Settings struct {
	Auth *AuthSetting `json:"auth,omitempty"`
	// CORSPolicy names a policy; "" explicitly turns CORS off.
	CORSPolicy       *string           `json:"cors_policy,omitempty"`
	Locale           *bool             `json:"locale,omitempty"`
	Responses        map[string]string `json:"responses,omitempty"`
	BodyLimit        *int64            `json:"body_limit,omitempty"`
	UpstreamTimeout  *Duration         `json:"upstream_timeout,omitempty"`
	RateLimitHeaders *bool             `json:"ratelimit_headers,omitempty"`
	// Block is block or log: answer 403 forbidden, or only log would_block.
	Block *string `json:"block,omitempty"`
}

// AuthSetting is a config rule's JWT requirement and the issuers it accepts.
type AuthSetting struct {
	Mode     string   `json:"mode"` // none | optional | required
	Accepted []string `json:"accepted,omitempty"`
}

// RateLimitRule counts and possibly blocks matching requests.
type RateLimitRule struct {
	ID           string    `json:"id"`
	Expression   expr.Node `json:"expression"`
	Algorithm    string    `json:"algorithm"`
	Limit        int64     `json:"limit"`
	Period       Duration  `json:"period"`
	Burst        int64     `json:"burst,omitempty"`
	Key          []string  `json:"key"`
	OnMissingKey string    `json:"on_missing_key"`
	Action       string    `json:"action"`
	Penalty      Duration  `json:"penalty,omitempty"`
	FailMode     string    `json:"fail_mode"`
	// CountStatuses makes the rule count upstream responses with these
	// statuses or classes, such as "404" or "4xx", in each replica's memory.
	CountStatuses []string `json:"count_statuses,omitempty"`
	// DistinctOf is what the distinct algorithm counts distinct values of:
	// path, query:<name>, ip, asnum or ja4.
	DistinctOf string `json:"distinct_of,omitempty"`
	// ExpiresAt is when the rule stops running, in RFC 3339; zero means
	// never. Edges compare it with their own clock.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// HeaderRule edits upstream request headers when its expression matches.
type HeaderRule struct {
	ID         string     `json:"id"`
	Expression expr.Node  `json:"expression"`
	Ops        []HeaderOp `json:"ops"`
}

// HeaderOp is one operation. Which fields apply depends on Op:
// set/append: Name, Value. remove: Name. copy/rename: From, To.
// forward: Mode, Names.
type HeaderOp struct {
	Op    string   `json:"op"`
	Name  string   `json:"name,omitempty"`
	Value string   `json:"value,omitempty"`
	From  string   `json:"from,omitempty"`
	To    string   `json:"to,omitempty"`
	Mode  string   `json:"mode,omitempty"`
	Names []string `json:"names,omitempty"`
}

// Duration is a time.Duration written as a Go duration string ("1m30s").
type Duration time.Duration

// MarshalJSON writes d as a Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON parses a Go duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`duration must be a string such as "30s" or "5m"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}
