// Package admin is the admin service: identity, sessions, permissions,
// audit, config publishing and the endpoints edges call.
package admin

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/envparse"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/tracing"
)

// Config is admin's deployment config.
type Config struct {
	ListenAddr string
	// InternalAddr serves /metrics, unauthenticated: never expose it publicly.
	InternalAddr string
	Tracing      tracing.Config
	DatabaseURL  string // the runtime role
	Audit        admindb.AuditKeys
	// Deployment is the edges' deployment, read from the same variables.
	Deployment       snapshot.Deployment
	Blocklist        map[string]bool // lowercased, from PASSWORD_BLOCKLIST_PATH
	JWKSAllowedHosts []string
	// VerifiedBotSources are the crawler range lists admin fetches, in
	// Google's JSON format. Deployment config, like JWKS_ALLOWED_HOSTS: no
	// admin user can point admin at another URL.
	VerifiedBotSources []string
	SessionIdle        time.Duration
	SessionMaxAge      time.Duration
	// TrustedProxies are admin's own HTTPS proxies (ADMIN_TRUSTED_PROXIES),
	// whose X-Forwarded-For names the client for the login throttle and audit.
	TrustedProxies []netip.Prefix
	// Replica names this admin instance (INSTANCE, default the hostname).
	Replica string
	// BootstrapUser and BootstrapPassword create the first admin when no user
	// exists, so an automated install needs no shell in the pod.
	BootstrapUser     string
	BootstrapPassword string
	// BootstrapPublish publishes the starter policy when no version has ever
	// been published, so edges on a fresh install load a policy and serve.
	BootstrapPublish bool
	// EdgeToken is the hash of an edge token defined by the deployment
	// (EDGE_SERVICE_TOKEN_FILE), the same file the edges read. It is accepted
	// alongside tokens created in admin and rotates with the deployment.
	EdgeToken []byte
	// LogToken is the hash of the log shipper's token (LOG_INGEST_TOKEN_FILE).
	// It may only post access logs.
	LogToken []byte
	// AutopilotToken is the hash of the autopilot runner's token
	// (AUTOPILOT_TOKEN_FILE). It holds only autopilot.agent.
	AutopilotToken []byte
	// AlertmanagerURL is where notifications send anomalies
	// (ALERTMANAGER_URL). Empty records them in admin only.
	AlertmanagerURL string
	// LogSearchURL is the deployment's log store search, a URL template
	// the UI fills to link counts to their lines (LOG_SEARCH_URL). Empty
	// shows no links.
	LogSearchURL string
	// Prometheus, Grafana and Datadog are the read-only connectors the
	// autopilot's tools query. Deployment config, so admin calls them
	// without the SSRF guard. An empty URL or API leaves its tools out.
	Prometheus Connector
	Grafana    Connector
	Datadog    DatadogConnector
	// MetricsLinkURL is a template for links to a Prometheus query a
	// person can open, with {query}, {from_ms} and {to_ms}.
	MetricsLinkURL string
	// UI is the built admin UI, or nil or empty to serve the API only.
	UI fs.FS
}

// Connector is an HTTP API and its bearer token, empty for none.
type Connector struct{ URL, Token string }

// DatadogConnector is a Datadog site: its API base URL and keys.
type DatadogConnector struct{ API, APIKey, AppKey string }

// ddSites are Datadog's site parameters, from
// https://docs.datadoghq.com/getting_started/site/
var ddSites = []string{"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com", "ap2.datadoghq.com",
	"uk1.datadoghq.com", "ddog-gov.com", "us2.ddog-gov.com"}

// minEdgeToken matches the 32 random bytes of tokens admin creates.
const minEdgeToken = 32

// minAuditKey is HMAC-SHA256's block-independent recommendation: a key at
// least as long as the hash output (RFC 2104 §3).
const minAuditKey = 32

// LoadConfig reads admin's config and reports every problem at once.
func LoadConfig(getenv func(string) string) (*Config, error) {
	p := &envparse.Parser{Get: getenv}
	c := &Config{
		ListenAddr:         p.Str("LISTEN_ADDR", ":8081"),
		InternalAddr:       p.Str("ADMIN_INTERNAL_ADDR", ":9091"),
		DatabaseURL:        getenv("DATABASE_URL"),
		SessionIdle:        p.Duration("SESSION_IDLE_TIMEOUT", 30*time.Minute),
		SessionMaxAge:      p.Duration("SESSION_MAX_AGE", 12*time.Hour),
		Blocklist:          map[string]bool{},
		Replica:            getenv("INSTANCE"),
		JWKSAllowedHosts:   p.List("JWKS_ALLOWED_HOSTS"),
		VerifiedBotSources: p.List("VERIFIED_BOT_SOURCES"),
		TrustedProxies:     p.Prefixes("ADMIN_TRUSTED_PROXIES"),
		BootstrapUser:      strings.ToLower(getenv("BOOTSTRAP_ADMIN_USERNAME")),
		BootstrapPublish:   p.Bool("BOOTSTRAP_PUBLISH_DEFAULT"),
		Tracing:            tracing.Load(p, "edge-proxy-admin"),
		AlertmanagerURL:    getenv("ALERTMANAGER_URL"),
		LogSearchURL:       getenv("LOG_SEARCH_URL"),
	}
	if u, err := url.Parse(c.AlertmanagerURL); c.AlertmanagerURL != "" && (err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.User != nil) {
		p.Fail("ALERTMANAGER_URL", "must be an http or https URL with no query or credentials, such as http://alertmanager:9093")
	}
	// Every signed-in user reads the template, so it must not carry credentials.
	if u, err := url.Parse(c.LogSearchURL); c.LogSearchURL != "" && (err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil) {
		p.Fail("LOG_SEARCH_URL", "must be an http or https URL with no credentials, such as https://logs.example.com/search?q=status:{status}&from={from}&to={to}")
	}
	if len(c.VerifiedBotSources) > snapshot.MaxBotSources {
		p.Fail("VERIFIED_BOT_SOURCES", fmt.Sprintf("lists %d URLs; at most %d are allowed", len(c.VerifiedBotSources), snapshot.MaxBotSources))
	}
	seen := map[string]bool{}
	for _, s := range c.VerifiedBotSources {
		// No query: the URL is logged and audited, and a query could hold a secret.
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(s) > snapshot.MaxBotSourceLen || seen[s] {
			p.Fail("VERIFIED_BOT_SOURCES", fmt.Sprintf("each must be a unique https URL of at most %d characters with no query, credentials or fragment", snapshot.MaxBotSourceLen))
			break
		}
		seen[s] = true
	}
	if c.Replica == "" {
		c.Replica, _ = os.Hostname()
	}
	if c.DatabaseURL == "" {
		p.Fail("DATABASE_URL", "is required")
	}
	c.Audit = admindb.AuditKeys{Current: getenv("AUDIT_HMAC_KEY_ID"), Keys: map[string][]byte{}}
	if c.Audit.Current == "" {
		p.Fail("AUDIT_HMAC_KEY_ID", "is required")
	}
	// AUDIT_HMAC_PREVIOUS_KEYS keeps rotated keys (id=base64,..., oldest
	// first) so older rows still verify; AUDIT_HMAC_KEY is the newest.
	pairs := append(p.List("AUDIT_HMAC_PREVIOUS_KEYS"), c.Audit.Current+"="+getenv("AUDIT_HMAC_KEY"))
	for _, pair := range pairs {
		id, b64, _ := strings.Cut(pair, "=")
		k, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(k) < minAuditKey || id == "" {
			p.Fail("AUDIT_HMAC_KEY", fmt.Sprintf("key %q must be base64 of at least %d bytes", id, minAuditKey))
			continue
		}
		c.Audit.Keys[id] = k
		c.Audit.Order = append(c.Audit.Order, id)
	}
	if path := getenv("PASSWORD_BLOCKLIST_PATH"); path != "" {
		b, err := os.ReadFile(path) //nolint:gosec // an operator-chosen path
		if err != nil {
			p.Fail("PASSWORD_BLOCKLIST_PATH", err.Error())
		}
		for l := range strings.SplitSeq(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				c.Blocklist[strings.ToLower(normalize(l))] = true
			}
		}
	}
	loadBootstrap(p, getenv, c)
	loadConnectors(p, getenv, c)
	d, err := edge.LoadDeployment(getenv)
	// Without sources the field is always false, so a rule reading it is refused.
	d.VerifiedBots = len(c.VerifiedBotSources) > 0
	c.Deployment = d
	if err = errors.Join(p.Err(), err); err != nil {
		return nil, err
	}
	return c, nil
}

// loadBootstrap reads the first-admin and edge-token settings. Files rather
// than variables keep the secrets out of the process environment.
func loadBootstrap(p *envparse.Parser, getenv func(string) string, c *Config) {
	if path := getenv("BOOTSTRAP_ADMIN_PASSWORD_FILE"); path != "" {
		if b, err := os.ReadFile(path); err != nil { //nolint:gosec // an operator-chosen path
			p.Fail("BOOTSTRAP_ADMIN_PASSWORD_FILE", "cannot read the file")
		} else {
			// The first line, as create-user reads stdin.
			line, _, _ := strings.Cut(string(b), "\n")
			c.BootstrapPassword = strings.TrimRight(line, "\r")
		}
	}
	switch {
	case (c.BootstrapUser == "") != (getenv("BOOTSTRAP_ADMIN_PASSWORD_FILE") == ""):
		p.Fail("BOOTSTRAP_ADMIN_USERNAME", "set it together with BOOTSTRAP_ADMIN_PASSWORD_FILE")
	case c.BootstrapUser != "":
		if why := passwordProblem(c.BootstrapPassword, c.BootstrapUser, c.Blocklist); why != "" {
			p.Fail("BOOTSTRAP_ADMIN_PASSWORD_FILE", "password "+why)
		}
	}
	c.EdgeToken = readTokenFile(p, getenv, "EDGE_SERVICE_TOKEN_FILE")
	c.LogToken = readTokenFile(p, getenv, "LOG_INGEST_TOKEN_FILE")
	// The edge token is checked first, so a shared token would let the
	// shipper fetch snapshots and post stats.
	if c.LogToken != nil && bytes.Equal(c.EdgeToken, c.LogToken) {
		p.Fail("LOG_INGEST_TOKEN_FILE", "must hold a different token from EDGE_SERVICE_TOKEN_FILE")
	}
	// Checked after both, so a shared token would leave the runner with the
	// edge's or the shipper's access instead of its own.
	c.AutopilotToken = readTokenFile(p, getenv, "AUTOPILOT_TOKEN_FILE")
	if c.AutopilotToken != nil && bytes.Equal(c.AutopilotToken, c.EdgeToken) {
		p.Fail("AUTOPILOT_TOKEN_FILE", "must hold a different token from EDGE_SERVICE_TOKEN_FILE")
	}
	if c.AutopilotToken != nil && bytes.Equal(c.AutopilotToken, c.LogToken) {
		p.Fail("AUTOPILOT_TOKEN_FILE", "must hold a different token from LOG_INGEST_TOKEN_FILE")
	}
}

// readTokenFile returns the hash of the token in the file name points to,
// or nil when name is unset.
func readTokenFile(p *envparse.Parser, getenv func(string) string, name string) []byte {
	path := getenv(name)
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // an operator-chosen path
	switch token := strings.TrimSpace(string(b)); {
	case err != nil:
		p.Fail(name, "cannot read the file")
	case len(token) < minEdgeToken:
		p.Fail(name, fmt.Sprintf("must hold a token of at least %d characters", minEdgeToken))
	default:
		return hashSecret(token)
	}
	return nil
}

// loadConnectors reads the metrics connectors. Tokens come from files, as
// the other secrets do, and no message ever holds one.
func loadConnectors(p *envparse.Parser, getenv func(string) string, c *Config) {
	c.Prometheus.URL = connectorURL(p, getenv, "PROMETHEUS_URL")
	c.Prometheus.Token = readSecretFile(p, getenv, "PROMETHEUS_TOKEN_FILE")
	if getenv("PROMETHEUS_TOKEN_FILE") != "" && getenv("PROMETHEUS_URL") == "" {
		p.Fail("PROMETHEUS_TOKEN_FILE", "set it with PROMETHEUS_URL")
	}
	c.Grafana.URL = connectorURL(p, getenv, "GRAFANA_URL")
	c.Grafana.Token = readSecretFile(p, getenv, "GRAFANA_TOKEN_FILE")
	if (getenv("GRAFANA_URL") == "") != (getenv("GRAFANA_TOKEN_FILE") == "") {
		p.Fail("GRAFANA_TOKEN_FILE", "set it together with GRAFANA_URL")
	}
	site := getenv("DATADOG_SITE")
	apiKey, appKey := readSecretFile(p, getenv, "DATADOG_API_KEY_FILE"), readSecretFile(p, getenv, "DATADOG_APP_KEY_FILE")
	switch {
	case site == "":
		for _, name := range []string{"DATADOG_API_KEY_FILE", "DATADOG_APP_KEY_FILE"} {
			if getenv(name) != "" {
				p.Fail(name, "set it with DATADOG_SITE")
			}
		}
	case !slices.Contains(ddSites, site):
		p.Fail("DATADOG_SITE", "must be one of "+strings.Join(ddSites, ", "))
	default:
		for _, name := range []string{"DATADOG_API_KEY_FILE", "DATADOG_APP_KEY_FILE"} {
			if getenv(name) == "" {
				p.Fail(name, "is required with DATADOG_SITE")
			}
		}
		c.Datadog = DatadogConnector{API: "https://api." + site, APIKey: apiKey, AppKey: appKey}
	}
	// Every signed-in user reads the links, so the template carries no credentials.
	c.MetricsLinkURL = getenv("METRICS_LINK_URL")
	if u, err := url.Parse(c.MetricsLinkURL); c.MetricsLinkURL != "" &&
		(err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || !strings.Contains(c.MetricsLinkURL, "{query}")) {
		p.Fail("METRICS_LINK_URL", "must be an http or https URL with no credentials that contains {query}, such as https://prometheus.example.com/query?g0.expr={query}&g0.tab=graph")
	}
	if c.MetricsLinkURL != "" && getenv("PROMETHEUS_URL") == "" {
		p.Fail("METRICS_LINK_URL", "set it with PROMETHEUS_URL")
	}
}

// connectorURL is the base URL in name with no trailing slash. A path is
// allowed, for a Prometheus behind a prefix such as Grafana Cloud's
// /api/prom; credentials, a query or a fragment are not, since the URL is
// logged and a token belongs in the token file.
func connectorURL(p *envparse.Parser, getenv func(string) string, name string) string {
	v := getenv(name)
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		p.Fail(name, "must be an http or https URL with a host and no credentials, query or fragment, such as http://prometheus:9090")
		return ""
	}
	return strings.TrimSuffix(v, "/")
}

// readSecretFile is the trimmed token in the file name points to, or ""
// when name is unset. A token is printable ASCII with no spaces, so it
// can go in a header as it is.
func readSecretFile(p *envparse.Parser, getenv func(string) string, name string) string {
	path := getenv(name)
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path) //nolint:gosec // an operator-chosen path
	token := strings.TrimSpace(string(b))
	switch {
	case err != nil:
		p.Fail(name, "cannot read the file")
	case token == "":
		p.Fail(name, "the file is empty")
	case strings.ContainsFunc(token, func(r rune) bool { return r < '!' || r > '~' }):
		p.Fail(name, "must hold one token of printable ASCII with no spaces")
	default:
		return token
	}
	return ""
}
