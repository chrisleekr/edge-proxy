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
	"os"
	"strings"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/edge"
	"github.com/chrisleekr/edge-proxy/internal/envparse"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// Config is admin's deployment config.
type Config struct {
	ListenAddr  string
	DatabaseURL string // the runtime role
	Audit       admindb.AuditKeys
	// Deployment is the edges' deployment, read from the same variables.
	Deployment       snapshot.Deployment
	Blocklist        map[string]bool // lowercased, from PASSWORD_BLOCKLIST_PATH
	JWKSAllowedHosts []string
	SessionIdle      time.Duration
	SessionMaxAge    time.Duration
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
	// UI is the built admin UI, or nil or empty to serve the API only.
	UI fs.FS
}

// minEdgeToken matches the 32 random bytes of tokens admin creates.
const minEdgeToken = 32

// minAuditKey is HMAC-SHA256's block-independent recommendation: a key at
// least as long as the hash output (RFC 2104 §3).
const minAuditKey = 32

// LoadConfig reads admin's config and reports every problem at once.
func LoadConfig(getenv func(string) string) (*Config, error) {
	p := &envparse.Parser{Get: getenv}
	c := &Config{
		ListenAddr:       p.Str("LISTEN_ADDR", ":8081"),
		DatabaseURL:      getenv("DATABASE_URL"),
		SessionIdle:      p.Duration("SESSION_IDLE_TIMEOUT", 30*time.Minute),
		SessionMaxAge:    p.Duration("SESSION_MAX_AGE", 12*time.Hour),
		Blocklist:        map[string]bool{},
		Replica:          getenv("INSTANCE"),
		JWKSAllowedHosts: p.List("JWKS_ALLOWED_HOSTS"),
		TrustedProxies:   p.Prefixes("ADMIN_TRUSTED_PROXIES"),
		BootstrapUser:    strings.ToLower(getenv("BOOTSTRAP_ADMIN_USERNAME")),
		BootstrapPublish: p.Bool("BOOTSTRAP_PUBLISH_DEFAULT"),
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
	d, err := edge.LoadDeployment(getenv)
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
