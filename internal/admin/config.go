// Package admin is the admin service: identity, sessions, permissions,
// audit, config publishing and the endpoints edges call.
package admin

import (
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
	// UI is the built admin UI, or nil or empty to serve the API only.
	UI fs.FS
}

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
	d, err := edge.LoadDeployment(getenv)
	c.Deployment = d
	if err = errors.Join(p.Err(), err); err != nil {
		return nil, err
	}
	return c, nil
}
