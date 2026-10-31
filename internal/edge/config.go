// Package edge is the edge proxy: the request pipeline, client
// identity, snapshot loading and the HTTP servers.
package edge

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/chrisleekr/edge-proxy/internal/envparse"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/tracing"
)

// memoryLimit is GOMEMLIMIT, or math.MaxInt64 when it isn't set. A variable
// so tests can choose it.
var memoryLimit = func() int64 { return debug.SetMemoryLimit(-1) }

// defaultMaxInflight sizes MAX_INFLIGHT to the memory limit. A load test put
// about 100 KiB on each in-flight request, kernel socket buffers included;
// 256 KiB each leaves the rest for streams, the baseline and GC headroom.
// Without GOMEMLIMIT the edge can't tell, and keeps the old fixed 10,000.
func defaultMaxInflight(limit int64) int {
	return int(min(max(limit/(256<<10), 1), 10_000))
}

// Config is the deployment config, read once from the environment. Admin
// users can't change any of it (CLAUDE.md, "Trust comes only from deployment config").
type Config struct {
	ListenAddr, InternalAddr string

	ClientIP ClientIPSource
	// TrustedProxies are the peers whose client-IP and viewer headers are honored.
	TrustedProxies []netip.Prefix
	// Viewer maps a viewer field (e.g. "ip.src.country") to its header.
	Viewer map[string]string
	// IngressSecretHeader, when set, must carry one of IngressSecrets.
	IngressSecretHeader string
	IngressSecrets      []string

	// Upstream is the load balancer or gateway every request is forwarded to.
	// It routes by Host; the edge never chooses where a request goes.
	Upstream *url.URL

	AdminURL            *url.URL
	ServiceToken        string
	CachePath           string
	BootstrapPath       string
	BootstrapMaxAge     time.Duration
	BootstrapAllowStale bool
	PollInterval        time.Duration

	MaxInflight    int
	MaxStreams     int
	MaxIdleConns   int
	MaxHeaderBytes int

	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	DialTimeout       time.Duration
	DrainDelay        time.Duration
	ShutdownTimeout   time.Duration
	StatsInterval     time.Duration

	// Valkey is nil when VALKEY_URL is unset: every rate-limit call then
	// takes its rule's fail_mode.
	Valkey        *valkey.ClientOption
	ValkeyTimeout time.Duration
	// ExpectedReplicas divides limits for fail_mode local when the snapshot
	// carries no fleet size.
	ExpectedReplicas int
	// TokenCacheSize bounds the verified-token cache.
	TokenCacheSize int
	// JWKSAllowedHosts may resolve to private addresses.
	JWKSAllowedHosts []string

	AllowRegex    bool
	LogSampleRate float64
	Instance      string

	Tracing tracing.Config
}

// ClientIPSource says where the client IP comes from.
type ClientIPSource struct {
	// Kind is cloudfront, cloudflare, gcp, header, xff or remote_addr.
	Kind string
	// Header and WithPort apply to every kind but xff and remote_addr.
	Header   string
	WithPort bool
}

// presets fill the client-IP header and viewer headers for known CDNs.
var presets = map[string]struct {
	ip     ClientIPSource
	viewer map[string]string
}{
	"cloudfront": {
		ClientIPSource{Kind: "cloudfront", Header: "CloudFront-Viewer-Address", WithPort: true},
		map[string]string{
			"ip.src.country":       "CloudFront-Viewer-Country",
			"ip.src.asnum":         "CloudFront-Viewer-ASN",
			"ssl":                  "CloudFront-Forwarded-Proto",
			"http.request.version": "CloudFront-Viewer-Http-Version",
		},
	},
	"cloudflare": {
		ClientIPSource{Kind: "cloudflare", Header: "CF-Connecting-IP"},
		map[string]string{
			"ip.src.country": "CF-IPCountry",
			"ssl":            "X-Forwarded-Proto",
		},
	},
	// An external Application Load Balancer has no fixed header names: the
	// LB's custom request headers must set these from {client_ip_address},
	// {client_region}, {client_protocol} and {client_encrypted}. The LB
	// overwrites only the headers it adds, so ASN and the TLS fingerprints
	// are opt-in through VIEWER_HEADERS: not every LB type has {asn} or the
	// fingerprint variables, and an unset header arrives as the client sent it.
	"gcp": {
		ClientIPSource{Kind: "gcp", Header: "X-Gclb-Client-Ip"},
		map[string]string{
			"ip.src.country":       "X-Gclb-Region",
			"http.request.version": "X-Gclb-Protocol",
			"ssl":                  "X-Gclb-Encrypted",
		},
	},
}

// LoadConfig reads the deployment config. It reports every problem at once,
// so a broken deployment fails at startup with a complete list.
func LoadConfig(getenv func(string) string) (*Config, error) {
	p := &envParser{envparse.Parser{Get: getenv}}
	host, _ := os.Hostname()
	c := &Config{
		ListenAddr:          p.Str("LISTEN_ADDR", ":8080"),
		InternalAddr:        p.Str("INTERNAL_ADDR", ":9090"),
		IngressSecretHeader: p.Str("INGRESS_SECRET_HEADER", ""),
		IngressSecrets:      p.List("INGRESS_SECRET_VALUES"),
		ServiceToken:        p.Str("EDGE_SERVICE_TOKEN", ""),
		CachePath:           p.Str("SNAPSHOT_CACHE_PATH", ""),
		BootstrapPath:       p.Str("BOOTSTRAP_PATH", ""),
		BootstrapMaxAge:     p.Duration("BOOTSTRAP_MAX_AGE", 7*24*time.Hour),
		BootstrapAllowStale: p.Bool("BOOTSTRAP_ALLOW_STALE"),
		PollInterval:        p.Duration("POLL_INTERVAL", 5*time.Second),
		MaxInflight:         p.Integer("MAX_INFLIGHT", defaultMaxInflight(memoryLimit())),
		MaxStreams:          p.Integer("MAX_STREAMS", 1_000),
		MaxIdleConns:        p.Integer("UPSTREAM_MAX_IDLE", 256),
		MaxHeaderBytes:      p.Integer("MAX_HEADER_BYTES", 64<<10),
		ReadHeaderTimeout:   p.Duration("READ_HEADER_TIMEOUT", 10*time.Second),
		// Above the 60s idle timeout common to cloud load balancers, so the
		// LB closes idle connections first and never sends on a closed one.
		IdleTimeout:     p.Duration("IDLE_TIMEOUT", 75*time.Second),
		DialTimeout:     p.Duration("UPSTREAM_DIAL_TIMEOUT", 5*time.Second),
		DrainDelay:      p.Duration("DRAIN_DELAY", 10*time.Second),
		ShutdownTimeout: p.Duration("SHUTDOWN_TIMEOUT", 30*time.Second),
		StatsInterval:   p.Duration("STATS_INTERVAL", 10*time.Second),
		// Generous until capacity inputs set the budget.
		ValkeyTimeout:    p.Duration("VALKEY_TIMEOUT", 50*time.Millisecond),
		ExpectedReplicas: p.Integer("EXPECTED_REPLICAS", 1),
		AllowRegex:       p.Bool("ALLOW_REGEX"),
		LogSampleRate:    p.Fraction("LOG_SAMPLE_RATE", 1),
		Instance:         p.Str("INSTANCE", host),
		JWKSAllowedHosts: p.List("JWKS_ALLOWED_HOSTS"),
		TokenCacheSize:   p.Integer("TOKEN_CACHE_SIZE", 10_000),
		Tracing:          tracing.Load(&p.Parser, "edge-proxy"),
	}
	p.clientIP(c)
	p.trustedProxies(c)
	p.upstream(c)
	if s := p.Str("ADMIN_URL", ""); s != "" {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			p.Fail("ADMIN_URL", "must be an http or https URL")
		} else {
			c.AdminURL = u
		}
	}
	if s := p.Str("VALKEY_URL", ""); s != "" {
		opt, err := valkey.ParseURL(s)
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err // url.Error quotes the whole URL, password included
		}
		if err != nil {
			p.Fail("VALKEY_URL", err.Error())
		} else {
			// Bounds the connect attempt before ready.
			if opt.Dialer.Timeout == 0 {
				opt.Dialer.Timeout = time.Second
			}
			c.Valkey = &opt
		}
	}
	if c.AdminURL == nil && c.CachePath == "" && c.BootstrapPath == "" {
		p.Fail("ADMIN_URL", "set at least one of ADMIN_URL, SNAPSHOT_CACHE_PATH or BOOTSTRAP_PATH")
	}
	// A file suits mounted secrets, which stay out of the process environment.
	if f := p.Str("EDGE_SERVICE_TOKEN_FILE", ""); f != "" {
		b, err := os.ReadFile(f) //nolint:gosec // path comes from deployment config, not from users
		switch {
		case c.ServiceToken != "":
			p.Fail("EDGE_SERVICE_TOKEN_FILE", "set EDGE_SERVICE_TOKEN or EDGE_SERVICE_TOKEN_FILE, not both")
		case err != nil:
			p.Fail("EDGE_SERVICE_TOKEN_FILE", "cannot read the file")
		default:
			c.ServiceToken = strings.TrimSpace(string(b))
		}
	}
	// Admin counts an edge toward fleet_size for a minute after its last
	// report, and local fallback limits divide by fleet_size. A longer
	// interval would drop edges from the count and loosen every limit.
	if c.StatsInterval > 30*time.Second {
		p.Fail("STATS_INTERVAL", "must be at most 30s, so a missed report keeps the edge in admin's fleet count")
	}
	if c.AdminURL != nil && c.ServiceToken == "" {
		p.Fail("EDGE_SERVICE_TOKEN", "is required with ADMIN_URL")
	}
	if (c.IngressSecretHeader == "") != (len(c.IngressSecrets) == 0) {
		p.Fail("INGRESS_SECRET_HEADER", "set both INGRESS_SECRET_HEADER and INGRESS_SECRET_VALUES, or neither")
	}
	if c.IngressSecretHeader != "" && !expr.IsToken(c.IngressSecretHeader) {
		p.Fail("INGRESS_SECRET_HEADER", "is not a valid header name")
	}
	if err := p.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

func (p *envParser) clientIP(c *Config) {
	kind := p.Str("CLIENT_IP_SOURCE", "")
	c.Viewer = map[string]string{}
	switch {
	case kind == "cloudfront" || kind == "cloudflare" || kind == "gcp":
		c.ClientIP = presets[kind].ip
		maps.Copy(c.Viewer, presets[kind].viewer)
	case kind == "xff" || kind == "remote_addr":
		c.ClientIP = ClientIPSource{Kind: kind}
	case strings.HasPrefix(kind, "header:"):
		// header:<Name>:<ip|ip_port>
		parts := strings.Split(kind, ":")
		if len(parts) != 3 || !expr.IsToken(parts[1]) || (parts[2] != "ip" && parts[2] != "ip_port") {
			p.Fail("CLIENT_IP_SOURCE", "header form is header:<Name>:<ip|ip_port>")
			return
		}
		c.ClientIP = ClientIPSource{Kind: "header", Header: parts[1], WithPort: parts[2] == "ip_port"}
	default:
		p.Fail("CLIENT_IP_SOURCE", "must be cloudfront, cloudflare, gcp, header:<Name>:<ip|ip_port>, xff or remote_addr")
		return
	}

	// VIEWER_HEADERS adds to or overrides the preset: field=Header,...
	for _, pair := range p.List("VIEWER_HEADERS") {
		f, h, ok := strings.Cut(pair, "=")
		fd, known := expr.LookupField(f)
		switch {
		case !ok || !expr.IsToken(h):
			p.Fail("VIEWER_HEADERS", fmt.Sprintf("%q must be field=Header", pair))
		case !known || fd.Source != expr.SourceViewer:
			p.Fail("VIEWER_HEADERS", fmt.Sprintf("%q is not a viewer field", f))
		default:
			c.Viewer[f] = h
		}
	}
	if kind == "remote_addr" && len(c.Viewer) > 0 {
		p.Fail("VIEWER_HEADERS", "can't be used with remote_addr: there is no trusted proxy to set them")
	}
}

// trustedProxies reads TRUSTED_PROXIES. Only the edge needs it: admin
// validates config without seeing traffic, and its own proxy is
// ADMIN_TRUSTED_PROXIES.
func (p *envParser) trustedProxies(c *Config) {
	c.TrustedProxies = p.Prefixes("TRUSTED_PROXIES")
	if k := c.ClientIP.Kind; k != "" && k != "remote_addr" && len(c.TrustedProxies) == 0 {
		p.Fail("TRUSTED_PROXIES", "is required unless CLIENT_IP_SOURCE is remote_addr")
	}
}

func (p *envParser) upstream(c *Config) {
	u, err := url.Parse(p.Str("UPSTREAM_URL", ""))
	// SetURL joins a query here to every request's, so none is allowed.
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		p.Fail("UPSTREAM_URL", "is required: the http(s)://host[:port][/path] of the load balancer or gateway that routes your apps, with no query or fragment")
		return
	}
	if u.Port() == "" {
		// Spelled out, so the dialer and TLS naming use one port.
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		u.Host = net.JoinHostPort(u.Hostname(), port)
	}
	c.Upstream = u
}

// LoadDeployment reads only what snapshot validation needs, from the same
// variables as the edge, so admin validates config against the deployment
// its edges run in.
func LoadDeployment(getenv func(string) string) (snapshot.Deployment, error) {
	p := &envParser{envparse.Parser{Get: getenv}}
	c := &Config{AllowRegex: p.Bool("ALLOW_REGEX"), IngressSecretHeader: p.Str("INGRESS_SECRET_HEADER", "")}
	p.clientIP(c)
	if err := p.Err(); err != nil {
		return snapshot.Deployment{}, err
	}
	return c.Deployment(), nil
}

// Deployment is what snapshot validation needs to know about this deployment.
func (c *Config) Deployment() snapshot.Deployment {
	d := snapshot.Deployment{AllowRegex: c.AllowRegex, VerifiedBots: true}
	for f, h := range c.Viewer {
		d.ViewerFields = append(d.ViewerFields, f)
		d.SourceHeaders = append(d.SourceHeaders, h)
	}
	if c.ClientIP.Header != "" {
		d.SourceHeaders = append(d.SourceHeaders, c.ClientIP.Header)
	}
	if c.IngressSecretHeader != "" {
		d.SourceHeaders = append(d.SourceHeaders, c.IngressSecretHeader)
	}
	slices.Sort(d.ViewerFields)
	return d
}

// sourceHeaders are stripped from every request before it is forwarded.
func sourceHeaders(d snapshot.Deployment) []string {
	var hs []string
	for _, h := range d.SourceHeaders {
		hs = append(hs, http.CanonicalHeaderKey(h))
	}
	return hs
}

// envParser adds the edge's compound variables to envparse.Parser.
type envParser struct{ envparse.Parser }
