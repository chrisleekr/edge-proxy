package edge

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// Mounted secrets end with a newline, which must not become part of the token.
const (
	tokenFile = "testdata/service-token"
	emptyFile = "testdata/empty-token"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// cloudfrontEnv is a typical production deployment behind CloudFront.
func cloudfrontEnv() map[string]string {
	return map[string]string{
		"CLIENT_IP_SOURCE":    "cloudfront",
		"TRUSTED_PROXIES":     "10.0.0.0/8, 192.0.2.10",
		"UPSTREAM_URL":        "https://lb.internal/base",
		"ADMIN_URL":           "http://edge-admin:8081",
		"EDGE_SERVICE_TOKEN":  "t0k",
		"SNAPSHOT_CACHE_PATH": "/var/cache/edge/snapshot.json",
		"BOOTSTRAP_PATH":      "/etc/edge/bootstrap.json",
	}
}

// A CloudFront deployment gets the preset headers and safe defaults.
func TestLoadConfigCloudFront(t *testing.T) {
	c, err := LoadConfig(env(cloudfrontEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientIP != (ClientIPSource{Kind: "cloudfront", Header: "CloudFront-Viewer-Address", WithPort: true}) {
		t.Errorf("ClientIP = %+v", c.ClientIP)
	}
	if c.Viewer["ip.src.country"] != "CloudFront-Viewer-Country" || len(c.TrustedProxies) != 2 || c.TrustedProxies[1].Bits() != 32 {
		t.Errorf("viewer %v, trusted %v", c.Viewer, c.TrustedProxies)
	}
	if c.Upstream.Host != "lb.internal:443" || c.Upstream.Path != "/base" {
		t.Errorf("upstream %v", c.Upstream)
	}
	if c.BootstrapMaxAge != 7*24*time.Hour || c.PollInterval != 5*time.Second || c.IdleTimeout != 75*time.Second || c.LogSampleRate != 1 || c.Instance == "" {
		t.Errorf("defaults not applied: %+v", c)
	}
	d := c.Deployment()
	if len(d.ViewerFields) != 4 || len(d.SourceHeaders) != 5 {
		t.Errorf("Deployment = %+v", d)
	}
}

// Other client-IP sources and overrides parse as documented.
func TestLoadConfigVariants(t *testing.T) {
	cases := []struct {
		name  string
		set   map[string]string
		check func(t *testing.T, c *Config)
	}{
		{"cloudflare preset", map[string]string{"CLIENT_IP_SOURCE": "cloudflare"}, func(t *testing.T, c *Config) {
			t.Helper()
			if c.ClientIP.Header != "CF-Connecting-IP" || c.ClientIP.WithPort || c.Viewer["ssl"] != "X-Forwarded-Proto" {
				t.Errorf("%+v %v", c.ClientIP, c.Viewer)
			}
		}},
		{"custom header with port", map[string]string{"CLIENT_IP_SOURCE": "header:X-Client-Addr:ip_port", "VIEWER_HEADERS": "ip.src.country=X-Geo-Country, client_cert.verified=X-Cert-Ok"}, func(t *testing.T, c *Config) {
			t.Helper()
			if c.ClientIP != (ClientIPSource{Kind: "header", Header: "X-Client-Addr", WithPort: true}) || c.Viewer["client_cert.verified"] != "X-Cert-Ok" {
				t.Errorf("%+v %v", c.ClientIP, c.Viewer)
			}
		}},
		{"xff", map[string]string{"CLIENT_IP_SOURCE": "xff"}, func(t *testing.T, c *Config) {
			t.Helper()
			if c.ClientIP.Kind != "xff" || c.ClientIP.Header != "" {
				t.Errorf("%+v", c.ClientIP)
			}
		}},
		{"remote_addr needs no trusted proxies", map[string]string{"CLIENT_IP_SOURCE": "remote_addr", "TRUSTED_PROXIES": ""}, func(t *testing.T, c *Config) {
			t.Helper()
			if c.ClientIP.Kind != "remote_addr" || len(c.Deployment().SourceHeaders) != 0 {
				t.Errorf("%+v", c)
			}
		}},
		{"ingress secret with rotation", map[string]string{"INGRESS_SECRET_HEADER": "X-Origin-Secret", "INGRESS_SECRET_VALUES": "old,new"}, func(t *testing.T, c *Config) {
			t.Helper()
			if len(c.IngressSecrets) != 2 || !slices.Contains(c.Deployment().SourceHeaders, "X-Origin-Secret") {
				t.Errorf("%+v", c)
			}
		}},
		{"bootstrap only", map[string]string{"ADMIN_URL": "", "EDGE_SERVICE_TOKEN": "", "SNAPSHOT_CACHE_PATH": ""}, func(t *testing.T, c *Config) {
			t.Helper()
			if c.AdminURL != nil || c.BootstrapPath == "" {
				t.Errorf("%+v", c)
			}
		}},
		{"service token from a mounted secret file", map[string]string{"EDGE_SERVICE_TOKEN": "", "EDGE_SERVICE_TOKEN_FILE": tokenFile}, func(t *testing.T, c *Config) {
			t.Helper()
			if c.ServiceToken != "from-file" {
				t.Errorf("token %q", c.ServiceToken)
			}
		}},
		{"valkey cluster with the default dial bound", map[string]string{"VALKEY_URL": "redis://u:p@vk-1:6379?addr=vk-2:6379&addr=vk-3:6379", "VALKEY_TIMEOUT": "5ms", "EXPECTED_REPLICAS": "6"}, func(t *testing.T, c *Config) {
			t.Helper()
			if len(c.Valkey.InitAddress) != 3 || c.Valkey.Username != "u" || c.Valkey.Dialer.Timeout != time.Second || c.ValkeyTimeout != 5*time.Millisecond || c.ExpectedReplicas != 6 {
				t.Errorf("%+v %+v", c.Valkey, c)
			}
		}},
		{"valkey dial timeout from the URL", map[string]string{"VALKEY_URL": "rediss://vk:6379?dial_timeout=300ms"}, func(t *testing.T, c *Config) {
			t.Helper()
			if c.Valkey.Dialer.Timeout != 300*time.Millisecond || c.Valkey.TLSConfig == nil {
				t.Errorf("%+v", c.Valkey)
			}
		}},
		{"no valkey", nil, func(t *testing.T, c *Config) {
			t.Helper()
			if c.Valkey != nil || c.ValkeyTimeout != 50*time.Millisecond || c.ExpectedReplicas != 1 {
				t.Errorf("%+v", c)
			}
		}},
		{"tuned limits", map[string]string{"MAX_INFLIGHT": "50", "BOOTSTRAP_MAX_AGE": "48h", "BOOTSTRAP_ALLOW_STALE": "true", "ALLOW_REGEX": "false", "LOG_SAMPLE_RATE": "0.05"}, func(t *testing.T, c *Config) {
			t.Helper()
			if c.MaxInflight != 50 || c.BootstrapMaxAge != 48*time.Hour || !c.BootstrapAllowStale || c.AllowRegex || c.LogSampleRate != 0.05 {
				t.Errorf("%+v", c)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := cloudfrontEnv()
			maps.Copy(e, tc.set)
			c, err := LoadConfig(env(e))
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, c)
		})
	}
}

// A broken deployment fails at startup with every problem listed, instead of
// starting half-configured.
func TestLoadConfigRejects(t *testing.T) {
	cases := []struct {
		name string
		set  map[string]string
		msg  string
	}{
		{"no client IP source", map[string]string{"CLIENT_IP_SOURCE": ""}, "CLIENT_IP_SOURCE: must be cloudfront"},
		{"malformed header source", map[string]string{"CLIENT_IP_SOURCE": "header:X-IP"}, "header:<Name>:<ip|ip_port>"},
		{"header source with a bad format", map[string]string{"CLIENT_IP_SOURCE": "header:X-IP:port"}, "header:<Name>:<ip|ip_port>"},
		{"no trusted proxies", map[string]string{"TRUSTED_PROXIES": ""}, "TRUSTED_PROXIES: is required"},
		{"trusted proxy that isn't an IP", map[string]string{"TRUSTED_PROXIES": "lb.internal"}, `"lb.internal" is not an IP or CIDR`},
		{"viewer header pair without a header", map[string]string{"VIEWER_HEADERS": "ip.src.country"}, "must be field=Header"},
		{"viewer header for a request field", map[string]string{"VIEWER_HEADERS": "http.host=X-Host"}, `"http.host" is not a viewer field`},
		{"viewer headers with remote_addr", map[string]string{"CLIENT_IP_SOURCE": "remote_addr", "VIEWER_HEADERS": "ssl=X-Proto"}, "can't be used with remote_addr"},
		{"upstream without a scheme", map[string]string{"UPSTREAM_URL": "lb:8080"}, "UPSTREAM_URL: is required"},
		{"no upstream", map[string]string{"UPSTREAM_URL": ""}, "UPSTREAM_URL: is required"},
		{"upstream with credentials", map[string]string{"UPSTREAM_URL": "https://u:s3cret@lb.internal"}, "UPSTREAM_URL: is required"},
		{"upstream with a query joined to every request", map[string]string{"UPSTREAM_URL": "https://lb.internal/?token=x"}, "UPSTREAM_URL: is required"},
		{"upstream with a fragment", map[string]string{"UPSTREAM_URL": "https://lb.internal/#x"}, "UPSTREAM_URL: is required"},
		{"stats interval too long for admin's fleet count", map[string]string{"STATS_INTERVAL": "1m"}, "STATS_INTERVAL: must be at most 30s"},
		{"admin URL that isn't http", map[string]string{"ADMIN_URL": "ftp://admin"}, "ADMIN_URL: must be an http or https URL"},
		{"no snapshot source at all", map[string]string{"ADMIN_URL": "", "SNAPSHOT_CACHE_PATH": "", "BOOTSTRAP_PATH": ""}, "set at least one of"},
		{"admin URL without a token", map[string]string{"EDGE_SERVICE_TOKEN": ""}, "EDGE_SERVICE_TOKEN: is required"},
		{"token set twice", map[string]string{"EDGE_SERVICE_TOKEN_FILE": tokenFile}, "set EDGE_SERVICE_TOKEN or EDGE_SERVICE_TOKEN_FILE, not both"},
		{"token file missing", map[string]string{"EDGE_SERVICE_TOKEN": "", "EDGE_SERVICE_TOKEN_FILE": "/nonexistent/token"}, "EDGE_SERVICE_TOKEN_FILE: cannot read"},
		{"token file empty", map[string]string{"EDGE_SERVICE_TOKEN": "", "EDGE_SERVICE_TOKEN_FILE": emptyFile}, "EDGE_SERVICE_TOKEN: is required"},
		{"ingress header without values", map[string]string{"INGRESS_SECRET_HEADER": "X-Secret"}, "set both"},
		{"ingress header that isn't a name", map[string]string{"INGRESS_SECRET_HEADER": "X Secret", "INGRESS_SECRET_VALUES": "s"}, "not a valid header name"},
		{"duration without a unit", map[string]string{"BOOTSTRAP_MAX_AGE": "7"}, "BOOTSTRAP_MAX_AGE"},
		{"days are not a Go duration", map[string]string{"BOOTSTRAP_MAX_AGE": "7d"}, "such as 30s or 168h"},
		{"zero in-flight cap", map[string]string{"MAX_INFLIGHT": "0"}, "MAX_INFLIGHT"},
		{"sample rate over 1", map[string]string{"LOG_SAMPLE_RATE": "2"}, "LOG_SAMPLE_RATE"},
		{"valkey URL with a bad port", map[string]string{"VALKEY_URL": "redis://u:s3cret@vk:notaport"}, `VALKEY_URL: invalid port ":notaport"`},
		{"valkey URL with an unknown scheme", map[string]string{"VALKEY_URL": "http://vk:6379"}, "VALKEY_URL: valkey: invalid URL scheme"},
		{"zero expected replicas", map[string]string{"EXPECTED_REPLICAS": "0"}, "EXPECTED_REPLICAS"},
		{"boolean typo", map[string]string{"BOOTSTRAP_ALLOW_STALE": "yes"}, "must be true or false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := cloudfrontEnv()
			maps.Copy(e, tc.set)
			_, err := LoadConfig(env(e))
			if err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("error = %v, want mention of %q", err, tc.msg)
			}
			// Startup logs this error; it must never carry a credential.
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("error leaks a password: %v", err)
			}
		})
	}
}

// An upstream URL without a port gets its scheme's, so the dialer and the
// TLS server name agree on one.
func TestUpstreamPortDefaultsByScheme(t *testing.T) {
	for raw, want := range map[string]string{"http://lb.internal": "lb.internal:80", "https://lb.internal": "lb.internal:443", "https://lb.internal:8443": "lb.internal:8443"} {
		e := cloudfrontEnv()
		e["UPSTREAM_URL"] = raw
		c, err := LoadConfig(env(e))
		if err != nil {
			t.Fatal(err)
		}
		if c.Upstream.Host != want {
			t.Errorf("%s: host %s, want %s", raw, c.Upstream.Host, want)
		}
	}
}

// Admin validates against the same deployment variables as its edges.
func TestLoadDeployment(t *testing.T) {
	d, err := LoadDeployment(env(map[string]string{
		"CLIENT_IP_SOURCE": "cloudfront", "TRUSTED_PROXIES": "10.0.0.0/8",
		"INGRESS_SECRET_HEADER": "X-Origin-Secret", "ALLOW_REGEX": "true",
	}))
	if err != nil || !d.AllowRegex || !slices.Contains(d.SourceHeaders, "X-Origin-Secret") || !slices.Contains(d.ViewerFields, "ip.src.country") {
		t.Fatalf("deployment %+v, %v", d, err)
	}
	// Admin never sees edge traffic, so it needs neither the trusted proxies
	// nor the upstream.
	if _, err := LoadDeployment(env(map[string]string{"CLIENT_IP_SOURCE": "cloudfront"})); err != nil {
		t.Fatalf("without TRUSTED_PROXIES and UPSTREAM_URL: %v", err)
	}
	// A deployment the edges would refuse is refused here too, so admin never
	// validates config against a client-IP source no edge runs with.
	if _, err := LoadDeployment(env(map[string]string{"CLIENT_IP_SOURCE": "x-real-ip"})); err == nil || !strings.Contains(err.Error(), "CLIENT_IP_SOURCE") {
		t.Fatalf("unknown CLIENT_IP_SOURCE: %v", err)
	}
}
