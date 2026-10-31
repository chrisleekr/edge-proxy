package edge

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/ratelimit"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// SimRequest is a synthetic request for config tests. Trust is
// deployment-specific, so the test states the trusted values directly.
type SimRequest struct {
	Method string
	Host   string
	// Target is the request target as sent: path plus optional query.
	Target  string
	IP      string
	Headers map[string][]string
	Country string
	ASN     int64
	SSL     bool
	// JA4, JA3 and HTTPVersion are what the CDN would send; malformed
	// fingerprints and unknown versions are absent, as live.
	JA4, JA3    string
	HTTPVersion string
	// VerifiedBot puts the IP in the verified crawler ranges.
	VerifiedBot bool
	// JWTClaims stand in for a verified token's claims.
	JWTClaims map[string][]string
}

// SimResult is what the edge would decide for a SimRequest.
type SimResult struct {
	// Rejected names the check that would reject the request, or "": a
	// step 2 path or method check, auth for required auth with no token, or
	// rate_limit_key for a missing key part under on_missing_key: reject.
	Rejected       string
	ConfigRules    []string
	RateLimitRules []string
	// RateLimitCapped is true when matching rules beyond the cap were skipped.
	RateLimitCapped bool
	// Preflight is true when the edge answers the request as a CORS
	// preflight (step 6), so no later step runs.
	Preflight bool
	Settings  SimSettings
	// UpstreamHeaders are the request's headers after the header phase
	// (step 9): forward filter, header rules and the locale header. The
	// forwarding headers the edge always sets (X-Forwarded-*,
	// X-Edge-Client-IP, X-Request-Id, and the trace context when tracing
	// is on) depend on deployment and are left out.
	UpstreamHeaders http.Header
}

// SimSettings are the resolved config-phase settings. The JSON names are
// the keys config tests compare by.
type SimSettings struct {
	AuthMode         string            `json:"auth_mode"`
	Accepted         []string          `json:"accepted"`
	CORSPolicy       string            `json:"cors_policy"`
	Locale           bool              `json:"locale"`
	Responses        map[string]string `json:"responses"`
	BodyLimit        int64             `json:"body_limit"`
	UpstreamTimeout  snapshot.Duration `json:"upstream_timeout"`
	RateLimitHeaders bool              `json:"ratelimit_headers"`
	Block            string            `json:"block"`
}

// Simulate runs the edge's own path and method checks, config phase, CORS
// preflight, auth, rate-limit selection and header phase on req, in serve's
// order, so config tests and live traffic can't disagree. Stateful steps
// (backstop, quotas) depend on the running edge and are left out.
func Simulate(c *snapshot.Compiled, req SimRequest) (SimResult, error) {
	ip, err := netip.ParseAddr(req.IP)
	if err != nil {
		return SimResult{}, fmt.Errorf("ip: %w", err)
	}
	r, err := http.NewRequest(req.Method, "http://"+req.Host+req.Target, nil)
	if err != nil {
		return SimResult{}, fmt.Errorf("request: %w", err)
	}
	for k, vs := range req.Headers {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	if checkMethod(r.Method) != nil {
		return SimResult{Rejected: reasonNames[reasonMethod]}, nil
	}
	r.RequestURI = req.Target // as the server would set it
	p, err := matchPath(r)
	if err != nil {
		return SimResult{Rejected: reasonNames[reasonPath]}, nil
	}
	cl := client{ip: clean(ip), country: isoCode(req.Country), ssl: req.SSL, asn: req.ASN, hasASN: req.ASN > 0, version: expr.HTTPVersion(req.HTTPVersion)}
	// As in identify: with an ssl source, a fingerprint on a plain request is
	// absent, since only TLS has one.
	if req.SSL || !slices.Contains(c.Deployment.ViewerFields, "ssl") {
		if expr.ValidJA4(req.JA4) {
			cl.ja4 = req.JA4
		}
		if expr.ValidJA3(req.JA3) {
			cl.ja3 = req.JA3
		}
	}
	// Rule expiry is judged at the time of the simulation.
	st := &reqState{client: cl, requestID: "simulated", start: time.Now()}
	st.fields = newFields(r, &st.client, p)
	f := &st.fields
	if req.VerifiedBot {
		bots := expr.NewIPSet([]netip.Prefix{netip.PrefixFrom(cl.ip, cl.ip.BitLen())})
		f.bots = &bots
	}
	set, matched := resolve(c, defaults(c), f, nil)
	if set.locale {
		f.loc = newLocaleResolver(c)
	}
	var res SimResult
	for _, i := range matched {
		res.ConfigRules = append(res.ConfigRules, c.Config.ConfigRules[i].ID)
	}
	res.Settings = SimSettings{
		AuthMode: set.authMode, Accepted: set.accepted, CORSPolicy: set.cors, Locale: set.locale,
		Responses: map[string]string{}, BodyLimit: set.bodyLimit,
		UpstreamTimeout: snapshot.Duration(set.upstreamTimeout), RateLimitHeaders: set.rateLimitHeaders, Block: set.block,
	}
	for k, name := range set.responses {
		res.Settings.Responses[kindNames[k]] = name
	}
	// Steps 4 to 9 in serve's order, stopping where live traffic stops.
	if set.block == "block" {
		res.Rejected = reasonNames[reasonBlocked]
		return res, nil
	}
	if set.cors != "" && isPreflight(r) {
		res.Preflight = true
		return res, nil
	}
	// Claims exist only where the request's auth setting verifies a token;
	// a verified token always has some.
	if set.authMode != "none" {
		if len(req.JWTClaims) == 0 && set.authMode != "optional" {
			res.Rejected = reasonNames[reasonAuth]
			return res, nil
		}
		f.claims = req.JWTClaims
	}
	checks, capped, reject := st.planChecks(&version{c: c, rules: ratelimit.Compile(c.Config.RateLimitRules)}, nil)
	for _, ch := range checks {
		res.RateLimitRules = append(res.RateLimitRules, ch.rule.ID)
	}
	res.RateLimitCapped = capped
	if reject {
		res.Rejected = reasonNames[reasonRateLimitKey]
		return res, nil
	}
	plan := compileHeaders(c)
	res.UpstreamHeaders = r.Header.Clone()
	upstreamHeaders(c, &plan, st, res.UpstreamHeaders, sourceHeaders(c.Deployment))
	return res, nil
}
