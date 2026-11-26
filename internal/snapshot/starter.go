package snapshot

import (
	"fmt"
	"net/http"
	"time"
)

// Starter is a valid config with no rules: the first draft when nothing has
// been published. Every kind's template has the default bodies.
func Starter() *Config {
	responses := map[string]Response{}
	defaults := map[string]string{}
	for kind, status := range statusOf {
		b := DefaultBodies(kind)
		responses[kind] = Response{Status: status, ContentType: b[0].ContentType, Body: b[0].Body, Variants: b[1:]}
		defaults[kind] = kind
	}
	return &Config{
		Schema: SupportedSchema,
		Global: Global{
			Backstop: Backstop{Limit: 100, Period: Duration(time.Second), Burst: 200, MaxEntries: 100_000},
			Defaults: Defaults{BodyLimit: 10 << 20, BodyReadTimeout: Duration(30 * time.Second),
				UpstreamTimeout: Duration(30 * time.Second), Responses: defaults},
			Responses:      responses,
			RequestHeaders: RequestHeaders{Forward: Forward{Mode: "all"}},
		},
	}
}

// pageText is the heading and sentence each kind's default HTML and text
// bodies show.
var pageText = map[string][2]string{
	"bad_request":       {"Bad request", "The request could not be understood."},
	"unauthorized":      {"Sign-in required", "This request needs a valid token."},
	"forbidden":         {"Access denied", "This request was refused."},
	"payload_too_large": {"Request too large", "The request body is over the size limit."},
	"rate_limited":      {"Too many requests", "Try again in {{retry_after}} seconds."},
	"bad_gateway":       {"Bad gateway", "The service sent an invalid response. Try again shortly."},
	"unavailable":       {"Service unavailable", "Try again in {{retry_after}} seconds."},
	"overloaded":        {"Service busy", "Try again in {{retry_after}} seconds."},
	"gateway_timeout":   {"Gateway timeout", "The service took too long to respond. Try again shortly."},
}

// DefaultBodies returns a kind's default bodies, problem+json first: fetch,
// API clients and curl send Accept */* or none and get the small JSON, while a
// browser opening a page lists text/html first. The HTML is minimal because a
// flood of browser-like requests is answered with it.
func DefaultBodies(kind string) []Variant {
	status, t := statusOf[kind], pageText[kind]
	return []Variant{
		{"application/problem+json", fmt.Sprintf(`{"status":%d,"title":%q}`, status, http.StatusText(status))},
		{"text/html; charset=utf-8", fmt.Sprintf(`<!doctype html><html lang=en><meta name=viewport content="width=device-width"><title>{{status}} %s</title><h1>%s</h1><p>%s<p>Request ID: {{request_id}}`, t[0], t[0], t[1])},
		{"text/plain; charset=utf-8", fmt.Sprintf("{{status}} %s\n%s\nRequest ID: {{request_id}}\n", t[0], t[1])},
	}
}
