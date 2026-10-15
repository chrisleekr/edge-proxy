package snapshot

import (
	"fmt"
	"net/http"
	"time"
)

// Starter is a valid config with no rules: the first draft when nothing has
// been published. Every edge response is a problem+json body.
func Starter() *Config {
	responses := map[string]Response{}
	defaults := map[string]string{}
	for kind, status := range statusOf {
		responses[kind] = Response{Status: status, ContentType: "application/problem+json",
			Body: fmt.Sprintf(`{"status":%d,"title":%q}`, status, http.StatusText(status))}
		defaults[kind] = kind
	}
	return &Config{
		Schema: 1,
		Global: Global{
			Backstop: Backstop{Limit: 100, Period: Duration(time.Second), Burst: 200, MaxEntries: 100_000},
			Defaults: Defaults{BodyLimit: 10 << 20, BodyReadTimeout: Duration(30 * time.Second),
				UpstreamTimeout: Duration(30 * time.Second), Responses: defaults},
			Responses:      responses,
			RequestHeaders: RequestHeaders{Forward: Forward{Mode: "all"}},
		},
	}
}
