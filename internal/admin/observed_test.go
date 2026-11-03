package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

const shipperToken = "shipper-token-0123456789abcdefghijklmnop"

// shipper is a log shipper client posting with the deployment's token.
func (h *harness) shipper() *client {
	h.s.cfg.LogToken = hashSecret(shipperToken)
	c := h.client()
	c.token = shipperToken
	return c
}

// post sends raw newline-delimited access lines.
func (c *client) post(lines ...string) *http.Response {
	c.h.t.Helper()
	req, _ := http.NewRequest("POST", c.h.srv.URL+"/v1/logs/access", strings.NewReader(strings.Join(lines, "\n")))
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.c.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	return resp
}

// access is one edge access line, as the edge writes it, with overrides.
func access(method, host, path string, extra ...any) string {
	m := map[string]any{"msg": "access", "level": "INFO", "http.request.method": method, "server.address": host, "url.path": path,
		"http.response.status_code": 200, "edge.decision": "allow", "duration_ms": 3.2, "edge.config_version": 1, "edge.config_rules": []string{}}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i].(string)] = extra[i+1]
	}
	b, _ := json.Marshal(m)
	return string(b)
}

type routeList struct {
	Routes      []routeStats      `json:"routes"`
	NotGrouped  int64             `json:"not_grouped"`
	Logged      int64             `json:"logged_requests"`
	Estimated   int64             `json:"estimated_requests"`
	Reported    int64             `json:"reported_requests"`
	Suggestions []routeSuggestion `json:"suggestions"`
	More        int               `json:"more"`
}

// routes flushes what admin holds and lists the routes.
func (h *harness) routes(c *client) routeList {
	h.t.Helper()
	if err := h.s.flushRoutes(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	return decode[routeList](h.t, c.do("GET", "/api/observed-routes", nil))
}

func find(l routeList, method, host, template string) *routeStats {
	i := slices.IndexFunc(l.Routes, func(r routeStats) bool { return r.Method == method && r.Host == host && r.Template == template })
	if i < 0 {
		return nil
	}
	return &l.Routes[i]
}

// Only the deployment's log shipper token may post access lines, and it can
// do nothing else.
func TestRouteIngestNeedsTheShipperToken(t *testing.T) {
	h, pub := published(t)
	sh := h.shipper()
	status(t, sh.post(access("GET", "api.example.com", "/")), http.StatusAccepted)

	edgeClient := h.client()
	edgeClient.token = h.edgeToken(pub)
	status(t, edgeClient.post(access("GET", "api.example.com", "/")), http.StatusForbidden)
	anon := h.client()
	status(t, anon.post(access("GET", "api.example.com", "/")), http.StatusUnauthorized)

	status(t, sh.do("GET", "/api/observed-routes", nil), http.StatusForbidden)
	status(t, sh.do("GET", "/v1/snapshot", nil), http.StatusForbidden)
}

// Access lines are grouped by host, method and path template, with their
// statuses, decisions, rules and query shapes. Lines that aren't about a
// route are skipped and counted.
func TestRoutesAreGroupedFromAccessLines(t *testing.T) {
	h, pub := published(t)
	h.putStats(1, 3, 2, 0, 0, []int64{2}, "[]", "[]") // the edges reported 6 requests
	resp := h.shipper().post(
		access("GET", "api.example.com", "/users/42", "edge.query_keys", []string{"page", "sort"}),
		access("GET", "api.example.com", "/users/7", "http.response.status_code", 429, "edge.decision", "rate_limited", "edge.rate_limit_rule", "login", "duration_ms", 0.4),
		access("GET", "api.example.com", "/users/550e8400-e29b-41d4-a716-446655440000/orders"),
		access("GET", "api.example.com", "/users/550e8400-e29b-41d4-a716-446655440000/orders", "http.response.status_code", 503, "edge.decision", "upstream_error", "duration_ms", 400),
		access("POST", "api.example.com", "/admin/login", "edge.config_rules", []string{"admin-route"}),
		"",
		`not json`,
		`{"msg":"snapshot loaded","level":"INFO"}`,
		access("GET", "evil.example", "/%2e%2e/etc/passwd", "edge.decision", "path", "http.response.status_code", 400),
		access("GET", "api.example.com", "no-slash"),
		access("GET", "api.example.com\u0000", "/"),
	)
	if got := decode[map[string]int](t, resp); got["accepted"] != 5 || got["skipped"] != 5 {
		t.Fatalf("ingest = %v", got)
	}
	l := h.routes(pub)
	if len(l.Routes) != 3 || l.Logged != 5 || l.Reported != 6 {
		t.Fatalf("routes = %+v", l)
	}
	users := find(l, "GET", "api.example.com", "/users/{id}")
	if users == nil || users.Requests != 2 || users.Status[2] != 1 || users.Status[4] != 1 ||
		users.Decisions["allow"] != 1 || users.Decisions["rate_limited"] != 1 || users.RateLimitRules["login"] != 1 ||
		users.QueryShapes["page&sort"] != 1 || users.QueryShapes[""] != 1 || users.P50MS != 1 || users.P95MS != 5 {
		t.Fatalf("users route = %+v", users)
	}
	if orders := find(l, "GET", "api.example.com", "/users/{uuid}/orders"); orders == nil || orders.Status[5] != 1 || orders.P95MS != 500 {
		t.Fatalf("orders route = %+v", orders)
	}
	if login := find(l, "POST", "api.example.com", "/admin/login"); login == nil || login.ConfigRules["admin-route"] != 1 {
		t.Fatalf("login route = %+v", login)
	}

	// A second batch adds to the same rows.
	status(t, h.shipper().post(access("GET", "api.example.com", "/users/9")), http.StatusAccepted)
	if users := find(h.routes(pub), "GET", "api.example.com", "/users/{id}"); users.Requests != 3 {
		t.Fatalf("after a second batch, users route = %+v", users)
	}
	h.wantMetrics(`admin_log_lines_total{result="accepted"} 6`, `admin_log_lines_total{result="rejected"} 5`)
}

// When the edges log a sample of allowed requests, each sampled line counts
// for 1/rate requests, so shares match the traffic; lines the edge always
// logs count once. The scaled part is reported as an estimate.
func TestSampledLinesCountForTheirShare(t *testing.T) {
	old := weightDraw
	t.Cleanup(func() { weightDraw = old })
	h, pub := published(t)
	resp := h.shipper().post(
		access("GET", "api.example.com", "/users/1", "edge.sample_rate", 0.25),
		access("GET", "api.example.com", "/users/2", "edge.sample_rate", 0.25),
		access("GET", "api.example.com", "/users/3", "http.response.status_code", 429, "edge.decision", "rate_limited", "edge.rate_limit_rule", "login"),
		access("GET", "api.example.com", "/users/4", "edge.sample_rate", 2.0),
	)
	if got := decode[map[string]int](t, resp); got["accepted"] != 3 || got["skipped"] != 1 {
		t.Fatalf("ingest = %v", got)
	}
	l := h.routes(pub)
	users := find(l, "GET", "api.example.com", "/users/{id}")
	if users == nil || users.Requests != 9 || users.Estimated != 8 || users.Status[2] != 8 || users.Status[4] != 1 ||
		users.Decisions["allow"] != 8 || users.Decisions["rate_limited"] != 1 || users.QueryShapes[""] != 9 || l.Logged != 9 || l.Estimated != 8 {
		t.Fatalf("users route = %+v, list = %+v", users, l)
	}

	// 1/0.3 is 3.33: a line counts 4 when the draw falls under the 0.33
	// remainder and 3 otherwise, so the expected count is exact.
	weightDraw = func() float64 { return 0.1 }
	status(t, h.shipper().post(access("GET", "api.example.com", "/health", "edge.sample_rate", 0.3)), http.StatusAccepted)
	if health := find(h.routes(pub), "GET", "api.example.com", "/health"); health == nil || health.Requests != 4 {
		t.Fatalf("rounded up, health route = %+v", health)
	}
	weightDraw = func() float64 { return 0.9 }
	status(t, h.shipper().post(access("GET", "api.example.com", "/health", "edge.sample_rate", 0.3)), http.StatusAccepted)
	if health := find(h.routes(pub), "GET", "api.example.com", "/health"); health.Requests != 7 || health.Estimated != 7 {
		t.Fatalf("rounded down, health route = %+v", health)
	}
}

// A route's detail lists its answers by status code, so an operator sees
// a 502 apart from a 503. Sampled lines count for their share, as in Status.
func TestRouteDetailCountsStatusCodes(t *testing.T) {
	h, pub := published(t)
	status(t, h.shipper().post(
		access("GET", "api.example.com", "/users/1", "edge.sample_rate", 0.5),
		access("GET", "api.example.com", "/users/2", "http.response.status_code", 502, "edge.decision", "upstream_error"),
		access("GET", "api.example.com", "/users/3", "http.response.status_code", 503),
		access("GET", "api.example.com", "/users/4", "http.response.status_code", 503),
	), http.StatusAccepted)
	users := find(h.routes(pub), "GET", "api.example.com", "/users/{id}")
	detail := decode[struct {
		StatusCodes map[int]int64 `json:"status_codes"`
	}](t, pub.do("GET", fmt.Sprint("/api/observed-routes/", users.ID), nil))
	if want := map[int]int64{200: 2, 502: 1, 503: 2}; !maps.Equal(detail.StatusCodes, want) {
		t.Fatalf("status codes %v, want %v", detail.StatusCodes, want)
	}
}

// A route's detail lists the edge's upstream failures by cause, so an
// operator sees a name that stopped resolving apart from a stopped upstream.
func TestRouteDetailCountsUpstreamErrorKinds(t *testing.T) {
	h, pub := published(t)
	failed := func(path, kind string) string {
		return access("GET", "api.example.com", path, "http.response.status_code", 502, "edge.decision", "upstream_error",
			"edge.upstream_answered", false, "edge.upstream_error", "dial tcp: connect: failure", "edge.upstream_error_kind", kind)
	}
	status(t, h.shipper().post(
		access("GET", "api.example.com", "/users/1"),
		failed("/users/2", "dns"),
		failed("/users/3", "refused"),
		failed("/users/4", "refused"),
	), http.StatusAccepted)
	users := find(h.routes(pub), "GET", "api.example.com", "/users/{id}")
	detail := decode[struct {
		UpstreamErrors map[string]int64 `json:"upstream_errors"`
	}](t, pub.do("GET", fmt.Sprint("/api/observed-routes/", users.ID), nil))
	if want := map[string]int64{"dns": 1, "refused": 2}; !maps.Equal(detail.UpstreamErrors, want) {
		t.Fatalf("upstream errors %v, want %v", detail.UpstreamErrors, want)
	}
}

// Segments that hold identifiers become placeholders; names stay.
func TestPathTemplates(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{"/", "/"},
		{"/users/42", "/users/{id}"},
		{"/users/42/", "/users/{id}/"},
		{"/orders/550E8400-E29B-41D4-A716-446655440000", "/orders/{uuid}"},
		{"/blobs/9f86d081884c7d659a2feaa0c55ad015", "/blobs/{hex}"},
		{"/files/deadbeef", "/files/deadbeef"},
		{"/reset/Xk29fQp3LmZ8sT1vB7nR", "/reset/{token}"},
		{"/docs/getting-started-with-the-edge", "/docs/getting-started-with-the-edge"},
		{"/a/" + strings.Repeat("x", 65), "/a/{token}"},
		{"/v2/api", "/v2/api"},
		{"/static/app.3f9a1c2b7d.js", "/static/app.{hex}.js"},
		{"/static/vendor-9f86d081.deadbeef.css", "/static/vendor-9f86d081.deadbeef.css"},
		{"/files/report.2026.pdf", "/files/report.{id}.pdf"},
		{"/api/v1.2/users", "/api/v1.2/users"},
	} {
		if got := templatePath("api.example.com", c.path, nil); got != c.want {
			t.Errorf("templatePath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
	pats := []routePattern{
		{Host: "api.example.com", Pattern: "/blog/*", segs: []string{"blog", "*"}},
		{Pattern: "/files/*/raw", segs: []string{"files", "*", "raw"}},
	}
	for _, c := range []struct{ host, path, want string }{
		{"api.example.com", "/blog/hello-world", "/blog/{*}"},
		{"other.example.com", "/blog/hello-world", "/blog/hello-world"},
		{"other.example.com", "/files/report/raw", "/files/{*}/raw"},
		{"api.example.com", "/blog/", "/blog/"}, // "*" needs a segment
	} {
		if got := templatePath(c.host, c.path, pats); got != c.want {
			t.Errorf("templatePath(%q, %q) = %q, want %q", c.host, c.path, got, c.want)
		}
	}
}

// Route count is bounded: traffic for new routes past the cap is counted
// as not grouped, and known routes keep counting.
func TestRoutesPastTheCapAreNotGrouped(t *testing.T) {
	h, pub := published(t)
	maxRoutes = 2
	t.Cleanup(func() { maxRoutes = 5000 })
	sh := h.shipper()
	status(t, sh.post(access("GET", "a.example.com", "/one"), access("GET", "a.example.com", "/two")), http.StatusAccepted)
	h.routes(pub)
	status(t, sh.post(access("GET", "a.example.com", "/three"), access("GET", "a.example.com", "/one")), http.StatusAccepted)
	l := h.routes(pub)
	if len(l.Routes) != 2 || l.NotGrouped != 1 || find(l, "GET", "a.example.com", "/one").Requests != 2 {
		t.Fatalf("routes = %+v", l)
	}
}

// A route that has only served errors, such as a login under attack whose
// every request is limited, is stored apart and marked, up to its own cap,
// so a scanner's 404s can't push real routes out. The mark goes once it
// serves a response that isn't an error.
func TestErrorOnlyRoutesAreKeptApart(t *testing.T) {
	h, pub := published(t)
	maxErrorRoutes = 1
	t.Cleanup(func() { maxErrorRoutes = 500 })
	sh := h.shipper()
	limited := access("POST", "api.example.com", "/login", "http.response.status_code", 429, "edge.decision", "rate_limited", "edge.rate_limit_rule", "login")
	status(t, sh.post(limited, limited, access("GET", "api.example.com", "/wp-login.php", "http.response.status_code", 404)), http.StatusAccepted)
	l := h.routes(pub)
	login := find(l, "POST", "api.example.com", "/login")
	if len(l.Routes) != 1 || login == nil || !login.ErrorsOnly || login.RateLimitRules["login"] != 2 || l.NotGrouped != 1 {
		t.Fatalf("routes = %+v", l)
	}
	status(t, sh.post(access("POST", "api.example.com", "/login", "http.response.status_code", 302)), http.StatusAccepted)
	if login := find(h.routes(pub), "POST", "api.example.com", "/login"); login == nil || login.ErrorsOnly || login.Requests != 3 {
		t.Fatalf("after a success, login = %+v", login)
	}
}

// A success on an errors-only route takes a place in the main budget, so
// a 404 then a 200 on made-up paths cannot grow the table past both caps.
func TestErrorOnlyRouteSuccessNeedsRouteBudget(t *testing.T) {
	h, pub := published(t)
	maxRoutes, maxErrorRoutes = 1, 1
	t.Cleanup(func() { maxRoutes, maxErrorRoutes = 5000, 500 })
	sh := h.shipper()
	// Each post is flushed before the next, as minutes apart in production.
	for _, line := range []string{
		access("GET", "app.example.com", "/home"),
		access("GET", "app.example.com", "/a", "http.response.status_code", 404),
		access("GET", "app.example.com", "/a"),
		access("GET", "app.example.com", "/b", "http.response.status_code", 404),
	} {
		status(t, sh.post(line), http.StatusAccepted)
		h.routes(pub)
	}
	l := h.routes(pub)
	if a := find(l, "GET", "app.example.com", "/a"); len(l.Routes) != 2 || a == nil || !a.ErrorsOnly || a.Requests != 1 || l.NotGrouped != 2 {
		t.Fatalf("routes = %+v", l)
	}
}

// Path segments and query keys that may hold secrets or personal data are
// stored as placeholders.
func TestSecretLikeValuesAreNotStored(t *testing.T) {
	h, pub := published(t)
	status(t, h.shipper().post(access("GET", "api.example.com", "/invite/jane@example.com", "edge.query_keys", []string{"page", "sk_live_51HxQ2eKf9a8b7c6d5"})), http.StatusAccepted)
	l := h.routes(pub)
	if r := find(l, "GET", "api.example.com", "/invite/{token}"); r == nil || r.QueryShapes["page&{token}"] != 1 {
		t.Fatalf("routes = %+v", l)
	}
}

// Between flushes, distinct routes are bounded too.
func TestPendingRoutesAreBounded(t *testing.T) {
	h, pub := published(t)
	maxPendingRoutes = 1
	t.Cleanup(func() { maxPendingRoutes = 10_000 })
	status(t, h.shipper().post(access("GET", "a.example.com", "/one"), access("GET", "a.example.com", "/two")), http.StatusAccepted)
	if l := h.routes(pub); len(l.Routes) != 1 || l.NotGrouped != 1 {
		t.Fatalf("routes = %+v", l)
	}
}

// Deleting a route, or all of them, is audited, and new traffic brings the
// route back with fresh counts.
func TestDeletedRoutesAreCollectedAgain(t *testing.T) {
	h, pub := published(t)
	h.user("view", "viewer")
	viewer := h.signedIn("view")
	sh := h.shipper()
	status(t, sh.post(access("GET", "api.example.com", "/users/1"), access("GET", "api.example.com", "/users/2"), access("GET", "api.example.com", "/health")), http.StatusAccepted)
	users := find(h.routes(pub), "GET", "api.example.com", "/users/{id}")

	status(t, viewer.do("DELETE", fmt.Sprint("/api/observed-routes/", users.ID), nil), http.StatusForbidden)
	status(t, pub.do("DELETE", fmt.Sprint("/api/observed-routes/", users.ID), nil), http.StatusNoContent)
	status(t, pub.do("DELETE", fmt.Sprint("/api/observed-routes/", users.ID), nil), http.StatusNotFound)
	if l := h.routes(pub); len(l.Routes) != 1 {
		t.Fatalf("after delete, routes = %+v", l)
	}
	status(t, sh.post(access("GET", "api.example.com", "/users/3")), http.StatusAccepted)
	if again := find(h.routes(pub), "GET", "api.example.com", "/users/{id}"); again == nil || again.Requests != 1 {
		t.Fatalf("collected again = %+v", again)
	}

	status(t, pub.do("DELETE", "/api/observed-routes", nil), http.StatusNoContent)
	if l := h.routes(pub); len(l.Routes) != 0 {
		t.Fatalf("after delete all, routes = %+v", l)
	}
	acts := h.actions()
	if !slices.Contains(acts, "route.delete GET api.example.com/users/{id}") || !slices.Contains(acts, "route.delete_all ") {
		t.Fatalf("audit = %v", acts)
	}
}

// limit keeps the busiest routes; the totals and suggestions still cover
// the routes it leaves out.
func TestLimitKeepsTheBusiestRoutes(t *testing.T) {
	h, pub := published(t)
	lines := []string{access("GET", "api.example.com", "/home"), access("GET", "api.example.com", "/home")}
	for i := range minSiblings {
		lines = append(lines, access("GET", "api.example.com", fmt.Sprintf("/blog/post-%c", 'a'+i)))
	}
	status(t, h.shipper().post(lines...), http.StatusAccepted)
	all := h.routes(pub)
	l := decode[routeList](t, pub.do("GET", "/api/observed-routes?limit=1", nil))
	if len(l.Routes) != 1 || l.Routes[0].Template != "/home" || l.More != minSiblings ||
		l.Logged != all.Logged || l.Estimated != all.Estimated || !slices.Equal(l.Suggestions, all.Suggestions) || len(l.Suggestions) != 1 {
		t.Fatalf("limit 1 = %+v, all = %+v", l, all)
	}
	for _, bad := range []string{"0", "-1", "abc"} {
		status(t, pub.do("GET", "/api/observed-routes?limit="+bad, nil), http.StatusBadRequest)
	}
}

// Many sibling routes get a suggested pattern; creating it merges their
// history into one route, and later traffic is grouped under it.
func TestPatternsGroupSiblingRoutes(t *testing.T) {
	h, pub := published(t)
	sh := h.shipper()
	var lines []string
	for i := range minSiblings {
		lines = append(lines, access("GET", "api.example.com", fmt.Sprintf("/blog/post-%c", 'a'+i)))
	}
	lines = append(lines, access("GET", "api.example.com", "/blog/post-a", "http.response.status_code", 404),
		access("GET", "api.example.com", "/blog/post-b", "http.response.status_code", 502, "edge.decision", "upstream_error",
			"edge.upstream_answered", false, "edge.upstream_error", "dial tcp: connect: failure", "edge.upstream_error_kind", "refused"))
	status(t, sh.post(lines...), http.StatusAccepted)
	l := h.routes(pub)
	if len(l.Suggestions) != 1 || l.Suggestions[0] != (routeSuggestion{Host: "api.example.com", Pattern: "/blog/*", Routes: minSiblings}) {
		t.Fatalf("suggestions = %+v", l.Suggestions)
	}

	status(t, pub.do("POST", "/api/route-patterns", map[string]string{"host": "api.example.com", "pattern": "/blog/x*"}), http.StatusUnprocessableEntity)
	status(t, pub.do("POST", "/api/route-patterns", map[string]string{"host": "api.example.com", "pattern": "/blog/*"}), http.StatusCreated)
	l = h.routes(pub)
	blog := find(l, "GET", "api.example.com", "/blog/{*}")
	if len(l.Routes) != 1 || blog.Requests != minSiblings+2 || len(l.Suggestions) != 0 {
		t.Fatalf("after grouping, routes = %+v", l)
	}
	type routeDetail struct {
		StatusCodes    map[int]int64    `json:"status_codes"`
		UpstreamErrors map[string]int64 `json:"upstream_errors"`
	}
	// The merged routes' answers by code and failure causes move with them.
	detail := decode[routeDetail](t, pub.do("GET", fmt.Sprint("/api/observed-routes/", blog.ID), nil))
	if want := map[int]int64{200: minSiblings, 404: 1, 502: 1}; !maps.Equal(detail.StatusCodes, want) {
		t.Fatalf("after grouping, status codes %v, want %v", detail.StatusCodes, want)
	}
	if want := map[string]int64{"refused": 1}; !maps.Equal(detail.UpstreamErrors, want) {
		t.Fatalf("after grouping, upstream errors %v, want %v", detail.UpstreamErrors, want)
	}
	status(t, sh.post(access("GET", "api.example.com", "/blog/new-post")), http.StatusAccepted)
	if blog := find(h.routes(pub), "GET", "api.example.com", "/blog/{*}"); blog.Requests != minSiblings+3 {
		t.Fatalf("new post not grouped: %+v", blog)
	}
	// A later flush into the grouped route's hour adds to its answers by code.
	detail = decode[routeDetail](t, pub.do("GET", fmt.Sprint("/api/observed-routes/", blog.ID), nil))
	if want := map[int]int64{200: minSiblings + 1, 404: 1, 502: 1}; !maps.Equal(detail.StatusCodes, want) {
		t.Fatalf("after a later flush, status codes %v, want %v", detail.StatusCodes, want)
	}

	// Lines held when a pattern is created are grouped by it at the flush,
	// so the merged routes don't come back.
	status(t, sh.post(access("GET", "api.example.com", "/blog/held-post")), http.StatusAccepted)
	status(t, pub.do("POST", "/api/route-patterns", map[string]string{"host": "", "pattern": "/docs/*"}), http.StatusCreated)
	if l := h.routes(pub); len(l.Routes) != 1 || find(l, "GET", "api.example.com", "/blog/{*}").Requests != minSiblings+4 {
		t.Fatalf("held lines = %+v", l)
	}

	pats := decode[[]routePattern](t, pub.do("GET", "/api/route-patterns", nil))
	pats = slices.DeleteFunc(pats, func(p routePattern) bool { return p.Pattern != "/blog/*" })
	status(t, pub.do("DELETE", fmt.Sprint("/api/route-patterns/", pats[0].ID), nil), http.StatusNoContent)
	status(t, sh.post(access("GET", "api.example.com", "/blog/newer-post")), http.StatusAccepted)
	if find(h.routes(pub), "GET", "api.example.com", "/blog/newer-post") == nil {
		t.Fatal("after deleting the pattern, new paths are not grouped")
	}
	acts := h.actions()
	if !slices.Contains(acts, "route_pattern.create api.example.com/blog/*") || !slices.Contains(acts, "route_pattern.delete api.example.com/blog/*") {
		t.Fatalf("audit = %v", acts)
	}
}

type flowView struct {
	Version *int64                 `json:"version"`
	Draft   bool                   `json:"draft"`
	Sample  TestRequest            `json:"sample"`
	Result  SimView                `json:"result"`
	Rules   map[string][]ruleMatch `json:"rules"`
}

// A new, broader pattern leaves routes a more specific pattern groups.
func TestBroaderPatternKeepsSpecificRoutes(t *testing.T) {
	h, pub := published(t)
	sh := h.shipper()
	status(t, pub.do("POST", "/api/route-patterns", map[string]string{"host": "", "pattern": "/api/users/*"}), http.StatusCreated)
	status(t, sh.post(access("GET", "api.example.com", "/api/users/jane"), access("GET", "api.example.com", "/api/teams/core")), http.StatusAccepted)
	h.routes(pub)
	status(t, pub.do("POST", "/api/route-patterns", map[string]string{"host": "", "pattern": "/api/*/*"}), http.StatusCreated)
	status(t, sh.post(access("GET", "api.example.com", "/api/users/john")), http.StatusAccepted)
	l := h.routes(pub)
	if users, all := find(l, "GET", "api.example.com", "/api/users/{*}"), find(l, "GET", "api.example.com", "/api/{*}/{*}"); len(l.Routes) != 2 || users.Requests != 2 || all.Requests != 1 {
		t.Fatalf("routes = %+v", l)
	}
}

// The flow runs the edge's simulation on a sample of the route and says,
// for every rule, whether it always, never or only sometimes applies.
func TestRouteFlowExplainsEveryRule(t *testing.T) {
	h, pub := published(t)
	c := testConfig()
	c.ConfigRules = append(c.ConfigRules,
		snapshot.ConfigRule{ID: "users", Expression: mustParse(`starts_with(http.request.uri.path, "/users/")`), Settings: snapshot.Settings{BodyLimit: new(int64(512))}},
		snapshot.ConfigRule{ID: "beta", Expression: mustParse(`http.request.headers["x-beta"] eq "1"`), Settings: snapshot.Settings{BodyLimit: new(int64(256))}},
		snapshot.ConfigRule{ID: "non-beta-users", Expression: mustParse(`not (http.request.headers["x-beta"] eq "1") and starts_with(http.request.uri.path, "/users/")`), Settings: snapshot.Settings{BodyLimit: new(int64(128))}},
		snapshot.ConfigRule{ID: "one-user", Expression: mustParse(`http.request.uri.path eq "/users/42"`), Settings: snapshot.Settings{BodyLimit: new(int64(64))}},
		snapshot.ConfigRule{ID: "has-42", Expression: mustParse(`http.request.uri.path contains "42"`), Settings: snapshot.Settings{BodyLimit: new(int64(48))}},
		snapshot.ConfigRule{ID: "other-host", Expression: mustParse(`http.host eq "other.example.com" and http.request.headers["x-beta"] eq "1"`), Settings: snapshot.Settings{BodyLimit: new(int64(32))}},
	)
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	status(t, pub.publishDraft("v2"), 201)
	status(t, h.shipper().post(access("GET", "api.example.com", "/users/7", "edge.query_keys", []string{"page"})), http.StatusAccepted)
	id := find(h.routes(pub), "GET", "api.example.com", "/users/{id}").ID

	f := decode[flowView](t, pub.do("GET", fmt.Sprintf("/api/observed-routes/%d/flow", id), nil))
	if f.Version == nil || *f.Version != 2 || f.Draft || f.Sample.Path != "/users/1?page=x" {
		t.Fatalf("flow = %+v", f)
	}
	if !slices.Equal(f.Result.ConfigRules, []string{"users", "non-beta-users"}) || f.Result.Settings.BodyLimit != 128 {
		t.Fatalf("simulated = %+v", f.Result)
	}
	want := []ruleMatch{
		{ID: "admin-route", Match: matchNever},
		{ID: "users", Match: matchAlways},
		{ID: "beta", Match: matchDepends, DependsOn: []string{"Header x-beta"}},
		{ID: "non-beta-users", Match: matchDepends, DependsOn: []string{"Header x-beta"}},
		{ID: "one-user", Match: matchDepends, DependsOn: []string{"Path value"}},
		{ID: "has-42", Match: matchDepends, DependsOn: []string{"Path value"}},
		{ID: "other-host", Match: matchNever},
	}
	if got := f.Rules["config"]; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("config rules = %+v", got)
	}
	if got := f.Rules["rate_limit"]; fmt.Sprint(got) != fmt.Sprint([]ruleMatch{{ID: "login", Match: matchNever}}) {
		t.Fatalf("rate limit rules = %+v", got)
	}

	// The draft is shown before it is published.
	c.RateLimitRules = append(c.RateLimitRules, snapshot.RateLimitRule{ID: "users-burst", Expression: mustParse(`starts_with(http.request.uri.path, "/users/")`),
		Algorithm: "sliding_window", Limit: 5, Period: snapshot.Duration(time.Second), Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"})
	status(t, pub.save(pub.revision(), c, adminTest), 200)
	d := decode[flowView](t, pub.do("GET", fmt.Sprintf("/api/observed-routes/%d/flow?version=draft", id), nil))
	if !d.Draft || !slices.Equal(d.Result.RateLimitRules, []string{"users-burst"}) || fmt.Sprint(d.Rules["rate_limit"][1]) != fmt.Sprint(ruleMatch{ID: "users-burst", Match: matchAlways}) {
		t.Fatalf("draft flow = %+v", d)
	}
	status(t, pub.do("GET", fmt.Sprintf("/api/observed-routes/%d/flow?version=abc", id), nil), http.StatusBadRequest)
	status(t, pub.do("GET", "/api/observed-routes/999999/flow", nil), http.StatusNotFound)
}

// A new rule can start from a condition that matches the route, and that
// condition is valid and matches the route's sample.
func TestRouteConditionStartsANewRule(t *testing.T) {
	h, pub := published(t)
	status(t, h.shipper().post(access("GET", "api.example.com", "/users/7/orders"), access("GET", "api.example.com", "/health"), access("GET", "api.example.com", "/static/app.3f9a1c2b7d.js")), http.StatusAccepted)
	// A grouped route's placeholder, {*}, holds the one character the
	// wildcard escapes.
	status(t, pub.do("POST", "/api/route-patterns", map[string]string{"host": "www.example.com", "pattern": "/blog/*"}), http.StatusCreated)
	status(t, h.shipper().post(access("GET", "www.example.com", "/blog/hello")), http.StatusAccepted)
	l := h.routes(pub)
	for _, c := range []struct{ template, text string }{
		{"/blog/{*}", `http.host eq "www.example.com" and http.request.method eq "GET" and http.request.uri.path wildcard "/blog/*"`},
		{"/users/{id}/orders", `http.host eq "api.example.com" and http.request.method eq "GET" and http.request.uri.path wildcard "/users/*/orders"`},
		{"/health", `http.host eq "api.example.com" and http.request.method eq "GET" and http.request.uri.path eq "/health"`},
		{"/static/app.{hex}.js", `http.host eq "api.example.com" and http.request.method eq "GET" and http.request.uri.path wildcard "/static/app.*.js"`},
	} {
		host := "api.example.com"
		if strings.HasPrefix(c.template, "/blog/") {
			host = "www.example.com"
		}
		r := find(l, "GET", host, c.template)
		got := decode[struct {
			Expression json.RawMessage `json:"expression"`
			Text       string          `json:"text"`
		}](t, pub.do("GET", fmt.Sprintf("/api/observed-routes/%d/condition", r.ID), nil))
		if got.Text != c.text {
			t.Fatalf("condition for %s = %s", c.template, got.Text)
		}
		cfg := testConfig()
		cfg.ConfigRules = append(cfg.ConfigRules, snapshot.ConfigRule{ID: "from-route", Expression: mustParse(got.Text), Settings: snapshot.Settings{BodyLimit: new(int64(10))}})
		status(t, pub.save(pub.revision(), cfg, adminTest), 200)
		f := decode[flowView](t, pub.do("GET", fmt.Sprintf("/api/observed-routes/%d/flow?version=draft", r.ID), nil))
		if !slices.Contains(f.Result.ConfigRules, "from-route") {
			t.Fatalf("the new rule doesn't match %s: %+v", c.template, f.Result)
		}
	}
}

// Ingest is bounded: an oversized line is skipped alone, an oversized
// template or query shape is not stored as a route, and past the concurrent
// limit the shipper is told to retry.
func TestIngestLimits(t *testing.T) {
	h, pub := published(t)
	sh := h.shipper()
	resp := sh.post(access("GET", "api.example.com", "/"+strings.Repeat("a", maxIngestLine)), access("GET", "api.example.com", "/ok"))
	if got := decode[map[string]int](t, resp); got["accepted"] != 1 || got["skipped"] != 1 {
		t.Fatalf("ingest = %v", got)
	}
	long := strings.Repeat("/abcdefgh", 40)
	keys := make([]string, 32)
	for i := range keys {
		keys[i] = fmt.Sprintf("f%c%c_%s", 'a'+i%26, 'a'+i/26, strings.Repeat("q", 30)) // names, not tokens
	}
	status(t, sh.post(access("GET", "api.example.com", long), access("GET", "api.example.com", "/ok", "edge.query_keys", keys)), http.StatusAccepted)
	l := h.routes(pub)
	if ok := find(l, "GET", "api.example.com", "/ok"); len(l.Routes) != 1 || l.NotGrouped != 1 || ok.QueryShapes[otherKey] != 1 {
		t.Fatalf("routes = %+v", l)
	}
	h.wantMetrics("admin_log_batches_busy_total 0")
	for range ingestSlots {
		h.s.ingest <- struct{}{}
	}
	status(t, sh.post(access("GET", "api.example.com", "/")), http.StatusTooManyRequests)
	// A refused batch is resent whole, so only the refusal counts, not its lines.
	h.wantMetrics("admin_log_batches_busy_total 1", `admin_log_lines_total{result="accepted"} 3`)
}

// Route hours older than retention are dropped, then routes with none left.
func TestRouteRetention(t *testing.T) {
	h, pub := published(t)
	status(t, h.shipper().post(access("GET", "api.example.com", "/old")), http.StatusAccepted)
	h.routes(pub)
	h.advance(time.Duration(retentionDays+1) * 24 * time.Hour)
	status(t, h.shipper().post(access("GET", "api.example.com", "/new")), http.StatusAccepted)
	h.routes(pub)
	if err := h.s.dropOldStats(t.Context()); err != nil {
		t.Fatal(err)
	}
	var routes []string
	rows, _ := h.db.Query(t.Context(), "SELECT template FROM observed_routes")
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		routes = append(routes, s)
	}
	if !slices.Equal(routes, []string{"/new"}) {
		t.Fatalf("routes after retention = %v", routes)
	}
}

// Any path the edge can log templates without panicking, keeps its segment
// count, and templates to itself again.
func FuzzTemplatePath(f *testing.F) {
	for _, s := range []string{"/", "/users/42", "/a//b/", "/x/550e8400-e29b-41d4-a716-446655440000", "/{id}", "/é/ü"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if !strings.HasPrefix(path, "/") {
			return
		}
		got := templatePath("h", path, nil)
		if strings.Count(got, "/") != strings.Count(path, "/") || templatePath("h", got, nil) != got {
			t.Fatalf("templatePath(%q) = %q", path, got)
		}
	})
}
