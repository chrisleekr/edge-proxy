package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// Each service answers its routes with the size and status a real one would,
// reports its own time in Server-Timing, and 404s routes it doesn't own, so a
// misrouted request shows up as an error in the load test.
func TestServicesAnswerTheirRoutes(t *testing.T) {
	cases := []struct {
		name, service, method, path string
		header                      map[string]string
		status, minSize, maxSize    int
	}{
		{"catalog items are 2 to 8 KB of JSON", "catalog", "GET", "/api/items", nil, 200, 2 << 10, 8 << 10},
		{"catalog fast is a small answer", "catalog", "GET", "/api/fast", nil, 200, 200, 200},
		{"orders accept a body", "orders", "POST", "/api/orders", nil, 201, 512, 512},
		{"login accepts a form", "account", "POST", "/login", nil, 200, 256, 256},
		{"private page with the edge's verified subject", "account", "GET", "/private/me", map[string]string{"X-Edge-Auth-Sub": "u1"}, 200, 1 << 10, 1 << 10},
		{"pages are 30 KB of HTML", "content", "GET", "/pages/home", nil, 200, 30 << 10, 30 << 10},
		{"static files are 100 KB or 1 MB", "content", "GET", "/static/app.js", nil, 200, 100 << 10, 1 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader("item=1"))
			for k, v := range tc.header {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			services[tc.service](w, r)
			if w.Code != tc.status || w.Body.Len() < tc.minSize || w.Body.Len() > tc.maxSize {
				t.Fatalf("status %d, %d bytes", w.Code, w.Body.Len())
			}
			if !strings.HasPrefix(w.Header().Get("Server-Timing"), "app;dur=") {
				t.Fatalf("Server-Timing %q", w.Header().Get("Server-Timing"))
			}
		})
	}
}

// A private request that reaches the account service without a verified
// subject means the edge skipped auth; it must fail loudly, not pass.
func TestPrivateWithoutEdgeSubjectFails(t *testing.T) {
	w := httptest.NewRecorder()
	services["account"](w, httptest.NewRequest("GET", "/private/me", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", w.Code)
	}
}

func TestServiceRefusesOtherServicesRoutes(t *testing.T) {
	w := httptest.NewRecorder()
	services["catalog"](w, httptest.NewRequest("GET", "/login", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
}

// The latency draw has the asked-for median and p99, within sampling noise.
func TestLognormalMatchesMedianAndP99(t *testing.T) {
	const n = 20000
	d := make([]time.Duration, n)
	for i := range d {
		d[i] = lognormal(15*time.Millisecond, 120*time.Millisecond)
	}
	slices.Sort(d)
	med, p99 := d[n/2], d[n*99/100]
	if med < 13*time.Millisecond || med > 17*time.Millisecond || p99 < 100*time.Millisecond || p99 > 140*time.Millisecond {
		t.Fatalf("median %v, p99 %v", med, p99)
	}
}
