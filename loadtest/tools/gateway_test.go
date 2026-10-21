package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The gateway behind the edge sends each path to its service by the longest
// matching prefix, with the Host the edge forwarded.
func TestGatewayRoutesByLongestPrefix(t *testing.T) {
	svc := func(name string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, name+" "+r.Host+" "+r.URL.Path)
		}))
		t.Cleanup(s.Close)
		return s
	}
	orders, catalog := svc("orders"), svc("catalog")
	h, err := newGateway("/=" + catalog.URL + ",/api/orders=" + orders.URL)
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(h)
	t.Cleanup(gw.Close)
	for path, want := range map[string]string{"/api/orders/7": "orders api.example.com /api/orders/7", "/api/fast": "catalog api.example.com /api/fast"} {
		req, _ := http.NewRequest("GET", gw.URL+path, nil)
		req.Host = "api.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != want {
			t.Errorf("%s: got %q, want %q", path, b, want)
		}
	}
	if _, err := newGateway("api=http://x"); err == nil {
		t.Error("a prefix without a leading slash was accepted")
	}
}

// Services behind the gateway see the forwarding headers the edge set, as
// they would behind a real LB.
func TestGatewayKeepsEdgeForwardingHeaders(t *testing.T) {
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Forwarded-For")+" "+r.Header.Get("X-Forwarded-Host")+" "+r.Header.Get("X-Forwarded-Proto"))
	}))
	t.Cleanup(svc.Close)
	h, err := newGateway("/=" + svc.URL)
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(h)
	t.Cleanup(gw.Close)
	req, _ := http.NewRequest("GET", gw.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.Header.Set("X-Forwarded-Host", "api.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := "198.51.100.7 api.example.com https"; string(b) != want {
		t.Errorf("service saw %q, want %q", b, want)
	}
}
