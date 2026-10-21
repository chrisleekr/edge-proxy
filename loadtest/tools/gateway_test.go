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
