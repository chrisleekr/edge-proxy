package admin

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func uiServer(t *testing.T, ui fstest.MapFS) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	cfg, err := LoadConfig(env(baseEnv("postgres://unused")))
	if err != nil {
		t.Fatal(err)
	}
	if ui != nil {
		cfg.UI = ui
	}
	var logs bytes.Buffer
	srv := httptest.NewServer(NewServer(cfg, nil, slog.New(slog.NewJSONHandler(&logs, nil))).Handler())
	t.Cleanup(srv.Close)
	return srv, &logs
}

func TestUIServing(t *testing.T) {
	srv, _ := uiServer(t, fstest.MapFS{
		"index.html":          {Data: []byte("<!doctype html>app")},
		"assets/index-abc.js": {Data: []byte("console.log(1)")},
		"favicon.svg":         {Data: []byte("<svg/>")},
	})
	cases := []struct {
		name, path   string
		status       int
		body, cache  string
		contentStart string
	}{
		{"root serves the app", "/", 200, "<!doctype html>app", "no-cache", "text/html"},
		{"a client route reloads into the app", "/versions/12", 200, "<!doctype html>app", "no-cache", "text/html"},
		{"hashed assets are cached for good", "/assets/index-abc.js", 200, "console.log(1)", "public, max-age=31536000, immutable", "text/javascript"},
		{"other files are served without long caching", "/favicon.svg", 200, "<svg/>", "", "image/svg+xml"},
		{"an unknown API path stays a JSON 404", "/api/nope", 404, "", "no-store", "application/problem+json"},
		{"an unknown edge path stays a JSON 404", "/v1/nope", 404, "", "no-store", "application/problem+json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.status || tc.body != "" && string(b) != tc.body || resp.Header.Get("Cache-Control") != tc.cache ||
				!strings.HasPrefix(resp.Header.Get("Content-Type"), tc.contentStart) {
				t.Fatalf("%d %q, cache %q, type %q", resp.StatusCode, b, resp.Header.Get("Cache-Control"), resp.Header.Get("Content-Type"))
			}
			if tc.status == 200 && (resp.Header.Get("Content-Security-Policy") != uiSecurity || resp.Header.Get("X-Content-Type-Options") != "nosniff") {
				t.Fatalf("security headers %v", resp.Header)
			}
		})
	}
}

func TestUINotBuilt(t *testing.T) {
	srv, logs := uiServer(t, fstest.MapFS{".gitkeep": {}})
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 || !strings.Contains(logs.String(), "admin UI not built") {
		t.Fatalf("status %d, logs %s", resp.StatusCode, logs)
	}
}
