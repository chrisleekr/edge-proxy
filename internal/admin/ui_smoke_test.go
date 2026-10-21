package admin

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestUISmoke runs the Playwright smoke tests in a browser
// against a real admin and Postgres. It needs Node and a built UI, so it
// runs only with UI_SMOKE=1 (scripts/ci/ui.sh).
func TestUISmoke(t *testing.T) {
	if os.Getenv("UI_SMOKE") == "" {
		t.Skip("set UI_SMOKE=1 after building web/admin")
	}
	ui := os.DirFS("../../web/admin/dist/app")
	if _, err := fs.Stat(ui, "index.html"); err != nil {
		t.Fatal("build the UI first: npm run build in web/admin")
	}
	h := newHarness(t)
	h.s.now = time.Now // the browser acts in real time
	h.s.cfg.UI = ui
	h.s.uiRoutes()
	h.user("smoke", "admin")

	// Access lines for the Routes page: a rate limited login, and blog
	// posts enough alike for a grouping suggestion.
	lines := []string{}
	for i := range 10 {
		if i < 2 {
			lines = append(lines, access("POST", "api.example.com", "/login", "http.response.status_code", 429, "edge.decision", "rate_limited", "edge.rate_limit_rule", "login"))
			continue
		}
		lines = append(lines, access("POST", "api.example.com", "/login"))
	}
	for i := range 22 {
		lines = append(lines, access("GET", "www.example.com", fmt.Sprintf("/blog/post-%c", 'a'+i), "edge.query_keys", []string{"utm_source"}))
	}
	status(t, h.shipper().post(lines...), http.StatusAccepted)
	if err := h.s.flushRoutes(t.Context()); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("npx", "playwright", "test")
	cmd.Dir = "../../web/admin"
	cmd.Env = append(os.Environ(), "BASE_URL="+h.srv.URL, "SMOKE_USER=smoke", "SMOKE_PASSWORD="+goodPassword)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("playwright: %v", err)
	}
}
