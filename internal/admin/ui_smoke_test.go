package admin

import (
	"io/fs"
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

	cmd := exec.Command("npx", "playwright", "test")
	cmd.Dir = "../../web/admin"
	cmd.Env = append(os.Environ(), "BASE_URL="+h.srv.URL, "SMOKE_USER=smoke", "SMOKE_PASSWORD="+goodPassword)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("playwright: %v", err)
	}
}
