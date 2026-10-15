package admin

import (
	"io/fs"
	"net/http"
	"strings"
)

func (s *Server) routes() {
	s.identityRoutes()
	s.configRoutes()
	s.edgeRoutes()
	s.canaryRoutes()
	s.guardRoutes()
	s.auditRoutes()
	s.uiRoutes()
}

// uiSecurity limits the SPA to its own scripts and forbids framing.
// CodeMirror injects <style> elements, so styles allow 'unsafe-inline';
// scripts stay 'self' only, which is what blocks injected code.
const uiSecurity = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

// uiRoutes serves the embedded SPA. Paths that are not files
// get index.html, so client-side routes load on refresh. Unknown API paths
// stay JSON 404s.
func (s *Server) uiRoutes() {
	if s.cfg.UI == nil {
		return
	}
	index, err := fs.ReadFile(s.cfg.UI, "index.html")
	if err != nil {
		s.log.Warn("admin UI not built; serving the API only")
		return
	}
	files := http.FileServerFS(s.cfg.UI)
	s.public("GET /", func(w http.ResponseWriter, r *http.Request) error {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") {
			return fail(http.StatusNotFound, "no such endpoint")
		}
		h := w.Header()
		h.Set("Content-Security-Policy", uiSecurity)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		name := strings.TrimPrefix(r.URL.Path, "/")
		if st, err := fs.Stat(s.cfg.UI, name); err == nil && !st.IsDir() && name != "index.html" {
			// Vite puts a content hash in every asset name.
			if strings.HasPrefix(name, "assets/") {
				h.Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			files.ServeHTTP(w, r)
			return nil
		}
		h.Set("Cache-Control", "no-cache")
		h.Set("Content-Type", "text/html; charset=utf-8")
		_, err := w.Write(index)
		return err
	})
}
