// Package adminui holds the built admin UI for embedding in cmd/admin.
// Build it with `npm ci && npm run build` before `go build ./cmd/admin`;
// without a build, admin serves the API only.
package adminui

import (
	"embed"
	"io/fs"
)

// dist/.gitkeep is committed so this compiles before the UI is built.
//
//go:embed all:dist
var dist embed.FS

// FS returns the built app, rooted at its index.html.
func FS() fs.FS {
	app, _ := fs.Sub(dist, "dist/app") // a constant, valid path
	return app
}
