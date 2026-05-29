// Package ui exposes webcore's embedded static frontend assets (JS and CSS).
// Consumers mount StaticFiles under their /static route:
//
//	staticFS, _ := fs.Sub(ui.StaticFiles, "static")
//	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
//
// templ components live in the sibling ui/components package.
package ui

import "embed"

// StaticFiles holds the embedded static/ tree (JS, CSS).
//
//go:embed all:static
var StaticFiles embed.FS
