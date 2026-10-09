package main

import (
	"embed"
	"net/http"
)

//go:embed openapi.json docs.html
var docsFS embed.FS

func serveSpec(w http.ResponseWriter) {
	b, _ := docsFS.ReadFile("openapi.json")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}
func serveDocs(w http.ResponseWriter) {
	b, _ := docsFS.ReadFile("docs.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Write(b)
}
