package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed assets
var assetsFS embed.FS

// The console's whole job is to render data it does not control, so a value
// from a table must never be able to become script. Everything it loads is
// served from this binary, which is what lets script-src stay at 'self' with
// no nonce, no hashes, and no eval.
//
// style-src is the one relaxation. CodeMirror positions its cursor, selection
// layer, and tooltips with style attributes, which no nonce can cover: CSP3
// ignores 'unsafe-inline' entirely when a nonce or hash is present in the same
// directive, so it is one or the other, and an editor without cursor
// positioning is not an editor.
//
// The exposure that buys is small, and deliberately bounded by the rest of the
// policy. CSS injection matters mainly as an exfiltration channel — attribute
// selectors paired with an outbound request — and img-src, font-src, and
// connect-src are all pinned to 'self', so there is nowhere to exfiltrate to.
// The console also never interpolates data into styles: every value from the
// database reaches the page through textContent.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'"

func assetHandler() http.Handler {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		panic("web: embedded assets missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		// Nothing here is cached: the console must never serve a stale
		// bundle against a newer API.
		h.Set("Cache-Control", "no-store")

		// The console is a single page; unknown paths render it rather than
		// 404ing, so a refresh on any route works.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		files.ServeHTTP(w, r)
	})
}
