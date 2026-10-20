package webui

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// Handler serves only the cloud console. API, authentication and probes remain
// owned by the caller's mux. Development builds intentionally do not require dist.
func Handler() http.Handler { return &handler{assets: staticFS()} }

type handler struct{ assets fs.FS }

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p != "/console" && !strings.HasPrefix(p, "/console/") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p == "/console" {
		http.Redirect(w, r, "/console/", http.StatusMovedPermanently)
		return
	}
	rel := strings.TrimPrefix(p, "/console/")
	// Reject traversal rather than canonicalizing it into another embedded file.
	if strings.Contains(rel, "\\") || strings.Contains(rel, "\x00") {
		http.NotFound(w, r)
		return
	}
	for _, segment := range strings.Split(rel, "/") {
		if segment == "." || segment == ".." {
			http.NotFound(w, r)
			return
		}
	}
	if rel == "" {
		rel = "index.html"
	}
	data, err := fs.ReadFile(h.assets, rel)
	isIndex := rel == "index.html"
	if err != nil {
		// Missing files and non-navigation requests must receive a real 404. A dot
		// may legitimately occur in a binding code; only the last path component
		// with a file extension is excluded from SPA fallback.
		accept := r.Header.Get("Accept")
		if path.Ext(rel) != "" || rel == "assets" || strings.HasPrefix(rel, "assets/") || (accept != "" && !strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*")) {
			http.NotFound(w, r)
			return
		}
		data, err = fs.ReadFile(h.assets, "index.html")
		isIndex = true
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if isIndex {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else {
		// Only Vite's content-hashed asset namespace is immutable. Build metadata
		// and public files can change between releases under a stable filename.
		if strings.HasPrefix(rel, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if ct := mime.TypeByExtension(path.Ext(rel)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", fmt.Sprintf(`"%x"`, sha256.Sum256(data)))
	// ServeContent correctly handles HEAD, byte ranges and conditional requests.
	// No on-the-fly compression is applied, so there is no representation mismatch.
	http.ServeContent(w, r, rel, time.Time{}, bytes.NewReader(data))
}
