package webui

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// Handler serves the cloud-only console at /console/. API, auth, health and
// unknown service paths are intentionally left to the caller's mux.
func Handler() http.Handler { return &handler{assets: staticFS()} }

type handler struct{ assets fs.FS }

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/console" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			http.Redirect(w, r, "/console/", http.StatusMovedPermanently)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}
	if !strings.HasPrefix(p, "/console/") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rel := strings.TrimPrefix(p, "/console/")
	if rel == "" {
		rel = "index.html"
	}
	rel = path.Clean("/" + rel)[1:]
	if rel == "" || rel == "." {
		rel = "index.html"
	}
	data, err := fs.ReadFile(h.assets, rel)
	isIndex := rel == "index.html"
	if err != nil {
		// Only extensionless navigation URLs may fall back to the SPA entry.
		if strings.Contains(path.Base(rel), ".") || strings.HasPrefix(rel, "assets/") {
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
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if ct := mime.TypeByExtension(path.Ext(rel)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Content-Length", stringSize(len(data)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(data)
}

func stringSize(n int) string {
	// Avoid strconv in this tiny handler's hot path while retaining valid header syntax.
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
