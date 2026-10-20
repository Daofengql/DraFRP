package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func fixture() http.Handler {
	return &handler{assets: fstest.MapFS{
		"index.html":              {Data: []byte("<!doctype html><main>console</main>")},
		"assets/index-abc123.js":  {Data: []byte("console.log('embedded')")},
		"assets/index-abc123.css": {Data: []byte("body{margin:0}")},
		"build.json":              {Data: []byte(`{"build_id":"test"}`)},
	}}
}

func TestNavigationAndServiceIsolation(t *testing.T) {
	for _, tc := range []struct {
		path, method, accept string
		status               int
		html                 bool
	}{
		{"/console", "GET", "", 301, false},
		{"/console/", "GET", "text/html", 200, true},
		{"/console/devices/agent-123", "GET", "text/html", 200, true},
		{"/console/bind/ONETIME", "HEAD", "text/html", 200, true},
		{"/console/not-a-page", "GET", "text/html", 200, true}, // SPA renders its own 404.
		{"/console/not-a-page", "GET", "application/json", 404, false},
		{"/console/assets/missing.js", "GET", "*/*", 404, false},
		{"/console/missing.css", "GET", "text/html", 404, false},
		{"/console/assets/missing", "GET", "text/html", 404, false},
		{"/console/assets", "GET", "text/html", 404, false},
		{"/console/../build.json", "GET", "text/html", 404, false},
		{"/console/devices/1", "POST", "text/html", 405, false},
		{"/console/", "OPTIONS", "*/*", 405, false},
		{"/api/v1/missing", "GET", "text/html", 404, false},
		{"/auth/callback", "GET", "text/html", 404, false},
		{"/healthz", "GET", "text/html", 404, false},
	} {
		t.Run(tc.method+tc.path+tc.accept, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Header.Set("Accept", tc.accept)
			w := httptest.NewRecorder()
			fixture().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.html && !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("navigation MIME %q", w.Header().Get("Content-Type"))
			}
			if tc.method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD returned a body")
			}
			if tc.html && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("navigation may be cached")
			}
		})
	}
}

func TestAssetCacheHeadAndConditionalRequests(t *testing.T) {
	h := fixture()
	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest("GET", "/console/assets/index-abc123.js", nil))
	if get.Code != 200 || !strings.Contains(get.Header().Get("Content-Type"), "javascript") || !strings.Contains(get.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset response: %d %v", get.Code, get.Header())
	}
	head := httptest.NewRecorder()
	h.ServeHTTP(head, httptest.NewRequest("HEAD", "/console/assets/index-abc123.js", nil))
	for _, header := range []string{"Content-Type", "Content-Length", "Cache-Control", "ETag"} {
		if get.Header().Get(header) == "" || head.Header().Get(header) != get.Header().Get(header) {
			t.Fatalf("HEAD differs: %s", header)
		}
	}
	if head.Body.Len() != 0 {
		t.Fatal("HEAD body")
	}
	r := httptest.NewRequest("GET", "/console/assets/index-abc123.js", nil)
	r.Header.Set("If-None-Match", get.Header().Get("ETag"))
	notModified := httptest.NewRecorder()
	h.ServeHTTP(notModified, r)
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Fatalf("conditional response %d", notModified.Code)
	}
	metadata := httptest.NewRecorder()
	h.ServeHTTP(metadata, httptest.NewRequest("GET", "/console/build.json", nil))
	if strings.Contains(metadata.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("stable metadata cannot be immutable")
	}
	if got, _ := io.ReadAll(metadata.Result().Body); !strings.Contains(string(got), "test") {
		t.Fatal("metadata not served")
	}
}

func TestBuildModeHasIndex(t *testing.T) {
	// In a release run this verifies the actual embedded Vite entry, without
	// depending on a filesystem dist at runtime. Default tests use devIndex.
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest("GET", "/console/sites/example", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<!doctype html>") {
		t.Fatalf("embedded index unavailable: %d", w.Code)
	}
}
