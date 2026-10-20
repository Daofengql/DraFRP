package cloud

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func captchaTestEntropy(code string, nonce byte) []byte {
	seed := bytes.Repeat([]byte{nonce}, 512)
	for i := range code {
		seed[i] = byte(strings.IndexByte(captchaAlphabet, code[i]))
	}
	return seed
}
func issueKnownCaptcha(t *testing.T, s *Server, code string, nonce byte) captchaChallenge {
	t.Helper()
	// Only the test substitutes entropy. The real HTTP handler, image encoder,
	// store, TTL, HMAC and single-use validation still execute unchanged.
	s.captchaEntropy = bytes.NewReader(captchaTestEntropy(code, nonce))
	defer func() { s.captchaEntropy = nil }()
	r := httptest.NewRequest("GET", "https://cloud.example/auth/captcha", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("issue captcha %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("captcha response may be cached")
	}
	var response captchaChallenge
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil || len(fields) != 3 {
		t.Fatalf("unexpected captcha fields: %v %v", fields, err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(response.Image, "data:image/png;base64,"))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil || img.Bounds().Dx() != 208 || img.Bounds().Dy() != 64 {
		t.Fatal("captcha is not a bounded PNG", err)
	}
	if response.ID == "" || response.ExpiresAt.Before(time.Now().Add(110*time.Second)) || response.ExpiresAt.After(time.Now().Add(121*time.Second)) {
		t.Fatalf("invalid captcha identity/TTL: %+v", response)
	}
	return response
}

func TestCaptchaHTTPImageHashExpiryAndSingleUse(t *testing.T) {
	s := &Server{key: bytes.Repeat([]byte{3}, 32)}
	challenge := issueKnownCaptcha(t, s, "ABCD23", 1)
	entry := s.captchas[challenge.ID]
	if entry.Digest != s.captchaDigest(challenge.ID, "ABCD23") {
		t.Fatal("captcha did not retain only its keyed answer proof")
	}
	if !s.verifyCaptcha(challenge.ID, " abcd23 ") || s.verifyCaptcha(challenge.ID, "ABCD23") {
		t.Fatal("captcha success was not single use")
	}
	challenge = issueKnownCaptcha(t, s, "ABCD23", 2)
	if s.verifyCaptcha(challenge.ID, "wrong") || s.verifyCaptcha(challenge.ID, "ABCD23") {
		t.Fatal("wrong attempt did not consume captcha")
	}
	challenge = issueKnownCaptcha(t, s, "ABCD23", 3)
	entry = s.captchas[challenge.ID]
	entry.ExpiresAt = time.Now().Add(-time.Second)
	s.captchas[challenge.ID] = entry
	if s.verifyCaptcha(challenge.ID, "ABCD23") {
		t.Fatal("expired captcha accepted")
	}
	if _, ok := s.captchas[challenge.ID]; ok {
		t.Fatal("expired challenge not consumed")
	}
	challenge = issueKnownCaptcha(t, s, "ABCD23", 4)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.verifyCaptcha(challenge.ID, "ABCD23") {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("concurrent captcha replay count=%d", accepted.Load())
	}
}

func TestCaptchaCapacityExpiryCleanupAndSourceRateLimit(t *testing.T) {
	s := &Server{key: bytes.Repeat([]byte{2}, 32), captchas: map[string]captchaEntry{}}
	for i := 0; i < captchaCapacity; i++ {
		s.captchas[fmt.Sprint(i)] = captchaEntry{ExpiresAt: time.Now().Add(time.Minute)}
	}
	if _, err := s.newCaptcha(); err == nil || len(s.captchas) != captchaCapacity {
		t.Fatal("captcha map exceeded its capacity")
	}
	for id, entry := range s.captchas {
		entry.ExpiresAt = time.Now().Add(-time.Second)
		s.captchas[id] = entry
	}
	if _, err := s.newCaptcha(); err != nil || len(s.captchas) != 1 {
		t.Fatal("expired captcha capacity was not recovered", err)
	}
	s = &Server{key: bytes.Repeat([]byte{2}, 32)}
	for i := 0; i < 31; i++ {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "https://cloud.example/auth/captcha", nil))
		want := 200
		if i == 30 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("captcha request %d: %d want %d", i, w.Code, want)
		}
	}
	if len(s.captchas) != 30 {
		t.Fatal("rate-limited request still issued captcha")
	}
}

func TestPublicAuthenticationOptionsAndMethodBoundaries(t *testing.T) {
	s := &Server{}
	for _, disabled := range []bool{false, true} {
		s.cfg.CaptchaDisabled, s.cfg.RegistrationDisabled = disabled, disabled
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "https://cloud.example/auth/options", nil))
		var response map[string]bool
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 || response["captcha_required"] == disabled || response["registration_enabled"] == disabled {
			t.Fatal("options do not reflect explicit configuration", response, err)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("auth options can be cached")
		}
	}
	for _, path := range []string{"/auth/options", "/auth/captcha"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "https://cloud.example"+path, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatal("method not rejected", path, w.Code)
		}
	}
	s.cfg.RegistrationDisabled = false
	s.cfg.CaptchaDisabled = false
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "https://cloud.example/auth/login", strings.NewReader(`{"username":"admin","password":"untrusted"}`)))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "captcha_invalid") {
		t.Fatal("login did not require captcha before database access", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("POST", "https://cloud.example/auth/register", strings.NewReader(`{"username":"attacker","password":"test-password"}`))
	r.Header.Set("Origin", "https://foreign.example")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin public registration accepted", w.Code)
	}
	for i := 0; i < 11; i++ {
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "https://cloud.example/auth/register", strings.NewReader(`{"username":"attacker","password":"test-password"}`)))
		want := 400
		if i == 10 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("registration source rate limit %d: %d want %d", i, w.Code, want)
		}
	}
}
