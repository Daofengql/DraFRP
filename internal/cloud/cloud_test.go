package cloud

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"drafrp/internal/model"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEncryptionAuthenticatesCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	a, e := encrypt(key, "sensitive certificate key")
	if e != nil {
		t.Fatal(e)
	}
	b, e := encrypt(key, "sensitive certificate key")
	if e != nil || a == b {
		t.Fatal("encryption must use independent nonces")
	}
	plain, e := decrypt(key, a)
	if e != nil || plain != "sensitive certificate key" {
		t.Fatalf("roundtrip: %q %v", plain, e)
	}
	raw, _ := base64.StdEncoding.DecodeString(a)
	raw[len(raw)-1] ^= 1
	if _, e = decrypt(key, base64.StdEncoding.EncodeToString(raw)); e == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	for _, v := range []string{"not-base64", base64.StdEncoding.EncodeToString([]byte{1})} {
		if _, e = decrypt(key, v); e == nil {
			t.Fatal("malformed ciphertext accepted")
		}
	}
	if _, e = encrypt([]byte{1}, "x"); e == nil {
		t.Fatal("invalid AES key accepted")
	}
}
func TestJSONRejectsUnknownAndTrailingValues(t *testing.T) {
	for _, v := range []string{`{"known":1,"unknown":2}`, `{"known":1} {"known":2}`, `{"known":1} null`, strings.Repeat(" ", 2<<20) + `{}`} {
		var target struct {
			Known int `json:"known"`
		}
		req := httptest.NewRequest("POST", "/", strings.NewReader(v))
		if e := readJSON(httptest.NewRecorder(), req, &target); e == nil {
			t.Fatalf("accepted invalid payload (length %d)", len(v))
		}
	}
}
func TestBrowserOriginAndBoundedLoginLimiter(t *testing.T) {
	s := &Server{}
	for _, origin := range []string{"https://other.example", "null", "https://same.example/path", "https://same.example?x=1"} {
		r := httptest.NewRequest("POST", "https://same.example/auth/login", nil)
		r.Header.Set("Origin", origin)
		if sameOrigin(r) {
			t.Fatalf("accepted origin %q", origin)
		}
	}
	r := httptest.NewRequest("POST", "https://same.example/auth/login", nil)
	r.Header.Set("Origin", "https://same.example")
	if !sameOrigin(r) {
		t.Fatal("same-origin rejected")
	}
	for i := 0; i < 20; i++ {
		if !s.allowLogin(r) {
			t.Fatalf("early limit at %d", i)
		}
	}
	if s.allowLogin(r) {
		t.Fatal("login attempts unbounded")
	}
	s.loginAttempts = map[string]loginAttempt{}
	for i := 0; i < 4096; i++ {
		s.loginAttempts[string(rune(i))] = loginAttempt{until: time.Now().Add(time.Minute)}
	}
	if s.allowLogin(r) || len(s.loginAttempts) != 4096 {
		t.Fatal("source cardinality bound failed")
	}
}
func TestRuleValidationSeparatesSourceModes(t *testing.T) {
	r := model.Rule{Name: "test", Protocol: "tcp", Target: "127.0.0.1:80", SourceMode: "socket", Transport: "auto", TimeoutSeconds: 30}
	if e := validateRule(r); e != nil {
		t.Fatal("automatic port allocation should be valid", e)
	}
	r.SourceMode = "native"
	if e := validateRule(r); e != nil {
		t.Fatal("native syntax should be validated separately from runtime capability", e)
	}
	r.Target = "[2001:db8::1]:80"
	if e := validateRule(r); e == nil {
		t.Fatal("unverified native IPv6 accepted")
	}
	r.Protocol = "http"
	r.Domain = "example.test"
	r.Target = "http://127.0.0.1:80"
	r.SourceMode = "forwarded_headers"
	if e := validateRule(r); e != nil {
		t.Fatal(e)
	}
	r.Target = "http://user:password@127.0.0.1:80"
	if e := validateRule(r); e == nil {
		t.Fatal("embedded credentials accepted")
	}
	for _, domain := range []string{"127.0.0.1", "a..test", "-a.test", "a_.test", "*.test"} {
		if validDomain(domain) {
			t.Fatalf("invalid domain %q accepted", domain)
		}
	}
}
func TestClientSignatureBindsEveryMutableField(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	r := model.ClientSyncRequest{DeviceID: "device", SessionID: "session-long-enough", Nonce: "nonce-long-enough", Timestamp: time.Now().Unix(), Capabilities: []string{"tcp"}, AppliedRevision: 5}
	sig := ed25519.Sign(key, model.ClientSyncPayload(r))
	if !ed25519.Verify(pub, model.ClientSyncPayload(r), sig) {
		t.Fatal("valid signature rejected")
	}
	r.Capabilities = []string{"native_tcp_v4"}
	if ed25519.Verify(pub, model.ClientSyncPayload(r), sig) {
		t.Fatal("capability tampering not detected")
	}
	encoded, _ := json.Marshal(r)
	if bytes.Contains(encoded, []byte("private")) {
		t.Fatal("private key leaked")
	}
}
