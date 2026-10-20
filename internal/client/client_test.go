package client

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"drafrp/internal/model"
)

func TestBindingFingerprintUsesConsoleContract(t *testing.T) {
	// RFC 8032 test vector 1 fixes the public key independently of this
	// implementation; the console hashes its Base64 spelling, not raw bytes.
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{key: ed25519.NewKeyFromSeed(seed)}
	const expected = "c9fc2f15f22401655f9b2622a8a37651c9e20b74dc305cc8df95ba005e1d64f9"
	if got := a.PublicKeyFingerprint(); got != expected {
		t.Fatalf("binding fingerprint %q differs from console contract %q", got, expected)
	}
}

func TestIndependentPersistentDeviceBindingAndProcessSessions(t *testing.T) {
	var pub ed25519.PublicKey
	var mu sync.Mutex
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/runtime/client/bind":
			var in model.BindRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			b, _ := base64.StdEncoding.DecodeString(in.PublicKey)
			pub = b
			_ = json.NewEncoder(w).Encode(model.BindResponse{ID: "binding", UserCode: "ABCD", PollToken: "secret", VerificationURI: "https://cloud.example/devices", ExpiresAt: time.Now().Add(time.Minute), Status: "pending"})
		case "/api/v1/runtime/client/bind/poll":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["id"] != "binding" || in["poll_token"] != "secret" {
				t.Error("incorrect binding credentials")
			}
			_ = json.NewEncoder(w).Encode(model.BindResponse{ID: "binding", DeviceID: "device", Status: "approved"})
		case "/api/v1/runtime/client/sync":
			var in model.ClientSyncRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			sig, _ := base64.StdEncoding.DecodeString(in.Signature)
			if !ed25519.Verify(pub, model.ClientSyncPayload(in), sig) || in.Nonce == "" || in.SessionID == "" {
				t.Error("sync is not bound to its complete payload")
			}
			_ = json.NewEncoder(w).Encode(model.ClientSnapshot{Revision: 1, ExpiresAt: time.Now().Add(time.Minute), Device: model.DeviceGrant{DeviceID: "device", TenantID: "tenant", PublicKey: base64.StdEncoding.EncodeToString(pub), Generation: 1, SessionID: in.SessionID, ExpiresAt: time.Now().Add(time.Minute)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	cfg := Config{CloudURL: srv.URL, StateDir: dir}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(cfg); err == nil {
		t.Fatal("a second process can overwrite the active identity")
	}
	firstKey := base64.StdEncoding.EncodeToString(a.key)
	firstSession := a.st.SessionID
	br, err := a.Bind(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.PollBind(context.Background(), "another-device", br.PollToken); err == nil {
		t.Fatal("unrelated binding was accepted")
	}
	if _, err = a.PollBind(context.Background(), br.ID, br.PollToken); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !a.Bound() {
		t.Fatal("approved identity was not applied")
	}
	a.Close()
	a, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if !a.Bound() || base64.StdEncoding.EncodeToString(a.key) != firstKey || a.st.SessionID == firstSession {
		t.Fatal("key persistence or fresh process session failed")
	}
	if _, err = a.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{CloudURL: srv.URL, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if base64.StdEncoding.EncodeToString(b.key) == firstKey || b.Bound() {
		t.Fatal("new directory shares the previous device authority")
	}
	info, err := os.Stat(filepath.Join(dir, "device.json"))
	if err != nil || info.Size() == 0 {
		t.Fatal("device identity was not persisted")
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 4 {
		t.Fatalf("unexpected cloud requests: %d", requests)
	}
}

func TestLocalTargetScopeChecksResolvedIPAndPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, tc := range []struct {
		name   string
		cidrs  []string
		ports  []int
		denied bool
	}{
		{"localhost DNS pinned to allowed IPv4", []string{"127.0.0.0/8"}, nil, false},
		{"mapped IPv4 prefix", []string{"::ffff:127.0.0.0/104"}, nil, false},
		{"resolved IP denied", []string{"192.0.2.0/24"}, nil, true},
		{"explicit empty scope", []string{}, nil, true},
		{"port denied", nil, []int{1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Agent{cfg: Config{AllowedTargetCIDRs: tc.cidrs, AllowedTargetPorts: tc.ports}}
			c, err := a.dialTarget(ctx, "tcp", net.JoinHostPort("localhost", port))
			if (err != nil) != tc.denied {
				if c != nil {
					c.Close()
				}
				t.Fatalf("dial %v", err)
			}
			if c != nil {
				if !strings.HasPrefix(c.RemoteAddr().String(), "127.") {
					t.Fatal("resolver result was not pinned")
				}
				c.Close()
			}
		})
	}
}

func TestSnapshotDoesNotExposeMutableAuthorization(t *testing.T) {
	a, err := New(Config{CloudURL: "http://127.0.0.1", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.mu.Lock()
	a.snap.Rules = []model.Rule{{ID: "r", Target: "127.0.0.1:1"}}
	a.snap.Edges = []model.Edge{{ID: "e", Endpoints: []model.Endpoint{{Address: "127.0.0.1:2"}}}}
	a.mu.Unlock()
	s := a.Snapshot()
	s.Rules[0].Target = "other"
	s.Edges[0].Endpoints[0].Address = "other"
	s = a.Snapshot()
	if s.Rules[0].Target != "127.0.0.1:1" || s.Edges[0].Endpoints[0].Address != "127.0.0.1:2" {
		t.Fatal("caller mutated live authorization")
	}
}

func TestCloseCancelsCloudOperations(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		close(finished)
	}))
	defer srv.Close()
	a, err := New(Config{CloudURL: srv.URL, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := a.Bind(context.Background()); done <- err }()
	<-started
	closed := make(chan struct{})
	go func() { a.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel cloud request")
	}
	if err := <-done; err == nil {
		t.Fatal("cancelled bind succeeded")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("HTTP connection was retained")
	}
}
