package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"drafrp/internal/model"
)

func TestHTTPFamiliesShareConnectionBudget(t *testing.T) {
	slots := make(chan struct{}, 1)
	var listeners []*limitedListener
	for i := 0; i < 2; i++ {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		listeners = append(listeners, &limitedListener{Listener: ln, slots: slots, ctx: context.Background()})
	}
	accept := func(l *limitedListener) <-chan net.Conn {
		out := make(chan net.Conn, 1)
		go func() {
			c, err := l.Accept()
			if err == nil {
				out <- c
			}
		}()
		return out
	}
	first := accept(listeners[0])
	visitor, err := net.Dial("tcp4", listeners[0].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	var held net.Conn
	select {
	case held = <-first:
	case <-time.After(time.Second):
		t.Fatal("first listener did not accept")
	}
	defer held.Close()
	second := accept(listeners[1])
	blocked, err := net.Dial("tcp4", listeners[1].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	blocked.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := blocked.Read(make([]byte, 1)); err == nil {
		t.Fatal("second family bypassed shared limit")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("excess HTTP connection retained")
	}
	if len(slots) != 1 {
		t.Fatal("shared connection count changed")
	}
	held.Close()
	next, err := net.Dial("tcp4", listeners[1].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	select {
	case c := <-second:
		c.Close()
	case <-time.After(time.Second):
		t.Fatal("budget not released for another listener")
	}
}

func TestDualStackHTTPAndIPv4BusinessListeners(t *testing.T) {
	v6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	v6.Close()
	f := fixture(t, model.Rule{ID: "tcp", Protocol: "tcp", Target: "127.0.0.1:80"}, model.Rule{ID: "udp", Protocol: "udp", Target: "127.0.0.1:80"}, model.Rule{ID: "http", Protocol: "http", SourceMode: "forwarded_headers", Domain: "site.test", Target: "http://127.0.0.1"})
	f.r.cfg.HTTPListenHosts = []string{"127.0.0.1", "::1"}
	f.s.Edge.HTTPPort = freePort(t)
	f.s.Revision++
	if err := f.r.apply(f.s); err != nil {
		t.Fatal(err)
	}
	status := f.r.RuntimeStatus()
	if len(status.Sites) != 1 || len(status.Sites[0].Bindings) != 2 || !status.Sites[0].Bindings[0].Listening || !status.Sites[0].Bindings[1].Listening {
		t.Fatalf("missing dual-stack HTTP listeners: %+v", status.Sites)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	for _, binding := range status.Sites[0].Bindings {
		req, _ := http.NewRequest("GET", "http://"+binding.Address, nil)
		req.Host = "site.test"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected no-agent response on %s, got %d", binding.Address, resp.StatusCode)
		}
	}
	for _, id := range []string{"tcp", "udp"} {
		_, err := f.r.beginFlow(context.Background(), id, "[2001:db8::1]:1234")
		if err == nil || !strings.Contains(err.Error(), "IPv4 visitor") {
			t.Fatalf("IPv6 business visitor was accepted: %v", err)
		}
	}
	// A failed family is reported individually while IPv4 remains usable.
	f.r.cfg.HTTPListenHosts = []string{"127.0.0.1", "2001:db8::123"}
	f.s.Revision++
	if err := f.r.apply(f.s); err != nil {
		t.Fatal(err)
	}
	status = f.r.RuntimeStatus()
	if !status.Sites[0].Listening || status.Sites[0].Bindings[1].Listening || status.Sites[0].Bindings[1].Error == "" {
		t.Fatalf("partial bind failure hidden: %+v", status.Sites)
	}
	for i := range f.s.Rules {
		if f.s.Rules[i].ID == "tcp" {
			f.s.Rules[i].Target = "[::1]:80"
		}
	}
	f.s.Revision++
	if err := f.r.apply(f.s); err != nil {
		t.Fatal(err)
	}
	f.r.mu.RLock()
	defer f.r.mu.RUnlock()
	if f.r.listeners["rule/tcp"].closer != nil || !strings.Contains(f.r.rules["tcp"].policyError, "address_family_unsupported") {
		t.Fatal("IPv6 business target retained public listener")
	}
}

func TestDedicatedCarrierPairAndQUICSocketRelease(t *testing.T) {
	for _, eps := range [][]model.Endpoint{
		{{Transport: "quic", Address: "edge.test:8443", ServerName: "edge.test"}},
		{{Transport: "tls", Address: "edge.test:8443", ServerName: "edge.test"}},
		{{Transport: "quic", Address: "edge.test:8443", ServerName: "edge.test"}, {Transport: "quic", Address: "edge.test:8444", ServerName: "edge.test"}},
	} {
		if validateCarrierPorts(eps) == nil {
			t.Fatal("invalid carrier plan accepted")
		}
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge.test"}, DNSNames: []string{"edge.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	cfg := Config{CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}
	if err := os.WriteFile(cfg.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct{ network, addr string }{{"udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0"}} {
		l, err := listenQUICNetwork(cfg, pair.network, pair.addr)
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		pc, err := net.ListenPacket(pair.network, addr)
		if err != nil {
			t.Fatalf("owned QUIC socket leaked after Close: %v", err)
		}
		pc.Close()
	}
}
