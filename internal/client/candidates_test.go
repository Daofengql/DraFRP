package client

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"drafrp/internal/model"
)

func TestDNSCandidateCooldownIsIndependentAndBounded(t *testing.T) {
	a, err := New(Config{CloudURL: "http://127.0.0.1", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	d := model.DeviceGrant{DeviceID: "device", SessionID: "session", Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}
	e := model.Edge{ID: "edge", Endpoints: []model.Endpoint{{Transport: "quic", Address: "edge.test:8443", ServerName: "edge.test"}, {Transport: "tls", Address: "edge.test:8443", ServerName: "edge.test"}}}
	a.mu.Lock()
	a.snap = model.ClientSnapshot{Device: d, Edges: []model.Edge{e}, ExpiresAt: d.ExpiresAt}
	k := pathKey(e, e.Endpoints[0], d)
	k.RemoteAddress = "[2001:db8::1]:8443"
	a.pathHealth[k] = &endpointHealth{Failures: 1, LastAttempt: time.Now(), RetryAt: time.Now().Add(time.Minute)}
	a.mu.Unlock()
	a.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("::"), netip.MustParseAddr("ff02::1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")}, nil
	}
	candidates, retry, err := a.dialCandidates(context.Background(), e, d, "auto")
	if err != nil || retry.IsZero() {
		t.Fatalf("lost cooldown: %v %v", retry, err)
	}
	if len(candidates) != 5 || candidates[0].ep.Transport != "quic" || candidates[0].ipv6 {
		t.Fatalf("IPv6 failure cooled IPv4 or candidate limit failed: %+v", candidates)
	}
	for _, c := range candidates {
		if c.key.RemoteAddress == k.RemoteAddress && c.ep.Transport == "quic" {
			t.Fatal("cooled address retried")
		}
	}
	a.mu.Lock()
	for i := 1; i <= 2048; i++ {
		old := pathKey(e, e.Endpoints[0], d)
		old.RemoteAddress = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 8443).String()
		a.pathHealth[old] = &endpointHealth{LastAttempt: time.Now().Add(-11 * time.Minute)}
	}
	a.mu.Unlock()
	fresh := pathKey(e, e.Endpoints[1], d)
	fresh.RemoteAddress = "192.0.2.99:8443"
	if !a.beginEndpoint(fresh, time.Now()) {
		t.Fatal("old DNS addresses permanently exhausted health budget")
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.pathHealth) > 2 {
		t.Fatalf("stale DNS entries retained: %d", len(a.pathHealth))
	}
}
