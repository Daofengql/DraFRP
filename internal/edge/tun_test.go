package edge

import (
	"drafrp/internal/config"
	"drafrp/internal/model"
	"testing"
)

func TestClientTUNUsesOrdinaryEdgeListener(t *testing.T) {
	f := fixture(t, model.Rule{ID: "tun", Protocol: "tcp", SourceMode: "native"})
	f.s.Devices[0].Capabilities = []string{"native_tcp_ipv4_ip_port", "tun_client_tcp_ipv4_ip_port"}
	f.s.Revision++
	if e := f.r.apply(f.s); e != nil {
		t.Fatal(e)
	}
	f.r.mu.RLock()
	defer f.r.mu.RUnlock()
	l, exists := f.r.listeners["rule/tun"]
	if !exists || l.kind != "tcp" {
		t.Fatal("Linux client TUN did not get an ordinary TCP edge listener")
	}
}

func TestEdgeRejectsRemovedTUNConfiguration(t *testing.T) {
	var cfg Config
	if e := config.Decode([]byte(`{"tun":{"state_dir":"/tmp/old-edge-tun"}}`), &cfg); e == nil {
		t.Fatal("obsolete edge TUN configuration was silently accepted")
	}
}
