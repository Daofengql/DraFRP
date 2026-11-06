package cloud

import (
	"testing"

	"drafrp/internal/model"
)

func TestNetworkScopeRuleAndEndpointValidation(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		if validTarget(proto, "[::1]:80") || validTarget(proto, "[::ffff:127.0.0.1]:80") || !validTarget(proto, "127.0.0.1:80") || !validTarget(proto, "local.test:80") {
			t.Fatalf("%s target family scope incorrect", proto)
		}
	}
	if !validTarget("http", "http://[::1]:80") {
		t.Fatal("HTTP origin incorrectly restricted by business address family")
	}
	e := model.Edge{Name: "edge", PublicHost: "edge.test", PortMin: 10000, PortMax: 20000, MaxCarriers: 2, CapacityBPS: -1, Endpoints: []model.Endpoint{{Transport: "quic", Address: "edge.test:8443", ServerName: "edge.test"}, {Transport: "tls", Address: "edge.test:8443", ServerName: "edge.test"}}}
	if err := validateEdge(e); err != nil {
		t.Fatal(err)
	}
	e.Endpoints[1].Transport = "quic"
	if validateEdge(e) == nil {
		t.Fatal("duplicate UDP endpoint accepted")
	}
	e.Endpoints = e.Endpoints[:1]
	if validateEdge(e) == nil {
		t.Fatal("one dedicated port accepted")
	}
}
