package acl

import (
	"drafrp/internal/model"
	"net/netip"
	"testing"
	"time"
)

func TestSourceTuplePriorityAndTime(t *testing.T) {
	start := time.Now()
	end := start.Add(time.Second)
	p, e := Compile(model.ACLPolicy{DefaultAction: "deny", Entries: []model.ACLEntry{
		{ID: "second", Priority: 20, Action: "deny", CIDRs: []string{"192.0.2.0/24"}},
		{ID: "temporary", Priority: 10, Action: "allow", CIDRs: []string{"::ffff:192.0.2.0/120"}, Protocol: "udp", Ports: []int{1234}, NotBefore: &start, ExpiresAt: &end},
	}})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		ip, proto string
		port      int
		at        time.Time
		want      bool
		id        string
	}{
		{"::ffff:192.0.2.7", "udp", 1234, start, true, "temporary"},
		{"192.0.2.7", "udp", 1234, end, false, "second"},
		{"192.0.2.7", "tcp", 1234, start, false, "second"},
		{"192.0.2.7", "udp", 4321, start, false, "second"},
		{"198.51.100.1", "udp", 1234, start, false, "default"},
	} {
		got, id := p.AllowAt(netip.MustParseAddr(tc.ip), tc.proto, tc.port, tc.at)
		if got != tc.want || id != tc.id {
			t.Fatalf("%+v got %v %s", tc, got, id)
		}
	}
}

func TestInvalidACLNeverBecomesAllowAll(t *testing.T) {
	for _, entry := range []model.ACLEntry{
		{ID: "a", Action: "allow", CIDRs: []string{}},
		{ID: "a", Action: "allow", Ports: []int{}},
		{ID: "a", Action: "allow", CIDRs: []string{"::ffff:192.0.2.0/80"}},
		{ID: "a", Action: "allow", Protocol: "http"},
		{ID: "a", Action: "allow", Ports: []int{65536}},
	} {
		if _, e := Compile(model.ACLPolicy{DefaultAction: "allow", Entries: []model.ACLEntry{entry}}); e == nil {
			t.Fatalf("accepted invalid entry %+v", entry)
		}
	}
	p, e := Compile(model.ACLPolicy{DefaultAction: "deny"})
	if e != nil {
		t.Fatal(e)
	}
	if ok, _ := p.Allow(netip.MustParseAddr("192.0.2.1"), "tcp", 80); ok {
		t.Fatal("empty deny ACL allowed traffic")
	}
}

func TestRegionalUnknownAndMissingCapability(t *testing.T) {
	p := model.ACLPolicy{DefaultAction: "allow", Entries: []model.ACLEntry{{ID: "region", Priority: 1, Action: "deny", Countries: []string{"AA"}, GeoUnknownAction: "deny"}}}
	if _, e := Compile(model.ACLPolicy{DefaultAction: "allow", Entries: []model.ACLEntry{{ID: "bad", Action: "allow", Countries: []string{"AA"}}}}); e == nil {
		t.Fatal("implicit unknown geographic behavior accepted")
	}
	missing, e := Compile(p)
	if e != nil {
		t.Fatal(e)
	}
	if !missing.RequiresGeo() {
		t.Fatal("missing geographic capability not marked")
	}
	if ok, id := missing.Allow(netip.MustParseAddr("203.0.113.1"), "tcp", 80); ok || id != "geoip_unavailable" {
		t.Fatal(ok, id)
	}
	lookup := func(ip netip.Addr) (string, string, bool) {
		if ip == netip.MustParseAddr("203.0.113.1") {
			return "AA", "AA-X", true
		}
		return "", "", false
	}
	compiled, e := CompileWithGeo(p, lookup)
	if e != nil {
		t.Fatal(e)
	}
	if ok, id := compiled.Allow(netip.MustParseAddr("198.51.100.1"), "tcp", 80); ok || id != "region:geo_unknown" {
		t.Fatal(ok, id)
	}
	p.Entries[0].GeoUnknownAction = "no_match"
	compiled, _ = CompileWithGeo(p, lookup)
	if ok, _ := compiled.Allow(netip.MustParseAddr("198.51.100.1"), "tcp", 80); !ok {
		t.Fatal("explicit unknown no_match ignored")
	}
	if ok, _ := compiled.Allow(netip.MustParseAddr("203.0.113.1"), "tcp", 80); ok {
		t.Fatal("matched regional deny ignored")
	}
}
