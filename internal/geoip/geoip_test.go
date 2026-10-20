package geoip

import (
	"net/netip"
	"testing"
)

func TestLongestPrefixAndUnknown(t *testing.T) {
	db, e := Parse([]byte(`{"version":"test-only","records":[{"cidr":"203.0.113.0/24","country":"AA"},{"cidr":"203.0.113.128/25","country":"BB","region":"BB-X"},{"cidr":"2001:db8::/32","country":"CC"}]}`))
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		ip, country, region string
		known               bool
	}{{"203.0.113.1", "AA", "", true}, {"::ffff:203.0.113.200", "BB", "BB-X", true}, {"2001:db8::1", "CC", "", true}, {"198.51.100.1", "", "", false}, {"127.0.0.1", "", "", false}} {
		c, r, k := db.Lookup(netip.MustParseAddr(tc.ip))
		if c != tc.country || r != tc.region || k != tc.known {
			t.Fatalf("%+v got %s %s %v", tc, c, r, k)
		}
	}
	for _, raw := range []string{`{"version":"v","records":[{"cidr":"0.0.0.0/0","country":"us"}]}`, `{"version":"v","records":[{"cidr":"1.2.3.0/24","country":"AA","region":"BB-X"}]}`, `{"version":"","records":[]}`, `{"version":"v","records":[],"unknown":true}`} {
		if _, e = Parse([]byte(raw)); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
