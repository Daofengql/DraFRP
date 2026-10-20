package acl

import (
	"drafrp/internal/model"
	"net/netip"
	"testing"
	"time"
)

func TestExplainDistinguishesEntryFromSyntheticReason(t *testing.T) {
	policy, err := Compile(model.ACLPolicy{DefaultAction: "deny", Entries: []model.ACLEntry{{ID: "default", Action: "allow", Ports: []int{50000}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{50000, 443} {
		got := policy.ExplainAt(netip.MustParseAddr("::ffff:192.0.2.5"), "tcp", port, time.Now())
		live, reason := policy.AllowAt(netip.MustParseAddr("192.0.2.5"), "tcp", port, time.Now())
		if live != got.Allowed || reason != got.Reason {
			t.Fatal("diagnostic differs from runtime decision", got, live, reason)
		}
		if port == 50000 && (got.UsedDefault || got.MatchedEntryID != "default" || got.Action != "allow") {
			t.Fatal("entry with synthetic-looking ID misidentified", got)
		}
		if port == 443 && (!got.UsedDefault || got.MatchedEntryID != "" || got.Action != "deny") {
			t.Fatal("default action lacks explicit origin", got)
		}
	}
}

func TestExplainReportsGeoUnknownEntryWithoutParsingItsID(t *testing.T) {
	p, err := CompileWithGeo(model.ACLPolicy{DefaultAction: "allow", Entries: []model.ACLEntry{{ID: "default:geo_unknown", Action: "allow", Countries: []string{"AA"}, GeoUnknownAction: "deny"}}}, func(netip.Addr) (string, string, bool) { return "", "", false })
	if err != nil {
		t.Fatal(err)
	}
	got := p.ExplainAt(netip.MustParseAddr("192.0.2.1"), "udp", 50000, time.Now())
	if got.Allowed || got.MatchedEntryID != "default:geo_unknown" || got.UsedDefault || got.Reason != "default:geo_unknown:geo_unknown" {
		t.Fatal(got)
	}
}
