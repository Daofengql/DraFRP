package cloud

import (
	"drafrp/internal/model"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSimulationUsesVisitorPortAndIntersectsPolicyLayers(t *testing.T) {
	policy := model.ACLPolicy{DefaultAction: "deny", Entries: []model.ACLEntry{{ID: "visitor-port", Action: "allow", Ports: []int{50000}}}}
	for _, port := range []int{50000, 443} {
		out := simulationResponse{EvaluatedAt: time.Now(), Chain: []simulationLayer{{Kind: "draft", policy: policy}}}
		out.Source.Protocol, out.Source.Port = "tcp", port
		if err := evaluateSimulation(&out, netip.MustParseAddr("192.0.2.5"), nil); err != nil {
			t.Fatal(err)
		}
		if out.Allowed != (port == 50000) {
			t.Fatal("simulation did not use visitor source port", out)
		}
	}
	out := simulationResponse{EvaluatedAt: time.Now(), Chain: []simulationLayer{
		{Kind: "mandatory_template", policy: model.ACLPolicy{DefaultAction: "deny"}},
		{Kind: "rule_inline", policy: model.ACLPolicy{DefaultAction: "allow"}},
	}}
	out.Source.Protocol, out.Source.Port = "udp", 50000
	if err := evaluateSimulation(&out, netip.MustParseAddr("192.0.2.5"), nil); err != nil {
		t.Fatal(err)
	}
	if out.Allowed || out.Reason != "policy_denied" || !out.Chain[1].Decision.Allowed || !out.Chain[0].Decision.UsedDefault {
		t.Fatal("child allow overrode mandatory deny or diagnostic omitted chain", out)
	}
}

func TestSimulationGeoCapabilityAndExplicitManualResults(t *testing.T) {
	for _, testcase := range []struct {
		geo     *simulationGeo
		unknown string
		want    bool
		reason  string
	}{
		{nil, "no_match", false, "capability_missing"},
		{&simulationGeo{State: "unavailable"}, "no_match", false, "capability_missing"},
		{&simulationGeo{State: "unknown"}, "deny", false, "policy_denied"},
		{&simulationGeo{State: "unknown"}, "no_match", true, "all_policies_allow"},
		{&simulationGeo{State: "known", Country: "AA", Region: "AA-X"}, "deny", false, "policy_denied"},
		{&simulationGeo{State: "known", Country: "BB"}, "deny", true, "all_policies_allow"},
	} {
		policy := model.ACLPolicy{DefaultAction: "allow", Entries: []model.ACLEntry{{ID: "manual-region", Action: "deny", Countries: []string{"AA"}, GeoUnknownAction: testcase.unknown}}}
		in := simulationRequest{SourceIP: "::ffff:192.0.2.5", SourcePort: 50000, Protocol: "tcp", Policy: &policy, Geo: testcase.geo}
		ip, lookup, err := validateSimulation(in)
		if err != nil {
			t.Fatal(err)
		}
		out := simulationResponse{EvaluatedAt: time.Now(), Chain: []simulationLayer{{policy: policy}}}
		out.Source.Port, out.Source.Protocol = in.SourcePort, in.Protocol
		if err := evaluateSimulation(&out, ip, lookup); err != nil {
			t.Fatal(err)
		}
		if out.Allowed != testcase.want || out.Reason != testcase.reason || !out.Chain[0].RequiresGeo {
			t.Fatal(testcase, out)
		}
	}
	// Edge readiness rejects a missing database for the whole regional policy,
	// even when a preceding ordinary entry would otherwise allow this tuple.
	policy := model.ACLPolicy{DefaultAction: "allow", Entries: []model.ACLEntry{
		{ID: "ordinary", Priority: 1, Action: "allow"},
		{ID: "regional", Priority: 2, Action: "deny", Countries: []string{"AA"}, GeoUnknownAction: "no_match"},
	}}
	out := simulationResponse{EvaluatedAt: time.Now(), Chain: []simulationLayer{{policy: policy}}}
	out.Source.Port, out.Source.Protocol = 50000, "tcp"
	if err := evaluateSimulation(&out, netip.MustParseAddr("192.0.2.5"), nil); err != nil || out.Allowed || out.Reason != "capability_missing" {
		t.Fatal("missing capability was treated as an unmatched geographic condition", out, err)
	}
}

func TestSimulationTimeBoundaryAndExplicitDefault(t *testing.T) {
	start := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)
	policy := model.ACLPolicy{DefaultAction: "deny", Entries: []model.ACLEntry{{ID: "temporary", Action: "allow", NotBefore: &start, ExpiresAt: &end}}}
	for _, testcase := range []struct {
		at   time.Time
		want bool
	}{{start.Add(-time.Nanosecond), false}, {start, true}, {end, false}} {
		out := simulationResponse{EvaluatedAt: testcase.at, Chain: []simulationLayer{{policy: policy}}}
		out.Source.Port, out.Source.Protocol = 50000, "tcp"
		if err := evaluateSimulation(&out, netip.MustParseAddr("2001:db8::1"), nil); err != nil || out.Allowed != testcase.want {
			t.Fatal(testcase, out, err)
		}
	}
	out := simulationResponse{EvaluatedAt: start, Chain: []simulationLayer{{policy: model.ACLPolicy{}}}}
	out.Source.Port, out.Source.Protocol = 50000, "tcp"
	if err := evaluateSimulation(&out, netip.MustParseAddr("192.0.2.5"), nil); err == nil {
		t.Fatal("diagnostic invented a missing default action")
	}
}

func TestSimulationRejectsAmbiguousInputs(t *testing.T) {
	valid := simulationRequest{SourceIP: "192.0.2.5", SourcePort: 50000, Protocol: "tcp", RuleID: "rule"}
	for _, mutate := range []func(*simulationRequest){
		func(in *simulationRequest) { in.SourceIP = "192.0.2.5:50000" },
		func(in *simulationRequest) { in.SourceIP = "fe80::1%eth0" },
		func(in *simulationRequest) { in.SourcePort = 0 },
		func(in *simulationRequest) { in.SourcePort = 65536 },
		func(in *simulationRequest) { in.Protocol = "http" },
		func(in *simulationRequest) { in.TemplateID = "template" },
		func(in *simulationRequest) { in.RuleID = "" },
		func(in *simulationRequest) { in.RuleID = strings.Repeat("r", 65) },
		func(in *simulationRequest) { in.TemplateRevision = "draft" },
		func(in *simulationRequest) { in.Geo = &simulationGeo{State: "ready"} },
		func(in *simulationRequest) { in.Geo = &simulationGeo{State: "known", Country: "aa"} },
		func(in *simulationRequest) { in.Geo = &simulationGeo{State: "known", Country: "AA", Region: "BB-X"} },
		func(in *simulationRequest) { in.Geo = &simulationGeo{State: "unknown", Country: "AA"} },
		func(in *simulationRequest) {
			in.Geo = &simulationGeo{State: "unavailable", Version: strings.Repeat("v", 129)}
		},
		func(in *simulationRequest) { at := time.Time{}; in.At = &at },
	} {
		in := valid
		mutate(&in)
		if _, _, err := validateSimulation(in); err == nil {
			t.Fatalf("accepted ambiguous diagnostic input %+v", in)
		}
	}
	if _, _, err := validateSimulation(valid); err != nil {
		t.Fatal(err)
	}
}

func TestSimulationMethodAndAuthenticationFailBeforeDatabase(t *testing.T) {
	s := &Server{}
	for _, testcase := range []struct {
		method string
		want   int
	}{{"GET", 405}, {"POST", 401}} {
		w := httptest.NewRecorder()
		s.aclSimulation(w, httptest.NewRequest(testcase.method, "https://cloud.example/api/v1/acl/simulate", strings.NewReader("{}")))
		if w.Code != testcase.want {
			t.Fatal(testcase, w.Code, w.Body.String())
		}
	}
	var out simulationResponse
	out.Geo.simulationGeo = simulationGeo{State: "known", Country: "AA", Region: "AA-X", Version: "manual-input"}
	out.Geo.Source = "manual"
	raw, err := json.Marshal(out)
	if err != nil || !strings.Contains(string(raw), `"state":"known"`) || !strings.Contains(string(raw), `"source":"manual"`) {
		t.Fatal("manual geography missing from wire response", string(raw), err)
	}
}
