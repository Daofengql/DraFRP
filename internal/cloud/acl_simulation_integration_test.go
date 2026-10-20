package cloud

import (
	"drafrp/internal/model"
	"testing"
)

func TestMySQLACLSimulationPrivilegeSnapshotAndReadOnly(t *testing.T) {
	f := newCloudFixture(t)
	user := f.createUser("simulation-owner")
	stranger := f.createUser("simulation-other")
	d, _ := f.bind(user, "simulation-device")
	edge := f.edge("simulation-edge")
	rule := f.createRule(user, d, edge, 0)
	policy := model.ACLPolicy{DefaultAction: "deny", Entries: []model.ACLEntry{{ID: "visitor-port", Action: "allow", CIDRs: []string{"192.0.2.0/24"}, Ports: []int{50000}}}}
	x := decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates", model.ACLTemplate{Name: "simulation-template"}, f.admin, nil), 201)
	x.Policy = policy
	x = decodeResponse[model.ACLTemplate](t, f.request("PUT", "/api/v1/acl-templates/"+x.ID, x, f.admin, nil), 200)
	request := simulationRequest{SourceIP: "::ffff:192.0.2.5", SourcePort: 50000, Protocol: "tcp", TemplateID: x.ID}
	// An unpublished draft is not disclosed to a normal user, even by explicit ID.
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/acl/simulate", request, user, nil), 404)
	request.TemplateRevision = "draft"
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/acl/simulate", request, user, nil), 403)
	draft := decodeResponse[simulationResponse](t, f.request("POST", "/api/v1/acl/simulate", request, f.admin, nil), 200)
	if !draft.Allowed || draft.Source.IP != "192.0.2.5" || draft.Chain[0].Decision.MatchedEntryID != "visitor-port" || draft.Chain[0].PolicyVersion != x.Version {
		t.Fatal("draft preview differs from specified source tuple", draft)
	}
	x = decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates/"+x.ID+"/publish", map[string]uint64{"version": x.Version}, f.admin, nil), 200)
	rule.ACLTemplateID = x.ID
	rule = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+rule.ID, rule, user, nil), 200)
	// Saving a different draft must not change a published-template or rule preview.
	x.Policy = model.ACLPolicy{DefaultAction: "deny"}
	x = decodeResponse[model.ACLTemplate](t, f.request("PUT", "/api/v1/acl-templates/"+x.ID, x, f.admin, nil), 200)
	request.TemplateRevision = "published"
	published := decodeResponse[simulationResponse](t, f.request("POST", "/api/v1/acl/simulate", request, user, nil), 200)
	if !published.Allowed || published.Chain[0].PolicyVersion != x.Published.Version {
		t.Fatal("unpublished draft affected a public preview", published)
	}
	request.TemplateRevision = "draft"
	draft = decodeResponse[simulationResponse](t, f.request("POST", "/api/v1/acl/simulate", request, f.admin, nil), 200)
	if draft.Allowed || draft.Chain[0].PolicyVersion != x.Version {
		t.Fatal("draft preview used published content", draft)
	}
	request.TemplateID, request.TemplateRevision, request.RuleID = "", "", rule.ID
	got := decodeResponse[simulationResponse](t, f.request("POST", "/api/v1/acl/simulate", request, user, nil), 200)
	if !got.Allowed || got.Scope != "rule_effective" || got.Rule == nil || got.Rule.PublicPort == request.SourcePort || got.Chain[0].Kind != "rule_template" || got.Chain[0].Decision.MatchedEntryID != "visitor-port" {
		t.Fatal("effective rule preview lost source/entry context", got)
	}
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/acl/simulate", request, stranger, nil), 404)
	decodeResponse[simulationResponse](t, f.request("POST", "/api/v1/acl/simulate", request, f.admin, nil), 200)
	request.Protocol = "udp"
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/acl/simulate", request, user, nil), 400)
	request.Protocol = "tcp"
	// A published mandatory deny must survive a permissive bound template.
	mandatory := decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates", model.ACLTemplate{Name: "simulation-mandatory", Policy: model.ACLPolicy{DefaultAction: "deny"}}, f.admin, nil), 201)
	mandatory = decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates/"+mandatory.ID+"/publish", map[string]uint64{"version": mandatory.Version}, f.admin, nil), 200)
	mandatory.Mandatory = true
	decodeResponse[model.ACLTemplate](t, f.request("PUT", "/api/v1/acl-templates/"+mandatory.ID, mandatory, f.admin, nil), 200)
	got = decodeResponse[simulationResponse](t, f.request("POST", "/api/v1/acl/simulate", request, user, nil), 200)
	if got.Allowed || len(got.Chain) != 2 || got.Chain[0].Kind != "mandatory_template" || !got.Chain[1].Decision.Allowed || got.Reason != "policy_denied" {
		t.Fatal("upper deny was overridden or omitted", got)
	}
	var auditBefore, auditAfter, replayBefore, replayAfter int
	var revisionBefore, revisionAfter uint64
	readCounts := func(audit, replay *int, revision *uint64) {
		t.Helper()
		if err := f.s.db.QueryRow("SELECT COUNT(*) FROM audit").Scan(audit); err != nil {
			t.Fatal(err)
		}
		if err := f.s.db.QueryRow("SELECT COUNT(*) FROM idempotency_keys").Scan(replay); err != nil {
			t.Fatal(err)
		}
		if err := f.s.db.QueryRow("SELECT revision FROM config_revision WHERE id=1").Scan(revision); err != nil {
			t.Fatal(err)
		}
	}
	readCounts(&auditBefore, &replayBefore, &revisionBefore)
	decodeResponse[simulationResponse](t, f.request("POST", "/api/v1/acl/simulate", request, user, map[string]string{"Idempotency-Key": "diagnostic-is-not-a-mutation"}), 200)
	readCounts(&auditAfter, &replayAfter, &revisionAfter)
	if auditBefore != auditAfter || replayBefore != replayAfter || revisionBefore != revisionAfter {
		t.Fatal("read-only diagnostic changed durable state", auditBefore, auditAfter, replayBefore, replayAfter, revisionBefore, revisionAfter)
	}
	request.RuleID, request.Policy = "", &policy
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/acl/simulate", request, user, nil), 403)
	decodeResponse[simulationResponse](t, f.request("POST", "/api/v1/acl/simulate", request, f.admin, nil), 200)
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/acl/simulate", request, f.admin, map[string]string{"X-CSRF-Token": "invalid"}), 403)
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/acl/simulate", request, f.admin, map[string]string{"Origin": "https://other.example"}), 403)
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/acl/simulate", request, nil, nil), 401)
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/acl/simulate", nil, f.admin, nil), 405)
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/acl/simulate", []byte(`{"source_ip":"192.0.2.5","source_port":50000,"protocol":"tcp","rule_id":"rule","tenant_id":"injected"}`), f.admin, nil), 400)
}
