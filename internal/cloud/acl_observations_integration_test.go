package cloud

import (
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type observationResult struct {
	Items []struct {
		model.ACLHit
		Current bool   `json:"current"`
		BootID  string `json:"boot_id"`
	} `json:"items"`
	Application    aclApplication    `json:"application"`
	HasMore        bool              `json:"has_more"`
	NextCursor     string            `json:"next_cursor"`
	CollectionLoss map[string]uint64 `json:"collection_loss"`
}
type applicationResult struct {
	Items []struct {
		Counts map[string]int   `json:"counts"`
		Rules  []aclApplication `json:"rules"`
	} `json:"items"`
}

func TestMySQLACLObservationPersistenceIsolationAndActualACK(t *testing.T) {
	f := newCloudFixture(t)
	user := f.createUser("acl-metrics-owner")
	other := f.createUser("acl-metrics-other")
	d, _ := f.bind(user, "device")
	edge := f.edge("metrics-edge")
	rule := f.createRule(user, d, edge, 0)
	template := decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates", model.ACLTemplate{Name: "observed-template", Policy: model.ACLPolicy{DefaultAction: "deny"}}, f.admin, nil), 201)
	template = decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates/"+template.ID+"/publish", map[string]uint64{"version": template.Version}, f.admin, nil), 200)
	rule.ACLTemplateID = template.ID
	rule = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+rule.ID, rule, user, nil), 200)
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "boot-a", nil, nil), 200)
	get := func(b *browser) observationResult {
		return decodeResponse[observationResult](t, f.request("GET", "/api/v1/acl/observations?rule_id="+rule.ID, nil, b, nil), 200)
	}
	apps := func() applicationResult {
		return decodeResponse[applicationResult](t, f.request("GET", "/api/v1/acl/applications?template_id="+template.ID, nil, f.admin, nil), 200)
	}
	if got := apps(); got.Items[0].Rules[0].State != "pending" {
		t.Fatal("sent snapshot incorrectly implies applied", got)
	}
	policy := *template.Published
	policy.TemplateID = template.ID
	refs := []model.ACLPolicyRef{acl.Reference(policy, "rule_template")}
	digest := acl.EffectiveDigest(rule.ID, rule.Version, refs)
	clock := now()
	report := &model.ACLReport{Sequence: 1, StartedAt: clock, ObservedAt: clock, Dropped: 2, Rows: []model.ACLHit{{RuleID: rule.ID, RuleVersion: rule.Version, EffectiveDigest: digest, Protocol: "tcp", Kind: "rule_total", Reason: "policy_denied", Denied: 3, StartedAt: clock}, {RuleID: rule.ID, RuleVersion: rule.Version, EffectiveDigest: digest, Protocol: "tcp", Kind: "policy", Policy: refs[0], UsedDefault: true, Reason: "default", Denied: 3, StartedAt: clock}}, ACKs: []model.ACLApplied{{RuleID: rule.ID, RuleVersion: rule.Version, EffectiveDigest: digest, Policies: refs, State: "applied", AppliedAt: clock, SampledAt: clock, ExpiresAt: clock.Add(time.Minute)}}}
	send := func(boot string, report *model.ACLReport, want int) {
		decodeResponse[map[string]any](t, f.request("POST", "/api/v1/runtime/edge/sync", model.EdgeSyncRequest{EdgeID: edge.ID, BootID: boot, AppliedRevision: 9999, ACL: report}, nil, map[string]string{"Authorization": "Bearer " + strings.Repeat(edge.Name, 24)}), want)
	}
	send("boot-a", report, 200)
	send("boot-a", report, 200)
	got := get(user)
	if len(got.Items) != 2 || got.Application.State != "applied" || len(got.CollectionLoss) != 0 {
		t.Fatal("bad tenant evidence", got)
	}
	for _, row := range got.Items {
		if row.Denied != 3 || !row.Current {
			t.Fatal("retry doubled counts", got)
		}
	}
	if got = get(f.admin); got.CollectionLoss["edge_dropped"] != 2 {
		t.Fatal("administrator lacks explicit loss", got)
	}
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/acl/observations?rule_id="+rule.ID, nil, other, nil), 404)
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/acl/applications?template_id="+template.ID, nil, user, nil), 403)
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/acl/observations?rule_id="+rule.ID, nil, nil, nil), 401)
	page := decodeResponse[observationResult](t, f.request("GET", "/api/v1/acl/observations?rule_id="+rule.ID+"&limit=1", nil, user, nil), 200)
	if !page.HasMore || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatal("pagination missing", page)
	}
	page = decodeResponse[observationResult](t, f.request("GET", "/api/v1/acl/observations?rule_id="+rule.ID+"&limit=1&cursor="+page.NextCursor, nil, user, nil), 200)
	if page.HasMore || len(page.Items) != 1 {
		t.Fatal("pagination duplicated rows", page)
	}
	// A later cumulative report can increase counts, never regress them.
	report.Sequence = 3
	report.Rows[0].Denied = 5
	send("boot-a", report, 200)
	report.Sequence = 2
	report.Rows[0].Denied = 4
	report.ACKs[0].State = "error"
	send("boot-a", report, 200)
	got = get(user)
	if got.Application.State != "applied" {
		t.Fatal("stale report overwrote ACK")
	}
	for _, row := range got.Items {
		if row.Kind == "rule_total" && row.Denied != 5 {
			t.Fatal("cumulative counts regressed", row)
		}
	}
	// A malformed batch rolls back its boot transition and all telemetry.
	report.Sequence = 4
	report.Rows[0].Protocol = "http"
	send("boot-b", report, 400)
	report.Rows[0].Protocol = "tcp"
	if get(user).Application.BootID != "boot-a" {
		t.Fatal("invalid report committed boot")
	}
	// A process restart invalidates old ACKs immediately, even without a report.
	send("boot-b", nil, 200)
	got = get(user)
	if got.Application.State != "pending" {
		t.Fatal("old boot ACK still current", got.Application)
	}
	for _, row := range got.Items {
		if row.Current {
			t.Fatal("old boot counts marked current")
		}
	}
	report.Sequence = 1
	report.ACKs[0].State = "applied"
	report.Rows[0].Denied = 1
	report.Rows[1].Denied = 1
	send("boot-b", report, 200)
	got = get(user)
	if len(got.Items) != 4 || got.Application.State != "applied" {
		t.Fatal("boots combined", got)
	}
	// Publishing invalidates the old version until its new real ACK arrives.
	template = decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates/"+template.ID+"/publish", map[string]uint64{"version": template.Version}, f.admin, nil), 200)
	if got := apps(); got.Items[0].Rules[0].State != "pending" {
		t.Fatal("new published version inferred applied", got)
	}
	rule = decodeResponse[model.Rule](t, f.request("GET", "/api/v1/rules/"+rule.ID, nil, user, nil), 200)
	policy = *template.Published
	policy.TemplateID = template.ID
	refs = []model.ACLPolicyRef{acl.Reference(policy, "rule_template")}
	report.Sequence = 2
	report.Rows = nil
	report.ACKs[0].RuleVersion = rule.Version
	report.ACKs[0].Policies = refs
	report.ACKs[0].EffectiveDigest = acl.EffectiveDigest(rule.ID, rule.Version, refs)
	report.ACKs[0].ExpiresAt = now().Add(-time.Second)
	send("boot-b", report, 200)
	if got := apps(); got.Items[0].Rules[0].State != "expired" {
		t.Fatal("expired authority accepted", got)
	}
	report.Sequence++
	report.ACKs[0].State = "error"
	report.ACKs[0].Error = "compile failure"
	send("boot-b", report, 200)
	if got := apps(); got.Items[0].Rules[0].State != "error" {
		t.Fatal("failure ACK missing", got)
	}
	// A report naming another edge's rule must not persist attacker labels.
	foreignEdge := f.edge("foreign-edge")
	foreign := f.createRule(user, d, foreignEdge, 0)
	report.Sequence++
	report.ACKs = nil
	report.Rows = []model.ACLHit{{RuleID: foreign.ID, RuleVersion: foreign.Version, EffectiveDigest: acl.EffectiveDigest(foreign.ID, foreign.Version, nil), Protocol: "tcp", Kind: "rule_total", Allowed: 900, StartedAt: clock}}
	send("boot-b", report, 200)
	var count int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM acl_observations WHERE rule_id=?", foreign.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("foreign report persisted", count, err)
	}
	// Fill the durable cardinality limit in one isolated MySQL operation. New
	// labels are explicitly dropped; existing cumulative counters still update.
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM acl_observations WHERE edge_id=?", edge.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	seed := make([]int, aclStoredRowLimit-count)
	encoded, _ := json.Marshal(seed)
	if _, err := f.s.db.Exec(`INSERT INTO acl_observations(edge_id,counter_key,tenant_id,rule_id,boot_id,payload,allowed,denied,observed_at,received_at) SELECT ?,LPAD(HEX(n),64,'0'),?,?,?,JSON_OBJECT(),0,0,?,? FROM JSON_TABLE(?, '$[*]' COLUMNS (n FOR ORDINALITY)) j`, edge.ID, user.user.TenantID, rule.ID, "capacity-fixture", clock, clock, string(encoded)); err != nil {
		t.Fatal(err)
	}
	report.Sequence++
	report.Rows[0].RuleID = rule.ID
	report.Rows[0].RuleVersion = rule.Version
	report.Rows[0].EffectiveDigest = acl.EffectiveDigest(rule.ID, rule.Version, refs)
	send("boot-b", report, 200)
	var stored int
	var dropped uint64
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM acl_observations WHERE edge_id=?", edge.ID).Scan(&stored); err != nil || stored != aclStoredRowLimit {
		t.Fatal("durable collector unbounded", stored, err)
	}
	if err := f.s.db.QueryRow("SELECT cloud_dropped FROM acl_edge_state WHERE edge_id=?", edge.ID).Scan(&dropped); err != nil || dropped != 1 {
		t.Fatal("capacity loss not explicit", dropped, err)
	}
	// Rows older than seven days are pruned on the next report, even at capacity.
	if _, err := f.s.db.Exec("UPDATE acl_observations SET received_at=? WHERE edge_id=?", now().Add(-8*24*time.Hour), edge.ID); err != nil {
		t.Fatal(err)
	}
	report.Sequence++
	send("boot-b", report, 200)
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM acl_observations WHERE edge_id=?", edge.ID).Scan(&stored); err != nil || stored != 1 {
		t.Fatal("retention did not reclaim capacity", stored, err)
	}
	rule.Enabled = false
	rule = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+rule.ID, rule, user, nil), 200)
	report.Sequence++
	report.Rows = nil
	report.ACKs = []model.ACLApplied{{RuleID: rule.ID, RuleVersion: rule.Version, State: "inactive", AppliedAt: clock, SampledAt: clock, ExpiresAt: clock.Add(time.Minute)}}
	send("boot-b", report, 200)
	if got := get(user); got.Application.State != "inactive" {
		t.Fatal("actual inactive ACK missing", got)
	}
}
