package cloud

import (
	"drafrp/internal/model"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMySQLPortResourceAuthorityAndIsolation(t *testing.T) {
	f := newCloudFixture(t)
	owner, stranger := f.createUser("port-owner"), f.createUser("port-stranger")
	d, _ := f.bind(owner, "port-private-device")
	edge, next := f.edge("port-first"), f.edge("port-next")
	rule := f.createRule(owner, d, edge, 20001)
	rule.Name = "private-rule-name"
	rule = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+rule.ID, rule, owner, nil), 200)
	udp := model.Rule{Name: "private-udp-name", DeviceID: d.ID, EdgeID: edge.ID, Protocol: "udp", PublicPort: 20001, Target: "127.0.0.1:8081", SourceMode: "socket", Transport: "auto", Enabled: true}
	udp = decodeResponse[model.Rule](t, f.request("POST", "/api/v1/rules", udp, owner, nil), 201)
	path := "/api/v1/port-resources?edge_id=" + edge.ID + "&limit=500"
	list := func(b *browser, path string) portResourcePage {
		t.Helper()
		return decodeResponse[portResourcePage](t, f.request("GET", path, nil, b, nil), 200)
	}
	find := func(page portResourcePage, protocol string, port int) portResource {
		t.Helper()
		for _, item := range page.Items {
			if item.Protocol == protocol && item.Port == port {
				return item
			}
		}
		t.Fatalf("missing port %s/%d in %+v", protocol, port, page)
		return portResource{}
	}
	before := now()
	page := list(owner, path)
	if page.EdgeID != edge.ID || page.PortMin != 20000 || page.PortMax != 20010 || page.Total != 26 || len(page.Items) != 26 || page.ObservedAt.Before(before) || page.ObservedAt.After(now()) {
		t.Fatalf("unexpected pool response: %+v", page)
	}
	for _, protocol := range []string{"tcp", "udp"} {
		x := find(page, protocol, 20001)
		if x.Status != "occupied" || x.Rule == nil || x.Rule.TenantID != owner.user.TenantID || !x.Rule.CurrentClaim || x.ReleaseAt != nil {
			t.Fatal("owner lost occupied claim detail", x)
		}
		if x = find(page, protocol, 8443); x.Status != "reserved" || x.InBusinessPool || len(x.Reservations) != 1 {
			t.Fatal("carrier listener is not a separate reserved resource", x)
		}
		if x = find(page, protocol, 20000); x.Status != "available" || !x.InBusinessPool || x.Rule != nil {
			t.Fatal("unused pool port is unavailable", x)
		}
	}
	for _, port := range []int{edge.HTTPPort, edge.HTTPSPort} {
		if x := find(page, "tcp", port); x.Status != "reserved" || x.InBusinessPool {
			t.Fatal("shared HTTP(S) listener omitted", x)
		}
	}
	private := f.request("GET", path, nil, stranger, nil)
	outsider := decodeResponse[portResourcePage](t, private, 200)
	for _, forbidden := range []string{rule.ID, udp.ID, owner.user.TenantID, d.ID, rule.Name, udp.Name, rule.Target, "rule\""} {
		if strings.Contains(private.Body.String(), forbidden) {
			t.Fatalf("other tenant's claim detail disclosed: %q: %s", forbidden, private.Body.String())
		}
	}
	if find(outsider, "tcp", 20001).Status != "occupied" || find(outsider, "udp", 20001).Status != "occupied" {
		t.Fatal("redaction incorrectly made another tenant's claim available")
	}
	admin := find(list(f.admin, path), "tcp", 20001)
	if admin.Rule == nil || admin.Rule.ID != rule.ID || admin.Rule.Name != rule.Name || admin.Rule.TenantID != owner.user.TenantID {
		t.Fatal("administrator lost claim ownership detail", admin)
	}
	// Moving the current rule leaves the old edge's claim until its old signed
	// snapshot expires. The current rule metadata must not imply a current claim.
	rule.EdgeID = next.ID
	rule = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+rule.ID, rule, owner, nil), 200)
	x := find(list(owner, path), "tcp", 20001)
	if x.Status != "releasing" || x.ReleaseAt == nil || x.Rule == nil || x.Rule.CurrentClaim {
		t.Fatal("moved rule made old snapshot port free", x)
	}
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/rules/"+rule.ID, nil, owner, nil), 200)
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(next, "port-next-boot", []model.RuleStatus{{ID: rule.ID, Version: rule.Version + 1, Status: "deleted"}}, nil), 200)
	// ACK on the new edge removes the current rule; the old orphan claim still
	// blocks reuse, while normal users cannot infer its former identity.
	x = find(list(owner, path), "tcp", 20001)
	if x.Status != "releasing" || x.Rule != nil || x.ReleaseAt == nil {
		t.Fatal("orphaned old claim lost protection or identity redaction", x)
	}
	x = find(list(f.admin, path), "tcp", 20001)
	if x.Status != "releasing" || x.Rule == nil || x.Rule.ID != rule.ID || x.Rule.CurrentClaim || x.Rule.TenantID != "" {
		t.Fatal("administrator cannot inspect orphaned claim", x)
	}
	// Expired claims are available to the allocator. GET observes that deadline
	// without deleting claims, changing revisions, auditing or reaping resources.
	if _, err := f.s.db.Exec("UPDATE resource_claims SET release_at=? WHERE edge_id=? AND resource_key='tcp/20001'", now().Add(-time.Second), edge.ID); err != nil {
		t.Fatal(err)
	}
	var revision, audit, claims int
	if err := f.s.db.QueryRow("SELECT revision FROM config_revision WHERE id=1").Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM audit").Scan(&audit); err != nil {
		t.Fatal(err)
	}
	x = find(list(owner, path), "tcp", 20001)
	if x.Status != "available" || x.Rule != nil || x.ReleaseAt != nil {
		t.Fatal("expired orphan claim still blocks candidate port", x)
	}
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM resource_claims WHERE edge_id=? AND resource_key='tcp/20001'", edge.ID).Scan(&claims); err != nil || claims != 1 {
		t.Fatal("GET reaped an expired claim", claims, err)
	}
	var after int
	if err := f.s.db.QueryRow("SELECT revision FROM config_revision WHERE id=1").Scan(&after); err != nil || after != revision {
		t.Fatal("GET changed revision", after, revision, err)
	}
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM audit").Scan(&after); err != nil || after != audit {
		t.Fatal("GET added audit events", after, audit, err)
	}
	// A deleting current rule stays releasing until the exact version ACK.
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/rules/"+udp.ID, nil, owner, nil), 200)
	if x := find(list(owner, path), "udp", 20001); x.Status != "releasing" || x.Rule == nil || !x.Rule.CurrentClaim {
		t.Fatal("deleting UDP rule did not preserve claim", x)
	}
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "port-first-boot", []model.RuleStatus{{ID: udp.ID, Version: udp.Version, Status: "deleted"}}, nil), 200)
	if x := find(list(owner, path), "udp", 20001); x.Status != "releasing" {
		t.Fatal("stale ACK freed resource", x)
	}
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "port-first-boot", []model.RuleStatus{{ID: udp.ID, Version: udp.Version + 1, Status: "deleted"}}, nil), 200)
	if x := find(list(owner, path), "udp", 20001); x.Status != "available" {
		t.Fatal("exact ACK failed to free resource", x)
	}
	if w := f.request("GET", path, nil, nil, nil); w.Code != 401 {
		t.Fatal("unauthenticated port enumeration accepted", w.Code)
	}
	if w := f.request("GET", "/api/v1/port-resources?edge_id=missing", nil, owner, nil); w.Code != 404 {
		t.Fatal("unknown edge response", w.Code, w.Body.String())
	}
	if w := f.request("POST", path, nil, owner, nil); w.Code != 405 {
		t.Fatal("port query accepted mutation", w.Code, w.Body.String())
	}
	tcpPage := list(owner, path+"&protocol=tcp&offset=2")
	if tcpPage.Total != 14 || tcpPage.Items[0].Protocol != "tcp" || tcpPage.Items[0].Port != 18443 {
		t.Fatal("filtered numeric pagination failed", tcpPage)
	}
	empty := list(owner, "/api/v1/port-resources?edge_id="+edge.ID+"&offset="+strconv.Itoa(page.Total))
	if len(empty.Items) != 0 || empty.Items == nil || empty.Limit != 100 {
		t.Fatal("past-end/default page response", empty)
	}
}
