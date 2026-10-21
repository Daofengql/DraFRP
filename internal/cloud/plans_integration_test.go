package cloud

import (
	"context"
	"drafrp/internal/model"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func createTestPlan(t *testing.T, f *cloudFixture, p model.Plan) model.Plan {
	t.Helper()
	return decodeResponse[model.Plan](t, f.request("POST", "/api/v1/plans", p, f.admin, nil), 201)
}

func assignTestPlan(t *testing.T, f *cloudFixture, b *browser, pid string) model.Quota {
	t.Helper()
	q := configurationQuota(t, f, b)
	return decodeResponse[model.Quota](t, f.request("PUT", "/api/v1/users/"+b.user.ID+"/plan", map[string]any{"plan_id": pid, "version": q.Version}, f.admin, nil), 200)
}

func TestPlanPolicyValidation(t *testing.T) {
	valid := model.Plan{Name: "策略", BandwidthBPS: 8000000, BurstEnabled: true, BurstBPS: 16000000, BurstSeconds: 10, TrafficMetered: true, TrafficBytes: 1024, PeriodSeconds: 60, OverageAction: "throttle", OverageBPS: 8000, AllEdges: true}
	for _, tc := range []struct {
		name string
		edit func(*model.Plan)
	}{
		{"unlimited burst", func(p *model.Plan) { p.BandwidthBPS = -1 }},
		{"low peak", func(p *model.Plan) { p.BurstBPS = p.BandwidthBPS }},
		{"zero duration", func(p *model.Plan) { p.BurstSeconds = 0 }},
		{"negative traffic", func(p *model.Plan) { p.TrafficBytes = -1 }},
		{"short cycle", func(p *model.Plan) { p.PeriodSeconds = 59 }},
		{"unknown action", func(p *model.Plan) { p.OverageAction = "allow" }},
		{"zero excess rate", func(p *model.Plan) { p.OverageBPS = 0 }},
		{"excess above base", func(p *model.Plan) { p.OverageBPS = p.BandwidthBPS + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			tc.edit(&p)
			if err := validatePlan(context.Background(), nil, &p); err == nil {
				t.Fatal("invalid plan policy accepted")
			}
		})
	}
	valid.BurstEnabled, valid.TrafficMetered = false, false
	if err := validatePlan(context.Background(), nil, &valid); err != nil || valid.BurstBPS != 0 || valid.BurstSeconds != 0 || valid.TrafficBytes != 0 || valid.PeriodSeconds != 0 || valid.OverageBPS != 0 || valid.OverageAction != "reject" {
		t.Fatal("disabled policies retained hidden limits", valid, err)
	}
}

func TestMySQLPlanTrafficAndBurstPolicies(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("traffic-package")
	d, key := f.bind(b, "metered-client")
	a, z := f.edge("traffic-a"), f.edge("traffic-z")
	p := createTestPlan(t, f, model.Plan{Name: "流量套餐", BandwidthBPS: 8000000, BurstEnabled: true, BurstBPS: 16000000, BurstSeconds: 2, TrafficMetered: true, TrafficBytes: 1000, PeriodSeconds: 60, OverageAction: "throttle", OverageBPS: 8000, MaxPorts: 2, MaxSites: 0, EdgeIDs: []string{a.ID, z.ID}})
	q := assignTestPlan(t, f, b, p.ID)
	if q.BaseBPS != 8000000 || q.PeakBPS != 16000000 || q.BurstBytes != 2000000 || q.PeriodBytes != 1000 || q.PeriodSeconds != 60 || q.OverageAction != "throttle" || q.OverageBPS != 8000 {
		t.Fatal("policy not copied into execution quota", q)
	}
	f.createRule(b, d, a, 20001)
	f.createRule(b, d, z, 20001)
	f.syncClient(d, key, "traffic-package-session")
	sa := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "traffic-boot-a", nil, nil), 200)
	sz := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(z, "traffic-boot-z", nil, nil), 200)
	ga, gz := sa.Grants[0], sz.Grants[0]
	originalID := ga.ID
	if ga.Bytes+gz.Bytes != 1000 || ga.BaseBPS+gz.BaseBPS != p.BandwidthBPS || ga.PeakBPS+gz.PeakBPS != p.BurstBPS || ga.BurstBytes+gz.BurstBytes != q.BurstBytes || !ga.WaitForCredit || !gz.WaitForCredit {
		t.Fatal("shared limits or burst authority multiplied", ga, gz)
	}
	// Reserving all included bytes is not consumption and cannot start excess.
	if ga.BaseBPS != 4000000 || gz.BaseBPS != 4000000 {
		t.Fatal("unspent reservation prematurely triggered excess", ga, gz)
	}
	seq := uint64(1)
	sa = decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "traffic-boot-a", nil, []model.Usage{{GrantID: ga.ID, Sequence: seq, UploadBytes: 500}}), 200)
	if sa.Grants[0].BaseBPS != ga.BaseBPS || sa.Grants[0].Bytes != ga.Bytes {
		t.Fatal("partial use refilled traffic or reduced rate", sa.Grants)
	}
	seq++
	sa = decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "traffic-boot-a", nil, []model.Usage{{GrantID: ga.ID, Sequence: seq, UploadBytes: 1000}}), 200)
	sz = decodeResponse[model.EdgeSnapshot](t, f.syncEdge(z, "traffic-boot-z", nil, nil), 200)
	ga, gz = sa.Grants[0], sz.Grants[0]
	if ga.ID != originalID || ga.BaseBPS != 4000 || gz.BaseBPS != 4000 || ga.PeakBPS != ga.BaseBPS || ga.BurstBytes+gz.BurstBytes != 0 || ga.Bytes <= 1000 || gz.Bytes <= 0 {
		t.Fatal("exhausted account did not receive shared reduced authority", ga, gz)
	}
	seq++
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "traffic-boot-a", nil, []model.Usage{{GrantID: ga.ID, Sequence: seq, UploadBytes: 1200}}), 200)
	q = configurationQuota(t, f, b)
	if q.UsedBytes != 1200 {
		t.Fatal("excess traffic was not metered", q)
	}
	p.OverageAction = "reject"
	p = decodeResponse[model.Plan](t, f.request("PUT", "/api/v1/plans/"+p.ID, p, f.admin, nil), 200)
	sa = decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "traffic-boot-a", nil, nil), 200)
	if sa.Grants[0].ID != ga.ID || sa.Grants[0].BaseBPS != 0 || sa.Grants[0].WaitForCredit {
		t.Fatal("reject policy did not revoke existing excess authority", sa.Grants)
	}
	p.TrafficMetered, p.BurstEnabled = false, false
	p = decodeResponse[model.Plan](t, f.request("PUT", "/api/v1/plans/"+p.ID, p, f.admin, nil), 200)
	q = configurationQuota(t, f, b)
	if q.UsedBytes != 1200 || q.PeriodBytes != -1 || q.PeriodSeconds != 0 || !q.PeriodEndsAt.IsZero() || q.PeakBPS != q.BaseBPS || q.BurstBytes != 0 {
		t.Fatal("disabling metering reset usage or retained hidden limits", q)
	}
	p.TrafficMetered, p.TrafficBytes, p.PeriodSeconds, p.OverageAction, p.OverageBPS = true, 2000, 60, "throttle", 8000
	p = decodeResponse[model.Plan](t, f.request("PUT", "/api/v1/plans/"+p.ID, p, f.admin, nil), 200)
	q = configurationQuota(t, f, b)
	if q.UsedBytes != 1200 {
		t.Fatal("reenabling metering reset spent credit", q)
	}
	oldPeriod := q.PeriodID
	boundary := now().Add(-time.Second)
	if _, err := f.s.db.Exec("UPDATE grants_table SET expires_at=? WHERE tenant_id=?", boundary, b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("UPDATE quotas SET period_ends_at=? WHERE tenant_id=?", boundary, b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	q = configurationQuota(t, f, b)
	if q.PeriodID == oldPeriod || q.UsedBytes != 0 || q.ReservedBytes != 0 || !q.PeriodEndsAt.After(now()) {
		t.Fatal("cycle did not reset its own balance", q)
	}
	f.syncClient(d, key, "traffic-package-session")
	sa = decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "traffic-boot-a", nil, nil), 200)
	if sa.Grants[0].BaseBPS != 4000000 || sa.Grants[0].Bytes != 2000 || sa.Grants[0].PeriodID != q.PeriodID {
		t.Fatal("cycle did not restore standard authority", sa.Grants)
	}
	oldPeriod = q.PeriodID
	if _, err := f.s.db.Exec("UPDATE grants_table SET expires_at=? WHERE tenant_id=?", boundary, b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("UPDATE quotas SET used_bytes=1500,period_ends_at=? WHERE tenant_id=?", boundary, b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	p.PeriodSeconds = 120
	decodeResponse[model.Plan](t, f.request("PUT", "/api/v1/plans/"+p.ID, p, f.admin, nil), 200)
	q = configurationQuota(t, f, b)
	if q.UsedBytes != 0 || q.PeriodID == oldPeriod || q.PeriodSeconds != 120 {
		t.Fatal("changing an elapsed schedule carried old consumption into a fresh cycle", q)
	}
}

func TestMySQLPlansDefaultsAssignmentAndAccess(t *testing.T) {
	f := newCloudFixture(t)
	a, z := f.edge("package-a"), f.edge("package-z")
	p := createTestPlan(t, f, model.Plan{Name: "基础套餐", BandwidthBPS: 8000000, MaxPorts: 2, MaxSites: 1, EdgeIDs: []string{a.ID, a.ID}, Default: true})
	if len(p.EdgeIDs) != 1 || p.Legacy {
		t.Fatal("invalid package normalization", p)
	}
	b := f.createUser("package-user")
	q := configurationQuota(t, f, b)
	if q.PlanID != p.ID || q.BaseBPS != p.BandwidthBPS || q.MaxPorts != 2 || q.MaxSites != 1 || !edgeAllowed(q, a.ID) || edgeAllowed(q, z.ID) {
		t.Fatal("default plan not applied", q)
	}
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/plans", nil, b, nil), 403)
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/plans", p, b, nil), 403)
	decodeResponse[map[string]any](t, f.request("PUT", "/api/v1/quotas/"+q.TenantID, q, f.admin, nil), 409)
	edges := decodeResponse[struct {
		Items []model.Edge `json:"items"`
	}](t, f.request("GET", "/api/v1/edges", nil, b, nil), 200)
	if len(edges.Items) != 1 || edges.Items[0].ID != a.ID {
		t.Fatal("unavailable exit node disclosed", edges)
	}
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/port-resources?edge_id="+z.ID, nil, b, nil), 403)
	decodeResponse[map[string]any](t, f.request("DELETE", "/api/v1/plans/"+p.ID, nil, f.admin, nil), 409)
	decodeResponse[map[string]any](t, f.request("DELETE", "/api/v1/edges/"+a.ID, nil, f.admin, nil), 409)
	shared := decodeResponse[model.User](t, f.request("POST", "/api/v1/users", map[string]string{"username": "package-shared", "password": "shared-user-password", "role": "user", "tenant_id": b.user.TenantID}, f.admin, nil), 201)
	decodeResponse[map[string]any](t, f.request("PUT", "/api/v1/users/"+shared.ID+"/plan", map[string]any{"plan_id": "", "version": q.Version}, b, nil), 403)
	decodeResponse[model.Quota](t, f.request("PUT", "/api/v1/users/"+shared.ID+"/plan", map[string]any{"plan_id": "", "version": q.Version}, f.admin, nil), 200)
	q = configurationQuota(t, f, b)
	if q.PlanID != "" || q.AllowedEdgeIDs == nil || len(q.AllowedEdgeIDs) != 0 || q.MaxPorts != 0 || q.MaxSites != 0 {
		t.Fatal("shared space package was not removed", q)
	}
	decodeResponse[map[string]any](t, f.request("PUT", "/api/v1/users/"+b.user.ID+"/plan", map[string]any{"plan_id": p.ID, "version": q.Version - 1}, f.admin, nil), 409)
	p.Default = false
	p = decodeResponse[model.Plan](t, f.request("PUT", "/api/v1/plans/"+p.ID, p, f.admin, nil), 200)
	registered := decodeResponse[struct {
		User model.User `json:"user"`
	}](t, f.request("POST", "/auth/register", map[string]string{"username": "package-unassigned", "password": "register-test-password"}, nil, nil), 201).User
	u := f.login(registered.Username, "register-test-password")
	q = configurationQuota(t, f, u)
	if q.PlanID != "" || q.AllowedEdgeIDs == nil || q.BaseBPS != 0 || q.MaxSites != 0 {
		t.Fatal("registration without a default was unrestricted", q)
	}
	if err := migrate(context.Background(), f.s.db); err != nil {
		t.Fatal(err)
	}
	if q = configurationQuota(t, f, u); q.PlanID != "" || q.AllowedEdgeIDs == nil {
		t.Fatal("restart granted unassigned account a legacy plan", q)
	}
	assignTestPlan(t, f, u, p.ID)
	account := decodeResponse[struct {
		User  model.User  `json:"user"`
		Plan  model.Plan  `json:"plan"`
		Quota model.Quota `json:"quota"`
	}](t, f.request("GET", "/api/v1/account", nil, u, nil), 200)
	if account.User.ID != u.user.ID || account.User.CreatedAt.IsZero() || account.Plan.ID != p.ID || account.Quota.TenantID != u.user.TenantID {
		t.Fatal("account returned wrong identity or plan", account)
	}
}

func TestMySQLPlanTotalPortsAndIndependentSites(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("package-capacity")
	d, _ := f.bind(b, "package-client")
	a, z := f.edge("capacity-a"), f.edge("capacity-z")
	p := createTestPlan(t, f, model.Plan{Name: "容量套餐", BandwidthBPS: 5000000, MaxPorts: 1, MaxSites: 1, EdgeIDs: []string{a.ID, z.ID}})
	assignTestPlan(t, f, b, p.ID)
	rule := model.Rule{Name: "TCP", Protocol: "tcp", DeviceID: d.ID, EdgeID: a.ID, PublicPort: 20001, Target: "127.0.0.1:8080", SourceMode: "socket", Transport: "auto", Enabled: true}
	other := rule
	other.Protocol, other.EdgeID, other.Name = "udp", z.ID, "UDP"
	responses := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for _, in := range []model.Rule{rule, other} {
		wg.Add(1)
		go func() { defer wg.Done(); responses <- f.request("POST", "/api/v1/rules", in, b, nil) }()
	}
	wg.Wait()
	close(responses)
	created, denied := 0, 0
	var portRule model.Rule
	for w := range responses {
		if w.Code == 201 {
			created++
			portRule = decodeResponse[model.Rule](t, w, 201)
		} else {
			requireConfigurationDenied(t, w)
			denied++
		}
	}
	if created != 1 || denied != 1 {
		t.Fatal("last total port admitted twice", created, denied)
	}
	for _, name := range []string{"one.package.example", "two.package.example"} {
		domain := decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains", map[string]string{"domain": name}, b, nil), 201)
		f.s.lookupTXT = func(context.Context, string) ([]string, error) { return []string{domain.TXTValue}, nil }
		decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains/"+domain.ID+"/verify", nil, b, nil), 200)
	}
	site := model.Rule{Name: "website", Protocol: "http", Domain: "one.package.example", DeviceID: d.ID, EdgeID: a.ID, Target: "http://127.0.0.1:8080", SourceMode: "forwarded_headers", Transport: "auto", Enabled: true}
	site = decodeResponse[model.Rule](t, f.request("POST", "/api/v1/rules", site, b, nil), 201)
	second := site
	second.Domain, second.EdgeID = "two.package.example", z.ID
	requireConfigurationDenied(t, f.request("POST", "/api/v1/rules", second, b, nil))
	q := configurationQuota(t, f, b)
	if q.Resources.Ports != 1 || q.Resources.Sites != 1 || q.Resources.Rules != 2 {
		t.Fatal("website and port counters are not independent", q.Resources)
	}
	// Converting a tunnel into a site is also an admission, even with a stable ID.
	conversion := portRule
	conversion.Protocol, conversion.Domain, conversion.SourceMode, conversion.Target = "http", "two.package.example", "forwarded_headers", "http://127.0.0.1:8080"
	requireConfigurationDenied(t, f.request("PUT", "/api/v1/rules/"+conversion.ID, conversion, b, nil))
	p.MaxPorts, p.MaxSites = 0, 0
	p = decodeResponse[model.Plan](t, f.request("PUT", "/api/v1/plans/"+p.ID, p, f.admin, nil), 200)
	site.Name = "existing site renamed"
	decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+site.ID, site, b, nil), 200)
	requireConfigurationDenied(t, f.request("POST", "/api/v1/rules", second, b, nil))
	if q = configurationQuota(t, f, b); q.MaxPorts != 0 || q.MaxSites != 0 || q.Resources.Sites != 1 {
		t.Fatal("downgrade lost resources or missed limits", q)
	}
}

func TestMySQLPlanNodeRemovalRevokesRuntimeAndBandwidth(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("package-runtime")
	d, key := f.bind(b, "package-runtime-client")
	a, z := f.edge("runtime-a"), f.edge("runtime-z")
	p := createTestPlan(t, f, model.Plan{Name: "运行套餐", BandwidthBPS: 8000000, MaxPorts: 5, MaxSites: 2, EdgeIDs: []string{a.ID, z.ID}})
	assignTestPlan(t, f, b, p.ID)
	r := f.createRule(b, d, a, 20001)
	f.createRule(b, d, z, 20001)
	f.syncClient(d, key, "package-runtime-session")
	sa := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "runtime-boot-a", nil, nil), 200)
	sz := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(z, "runtime-boot-z", nil, nil), 200)
	if len(sa.Grants) != 1 || len(sz.Grants) != 1 || sa.Grants[0].PeakBPS+sz.Grants[0].PeakBPS > p.BandwidthBPS {
		t.Fatal("bandwidth duplicated across exit nodes")
	}
	p.EdgeIDs, p.BandwidthBPS = []string{z.ID}, 1000000
	p = decodeResponse[model.Plan](t, f.request("PUT", "/api/v1/plans/"+p.ID, p, f.admin, nil), 200)
	decodeResponse[map[string]any](t, f.request("PUT", "/api/v1/plans/"+p.ID, model.Plan{Version: p.Version - 1}, f.admin, nil), 409)
	sa = decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "runtime-boot-a", nil, nil), 200)
	if len(sa.Grants) != 0 || len(sa.Devices) != 0 || len(sa.Rules) != 1 || sa.Rules[0].Enabled {
		t.Fatal("removed exit node retained forwarding authority", sa)
	}
	cs := f.syncClient(d, key, "package-runtime-session")
	if len(cs.Edges) != 1 || cs.Edges[0].ID != z.ID {
		t.Fatal("client retained removed exit node", cs.Edges)
	}
	g, err := f.s.allocateGrant(context.Background(), b.user.TenantID, a.ID, "bypass")
	if err != nil || g.ID != "" {
		t.Fatal("grant allocator bypassed node restriction", g, err)
	}
	w := f.request("POST", "/api/v1/rules", r, b, nil)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "套餐未包含") {
		t.Fatal("new service bypassed node restriction", w.Code, w.Body.String())
	}
	r.Enabled = false
	decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+r.ID, r, b, nil), 200)
	sz = decodeResponse[model.EdgeSnapshot](t, f.syncEdge(z, "runtime-boot-z", nil, nil), 200)
	if len(sz.Grants) != 1 || sz.Grants[0].PeakBPS > p.BandwidthBPS {
		t.Fatal("remaining node did not tighten bandwidth", sz.Grants)
	}
	assignTestPlan(t, f, b, "")
	sz = decodeResponse[model.EdgeSnapshot](t, f.syncEdge(z, "runtime-boot-z", nil, nil), 200)
	if len(sz.Grants) != 0 || len(sz.Devices) != 0 {
		t.Fatal("unassigned user retained runtime grants")
	}
}

func TestMySQLPlanMigrationPreservesExistingPolicy(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("package-migration")
	if _, err := f.s.db.Exec("UPDATE quotas SET plan_id=NULL,allowed_edge_ids=NULL,base_bps=123456,peak_bps=789012,max_ports=3,max_rules=7 WHERE tenant_id=?", b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	if err := migrate(context.Background(), f.s.db); err != nil {
		t.Fatal(err)
	}
	q := configurationQuota(t, f, b)
	p, err := readPlan(context.Background(), f.s.db, q.PlanID)
	if err != nil || !p.Legacy || !p.AllEdges || q.AllowedEdgeIDs != nil || q.BaseBPS != 123456 || q.PeakBPS != 789012 || q.MaxPorts != 3 || q.MaxRules != 7 {
		t.Fatal("migration changed existing policy", q, p, err)
	}
	if err = migrate(context.Background(), f.s.db); err != nil {
		t.Fatal(err)
	}
	if next := configurationQuota(t, f, b); next.PlanID != q.PlanID {
		t.Fatal("migration created a second plan")
	}
}

func TestMySQLAccountPasswordAndOtherSessions(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("account-password")
	other := f.login(b.user.Username, "user-test-password")
	decodeResponse[map[string]any](t, f.request("PUT", "/api/v1/account/password", map[string]string{"current_password": "incorrect", "password": "changed-account-password"}, b, nil), 400)
	decodeResponse[map[string]any](t, f.request("PUT", "/api/v1/account/password", map[string]string{"current_password": "user-test-password", "password": "changed-account-password"}, b, nil), 200)
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/account", nil, other, nil), 401)
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/account", nil, b, nil), 200)
	decodeResponse[map[string]any](t, f.request("POST", "/auth/login", map[string]string{"username": b.user.Username, "password": "user-test-password"}, nil, nil), 401)
	f.login(b.user.Username, "changed-account-password")
}

func TestMySQLUsageSummaryCountsAllGrantsAndScopesTenant(t *testing.T) {
	f := newCloudFixture(t)
	b, other := f.createUser("usage-summary-owner"), f.createUser("usage-summary-other")
	edge := f.edge("summary-exit")
	// More records than the raw /usage page cap; each row is cumulative for a
	// grant, and a later report replaces that grant's previous counters.
	seedSummaryGrant := func(gid, tid string, eid any, issued string, up, down int64) {
		t.Helper()
		if _, err := f.s.quotaSnapshot(context.Background(), tid); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`INSERT INTO grants_table(id,tenant_id,edge_id,issued_edge_id,boot_id,expires_at,bytes,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,reserved,used,closed,created_at)
   VALUES(?,?,?,?,'summary',?,?,-1,-1,0,-1,-1,?,?,1,?)`, gid, tid, eid, issued, now(), up+down, up+down, up+down, now()); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec("INSERT INTO usage_table(grant_id,sequence_no,upload_bytes,download_bytes,observed_at) VALUES(?,1,?,?,?)", gid, up, down, now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s.quotaSnapshot(context.Background(), b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	args, usageArgs := []any{}, []any{}
	for i := 0; i < 1005; i++ {
		gid := fmt.Sprintf("summary-%d", i)
		args = append(args, gid, b.user.TenantID, edge.ID, edge.ID, now(), now())
		usageArgs = append(usageArgs, gid, now())
	}
	query := "INSERT INTO grants_table(id,tenant_id,edge_id,issued_edge_id,boot_id,expires_at,bytes,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,reserved,used,closed,created_at) VALUES " + strings.TrimSuffix(strings.Repeat("(?,?,?,?,'summary',?,33,-1,-1,0,-1,-1,33,3,1,?),", 1005), ",")
	if _, err := f.s.db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("INSERT INTO usage_table(grant_id,sequence_no,upload_bytes,download_bytes,observed_at) VALUES "+strings.TrimSuffix(strings.Repeat("(?,1,1,2,?),", 1005), ","), usageArgs...); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("UPDATE usage_table SET upload_bytes=11,download_bytes=22,sequence_no=2 WHERE grant_id='summary-0'"); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id, tid  string
		eid      any
		issued   string
		up, down int
	}{{"removed", b.user.TenantID, nil, "removed-exit", 7, 9}, {"private", other.user.TenantID, edge.ID, edge.ID, 999999, 999999}} {
		seedSummaryGrant(row.id, row.tid, row.eid, row.issued, int64(row.up), int64(row.down))
	}
	list := decodeResponse[struct {
		Items []struct {
			EdgeID string `json:"edge_id"`
			Name   string `json:"edge_name"`
			Up     int64  `json:"upload_bytes"`
			Down   int64  `json:"download_bytes"`
		} `json:"items"`
	}](t, f.request("GET", "/api/v1/usage-summary?tenant_id="+other.user.TenantID, nil, b, nil), 200)
	var up, down int64
	for _, row := range list.Items {
		up += row.Up
		down += row.Down
		if row.EdgeID == edge.ID && row.Name != edge.Name {
			t.Fatal("missing exit name", row)
		}
		if row.EdgeID == "removed-exit" && (row.Up != 7 || row.Down != 9) {
			t.Fatal("deleted exit lost its own usage group", row)
		}
	}
	if len(list.Items) != 2 || up != 1022 || down != 2039 {
		t.Fatal("summary truncated, doubled cumulative reports or leaked another tenant", list, up, down)
	}
}
