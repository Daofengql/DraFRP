package cloud

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"drafrp/internal/model"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func configurationQuota(t *testing.T, f *cloudFixture, b *browser) model.Quota {
	t.Helper()
	list := decodeResponse[struct {
		Items []model.Quota `json:"items"`
	}](t, f.request("GET", "/api/v1/quotas", nil, b, nil), 200)
	for _, q := range list.Items {
		if q.TenantID == b.user.TenantID {
			return q
		}
	}
	t.Fatal("own configuration quota missing")
	return model.Quota{}
}

func saveConfigurationQuota(t *testing.T, f *cloudFixture, q model.Quota) model.Quota {
	t.Helper()
	return decodeResponse[model.Quota](t, f.request("PUT", "/api/v1/quotas/"+q.TenantID, q, f.admin, nil), 200)
}

func pendingResourceBinding(t *testing.T, f *cloudFixture, name string) model.BindResponse {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return decodeResponse[model.BindResponse](t, f.request("POST", "/api/v1/runtime/client/bind", model.BindRequest{Name: name, PublicKey: base64.StdEncoding.EncodeToString(pub)}, nil, nil), 201)
}

func requireConfigurationDenied(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != 409 || !strings.Contains(response.Body.String(), `"code":"resource_quota_exceeded"`) {
		t.Fatalf("resource quota did not deny creation: %d %s", response.Code, response.Body.String())
	}
}

func TestMySQLResourceQuotaDefaultsCompatibilityAndIsolation(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("configuration-defaults")
	q := configurationQuota(t, f, b)
	if q.MaxDevices != -1 || q.MaxRules != -1 || q.MaxPorts != -1 || q.MaxDomains != -1 || q.Resources == nil || q.Resources.Devices != 0 || q.Resources.ObservedAt.IsZero() {
		t.Fatalf("new account resource defaults: %+v", q)
	}
	q.MaxDevices, q.MaxRules, q.MaxPorts, q.MaxDomains = 3, 4, 5, 6
	q = saveConfigurationQuota(t, f, q)
	if w := f.request("PUT", "/api/v1/quotas/"+q.TenantID, q, b, nil); w.Code != 403 {
		t.Fatal("ordinary user changed configuration limits", w.Code)
	}
	// An older console has none of the new fields. A runtime budget update
	// cannot silently reset these saved limits to unlimited or zero.
	encoded, _ := json.Marshal(q)
	var legacy map[string]any
	_ = json.Unmarshal(encoded, &legacy)
	for _, key := range []string{"max_devices", "max_rules", "max_ports", "max_domains", "resources"} {
		delete(legacy, key)
	}
	legacy["base_bps"] = 8000
	q = decodeResponse[model.Quota](t, f.request("PUT", "/api/v1/quotas/"+q.TenantID, legacy, f.admin, nil), 200)
	if q.MaxDevices != 3 || q.MaxRules != 4 || q.MaxPorts != 5 || q.MaxDomains != 6 || q.BaseBPS != 8000 {
		t.Fatal("legacy update discarded resource policy", q)
	}
	for _, bad := range []int{-2, 1000001} {
		invalid := q
		invalid.MaxDevices = bad
		if w := f.request("PUT", "/api/v1/quotas/"+q.TenantID, invalid, f.admin, nil); w.Code != 400 {
			t.Fatal("invalid resource limit accepted", w.Code, w.Body.String())
		}
	}
	other := f.createUser("configuration-other")
	f.bind(other, "other-private-device")
	if own := configurationQuota(t, f, b); own.Resources.Devices != 0 {
		t.Fatal("other tenant consumed this account's configuration slots", own.Resources)
	}
	list := decodeResponse[struct {
		Items []model.Quota `json:"items"`
	}](t, f.request("GET", "/api/v1/quotas", nil, b, nil), 200)
	if len(list.Items) != 1 || list.Items[0].TenantID != b.user.TenantID {
		t.Fatal("other tenant's quota usage disclosed", list)
	}
}

func TestMySQLResourceQuotaConcurrentBindingAndDomains(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("configuration-concurrent")
	q := configurationQuota(t, f, b)
	q.MaxDevices, q.MaxDomains = 1, 1
	saveConfigurationQuota(t, f, q)
	bindings := make([]model.BindResponse, 4)
	for i := range bindings {
		bindings[i] = pendingResourceBinding(t, f, fmt.Sprint("limited-", i))
	}
	responses := make([]*httptest.ResponseRecorder, len(bindings))
	var wg sync.WaitGroup
	for i := range bindings {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			responses[i] = f.request("POST", "/api/v1/bind/confirm", map[string]string{"user_code": bindings[i].UserCode}, b, nil)
		}(i)
	}
	wg.Wait()
	var winner string
	loser := -1
	for i, response := range responses {
		if response.Code == 200 {
			if winner != "" {
				t.Fatal("concurrent binding exceeded the device count limit")
			}
			winner = decodeResponse[struct {
				DeviceID string `json:"device_id"`
			}](t, response, 200).DeviceID
		} else {
			requireConfigurationDenied(t, response)
			loser = i
		}
	}
	if winner == "" || loser < 0 {
		t.Fatal("expected one bound device and three quota denials")
	}
	var pending int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM bindings WHERE status='pending'").Scan(&pending); err != nil || pending != 3 {
		t.Fatal("denied approval consumed a pending binding", pending, err)
	}
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/devices/"+winner, nil, b, nil), 200)
	decodeResponse[map[string]any](t, f.request("POST", "/api/v1/bind/confirm", map[string]string{"user_code": bindings[loser].UserCode}, b, nil), 200)
	if usage := configurationQuota(t, f, b).Resources; usage.Devices != 1 {
		t.Fatal("revocation did not release the configuration device slot", usage)
	}
	responses = make([]*httptest.ResponseRecorder, 8)
	for i := range responses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			responses[i] = f.request("POST", "/api/v1/domains", map[string]string{"domain": fmt.Sprintf("limited-%d.example.com", i)}, b, nil)
		}(i)
	}
	wg.Wait()
	var domainID string
	for _, response := range responses {
		if response.Code == 201 {
			if domainID != "" {
				t.Fatal("concurrent domain creation exceeded the quota")
			}
			domainID = decodeResponse[verifiedDomain](t, response, 201).ID
		} else {
			requireConfigurationDenied(t, response)
		}
	}
	if domainID == "" || configurationQuota(t, f, b).Resources.Domains != 1 {
		t.Fatal("expected exactly one pending domain")
	}
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/domains/"+domainID, nil, b, nil), 200)
	body := map[string]string{"domain": "retry.example.com"}
	headers := map[string]string{"Idempotency-Key": "limited-domain-create"}
	first := decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains", body, b, headers), 201)
	replay := decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains", body, b, headers), 201)
	if first.ID != replay.ID || configurationQuota(t, f, b).Resources.Domains != 1 {
		t.Fatal("replaying a successful create consumed another configuration slot")
	}
}

func TestMySQLResourceQuotaRuleAndOrphanPortLifecycle(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("configuration-ports")
	d, _ := f.bind(b, "configured-device")
	e, next := f.edge("configuration-first"), f.edge("configuration-next")
	q := configurationQuota(t, f, b)
	q.MaxRules, q.MaxPorts = 2, 2
	saveConfigurationQuota(t, f, q)
	tcp := f.createRule(b, d, e, 20001)
	udp := tcp
	udp.Protocol = "udp"
	udp = decodeResponse[model.Rule](t, f.request("POST", "/api/v1/rules", udp, b, nil), 201)
	if usage := configurationQuota(t, f, b).Resources; usage.Rules != 2 || usage.Ports != 2 {
		t.Fatal("TCP and UDP on the same number did not consume two resources", usage)
	}
	third := tcp
	third.PublicPort = 20002
	requireConfigurationDenied(t, f.request("POST", "/api/v1/rules", third, b, nil))
	q = configurationQuota(t, f, b)
	q.MaxRules = 0 // Existing metadata edits remain possible above a new limit.
	saveConfigurationQuota(t, f, q)
	tcp.Name = "rename at capacity"
	tcp = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+tcp.ID, tcp, b, nil), 200)
	moved := tcp
	moved.EdgeID = next.ID
	requireConfigurationDenied(t, f.request("PUT", "/api/v1/rules/"+tcp.ID, moved, b, nil))
	q = configurationQuota(t, f, b)
	q.MaxPorts = 3
	saveConfigurationQuota(t, f, q)
	moved = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+tcp.ID, moved, b, nil), 200)
	if usage := configurationQuota(t, f, b).Resources; usage.Ports != 3 {
		t.Fatal("rule move prematurely refunded its old port", usage)
	}
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/rules/"+moved.ID, nil, b, nil), 200)
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(next, "configuration-boot", []model.RuleStatus{{ID: moved.ID, Version: moved.Version + 1, Status: "deleted"}}, nil), 200)
	q = configurationQuota(t, f, b)
	if q.Resources.Rules != 1 || q.Resources.Ports != 2 {
		t.Fatal("orphaned old port stopped counting after the new edge ACK", q.Resources)
	}
	// Simulate the previous schema: one claim still has a rule and the old
	// moved claim only retains its creation audit. Both owners must survive an
	// additive, repeatable migration, along with the account's saved limits.
	if _, err := f.s.db.Exec("UPDATE resource_claims SET tenant_id=NULL WHERE tenant_id=?", b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("ALTER TABLE resource_claims DROP FOREIGN KEY fk_claims_tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("ALTER TABLE resource_claims DROP INDEX owner_release"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("DELETE FROM schema_migrations WHERE version='20261021_relational_integrity'"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := migrate(context.Background(), f.s.db); err != nil {
			t.Fatal("resource owner migration", err)
		}
	}
	q = configurationQuota(t, f, b)
	if q.Resources.Ports != 2 || q.MaxRules != 0 || q.MaxPorts != 3 {
		t.Fatal("upgrade lost orphan ownership or saved resource policy", q)
	}
	q.MaxRules, q.MaxPorts = 10, 2
	saveConfigurationQuota(t, f, q)
	requireConfigurationDenied(t, f.request("POST", "/api/v1/rules", third, b, nil))
	if _, err := f.s.db.Exec("UPDATE resource_claims SET release_at=? WHERE edge_id=? AND resource_key='tcp/20001'", now().Add(-time.Second), e.ID); err != nil {
		t.Fatal(err)
	}
	decodeResponse[model.Rule](t, f.request("POST", "/api/v1/rules", third, b, nil), 201)
	if q = configurationQuota(t, f, b); q.Resources.Ports != 2 || q.Resources.Rules != 2 {
		t.Fatal("expired reservation was not released for a new port", q.Resources)
	}
}

func TestMySQLResourceQuotaConcurrentRulesAcrossEdges(t *testing.T) {
	f := newCloudFixture(t)
	for _, constrained := range []string{"rules", "ports"} {
		t.Run(constrained, func(t *testing.T) {
			edges := []model.Edge{f.edge("quota-race-one-" + constrained), f.edge("quota-race-two-" + constrained), f.edge("quota-race-three-" + constrained)}
			b := f.createUser("configuration-race-" + constrained)
			d, _ := f.bind(b, "cross-edge-device")
			q := configurationQuota(t, f, b)
			if constrained == "rules" {
				q.MaxRules = 1
			} else {
				q.MaxPorts = 1
			}
			saveConfigurationQuota(t, f, q)
			responses := make([]*httptest.ResponseRecorder, 6)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range responses {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					rule := model.Rule{Name: fmt.Sprintf("cross-edge-%d", i), Protocol: "tcp", DeviceID: d.ID, EdgeID: edges[i%len(edges)].ID, PublicPort: 20003 + i, Target: "127.0.0.1:8080", SourceMode: "socket", Transport: "auto", Enabled: true}
					responses[i] = f.request("POST", "/api/v1/rules", rule, b, nil)
				}(i)
			}
			close(start)
			wg.Wait()
			created := 0
			for _, response := range responses {
				if response.Code == 201 {
					created++
				} else {
					requireConfigurationDenied(t, response)
				}
			}
			usage := configurationQuota(t, f, b).Resources
			if created != 1 || usage.Rules != 1 || usage.Ports != 1 {
				t.Fatalf("cross-edge %s limit exceeded: created=%d usage=%+v", constrained, created, usage)
			}
		})
	}
}

func TestMySQLResourceQuotaSitesAndUnknownLegacyClaims(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("configuration-sites")
	d, _ := f.bind(b, "site-device")
	edge := f.edge("configuration-site-edge")
	domain := decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains", map[string]string{"domain": "quota.example.com"}, b, nil), 201)
	f.s.lookupTXT = func(context.Context, string) ([]string, error) { return []string{domain.TXTValue}, nil }
	decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains/"+domain.ID+"/verify", nil, b, nil), 200)
	q := configurationQuota(t, f, b)
	q.MaxRules, q.MaxPorts, q.MaxDomains = 1, 0, 0
	saveConfigurationQuota(t, f, q)
	site := model.Rule{Name: "shared HTTP listener", Protocol: "http", Domain: domain.Domain, DeviceID: d.ID, EdgeID: edge.ID, Target: "http://127.0.0.1:8080", SourceMode: "forwarded_headers", Transport: "auto", Enabled: true}
	decodeResponse[model.Rule](t, f.request("POST", "/api/v1/rules", site, b, nil), 201)
	q = configurationQuota(t, f, b)
	if q.Resources.Rules != 1 || q.Resources.Ports != 0 || q.Resources.Domains != 1 {
		t.Fatal("site incorrectly consumed a shared public listener as a TCP port", q.Resources)
	}
	requireConfigurationDenied(t, f.request("POST", "/api/v1/domains", map[string]string{"domain": "another.example.com"}, b, nil))
	q.MaxRules, q.MaxPorts = 10, 1
	saveConfigurationQuota(t, f, q)
	// A pre-upgrade orphan without an owner cannot silently bypass a finite
	// port quota. It is quarantined until its old authority expires.
	if _, err := f.s.db.Exec("INSERT INTO resource_claims(edge_id,resource_key,rule_id,release_at) VALUES(?,?,?,?)", edge.ID, "tcp/20009", "legacy-unknown-rule", now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rule := model.Rule{Name: "new TCP", Protocol: "tcp", PublicPort: 20002, DeviceID: d.ID, EdgeID: edge.ID, Target: "127.0.0.1:8080", SourceMode: "socket", Transport: "auto", Enabled: true}
	w := f.request("POST", "/api/v1/rules", rule, b, nil)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "resource_quota_pending") {
		t.Fatal("unattributed reservation ignored", w.Code, w.Body.String())
	}
	if _, err := f.s.db.Exec("UPDATE resource_claims SET release_at=? WHERE rule_id='legacy-unknown-rule'", now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	decodeResponse[model.Rule](t, f.request("POST", "/api/v1/rules", rule, b, nil), 201)
}
