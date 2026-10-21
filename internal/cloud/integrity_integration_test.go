package cloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"drafrp/internal/model"
	"github.com/go-sql-driver/mysql"
)

func requireMySQLError(t *testing.T, err error, number uint16) {
	t.Helper()
	var databaseError *mysql.MySQLError
	if !errors.As(err, &databaseError) || databaseError.Number != number {
		t.Fatalf("database error %v; want MySQL %d", err, number)
	}
}

func requireSQLCount(t *testing.T, f *cloudFixture, want int, query string, args ...any) {
	t.Helper()
	var got int
	if err := f.s.db.QueryRow(query, args...).Scan(&got); err != nil || got != want {
		t.Fatalf("%s: got %d, want %d: %v", query, got, want, err)
	}
}

func TestMySQLIntegrityForeignKeysAndCascades(t *testing.T) {
	f := newCloudFixture(t)
	b, other := f.createUser("integrity-owner"), f.createUser("integrity-other")
	edge := f.edge("integrity-exit")
	d, _ := f.bind(b, "referenced-client")
	foreign, _ := f.bind(other, "foreign-client")
	rule := f.createRule(b, d, edge, 20001)
	for _, change := range []struct {
		query string
		args  []any
	}{
		{"UPDATE rules SET device_id=? WHERE id=?", []any{foreign.ID, rule.ID}},
		{"UPDATE rules SET edge_id='missing-exit' WHERE id=?", []any{rule.ID}},
		{"INSERT INTO runtime_nonces(device_id,nonce,expires_at) VALUES('missing-client','nonce',?)", []any{now()}},
		{"INSERT INTO edge_boots(edge_id,boot_id,created_at) VALUES('missing-exit','boot',?)", []any{now()}},
		{"INSERT INTO plan_edges(plan_id,edge_id) VALUES('missing-plan',?)", []any{edge.ID}},
		{"UPDATE quotas SET plan_id='missing-plan' WHERE tenant_id=?", []any{b.user.TenantID}},
		{"UPDATE plan_settings SET default_plan_id='missing-plan' WHERE id=1", nil},
		{"INSERT INTO usage_table(grant_id,observed_at) VALUES('missing-grant',?)", []any{now()}},
	} {
		_, err := f.s.db.Exec(change.query, change.args...)
		requireMySQLError(t, err, 1452)
	}
	for _, change := range []struct {
		query string
		id    string
	}{
		{"DELETE FROM devices WHERE id=?", d.ID},
		{"DELETE FROM edges WHERE id=?", edge.ID},
	} {
		_, err := f.s.db.Exec(change.query, change.id)
		requireMySQLError(t, err, 1451)
	}
	certPEM, keyPEM := testCertificate(t)
	cert := decodeResponse[model.Certificate](t, f.request("POST", "/api/v1/certificates", model.Certificate{Name: "foreign-cert", CertPEM: certPEM, KeyPEM: keyPEM}, other, nil), 201)
	_, err := f.s.db.Exec("UPDATE rules SET certificate_id=? WHERE id=?", cert.ID, rule.ID)
	requireMySQLError(t, err, 1452)
	// A global domain owner must belong to an actual registration in that space.
	_, err = f.s.db.Exec("INSERT INTO domain_ownership(domain,tenant_id) VALUES('unregistered.example',?)", b.user.TenantID)
	requireMySQLError(t, err, 1452)
	domain := decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains", map[string]string{"domain": "integrity.example"}, b, nil), 201)
	if _, err = f.s.db.Exec("INSERT INTO domain_ownership(domain,tenant_id) VALUES(?,?)", domain.Domain, b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.db.Exec("UPDATE rules SET domain=? WHERE id=?", domain.Domain, rule.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.db.Exec("DELETE FROM domains WHERE id=?", domain.ID)
	requireMySQLError(t, err, 1451)
	if _, err = f.s.db.Exec("UPDATE rules SET domain=NULL WHERE id=?", rule.ID); err != nil {
		t.Fatal(err)
	}
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/domains/"+domain.ID, nil, b, nil), 200)
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM domain_ownership WHERE domain=?", domain.Domain)
	// Client-owned handshake state is disposable; a referenced client is not.
	temporary, key := f.bind(b, "temporary-client")
	f.syncClient(temporary, key, "temporary-session")
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM runtime_nonces WHERE device_id=?", temporary.ID)
	if _, err = f.s.db.Exec("DELETE FROM devices WHERE id=?", temporary.ID); err != nil {
		t.Fatal(err)
	}
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM runtime_nonces WHERE device_id=?", temporary.ID)
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM bindings WHERE device_id=?", temporary.ID)
	// User deletion cascades ephemeral sessions/replay responses. Tenant and
	// audit lifetimes are independent from individual account membership.
	actor := f.createUser("temporary-actor")
	decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains", map[string]string{"domain": "temporary.example"}, actor, map[string]string{"Idempotency-Key": "integrity-replay"}), 201)
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM idempotency_keys WHERE actor_id=?", actor.user.ID)
	if _, err = f.s.db.Exec("INSERT INTO acl_templates(id,name,policy,created_by,updated_at) VALUES('temporary-template','temporary',JSON_OBJECT(),?,?)", actor.user.ID, now()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.db.Exec("INSERT INTO acl_template_versions(template_id,version,policy,created_at) VALUES('temporary-template',1,JSON_OBJECT(),?)", now()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.db.Exec("DELETE FROM users WHERE id=?", actor.user.ID); err != nil {
		t.Fatal(err)
	}
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM sessions WHERE user_id=?", actor.user.ID)
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM idempotency_keys WHERE actor_id=?", actor.user.ID)
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM acl_templates WHERE id='temporary-template' AND created_by IS NULL")
	if _, err = f.s.db.Exec("DELETE FROM acl_templates WHERE id='temporary-template'"); err != nil {
		t.Fatal(err)
	}
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM acl_template_versions WHERE template_id='temporary-template'")
	if _, err = f.s.quotaSnapshot(context.Background(), actor.user.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.db.Exec("DELETE FROM tenants WHERE id=?", actor.user.TenantID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"quotas", "quota_periods", "domains", "devices"} {
		requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM "+table+" WHERE tenant_id=?", actor.user.TenantID)
	}
	requireSQLCount(t, f, 1, "SELECT COUNT(*)>0 FROM audit WHERE actor_id=?", actor.user.ID)
}

func TestMySQLEdgeDeletionSettlesAndPreservesMetering(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("exit-history-owner")
	edge := f.edge("exit-history")
	d, key := f.bind(b, "history-client")
	rule := f.createRule(b, d, edge, 20001)
	f.syncClient(d, key, "history-client-session")
	snap := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "history-boot", nil, nil), 200)
	grant := snap.Grants[0]
	_, err := f.s.db.Exec("UPDATE grants_table SET issued_edge_id='' WHERE id=?", grant.ID)
	requireMySQLError(t, err, 1644)
	_, err = f.s.db.Exec("UPDATE grants_table SET issued_edge_id='another-exit' WHERE id=?", grant.ID)
	requireMySQLError(t, err, 1644)
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "history-boot", nil, []model.Usage{{GrantID: grant.ID, Sequence: 1, UploadBytes: 7, DownloadBytes: 9}}), 200)
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/rules/"+rule.ID, nil, b, nil), 200)
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "history-boot", []model.RuleStatus{{ID: rule.ID, Version: rule.Version + 1, Status: "deleted"}}, nil), 200)
	if _, err := f.s.db.Exec("INSERT INTO acl_observations(edge_id,counter_key,tenant_id,rule_id,boot_id,payload,allowed,denied,observed_at,received_at) VALUES(?,?,?,?,?,JSON_OBJECT(),1,0,?,?)", edge.ID, strings.Repeat("a", 64), b.user.TenantID, rule.ID, "history-boot", now(), now()); err != nil {
		t.Fatal(err)
	}
	if w := f.request("DELETE", "/api/v1/edges/"+edge.ID, nil, f.admin, nil); w.Code != 409 {
		t.Fatalf("live grant deletion: %d %s", w.Code, w.Body.String())
	}
	_, err = f.s.db.Exec("DELETE FROM edges WHERE id=?", edge.ID)
	requireMySQLError(t, err, 1644)
	if _, err = f.s.db.Exec("UPDATE grants_table SET expires_at=? WHERE id=?", now().Add(-time.Second), grant.ID); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.db.Exec("DELETE FROM edges WHERE id=?", edge.ID)
	requireMySQLError(t, err, 1644)
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/edges/"+edge.ID, nil, f.admin, nil), 200)
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM edge_boots WHERE edge_id=?", edge.ID)
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM grants_table WHERE id=? AND edge_id IS NULL AND issued_edge_id=? AND closed=1", grant.ID, edge.ID)
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM usage_table WHERE grant_id=? AND upload_bytes=7 AND download_bytes=9", grant.ID)
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM acl_observations WHERE edge_id=? AND rule_id=?", edge.ID, rule.ID)
	_, err = f.s.db.Exec("DELETE FROM grants_table WHERE id=?", grant.ID)
	requireMySQLError(t, err, 1451)
	_, err = f.s.db.Exec("DELETE FROM quota_periods WHERE tenant_id=? AND period_id=?", b.user.TenantID, grant.PeriodID)
	requireMySQLError(t, err, 1451)
	_, err = f.s.db.Exec("DELETE FROM quotas WHERE tenant_id=?", b.user.TenantID)
	requireMySQLError(t, err, 1451)
	q, err := f.s.quotaSnapshot(context.Background(), b.user.TenantID)
	if err != nil || q.UsedBytes != grant.Bytes || q.ReservedBytes != 0 {
		t.Fatalf("expired lease settlement: %+v %v", q, err)
	}
	list := decodeResponse[struct {
		Items []struct {
			EdgeID string `json:"edge_id"`
			Up     int64  `json:"upload_bytes"`
			Down   int64  `json:"download_bytes"`
		} `json:"items"`
	}](t, f.request("GET", "/api/v1/usage-summary", nil, b, nil), 200)
	if len(list.Items) != 1 || list.Items[0].EdgeID != edge.ID || list.Items[0].Up != 7 || list.Items[0].Down != 9 {
		t.Fatalf("deleted exit lost reported history: %+v", list)
	}
}

func TestMySQLIntegrityMigrationLegacyAndConcurrentStartup(t *testing.T) {
	f := newCloudFixture(t)
	f.s.cancel() // keep maintenance from touching the intentionally old fixture
	b := f.createUser("legacy-integrity-owner")
	edge := f.edge("legacy-membership-exit")
	p := decodeResponse[model.Plan](t, f.request("POST", "/api/v1/plans", model.Plan{Name: "legacy-selected-nodes", BandwidthBPS: 1234, MaxPorts: 3, MaxSites: 2, EdgeIDs: []string{edge.ID}}, f.admin, nil), 201)
	if _, err := f.s.quotaSnapshot(context.Background(), b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"INSERT INTO grants_table(id,tenant_id,edge_id,issued_edge_id,boot_id,expires_at,bytes,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,reserved,used,created_at) VALUES('legacy-grant',?,?,?,'legacy-boot',UTC_TIMESTAMP(6)+INTERVAL 1 MINUTE,20,-1,-1,0,-1,-1,20,3,UTC_TIMESTAMP(6))",
	} {
		if _, err := f.s.db.Exec(query, b.user.TenantID, edge.ID, edge.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s.db.Exec("INSERT INTO usage_table(grant_id,sequence_no,upload_bytes,download_bytes,observed_at) VALUES('legacy-grant',1,1,2,?)", now()); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the old representation, including real previously orphanable
	// rows. No FOREIGN_KEY_CHECKS bypass is used in production or in this test.
	for _, key := range integrityKeys {
		if _, err := f.s.db.Exec("ALTER TABLE " + key.table + " DROP FOREIGN KEY " + key.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s.db.Exec("ALTER TABLE acl_observations ADD CONSTRAINT old_acl_observations_edge FOREIGN KEY(edge_id) REFERENCES edges(id) ON DELETE CASCADE"); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"DROP TRIGGER guard_exit_deletion",
		"DROP TRIGGER guard_grant_origin",
		"DELETE FROM schema_migrations",
		"ALTER TABLE grants_table DROP CHECK ck_grants_issued_edge",
		"ALTER TABLE grants_table DROP COLUMN issued_edge_id",
		"ALTER TABLE plans ADD edge_ids JSON NULL",
		"UPDATE plans p SET edge_ids=COALESCE((SELECT JSON_ARRAYAGG(pe.edge_id) FROM plan_edges pe WHERE pe.plan_id=p.id),JSON_ARRAY())",
		"DROP TABLE plan_edges",
		"ALTER TABLE usage_table ADD tenant_id VARCHAR(64),ADD edge_id VARCHAR(64),ADD boot_id VARCHAR(96)",
		"UPDATE usage_table u JOIN grants_table g ON g.id=u.grant_id SET u.tenant_id=g.tenant_id,u.edge_id=g.edge_id,u.boot_id=g.boot_id",
		"INSERT INTO runtime_nonces(device_id,nonce,expires_at) VALUES('old-missing-client','old-nonce',UTC_TIMESTAMP(6))",
		"INSERT INTO edge_boots(edge_id,boot_id,created_at) VALUES('old-missing-exit','old-boot',UTC_TIMESTAMP(6))",
		"INSERT INTO acl_template_versions(template_id,version,policy,created_at) VALUES('old-missing-template',1,JSON_OBJECT(),UTC_TIMESTAMP(6))",
	} {
		if _, err := f.s.db.Exec(query); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	if _, err := f.s.db.Exec("UPDATE plans SET edge_ids=JSON_ARRAY('missing-legacy-exit') WHERE id=?", p.ID); err != nil {
		t.Fatal(err)
	}
	if err := migrate(context.Background(), f.s.db); err == nil || !strings.Contains(err.Error(), "original JSON retained") {
		t.Fatalf("invalid legacy membership must stop upgrade: %v", err)
	}
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='plans' AND column_name='edge_ids'")
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM plan_edges WHERE plan_id=?", p.ID)
	if _, err := f.s.db.Exec("UPDATE plans SET edge_ids=JSON_ARRAY(?) WHERE id=?", edge.ID, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("UPDATE usage_table SET tenant_id='wrong-tenant' WHERE grant_id='legacy-grant'"); err != nil {
		t.Fatal(err)
	}
	if err := migrate(context.Background(), f.s.db); err == nil || !strings.Contains(err.Error(), "usage_authority_mismatch=1") {
		t.Fatalf("misattributed legacy usage must stop upgrade: %v", err)
	}
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='usage_table' AND column_name='tenant_id'")
	if _, err := f.s.db.Exec("UPDATE usage_table SET tenant_id=? WHERE grant_id='legacy-grant'", b.user.TenantID); err != nil {
		t.Fatal(err)
	}
	if err := migrate(context.Background(), f.s.db); err != nil {
		t.Fatal(err)
	}
	got, err := readPlan(context.Background(), f.s.db, p.ID)
	if err != nil || len(got.EdgeIDs) != 1 || got.EdgeIDs[0] != edge.ID || got.BandwidthBPS != 1234 {
		t.Fatalf("plan upgrade: %+v %v", got, err)
	}
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM usage_table WHERE grant_id='legacy-grant' AND upload_bytes=1 AND download_bytes=2")
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM grants_table WHERE id='legacy-grant' AND issued_edge_id=?", edge.ID)
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND ((table_name='usage_table' AND column_name IN ('tenant_id','edge_id','boot_id')) OR (table_name='plans' AND column_name='edge_ids'))")
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM runtime_nonces WHERE device_id='old-missing-client'")
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM edge_boots WHERE edge_id='old-missing-exit'")
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM acl_template_versions WHERE template_id='old-missing-template'")
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM information_schema.key_column_usage WHERE table_schema=DATABASE() AND table_name='acl_observations' AND referenced_table_name='edges'")
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { results <- migrate(context.Background(), f.s.db) }()
	}
	for i := 0; i < 2; i++ {
		if err = <-results; err != nil {
			t.Fatal("concurrent upgrade", err)
		}
	}
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM schema_migrations WHERE version='20261021_relational_integrity'")
}

func TestMySQLIntegrityMigrationRetainsUnresolvedUsage(t *testing.T) {
	f := newCloudFixture(t)
	f.s.cancel()
	for _, query := range []string{
		"ALTER TABLE usage_table DROP FOREIGN KEY fk_usage_grant",
		"DELETE FROM schema_migrations",
		"INSERT INTO usage_table(grant_id,upload_bytes,download_bytes,observed_at) VALUES('unrecoverable-old-grant',42,43,UTC_TIMESTAMP(6))",
	} {
		if _, err := f.s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	err := migrate(context.Background(), f.s.db)
	if err == nil || !strings.Contains(err.Error(), "fk_usage_grant=1") || strings.Contains(err.Error(), "unrecoverable-old-grant") {
		t.Fatalf("unresolved usage must stop migration with relation counts: %v", err)
	}
	requireSQLCount(t, f, 1, "SELECT COUNT(*) FROM usage_table WHERE upload_bytes=42 AND download_bytes=43")
	requireSQLCount(t, f, 0, "SELECT COUNT(*) FROM schema_migrations")
	// A repaired parent allows the exact same migration to resume.
	_, err = f.s.db.Exec("DELETE FROM usage_table WHERE grant_id='unrecoverable-old-grant'")
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(context.Background(), f.s.db); err != nil {
		t.Fatal(fmt.Errorf("resume after repair: %w", err))
	}
}
