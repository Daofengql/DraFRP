package cloud

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Read a metadata inventory once, instead of one round trip per column/key.
// Callers supply only fixed information_schema view/column names.
func schemaNames(ctx context.Context, db *sql.DB, view, name string) (map[string]bool, error) {
	schemaColumn := "table_schema"
	if view == "referential_constraints" {
		schemaColumn = "constraint_schema"
	}
	rows, err := db.QueryContext(ctx, "SELECT DISTINCT table_name,"+name+" FROM information_schema."+view+" WHERE "+schemaColumn+"=DATABASE()")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]bool{}
	for rows.Next() {
		var table, key string
		if err = rows.Scan(&table, &key); err != nil {
			return nil, err
		}
		result[table+"."+key] = true
	}
	return result, rows.Err()
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// Node membership is relational; JSON remains only in the public API and in
// the independently locked effective quota snapshot.
func migratePlanEdges(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS plan_edges(
		plan_id VARCHAR(64) NOT NULL,edge_id VARCHAR(64) NOT NULL,
		PRIMARY KEY(plan_id,edge_id),INDEX(edge_id),
		CONSTRAINT fk_plan_edges_plan FOREIGN KEY(plan_id) REFERENCES plans(id) ON DELETE CASCADE,
		CONSTRAINT fk_plan_edges_edge FOREIGN KEY(edge_id) REFERENCES edges(id) ON DELETE RESTRICT
	) ENGINE=InnoDB`); err != nil {
		return fmt.Errorf("plan membership schema: %w", err)
	}
	var oldColumn int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='plans' AND column_name='edge_ids'").Scan(&oldColumn); err != nil {
		return err
	}
	if oldColumn == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx, "SELECT id,edge_ids FROM plans WHERE all_edges=0")
	if err != nil {
		return err
	}
	type membership struct {
		plan  string
		edges []string
	}
	items := []membership{}
	for rows.Next() {
		var pid, raw string
		if err = rows.Scan(&pid, &raw); err != nil {
			break
		}
		item := membership{plan: pid}
		if err = json.Unmarshal([]byte(raw), &item.edges); err != nil || item.edges == nil || len(item.edges) > 1024 {
			err = errors.New("schema: invalid plans.edge_ids; repair node membership before upgrading")
			break
		}
		slices.Sort(item.edges)
		item.edges = slices.Compact(item.edges)
		items = append(items, item)
	}
	readErr := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		if err = writePlanEdges(ctx, tx, item.plan, item.edges); err != nil {
			return fmt.Errorf("schema: plans.edge_ids references an unavailable node; original JSON retained: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	// Only remove the old representation after the entire backfill committed.
	_, err = db.ExecContext(ctx, "ALTER TABLE plans DROP COLUMN edge_ids")
	return err
}

func writePlanEdges(ctx context.Context, db sqlStore, pid string, edges []string) error {
	if _, err := db.ExecContext(ctx, "DELETE FROM plan_edges WHERE plan_id=?", pid); err != nil {
		return err
	}
	if len(edges) == 0 {
		return nil
	}
	args := make([]any, 0, len(edges)*2)
	for _, edge := range edges {
		args = append(args, pid, edge)
	}
	_, err := db.ExecContext(ctx, "INSERT INTO plan_edges(plan_id,edge_id) VALUES "+strings.TrimSuffix(strings.Repeat("(?,?),", len(edges)), ","), args...)
	return err
}

type foreignKey struct{ table, name, columns, parent, parentColumns, deletion string }

// These are ownership or current configuration references. Historical labels
// in audit, ACL observations, grant boot IDs and resource_claims.rule_id are
// snapshots with a different lifetime from the original live object.
var integrityKeys = []foreignKey{
	{"runtime_nonces", "fk_nonces_device", "device_id", "devices", "id", "CASCADE"},
	{"edge_boots", "fk_boots_edge", "edge_id", "edges", "id", "CASCADE"},
	{"acl_template_versions", "fk_acl_versions_template", "template_id", "acl_templates", "id", "CASCADE"},
	{"acl_templates", "fk_acl_creator", "created_by", "users", "id", "SET NULL"},
	{"idempotency_keys", "fk_idempotency_user", "actor_id", "users", "id", "CASCADE"},
	{"quotas", "fk_quotas_tenant", "tenant_id", "tenants", "id", "CASCADE"},
	{"quotas", "fk_quotas_plan", "plan_id", "plans", "id", "RESTRICT"},
	{"plan_settings", "fk_default_plan", "default_plan_id", "plans", "id", "RESTRICT"},
	{"quota_periods", "fk_periods_quota", "tenant_id", "quotas", "tenant_id", "CASCADE"},
	{"grants_table", "fk_grants_period", "tenant_id,period_id", "quota_periods", "tenant_id,period_id", "RESTRICT"},
	{"grants_table", "fk_grants_edge", "edge_id", "edges", "id", "SET NULL"},
	{"usage_table", "fk_usage_grant", "grant_id", "grants_table", "id", "RESTRICT"},
	{"resource_claims", "fk_claims_edge", "edge_id", "edges", "id", "RESTRICT"},
	{"resource_claims", "fk_claims_tenant", "tenant_id", "tenants", "id", "RESTRICT"},
	{"rules", "fk_rules_device_owner", "tenant_id,device_id", "devices", "tenant_id,id", "RESTRICT"},
	{"rules", "fk_rules_edge", "edge_id", "edges", "id", "RESTRICT"},
	{"rules", "fk_rules_certificate_owner", "tenant_id,certificate_id", "certificates", "tenant_id,id", "RESTRICT"},
	{"rules", "fk_rules_acl", "acl_template_id", "acl_templates", "id", "RESTRICT"},
	{"rules", "fk_rules_domain_owner", "tenant_id,domain", "domain_ownership", "tenant_id,domain", "RESTRICT"},
	{"domain_ownership", "fk_ownership_domain", "tenant_id,domain", "domains", "tenant_id,domain", "CASCADE"},
	{"bindings", "fk_bindings_tenant", "tenant_id", "tenants", "id", "CASCADE"},
	{"bindings", "fk_bindings_device_owner", "tenant_id,device_id", "devices", "tenant_id,id", "CASCADE"},
	{"acl_rule_acks", "fk_ack_rule", "rule_id", "rules", "id", "CASCADE"},
	{"acl_observations", "fk_observations_tenant", "tenant_id", "tenants", "id", "CASCADE"},
}

func migrateIntegrity(ctx context.Context, db *sql.DB) error {
	const version = "20261021_relational_integrity"
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version VARCHAR(96) PRIMARY KEY,applied_at DATETIME(6) NOT NULL) ENGINE=InnoDB`); err != nil {
		return err
	}
	var applied int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version=?", version).Scan(&applied); err != nil {
		return err
	}
	if applied != 0 {
		return nil
	}
	// These old-data scans run only while this migration is incomplete.
	// Port claims can outlive rules, so recover their owner from the rule or
	// its creation audit before enforcing the tenant reference.
	for _, query := range []string{
		`UPDATE grants_table SET issued_edge_id=edge_id WHERE issued_edge_id='' AND edge_id IS NOT NULL`,
		`UPDATE resource_claims c JOIN rules r ON r.id=c.rule_id SET c.tenant_id=r.tenant_id WHERE COALESCE(c.tenant_id,'')=''`,
		`UPDATE resource_claims c JOIN audit a ON a.resource_id=c.rule_id AND a.action='rule.create' SET c.tenant_id=a.tenant_id WHERE COALESCE(c.tenant_id,'')='' AND a.tenant_id IS NOT NULL AND a.tenant_id<>''`,
		`INSERT IGNORE INTO quota_periods(tenant_id,period_id,started_at,ends_at,used_bytes,reserved_bytes) SELECT tenant_id,period_id,COALESCE(period_started_at,updated_at),period_ends_at,used_bytes,reserved_bytes FROM quotas`,
	} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("schema legacy backfill: %w", err)
		}
	}
	rows, err := db.QueryContext(ctx, "SELECT table_name,column_name,is_nullable FROM information_schema.columns WHERE table_schema=DATABASE()")
	if err != nil {
		return err
	}
	columns := map[string]string{}
	for rows.Next() {
		var table, column, nullable string
		if err = rows.Scan(&table, &column, &nullable); err != nil {
			break
		}
		columns[table+"."+column] = nullable
	}
	readErr := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	for _, col := range []struct{ table, column string }{
		{"quotas", "plan_id"}, {"plan_settings", "default_plan_id"}, {"grants_table", "edge_id"}, {"resource_claims", "tenant_id"},
	} {
		if columns[col.table+"."+col.column] != "YES" {
			if _, err = db.ExecContext(ctx, "ALTER TABLE "+col.table+" MODIFY "+col.column+" VARCHAR(64) NULL DEFAULT NULL"); err != nil {
				return err
			}
		}
	}
	// Empty strings were used as absent references in the early schema.
	for _, query := range []string{
		"UPDATE quotas SET plan_id=NULL WHERE plan_id=''",
		"UPDATE plan_settings SET default_plan_id=NULL WHERE default_plan_id=''",
		"UPDATE rules SET certificate_id=NULL WHERE certificate_id=''",
		"UPDATE rules SET acl_template_id=NULL WHERE acl_template_id=''",
		"UPDATE rules SET domain=NULL WHERE domain=''",
		"UPDATE resource_claims c LEFT JOIN tenants t ON t.id=c.tenant_id SET c.tenant_id=NULL WHERE t.id IS NULL",
		"UPDATE acl_templates a LEFT JOIN users u ON u.id=a.created_by SET a.created_by=NULL WHERE u.id IS NULL",
		"DELETE n FROM runtime_nonces n LEFT JOIN devices d ON d.id=n.device_id WHERE d.id IS NULL",
		"DELETE b FROM edge_boots b LEFT JOIN edges e ON e.id=b.edge_id WHERE e.id IS NULL",
		"DELETE v FROM acl_template_versions v LEFT JOIN acl_templates a ON a.id=v.template_id WHERE a.id IS NULL",
		"DELETE k FROM idempotency_keys k LEFT JOIN users u ON u.id=k.actor_id WHERE u.id IS NULL",
		"DELETE b FROM bindings b LEFT JOIN tenants t ON t.id=b.tenant_id LEFT JOIN devices d ON d.id=b.device_id AND d.tenant_id=b.tenant_id WHERE (b.tenant_id IS NOT NULL AND t.id IS NULL) OR (b.device_id IS NOT NULL AND d.id IS NULL)",
		"DELETE a FROM acl_rule_acks a LEFT JOIN rules r ON r.id=a.rule_id WHERE r.id IS NULL",
		"DELETE a FROM acl_observations a LEFT JOIN tenants t ON t.id=a.tenant_id WHERE t.id IS NULL",
	} {
		if _, err = db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("schema cleanup: %w", err)
		}
	}
	// Never discard orphan or inconsistently attributed metering. The operator
	// gets relation names/counts, without credentials or customer row contents.
	checks := []string{}
	for _, key := range integrityKeys {
		if key.table == "usage_table" {
			continue
		}
		childCols, parentCols := strings.Split(key.columns, ","), strings.Split(key.parentColumns, ",")
		join, required := []string{}, []string{}
		for i, col := range childCols {
			join = append(join, "c."+col+"=p."+parentCols[i])
			required = append(required, "c."+col+" IS NOT NULL")
		}
		checks = append(checks, "SELECT '"+key.name+"' relation,COUNT(*) invalid_rows FROM "+key.table+" c LEFT JOIN "+key.parent+" p ON "+strings.Join(join, " AND ")+" WHERE "+strings.Join(required, " AND ")+" AND p."+parentCols[0]+" IS NULL HAVING COUNT(*)>0")
	}
	// Deleted exit nodes are valid historical grant references. Settle their
	// remaining authority conservatively before making that reference nullable.
	for i, query := range checks {
		if strings.Contains(query, "'fk_grants_edge'") {
			checks = append(checks[:i], checks[i+1:]...)
			break
		}
	}
	checks = append(checks, "SELECT 'fk_usage_grant',COUNT(*) FROM usage_table u LEFT JOIN grants_table g ON g.id=u.grant_id WHERE g.id IS NULL HAVING COUNT(*)>0")
	checks = append(checks, "SELECT 'grant_origin_missing',COUNT(*) FROM grants_table WHERE issued_edge_id='' HAVING COUNT(*)>0")
	if _, old := columns["usage_table.tenant_id"]; old {
		checks = append(checks, "SELECT 'usage_authority_mismatch',COUNT(*) FROM usage_table u JOIN grants_table g ON g.id=u.grant_id WHERE NOT(u.tenant_id<=>g.tenant_id) OR NOT(u.edge_id<=>g.issued_edge_id) OR NOT(u.boot_id<=>g.boot_id) HAVING COUNT(*)>0")
	}
	rows, err = db.QueryContext(ctx, strings.Join(checks, " UNION ALL "))
	if err != nil {
		return err
	}
	invalid := []string{}
	for rows.Next() {
		var relation string
		var count int64
		if err = rows.Scan(&relation, &count); err != nil {
			break
		}
		invalid = append(invalid, fmt.Sprintf("%s=%d", relation, count))
	}
	readErr = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	if len(invalid) > 0 {
		return fmt.Errorf("schema: unresolved references; data retained, repair before retry: %s", strings.Join(invalid, ", "))
	}
	constraints, err := schemaNames(ctx, db, "table_constraints", "constraint_name")
	if err != nil {
		return err
	}
	if !constraints["grants_table.ck_grants_issued_edge"] {
		if _, err = db.ExecContext(ctx, "ALTER TABLE grants_table ADD CONSTRAINT ck_grants_issued_edge CHECK (issued_edge_id<>'')"); err != nil {
			return fmt.Errorf("schema grant origin constraint: %w", err)
		}
	}
	// Drop duplicated identity before a legacy missing node is settled. A
	// failure after this DDL can then resume without comparing stale copies.
	if _, old := columns["usage_table.tenant_id"]; old {
		if _, err = db.ExecContext(ctx, "ALTER TABLE usage_table DROP COLUMN tenant_id,DROP COLUMN edge_id,DROP COLUMN boot_id"); err != nil {
			return err
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, query := range []string{
		`UPDATE quota_periods p JOIN (SELECT g.tenant_id,g.period_id,SUM(GREATEST(0,g.reserved-g.used)) credit FROM grants_table g LEFT JOIN edges e ON e.id=g.edge_id WHERE e.id IS NULL AND g.closed=0 GROUP BY g.tenant_id,g.period_id) x ON x.tenant_id=p.tenant_id AND x.period_id=p.period_id SET p.used_bytes=p.used_bytes+x.credit,p.reserved_bytes=GREATEST(0,p.reserved_bytes-x.credit)`,
		`UPDATE quotas q JOIN (SELECT g.tenant_id,g.period_id,SUM(GREATEST(0,g.reserved-g.used)) credit FROM grants_table g LEFT JOIN edges e ON e.id=g.edge_id WHERE e.id IS NULL AND g.closed=0 GROUP BY g.tenant_id,g.period_id) x ON x.tenant_id=q.tenant_id AND x.period_id=q.period_id SET q.used_bytes=q.used_bytes+x.credit,q.reserved_bytes=GREATEST(0,q.reserved_bytes-x.credit)`,
		`UPDATE grants_table g LEFT JOIN edges e ON e.id=g.edge_id SET g.closed=1,g.edge_id=NULL WHERE e.id IS NULL`,
	} {
		if _, err = tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	// ACL observations have a seven-day retention window. Their edge and rule
	// IDs are historical labels, while edge state and ACKs are live children.
	rows, err = db.QueryContext(ctx, "SELECT DISTINCT constraint_name FROM information_schema.key_column_usage WHERE table_schema=DATABASE() AND table_name='acl_observations' AND column_name='edge_id' AND referenced_table_name='edges'")
	if err != nil {
		return err
	}
	oldEdgeKeys := []string{}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			break
		}
		oldEdgeKeys = append(oldEdgeKeys, name)
	}
	readErr = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	for _, name := range oldEdgeKeys {
		if _, err = db.ExecContext(ctx, "ALTER TABLE acl_observations DROP FOREIGN KEY `"+strings.ReplaceAll(name, "`", "``")+"`"); err != nil {
			return fmt.Errorf("schema ACL history reference: %w", err)
		}
	}
	indexes, err := schemaNames(ctx, db, "statistics", "index_name")
	if err != nil {
		return err
	}
	keys, err := schemaNames(ctx, db, "referential_constraints", "constraint_name")
	if err != nil {
		return err
	}

	// Unique composite parent keys enforce ownership, including direct SQL.
	for _, idx := range []struct{ table, name, definition string }{
		{"devices", "device_owner", "UNIQUE INDEX device_owner(tenant_id,id)"},
		{"certificates", "certificate_owner", "UNIQUE INDEX certificate_owner(tenant_id,id)"},
		{"domain_ownership", "ownership_domain", "UNIQUE INDEX ownership_domain(tenant_id,domain)"},
		{"resource_claims", "claim_expiry", "INDEX claim_expiry(release_at)"},
		{"resource_claims", "claim_resource_release", "INDEX claim_resource_release(resource_key,release_at)"},
		{"grants_table", "grant_tenant_live", "INDEX grant_tenant_live(tenant_id,closed,expires_at)"},
		{"grants_table", "grant_edge_live", "INDEX grant_edge_live(edge_id,closed,expires_at)"},
		{"quotas", "quota_due", "INDEX quota_due(period_ends_at)"},
		{"bindings", "binding_expiry", "INDEX binding_expiry(expires_at)"},
	} {
		if !indexes[idx.table+"."+idx.name] {
			if _, err = db.ExecContext(ctx, "ALTER TABLE "+idx.table+" ADD "+idx.definition); err != nil {
				return err
			}
		}
	}
	for _, key := range integrityKeys {
		if !keys[key.table+"."+key.name] {
			query := "ALTER TABLE " + key.table + " ADD CONSTRAINT " + key.name + " FOREIGN KEY(" + key.columns + ") REFERENCES " + key.parent + "(" + key.parentColumns + ") ON DELETE " + key.deletion
			if _, err = db.ExecContext(ctx, query); err != nil {
				return fmt.Errorf("schema %s: %w", key.name, err)
			}
		}
	}
	var triggerExists int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema=DATABASE() AND trigger_name='guard_exit_deletion'").Scan(&triggerExists); err != nil {
		return err
	}
	if triggerExists == 0 {
		if _, err = db.ExecContext(ctx, `CREATE TRIGGER guard_exit_deletion BEFORE DELETE ON edges FOR EACH ROW
		BEGIN
		 IF EXISTS(SELECT 1 FROM grants_table WHERE edge_id=OLD.id AND closed=0) THEN
		  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='exit node still has live accounting leases';
		 END IF;
		END`); err != nil {
			return fmt.Errorf("schema exit deletion guard: %w", err)
		}
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema=DATABASE() AND trigger_name='guard_grant_origin'").Scan(&triggerExists); err != nil {
		return err
	}
	if triggerExists == 0 {
		if _, err = db.ExecContext(ctx, `CREATE TRIGGER guard_grant_origin BEFORE UPDATE ON grants_table FOR EACH ROW
		BEGIN
		 IF NEW.issued_edge_id<>OLD.issued_edge_id THEN
		  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='grant origin is immutable';
		 END IF;
		END`); err != nil {
			return fmt.Errorf("schema grant origin guard: %w", err)
		}
	}
	// Composite owner/live indexes cover these earlier single-column indexes.
	for _, idx := range []struct{ table, name string }{{"devices", "tenant_id"}, {"certificates", "tenant_id"}, {"grants_table", "tenant_id"}, {"grants_table", "edge_id"}} {
		if indexes[idx.table+"."+idx.name] {
			if _, err = db.ExecContext(ctx, "ALTER TABLE "+idx.table+" DROP INDEX "+idx.name); err != nil {
				return err
			}
		}
	}
	_, err = db.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", version, now())
	return err
}

var errEdgeLeases = errors.New("出口节点仍有未结算授权，等待用量结算或授权到期后删除")

func (s *Server) prepareEdgeDeletion(ctx context.Context, tx *businessTx, eid string) error {
	var live int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM grants_table WHERE edge_id=? AND closed=0 AND expires_at>?", eid, now()).Scan(&live); err != nil {
		return err
	}
	if live > 0 {
		return errEdgeLeases
	}
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT tenant_id FROM grants_table WHERE edge_id=? AND closed=0 ORDER BY tenant_id", eid)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var tid string
		if err = rows.Scan(&tid); err != nil {
			break
		}
		ids = append(ids, tid)
	}
	readErr := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	for _, tid := range ids {
		if _, err = s.currentQuota(ctx, tx, tid); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM resource_claims WHERE edge_id=? AND release_at<=?", eid, now())
	return err
}
