package cloud

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"
)

func migrate(ctx context.Context, db *sql.DB) error {
	// DDL commits implicitly in MySQL. A connection-scoped advisory lock makes
	// independently restartable upgrades safe against concurrent cloud startups.
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var database string
	if err = conn.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database); err != nil {
		return err
	}
	lock := fmt.Sprintf("drafrp-schema:%x", sha256.Sum256([]byte(database)))[:60]
	var acquired int
	if err = conn.QueryRowContext(ctx, "SELECT GET_LOCK(?,30)", lock).Scan(&acquired); err != nil {
		return err
	}
	if acquired != 1 {
		return fmt.Errorf("schema: another upgrade holds the database lock")
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(release, "SELECT RELEASE_LOCK(?)", lock)
	}()
	return migrateLocked(ctx, db)
}

func migrateLocked(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tenants(id VARCHAR(64) PRIMARY KEY,name VARCHAR(255) NOT NULL,created_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS users(id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,username VARCHAR(255) NOT NULL UNIQUE,password_hash VARCHAR(255) NOT NULL,role VARCHAR(32) NOT NULL,disabled BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,INDEX(tenant_id),FOREIGN KEY(tenant_id) REFERENCES tenants(id)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS sessions(id VARCHAR(96) PRIMARY KEY,user_id VARCHAR(64) NOT NULL,token_hash CHAR(64) NOT NULL UNIQUE,csrf_hash CHAR(64) NOT NULL,expires_at DATETIME(6) NOT NULL,revoked BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,INDEX(user_id),INDEX(expires_at),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS devices(id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,name VARCHAR(255) NOT NULL,public_key TEXT NOT NULL,revoked BOOLEAN NOT NULL DEFAULT 0,generation BIGINT UNSIGNED NOT NULL DEFAULT 0,session_id VARCHAR(96),lease_until DATETIME(6),last_seen DATETIME(6),capabilities JSON NOT NULL,applied_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,INDEX(tenant_id),FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS runtime_nonces(device_id VARCHAR(64) NOT NULL,nonce VARCHAR(64) NOT NULL,expires_at DATETIME(6) NOT NULL,PRIMARY KEY(device_id,nonce),INDEX(expires_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS edges(id VARCHAR(64) PRIMARY KEY,name VARCHAR(255) NOT NULL,endpoints JSON NOT NULL,ca_cert TEXT,public_host VARCHAR(255),listen_host VARCHAR(255),http_port INT,https_port INT,port_min INT,port_max INT,max_carriers INT,capacity_bps BIGINT,token_hash CHAR(64) NOT NULL UNIQUE,boot_id VARCHAR(96),last_seen DATETIME(6),applied_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS edge_boots(edge_id VARCHAR(64) NOT NULL,boot_id VARCHAR(96) NOT NULL,retired BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,PRIMARY KEY(edge_id,boot_id)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS rules(id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,name VARCHAR(255) NOT NULL,protocol VARCHAR(16) NOT NULL,device_id VARCHAR(64) NOT NULL,edge_id VARCHAR(64) NOT NULL,public_port INT NOT NULL,domain VARCHAR(255),target VARCHAR(512) NOT NULL,host VARCHAR(255),server_name VARCHAR(255),certificate_id VARCHAR(64),source_mode VARCHAR(32) NOT NULL,transport VARCHAR(32) NOT NULL,acl_template_id VARCHAR(64),acl JSON,enabled BOOLEAN NOT NULL DEFAULT 1,deleting BOOLEAN NOT NULL DEFAULT 0,version BIGINT UNSIGNED NOT NULL DEFAULT 1,status VARCHAR(32) NOT NULL,last_error TEXT,applied_version BIGINT UNSIGNED NOT NULL DEFAULT 0,timeout_seconds INT NOT NULL DEFAULT 30,created_at DATETIME(6) NOT NULL,updated_at DATETIME(6) NOT NULL,INDEX(tenant_id),INDEX(edge_id),INDEX(device_id),FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS resource_claims(edge_id VARCHAR(64) NOT NULL,resource_key VARCHAR(320) NOT NULL,rule_id VARCHAR(64) NOT NULL,tenant_id VARCHAR(64) NULL DEFAULT NULL,release_at DATETIME(6),PRIMARY KEY(edge_id,resource_key),INDEX(rule_id),INDEX owner_release(tenant_id,release_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS acl_templates(id VARCHAR(64) PRIMARY KEY,name VARCHAR(255) NOT NULL,policy JSON NOT NULL,published JSON,version BIGINT UNSIGNED NOT NULL DEFAULT 1,default_flag BOOLEAN NOT NULL DEFAULT 0,mandatory BOOLEAN NOT NULL DEFAULT 0,created_by VARCHAR(64),updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS acl_template_versions(template_id VARCHAR(64) NOT NULL,version BIGINT UNSIGNED NOT NULL,policy JSON NOT NULL,created_at DATETIME(6) NOT NULL,PRIMARY KEY(template_id,version)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS certificates(id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,name VARCHAR(255) NOT NULL,domains JSON NOT NULL,cert_pem TEXT NOT NULL,key_enc TEXT NOT NULL,expires_at DATETIME(6),created_at DATETIME(6) NOT NULL,INDEX(tenant_id),FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS domains(id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,domain VARCHAR(253) NOT NULL,challenge VARCHAR(96) NOT NULL,status VARCHAR(16) NOT NULL DEFAULT 'pending',verified_at DATETIME(6),created_at DATETIME(6) NOT NULL,UNIQUE KEY tenant_domain(tenant_id,domain),FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS domain_ownership(domain VARCHAR(253) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS quotas(tenant_id VARCHAR(64) PRIMARY KEY,base_bps BIGINT NOT NULL DEFAULT -1,peak_bps BIGINT NOT NULL DEFAULT -1,burst_bytes BIGINT NOT NULL DEFAULT 0,max_connections INT NOT NULL DEFAULT -1,new_flows_per_second INT NOT NULL DEFAULT -1,period_bytes BIGINT NOT NULL DEFAULT -1,used_bytes BIGINT NOT NULL DEFAULT 0,reserved_bytes BIGINT NOT NULL DEFAULT 0,version BIGINT UNSIGNED NOT NULL DEFAULT 1,updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS plans(id VARCHAR(64) PRIMARY KEY,name VARCHAR(255) NOT NULL,bandwidth_bps BIGINT NOT NULL,max_ports INT NOT NULL,max_sites INT NOT NULL,all_edges BOOLEAN NOT NULL DEFAULT 0,version BIGINT UNSIGNED NOT NULL DEFAULT 1,legacy BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS plan_settings(id INT PRIMARY KEY,default_plan_id VARCHAR(64) NULL DEFAULT NULL) ENGINE=InnoDB`,
		`INSERT IGNORE INTO plan_settings(id) VALUES(1)`,
		`CREATE TABLE IF NOT EXISTS quota_periods(tenant_id VARCHAR(64) NOT NULL,period_id VARCHAR(64) NOT NULL,started_at DATETIME(6) NOT NULL,ends_at DATETIME(6),used_bytes BIGINT NOT NULL DEFAULT 0,reserved_bytes BIGINT NOT NULL DEFAULT 0,PRIMARY KEY(tenant_id,period_id)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS grants_table(id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,edge_id VARCHAR(64) NULL,issued_edge_id VARCHAR(64) NOT NULL DEFAULT '',boot_id VARCHAR(96) NOT NULL,expires_at DATETIME(6) NOT NULL,bytes BIGINT NOT NULL,base_bps BIGINT NOT NULL,peak_bps BIGINT NOT NULL,burst_bytes BIGINT NOT NULL,max_connections INT NOT NULL,new_flows_per_second INT NOT NULL,policy_version BIGINT UNSIGNED NOT NULL DEFAULT 1,reserved BIGINT NOT NULL DEFAULT 0,used BIGINT NOT NULL DEFAULT 0,closed BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,INDEX(edge_id),INDEX(tenant_id)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS usage_table(grant_id VARCHAR(64) PRIMARY KEY,sequence_no BIGINT UNSIGNED NOT NULL DEFAULT 0,upload_bytes BIGINT NOT NULL DEFAULT 0,download_bytes BIGINT NOT NULL DEFAULT 0,closed BOOLEAN NOT NULL DEFAULT 0,observed_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS bindings(id VARCHAR(64) PRIMARY KEY,user_code VARCHAR(32) NOT NULL UNIQUE,poll_hash CHAR(64) NOT NULL UNIQUE,name VARCHAR(255) NOT NULL,public_key TEXT NOT NULL,status VARCHAR(32) NOT NULL,tenant_id VARCHAR(64),device_id VARCHAR(64),expires_at DATETIME(6) NOT NULL,created_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS audit(id VARCHAR(64) PRIMARY KEY,actor_id VARCHAR(64),tenant_id VARCHAR(64),action VARCHAR(128) NOT NULL,resource_id VARCHAR(128),created_at DATETIME(6) NOT NULL,INDEX(tenant_id),INDEX(created_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS config_revision(id INT PRIMARY KEY,revision BIGINT UNSIGNED NOT NULL) ENGINE=InnoDB`,
		`INSERT IGNORE INTO config_revision(id,revision) VALUES(1,1)`,
		`CREATE TABLE IF NOT EXISTS idempotency_keys(actor_id VARCHAR(64) NOT NULL,request_key VARCHAR(128) NOT NULL,fingerprint CHAR(64) NOT NULL,status_code INT NOT NULL DEFAULT 0,response MEDIUMBLOB,created_at DATETIME(6) NOT NULL,PRIMARY KEY(actor_id,request_key),INDEX(created_at)) ENGINE=InnoDB`,
	}
	for _, q := range stmts {
		if _, e := db.ExecContext(ctx, q); e != nil {
			return fmt.Errorf("schema: %w", e)
		}
	}

	columnRows, err := db.QueryContext(ctx, "SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=DATABASE()")
	if err != nil {
		return err
	}
	existingColumns := map[string]bool{}
	for columnRows.Next() {
		var table, column string
		if err = columnRows.Scan(&table, &column); err != nil {
			break
		}
		existingColumns[table+"."+column] = true
	}
	columnErr := columnRows.Err()
	columnRows.Close()
	if err != nil {
		return err
	}
	if columnErr != nil {
		return columnErr
	}
	indexes, err := schemaNames(ctx, db, "statistics", "index_name")
	if err != nil {
		return err
	}
	// Additive upgrades from the initial, unpublished development schema.
	for _, col := range []struct{ table, name, definition string }{
		{"devices", "lease_until", "DATETIME(6) NULL"}, {"grants_table", "policy_version", "BIGINT UNSIGNED NOT NULL DEFAULT 1"},
		{"grants_table", "issued_edge_id", "VARCHAR(64) NOT NULL DEFAULT ''"},
		{"quotas", "period_id", "VARCHAR(64) NOT NULL DEFAULT 'lifetime'"},
		{"quotas", "max_devices", "INT NOT NULL DEFAULT -1"},
		{"quotas", "max_rules", "INT NOT NULL DEFAULT -1"},
		{"quotas", "max_ports", "INT NOT NULL DEFAULT -1"},
		{"quotas", "max_domains", "INT NOT NULL DEFAULT -1"},
		{"quotas", "max_sites", "INT NOT NULL DEFAULT -1"},
		{"quotas", "plan_id", "VARCHAR(64) NULL DEFAULT NULL"},
		{"quotas", "allowed_edge_ids", "JSON NULL"},
		{"quotas", "overage_action", "VARCHAR(16) NOT NULL DEFAULT 'reject'"},
		{"quotas", "overage_bps", "BIGINT NOT NULL DEFAULT 0"},
		{"plans", "burst_enabled", "BOOLEAN NOT NULL DEFAULT 0"},
		{"plans", "burst_bps", "BIGINT NOT NULL DEFAULT 0"},
		{"plans", "burst_seconds", "BIGINT NOT NULL DEFAULT 0"},
		{"plans", "traffic_metered", "BOOLEAN NOT NULL DEFAULT 0"},
		{"plans", "traffic_bytes", "BIGINT NOT NULL DEFAULT 0"},
		{"plans", "period_seconds", "BIGINT NOT NULL DEFAULT 0"},
		{"plans", "overage_action", "VARCHAR(16) NOT NULL DEFAULT 'reject'"},
		{"plans", "overage_bps", "BIGINT NOT NULL DEFAULT 0"},
		{"resource_claims", "tenant_id", "VARCHAR(64) NOT NULL DEFAULT ''"},
		{"quotas", "period_seconds", "BIGINT NOT NULL DEFAULT 0"},
		{"quotas", "period_started_at", "DATETIME(6) NULL"},
		{"quotas", "period_ends_at", "DATETIME(6) NULL"},
		{"grants_table", "period_id", "VARCHAR(64) NOT NULL DEFAULT 'lifetime'"},
		{"audit", "resource_type", "VARCHAR(64) NOT NULL DEFAULT ''"},
		{"edges", "runtime", "JSON NULL"},
		{"devices", "runtime", "JSON NULL"},
	} {
		if !existingColumns[col.table+"."+col.name] {
			if _, e := db.ExecContext(ctx, "ALTER TABLE "+col.table+" ADD COLUMN "+col.name+" "+col.definition); e != nil {
				return e
			}
		}
	}
	if !indexes["resource_claims.owner_release"] {
		if _, e := db.ExecContext(ctx, "ALTER TABLE resource_claims ADD INDEX owner_release(tenant_id,release_at)"); e != nil {
			return e
		}
	}
	if !indexes["quotas.plan_assignment"] {
		if _, e := db.ExecContext(ctx, "ALTER TABLE quotas ADD INDEX plan_assignment(plan_id,tenant_id)"); e != nil {
			return e
		}
	}
	for _, idx := range []struct{ table, name string }{{"rules", "uniq_edge_port"}, {"grants_table", "grant_live"}} {
		if indexes[idx.table+"."+idx.name] {
			if _, e := db.ExecContext(ctx, "ALTER TABLE "+idx.table+" DROP INDEX "+idx.name); e != nil {
				return e
			}
		}
	}
	if err := migratePlanEdges(ctx, db); err != nil {
		return err
	}
	if err := migratePlans(ctx, db); err != nil {
		return err
	}
	if err := migrateACLObservations(ctx, db); err != nil {
		return err
	}
	return migrateIntegrity(ctx, db)
}
