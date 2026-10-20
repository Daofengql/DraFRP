package cloud

import (
	"context"
	"database/sql"
)

func migrate(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tenants (id VARCHAR(64) PRIMARY KEY,name VARCHAR(255) NOT NULL,created_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS users (id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,username VARCHAR(255) NOT NULL UNIQUE,password_hash VARCHAR(255) NOT NULL,role VARCHAR(32) NOT NULL,disabled BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,INDEX(tenant_id),CONSTRAINT fk_user_tenant FOREIGN KEY(tenant_id) REFERENCES tenants(id)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS sessions (id VARCHAR(96) PRIMARY KEY,user_id VARCHAR(64) NOT NULL,token_hash CHAR(64) NOT NULL UNIQUE,csrf_hash CHAR(64) NOT NULL,expires_at DATETIME(6) NOT NULL,revoked BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,INDEX(user_id),INDEX(expires_at),CONSTRAINT fk_session_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS devices (id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,name VARCHAR(255) NOT NULL,public_key TEXT NOT NULL,revoked BOOLEAN NOT NULL DEFAULT 0,generation BIGINT UNSIGNED NOT NULL DEFAULT 0,session_id VARCHAR(96),last_seen DATETIME(6) NULL,capabilities JSON NOT NULL,applied_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,INDEX(tenant_id),CONSTRAINT fk_device_tenant FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS edges (id VARCHAR(64) PRIMARY KEY,name VARCHAR(255) NOT NULL,endpoints JSON NOT NULL,ca_cert TEXT,public_host VARCHAR(255),listen_host VARCHAR(255),http_port INT,https_port INT,port_min INT,port_max INT,max_carriers INT,capacity_bps BIGINT,token_hash CHAR(64) NOT NULL UNIQUE,boot_id VARCHAR(96),last_seen DATETIME(6),applied_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS rules (id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,name VARCHAR(255) NOT NULL,protocol VARCHAR(16) NOT NULL,device_id VARCHAR(64) NOT NULL,edge_id VARCHAR(64) NOT NULL,public_port INT NOT NULL,domain VARCHAR(255),target VARCHAR(512) NOT NULL,host VARCHAR(255),server_name VARCHAR(255),certificate_id VARCHAR(64),source_mode VARCHAR(32) NOT NULL,transport VARCHAR(32) NOT NULL,acl_template_id VARCHAR(64),acl JSON,enabled BOOLEAN NOT NULL DEFAULT 1,deleting BOOLEAN NOT NULL DEFAULT 0,version BIGINT UNSIGNED NOT NULL DEFAULT 1,status VARCHAR(32) NOT NULL,last_error TEXT,applied_version BIGINT UNSIGNED NOT NULL DEFAULT 0,timeout_seconds INT NOT NULL DEFAULT 30,created_at DATETIME(6) NOT NULL,updated_at DATETIME(6) NOT NULL,INDEX(tenant_id),INDEX(edge_id),INDEX(device_id),UNIQUE KEY uniq_edge_port(edge_id,public_port),CONSTRAINT fk_rule_tenant FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS acl_templates (id VARCHAR(64) PRIMARY KEY,name VARCHAR(255) NOT NULL,policy JSON NOT NULL, published JSON NULL,version BIGINT UNSIGNED NOT NULL DEFAULT 1,default_flag BOOLEAN NOT NULL DEFAULT 0,mandatory BOOLEAN NOT NULL DEFAULT 0,created_by VARCHAR(64),updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,name VARCHAR(255) NOT NULL,domains JSON NOT NULL,cert_pem TEXT NOT NULL,key_enc TEXT NOT NULL,expires_at DATETIME(6) NULL,created_at DATETIME(6) NOT NULL,INDEX(tenant_id),CONSTRAINT fk_cert_tenant FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS quotas (tenant_id VARCHAR(64) PRIMARY KEY,base_bps BIGINT NOT NULL DEFAULT 0,peak_bps BIGINT NOT NULL DEFAULT 0,burst_bytes BIGINT NOT NULL DEFAULT 0,max_connections INT NOT NULL DEFAULT 0,new_flows_per_second INT NOT NULL DEFAULT 0,period_bytes BIGINT NOT NULL DEFAULT 0,used_bytes BIGINT NOT NULL DEFAULT 0,reserved_bytes BIGINT NOT NULL DEFAULT 0,version BIGINT UNSIGNED NOT NULL DEFAULT 1,updated_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS grants_table (id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,edge_id VARCHAR(64) NOT NULL,boot_id VARCHAR(96) NOT NULL,expires_at DATETIME(6) NOT NULL,bytes BIGINT NOT NULL,base_bps BIGINT NOT NULL,peak_bps BIGINT NOT NULL,burst_bytes BIGINT NOT NULL,max_connections INT NOT NULL,new_flows_per_second INT NOT NULL,reserved BIGINT NOT NULL DEFAULT 0,used BIGINT NOT NULL DEFAULT 0,closed BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME(6) NOT NULL,INDEX(edge_id),INDEX(tenant_id),UNIQUE KEY grant_live(tenant_id,edge_id,boot_id,closed)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS usage_table (grant_id VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(64) NOT NULL,edge_id VARCHAR(64) NOT NULL,boot_id VARCHAR(96) NOT NULL,sequence_no BIGINT UNSIGNED NOT NULL DEFAULT 0,upload_bytes BIGINT NOT NULL DEFAULT 0,download_bytes BIGINT NOT NULL DEFAULT 0,closed BOOLEAN NOT NULL DEFAULT 0,observed_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS bindings (id VARCHAR(64) PRIMARY KEY,user_code VARCHAR(32) NOT NULL UNIQUE,poll_hash CHAR(64) NOT NULL UNIQUE,name VARCHAR(255) NOT NULL,public_key TEXT NOT NULL,status VARCHAR(32) NOT NULL,tenant_id VARCHAR(64),device_id VARCHAR(64),expires_at DATETIME(6) NOT NULL,created_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS audit (id VARCHAR(64) PRIMARY KEY,actor_id VARCHAR(64),tenant_id VARCHAR(64),action VARCHAR(128) NOT NULL,resource_id VARCHAR(128),created_at DATETIME(6) NOT NULL,INDEX(tenant_id),INDEX(created_at)) ENGINE=InnoDB`,
	}
	for _, q := range stmts {
		if _, e := db.ExecContext(ctx, q); e != nil {
			return e
		}
	}
	return nil
}
