package cloud

import (
	"database/sql"
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

func (s *Server) edges(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, e := s.db.QueryContext(r.Context(), "SELECT id,name,endpoints,ca_cert,public_host,listen_host,http_port,https_port,port_min,port_max,max_carriers,capacity_bps,boot_id,last_seen,applied_revision FROM edges ORDER BY created_at DESC")
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		defer rows.Close()
		out := []model.Edge{}
		for rows.Next() {
			var x model.Edge
			var ep, ca, ph, lh, boot sql.NullString
			var last sql.NullTime
			_ = rows.Scan(&x.ID, &x.Name, &ep, &ca, &ph, &lh, &x.HTTPPort, &x.HTTPSPort, &x.PortMin, &x.PortMax, &x.MaxCarriers, &x.CapacityBPS, &boot, &last, &x.AppliedRevision)
			decodeJSON(ep.String, &x.Endpoints)
			x.CACert = ca.String
			x.PublicHost = ph.String
			x.ListenHost = lh.String
			x.BootID = boot.String
			if last.Valid {
				x.LastSeen = last.Time
			}
			out = append(out, x)
		}
		writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
		return
	}
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var in model.Edge
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	tok := randomToken(32)
	in.ID = id()
	in.LastSeen = time.Time{}
	_, e := s.db.ExecContext(r.Context(), "INSERT INTO edges(id,name,endpoints,ca_cert,public_host,listen_host,http_port,https_port,port_min,port_max,max_carriers,capacity_bps,token_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", in.ID, in.Name, encodeJSON(in.Endpoints), in.CACert, in.PublicHost, in.ListenHost, in.HTTPPort, in.HTTPSPort, in.PortMin, in.PortMax, in.MaxCarriers, in.CapacityBPS, hashToken(tok), now())
	if e != nil {
		apiErr(w, 409, "edge_exists", "edge already exists")
		return
	}
	writeJSON(w, 201, map[string]any{"edge": in, "token": tok})
}
func (s *Server) edge(w http.ResponseWriter, r *http.Request) {
	eid := strings.TrimPrefix(r.URL.Path, "/api/v1/edges/")
	if r.Method == "DELETE" {
		_, e := s.db.ExecContext(r.Context(), "DELETE FROM edges WHERE id=?", eid)
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if r.Method != "PUT" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var in model.Edge
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	_, e := s.db.ExecContext(r.Context(), "UPDATE edges SET name=?,endpoints=?,ca_cert=?,public_host=?,listen_host=?,http_port=?,https_port=?,port_min=?,port_max=?,max_carriers=?,capacity_bps=? WHERE id=?", in.Name, encodeJSON(in.Endpoints), in.CACert, in.PublicHost, in.ListenHost, in.HTTPPort, in.HTTPSPort, in.PortMin, in.PortMax, in.MaxCarriers, in.CapacityBPS, eid)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	in.ID = eid
	writeJSON(w, 200, in)
}

func (s *Server) templates(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, e := s.db.QueryContext(r.Context(), "SELECT id,name,policy,published,version,default_flag,mandatory FROM acl_templates ORDER BY name")
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		defer rows.Close()
		out := []model.ACLTemplate{}
		for rows.Next() {
			var x model.ACLTemplate
			var p, pub string
			_ = rows.Scan(&x.ID, &x.Name, &p, &pub, &x.Version, &x.Default, &x.Mandatory)
			decodeJSON(p, &x.Policy)
			if pub != "" {
				x.Published = &model.ACLPolicy{}
				decodeJSON(pub, x.Published)
			}
			out = append(out, x)
		}
		writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
		return
	}
	if !isAdmin(r) {
		apiErr(w, 403, "forbidden", "administrator role required")
		return
	}
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var x model.ACLTemplate
	if e := readJSON(w, r, &x); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if _, e := acl.Compile(x.Policy); e != nil {
		apiErr(w, 400, "invalid_acl", e.Error())
		return
	}
	x.ID = id()
	x.Version = 1
	_, e := s.db.ExecContext(r.Context(), "INSERT INTO acl_templates(id,name,policy,version,default_flag,mandatory,updated_at) VALUES(?,?,?,?,?,?,?)", x.ID, x.Name, encodeJSON(x.Policy), 1, x.Default, x.Mandatory, now())
	if e != nil {
		apiErr(w, 409, "template_exists", "template conflict")
		return
	}
	writeJSON(w, 201, x)
}
func (s *Server) template(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/acl-templates/")
	parts := strings.Split(path, "/")
	tid := parts[0]
	if len(parts) > 1 && parts[1] == "publish" {
		if !isAdmin(r) {
			apiErr(w, 403, "forbidden", "administrator role required")
			return
		}
		_, e := s.db.ExecContext(r.Context(), "UPDATE acl_templates SET published=policy,version=version+1,updated_at=? WHERE id=?", now(), tid)
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if r.Method == "DELETE" {
		if !isAdmin(r) {
			apiErr(w, 403, "forbidden", "administrator role required")
			return
		}
		var n int
		_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM rules WHERE acl_template_id=?", tid).Scan(&n)
		if n > 0 {
			apiErr(w, 409, "template_in_use", "template referenced by rules")
			return
		}
		_, e := s.db.ExecContext(r.Context(), "DELETE FROM acl_templates WHERE id=?", tid)
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if r.Method != "PUT" || !isAdmin(r) {
		apiErr(w, 403, "forbidden", "administrator role required")
		return
	}
	var x model.ACLTemplate
	if e := readJSON(w, r, &x); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if _, e := acl.Compile(x.Policy); e != nil {
		apiErr(w, 400, "invalid_acl", e.Error())
		return
	}
	_, e := s.db.ExecContext(r.Context(), "UPDATE acl_templates SET name=?,policy=?,default_flag=?,mandatory=?,version=version+1,updated_at=? WHERE id=?", x.Name, encodeJSON(x.Policy), x.Default, x.Mandatory, now(), tid)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	x.ID = tid
	writeJSON(w, 200, x)
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(pkey{}).(*principal)
	if r.Method == "GET" {
		rows, e := s.db.QueryContext(r.Context(), "SELECT id,name,domains,expires_at FROM certificates WHERE tenant_id=?", p.User.TenantID)
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		defer rows.Close()
		out := []model.Certificate{}
		for rows.Next() {
			var x model.Certificate
			var d string
			var exp sql.NullTime
			_ = rows.Scan(&x.ID, &x.Name, &d, &exp)
			x.TenantID = p.User.TenantID
			decodeJSON(d, &x.Domains)
			if exp.Valid {
				x.ExpiresAt = exp.Time
			}
			out = append(out, x)
		}
		writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
		return
	}
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var x model.Certificate
	if e := readJSON(w, r, &x); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	enc, e := encrypt(s.key, x.KeyPEM)
	if e != nil {
		apiErr(w, 500, "encryption", e.Error())
		return
	}
	x.ID = id()
	x.TenantID = p.User.TenantID
	_, e = s.db.ExecContext(r.Context(), "INSERT INTO certificates(id,tenant_id,name,domains,cert_pem,key_enc,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)", x.ID, x.TenantID, x.Name, encodeJSON(x.Domains), x.CertPEM, enc, x.ExpiresAt, now())
	if e != nil {
		apiErr(w, 409, "certificate_conflict", "certificate conflict")
		return
	}
	x.KeyPEM = ""
	writeJSON(w, 201, x)
}
func (s *Server) certificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	p, _ := r.Context().Value(pkey{}).(*principal)
	cid := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	_, e := s.db.ExecContext(r.Context(), "DELETE FROM certificates WHERE id=? AND tenant_id=?", cid, p.User.TenantID)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) quotas(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(pkey{}).(*principal)
	rows, e := s.db.QueryContext(r.Context(), "SELECT tenant_id,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,period_bytes,used_bytes,reserved_bytes,version FROM quotas WHERE tenant_id=?", p.User.TenantID)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	defer rows.Close()
	out := []model.Quota{}
	for rows.Next() {
		var q model.Quota
		_ = rows.Scan(&q.TenantID, &q.BaseBPS, &q.PeakBPS, &q.BurstBytes, &q.MaxConnections, &q.NewFlowsPerSecond, &q.PeriodBytes, &q.UsedBytes, &q.ReservedBytes, &q.Version)
		out = append(out, q)
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}
func (s *Server) quota(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	tid := strings.TrimPrefix(r.URL.Path, "/api/v1/quotas/")
	var q model.Quota
	if e := readJSON(w, r, &q); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	q.TenantID = tid
	_, e := s.db.ExecContext(r.Context(), "INSERT INTO quotas(tenant_id,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,period_bytes,version,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE base_bps=VALUES(base_bps),peak_bps=VALUES(peak_bps),burst_bytes=VALUES(burst_bytes),max_connections=VALUES(max_connections),new_flows_per_second=VALUES(new_flows_per_second),period_bytes=VALUES(period_bytes),version=version+1,updated_at=VALUES(updated_at)", tid, q.BaseBPS, q.PeakBPS, q.BurstBytes, q.MaxConnections, q.NewFlowsPerSecond, q.PeriodBytes, 1, now())
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	writeJSON(w, 200, q)
}
func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, e := s.db.QueryContext(r.Context(), "SELECT id,tenant_id,username,role,disabled FROM users ORDER BY username")
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		defer rows.Close()
		out := []model.User{}
		for rows.Next() {
			var u model.User
			_ = rows.Scan(&u.ID, &u.TenantID, &u.Username, &u.Role, &u.Disabled)
			out = append(out, u)
		}
		writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
		return
	}
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var in struct{ Username, Password, Role, TenantID string }
	if e := readJSON(w, r, &in); e != nil || in.Username == "" || in.Password == "" {
		apiErr(w, 400, "invalid_user", "username and password required")
		return
	}
	if !validRole(in.Role) {
		in.Role = "user"
	}
	tid := in.TenantID
	if tid == "" {
		tid = id()
		if _, e := s.db.ExecContext(r.Context(), "INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)", tid, in.Username, now()); e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
	}
	pw, _ := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	u := model.User{ID: id(), TenantID: tid, Username: in.Username, Role: in.Role}
	_, e := s.db.ExecContext(r.Context(), "INSERT INTO users(id,tenant_id,username,password_hash,role,created_at) VALUES(?,?,?,?,?,?)", u.ID, tid, in.Username, string(pw), in.Role, now())
	if e != nil {
		apiErr(w, 409, "user_exists", "user conflict")
		return
	}
	writeJSON(w, 201, u)
}
func (s *Server) usage(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(pkey{}).(*principal)
	rows, e := s.db.QueryContext(r.Context(), "SELECT grant_id,edge_id,boot_id,sequence_no,upload_bytes,download_bytes,closed,observed_at FROM usage_table WHERE tenant_id=? ORDER BY observed_at DESC LIMIT 1000", p.User.TenantID)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, edge, boot string
		var seq, up, down int64
		var closed bool
		var at time.Time
		_ = rows.Scan(&id, &edge, &boot, &seq, &up, &down, &closed, &at)
		out = append(out, map[string]any{"grant_id": id, "tenant_id": p.User.TenantID, "edge_id": edge, "boot_id": boot, "sequence": seq, "upload_bytes": up, "download_bytes": down, "closed": closed, "observed_at": at})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}
func (s *Server) auditAPI(w http.ResponseWriter, r *http.Request) {
	rows, e := s.db.QueryContext(r.Context(), "SELECT id,actor_id,tenant_id,action,resource_id,created_at FROM audit ORDER BY created_at DESC LIMIT 1000")
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, a, t, action, res string
		var at time.Time
		_ = rows.Scan(&id, &a, &t, &action, &res, &at)
		out = append(out, map[string]any{"id": id, "actor_id": a, "tenant_id": t, "action": action, "resource_id": res, "created_at": at})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}
func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	var n int
	mysql := "healthy"
	if e := s.db.PingContext(r.Context()); e != nil {
		mysql = "unhealthy"
	}
	_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM users").Scan(&n)
	writeJSON(w, 200, map[string]any{"mysql": mysql, "cache": s.tmp.Stats(), "build_id": s.cfg.BuildID, "started_at": s.started, "users": n})
}

var _ = errors.New
var _ = json.Valid
