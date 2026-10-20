package cloud

import (
	"database/sql"
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(pkey{}).(*principal)
	switch r.Method {
	case "GET":
		rows, e := s.db.QueryContext(r.Context(), "SELECT id,name,public_key,revoked,generation,session_id,last_seen,capabilities,applied_revision FROM devices WHERE tenant_id=? ORDER BY created_at DESC", p.User.TenantID)
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		defer rows.Close()
		items := []model.Device{}
		for rows.Next() {
			var d model.Device
			var caps string
			var sid sql.NullString
			var ls sql.NullTime
			_ = rows.Scan(&d.ID, &d.Name, &d.PublicKey, &d.Revoked, &d.Generation, &sid, &ls, &caps, &d.AppliedRevision)
			d.TenantID = p.User.TenantID
			d.SessionID = sid.String
			if ls.Valid {
				d.LastSeen = ls.Time
			}
			decodeJSON(caps, &d.Capabilities)
			items = append(items, d)
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
	case "POST":
		var in model.BindRequest
		if e := readJSON(w, r, &in); e != nil {
			apiErr(w, 400, "invalid_json", e.Error())
			return
		}
		if _, e := verifyPub(in.PublicKey); e != nil {
			apiErr(w, 400, "invalid_public_key", e.Error())
			return
		}
		d := model.Device{ID: id(), TenantID: p.User.TenantID, Name: in.Name, PublicKey: in.PublicKey, Capabilities: []string{}, LastSeen: time.Time{}}
		if d.Name == "" {
			d.Name = "device-" + d.ID[:8]
		}
		_, e := s.db.ExecContext(r.Context(), "INSERT INTO devices(id,tenant_id,name,public_key,capabilities,last_seen,created_at) VALUES(?,?,?,?,?,?,?)", d.ID, d.TenantID, d.Name, d.PublicKey, "[]", nil, now())
		if e != nil {
			apiErr(w, 409, "device_exists", "could not create device")
			return
		}
		s.audit(r.Context(), p.User.ID, p.User.TenantID, "device.create", "device", d.ID)
		writeJSON(w, 201, d)
	default:
		apiErr(w, 405, "method_not_allowed", "method not allowed")
	}
}
func (s *Server) device(w http.ResponseWriter, r *http.Request) {
	idv := strings.TrimPrefix(r.URL.Path, "/api/v1/devices/")
	if idv == "" {
		apiErr(w, 404, "not_found", "device not found")
		return
	}
	p, _ := r.Context().Value(pkey{}).(*principal)
	if r.Method == "DELETE" {
		res, e := s.db.ExecContext(r.Context(), "UPDATE devices SET revoked=1,generation=generation+1 WHERE id=? AND tenant_id=?", idv, p.User.TenantID)
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			apiErr(w, 404, "not_found", "device not found")
			return
		}
		s.db.ExecContext(r.Context(), "UPDATE rules SET enabled=0,status='offline',updated_at=? WHERE device_id=?", now(), idv)
		s.audit(r.Context(), p.User.ID, p.User.TenantID, "device.revoke", "device", idv)
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if r.Method != "PATCH" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if e := readJSON(w, r, &in); e != nil || in.Name == "" {
		apiErr(w, 400, "invalid_name", "name required")
		return
	}
	_, e := s.db.ExecContext(r.Context(), "UPDATE devices SET name=? WHERE id=? AND tenant_id=?", in.Name, idv, p.User.TenantID)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	var d model.Device
	var caps string
	var sid sql.NullString
	var ls sql.NullTime
	e = s.db.QueryRowContext(r.Context(), "SELECT id,tenant_id,name,public_key,revoked,generation,session_id,last_seen,capabilities,applied_revision FROM devices WHERE id=? AND tenant_id=?", idv, p.User.TenantID).Scan(&d.ID, &d.TenantID, &d.Name, &d.PublicKey, &d.Revoked, &d.Generation, &sid, &ls, &caps, &d.AppliedRevision)
	if e != nil {
		apiErr(w, 404, "not_found", "device not found")
		return
	}
	d.SessionID = sid.String
	if ls.Valid {
		d.LastSeen = ls.Time
	}
	decodeJSON(caps, &d.Capabilities)
	writeJSON(w, 200, d)
}

func (s *Server) clientBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var in model.BindRequest
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if _, e := verifyPub(in.PublicKey); e != nil {
		apiErr(w, 400, "invalid_public_key", e.Error())
		return
	}
	code := strings.ToUpper(randomToken(5))
	poll := randomToken(32)
	b := model.BindResponse{ID: id(), UserCode: code, PollToken: poll, VerificationURI: "/console/bind/" + code, ExpiresAt: now().Add(s.cfg.BindTTL), Status: "pending"}
	_, e := s.db.ExecContext(r.Context(), "INSERT INTO bindings(id,user_code,poll_hash,name,public_key,status,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)", b.ID, code, hashToken(poll), in.Name, in.PublicKey, "pending", b.ExpiresAt, now())
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	writeJSON(w, 201, b)
}
func (s *Server) bindConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	p, _ := r.Context().Value(pkey{}).(*principal)
	var in struct {
		UserCode string `json:"user_code"`
		Name     string `json:"name"`
	}
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	var bid, bname, pub, status string
	var exp time.Time
	e := s.db.QueryRowContext(r.Context(), "SELECT id,name,public_key,status,expires_at FROM bindings WHERE user_code=?", strings.ToUpper(in.UserCode)).Scan(&bid, &bname, &pub, &status, &exp)
	if e != nil || status != "pending" || time.Now().After(exp) {
		apiErr(w, 404, "binding_expired", "binding not found or expired")
		return
	}
	did := id()
	name := in.Name
	if name == "" {
		name = bname
	}
	_, e = s.db.ExecContext(r.Context(), "INSERT INTO devices(id,tenant_id,name,public_key,capabilities,last_seen,created_at) VALUES(?,?,?,?,?,?,?)", did, p.User.TenantID, name, pub, "[]", nil, now())
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	_, e = s.db.ExecContext(r.Context(), "UPDATE bindings SET status='approved',tenant_id=?,device_id=? WHERE id=? AND status='pending'", p.User.TenantID, did, bid)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	s.audit(r.Context(), p.User.ID, p.User.TenantID, "device.bind", "device", did)
	writeJSON(w, 200, map[string]any{"ok": true, "device_id": did})
}
func (s *Server) clientBindPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var in struct {
		ID        string `json:"id"`
		PollToken string `json:"poll_token"`
	}
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	var b model.BindResponse
	var pub, name, status, tid, did string
	var exp time.Time
	e := s.db.QueryRowContext(r.Context(), "SELECT id,user_code,name,status,expires_at,public_key,tenant_id,device_id FROM bindings WHERE id=? AND poll_hash=?", in.ID, hashToken(in.PollToken)).Scan(&b.ID, &b.UserCode, &name, &status, &exp, &pub, &tid, &did)
	if e != nil {
		apiErr(w, 404, "binding_not_found", "binding not found")
		return
	}
	b.Status = status
	b.ExpiresAt = exp
	if status == "approved" {
		var generation uint64
		_ = s.db.QueryRowContext(r.Context(), "SELECT generation FROM devices WHERE id=?", did).Scan(&generation)
		b.DeviceID = did
		_ = generation
	}
	writeJSON(w, 200, b)
}

func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(pkey{}).(*principal)
	if r.Method == "GET" {
		items, e := s.listRules(r, p.User.TenantID, "")
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
		return
	}
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var in model.Rule
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	in.TenantID = p.User.TenantID
	if e := validateRule(in); e != nil {
		apiErr(w, 400, "invalid_rule", e.Error())
		return
	}
	var n int
	if e := s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM devices WHERE id=? AND tenant_id=? AND revoked=0", in.DeviceID, in.TenantID).Scan(&n); e != nil || n != 1 {
		apiErr(w, 400, "invalid_device", "device not found")
		return
	}
	if !isAdmin(r) {
		_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM edges WHERE id=?", in.EdgeID).Scan(&n)
	}
	in.ID = id()
	in.Version = 1
	in.Status = "pending"
	in.Enabled = true
	in.TimeoutSeconds = max(1, in.TimeoutSeconds)
	b, _ := json.Marshal(in.ACL)
	_, e := s.db.ExecContext(r.Context(), "INSERT INTO rules(id,tenant_id,name,protocol,device_id,edge_id,public_port,domain,target,host,server_name,certificate_id,source_mode,transport,acl_template_id,acl,enabled,version,status,applied_version,timeout_seconds,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", in.ID, in.TenantID, in.Name, in.Protocol, in.DeviceID, in.EdgeID, in.PublicPort, in.Domain, in.Target, in.Host, in.ServerName, in.CertificateID, in.SourceMode, in.Transport, in.ACLTemplateID, string(b), true, 1, in.Status, 0, in.TimeoutSeconds, now(), now())
	if e != nil {
		apiErr(w, 409, "resource_conflict", "port or rule conflict")
		return
	}
	s.audit(r.Context(), p.User.ID, p.User.TenantID, "rule.create", "rule", in.ID)
	s.notify()
	writeJSON(w, 201, in)
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func (s *Server) listRules(r *http.Request, tenantID, idfilter string) ([]model.Rule, error) {
	q := `SELECT id,tenant_id,name,protocol,device_id,edge_id,public_port,domain,target,host,server_name,certificate_id,source_mode,transport,acl_template_id,acl,enabled,deleting,version,status,last_error,applied_version,timeout_seconds FROM rules WHERE tenant_id=?`
	args := []any{tenantID}
	if idfilter != "" {
		q += " AND id=?"
		args = append(args, idfilter)
	}
	rows, e := s.db.QueryContext(r.Context(), q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Rule{}
	for rows.Next() {
		var x model.Rule
		var dom, host, sn, cert, tid, ac, last sql.NullString
		var aclRaw string
		var en, del bool
		e = rows.Scan(&x.ID, &x.TenantID, &x.Name, &x.Protocol, &x.DeviceID, &x.EdgeID, &x.PublicPort, &dom, &x.Target, &host, &sn, &cert, &x.SourceMode, &x.Transport, &tid, &aclRaw, &en, &del, &x.Version, &x.Status, &last, &x.AppliedVersion, &x.TimeoutSeconds)
		if e != nil {
			return nil, e
		}
		x.Domain = dom.String
		x.Host = host.String
		x.ServerName = sn.String
		x.CertificateID = cert.String
		x.ACLTemplateID = tid.String
		x.LastError = last.String
		x.Enabled = en
		x.Deleting = del
		decodeJSON(aclRaw, &x.ACL)
		out = append(out, x)
	}
	return out, nil
}
func (s *Server) rule(w http.ResponseWriter, r *http.Request) {
	rid := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	p, _ := r.Context().Value(pkey{}).(*principal)
	items, e := s.listRules(r, p.User.TenantID, rid)
	if e != nil || len(items) == 0 {
		apiErr(w, 404, "not_found", "rule not found")
		return
	}
	if r.Method == "GET" {
		writeJSON(w, 200, items[0])
		return
	}
	if r.Method == "DELETE" {
		_, e = s.db.ExecContext(r.Context(), "UPDATE rules SET deleting=1,enabled=0,status='deleting',updated_at=? WHERE id=? AND tenant_id=?", now(), rid, p.User.TenantID)
		if e != nil {
			apiErr(w, 500, "database", e.Error())
			return
		}
		s.audit(r.Context(), p.User.ID, p.User.TenantID, "rule.delete", "rule", rid)
		s.notify()
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if r.Method != "PUT" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var in model.Rule
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if in.Version != items[0].Version {
		apiErr(w, 409, "version_conflict", "rule version changed")
		return
	}
	in.ID = rid
	in.TenantID = p.User.TenantID
	if e := validateRule(in); e != nil {
		apiErr(w, 400, "invalid_rule", e.Error())
		return
	}
	b, _ := json.Marshal(in.ACL)
	res, e := s.db.ExecContext(r.Context(), "UPDATE rules SET name=?,protocol=?,device_id=?,edge_id=?,public_port=?,domain=?,target=?,host=?,server_name=?,certificate_id=?,source_mode=?,transport=?,acl_template_id=?,acl=?,enabled=?,version=version+1,status='pending',updated_at=? WHERE id=? AND tenant_id=? AND version=?", in.Name, in.Protocol, in.DeviceID, in.EdgeID, in.PublicPort, in.Domain, in.Target, in.Host, in.ServerName, in.CertificateID, in.SourceMode, in.Transport, in.ACLTemplateID, string(b), in.Enabled, now(), rid, p.User.TenantID, in.Version)
	if e != nil {
		apiErr(w, 409, "resource_conflict", e.Error())
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		apiErr(w, 409, "version_conflict", "rule version changed")
		return
	}
	items, _ = s.listRules(r, p.User.TenantID, rid)
	s.notify()
	writeJSON(w, 200, items[0])
}

var _ = acl.Compile
var _ = strconv.Itoa
var _ = base64.StdEncoding
var _ = fmt.Sprint
