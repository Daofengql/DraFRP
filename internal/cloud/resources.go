package cloud

import (
	"context"
	"database/sql"
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const ruleColumns = "id,tenant_id,name,protocol,device_id,edge_id,public_port,domain,target,host,server_name,certificate_id,source_mode,transport,acl_template_id,acl,enabled,deleting,version,status,last_error,applied_version,timeout_seconds"

func (s *Server) queryRules(ctx context.Context, filter string, args ...any) ([]model.Rule, error) {
	rows, e := s.store(ctx).QueryContext(ctx, "SELECT "+ruleColumns+" FROM rules"+filter, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Rule{}
	for rows.Next() {
		var x model.Rule
		var dom, host, sn, cert, tid, ac, last sql.NullString
		if e = rows.Scan(&x.ID, &x.TenantID, &x.Name, &x.Protocol, &x.DeviceID, &x.EdgeID, &x.PublicPort, &dom, &x.Target, &host, &sn, &cert, &x.SourceMode, &x.Transport, &tid, &ac, &x.Enabled, &x.Deleting, &x.Version, &x.Status, &last, &x.AppliedVersion, &x.TimeoutSeconds); e != nil {
			return nil, e
		}
		x.Domain = dom.String
		x.Host = host.String
		x.ServerName = sn.String
		x.CertificateID = cert.String
		x.ACLTemplateID = tid.String
		x.LastError = last.String
		decodeJSON(ac.String, &x.ACL)
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Server) listRules(r *http.Request, tid, rid string) ([]model.Rule, error) {
	if rid != "" {
		return s.queryRules(r.Context(), " WHERE tenant_id=? AND id=?", tid, rid)
	}
	return s.queryRules(r.Context(), " WHERE tenant_id=? ORDER BY created_at DESC", tid)
}
func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	rows, e := s.store(r.Context()).QueryContext(r.Context(), "SELECT id,name,public_key,revoked,generation,session_id,last_seen,capabilities,applied_revision,runtime,lease_until FROM devices WHERE tenant_id=? ORDER BY created_at DESC", tenant(r))
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	defer rows.Close()
	out := []model.Device{}
	for rows.Next() {
		var d model.Device
		var caps string
		var sid sql.NullString
		var runtimeJSON sql.NullString
		var last, lease sql.NullTime
		if e = rows.Scan(&d.ID, &d.Name, &d.PublicKey, &d.Revoked, &d.Generation, &sid, &last, &caps, &d.AppliedRevision, &runtimeJSON, &lease); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		d.TenantID = tenant(r)
		d.SessionID = sid.String
		if last.Valid {
			d.LastSeen = last.Time
		}
		decodeJSON(caps, &d.Capabilities)
		if !d.Revoked && lease.Valid && now().Before(lease.Time) && runtimeJSON.Valid {
			decodeJSON(runtimeJSON.String, &d.Runtime)
			if d.Runtime != nil && (d.Runtime.SessionID != d.SessionID || d.Runtime.Generation != d.Generation || d.Runtime.ReceivedAt.IsZero()) {
				d.Runtime = nil
			}
		}
		out = append(out, d)
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}
func (s *Server) device(w http.ResponseWriter, r *http.Request) {
	did := strings.TrimPrefix(r.URL.Path, "/api/v1/devices/")
	p := r.Context().Value(pkey{}).(*principal)
	if r.Method == "DELETE" {
		tx, e := s.beginTx(r.Context(), nil)
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		defer tx.Rollback()
		res, e := tx.ExecContext(r.Context(), "UPDATE devices SET revoked=1,generation=generation+1,lease_until=?,runtime=NULL WHERE id=? AND tenant_id=? AND revoked=0", now(), did, p.User.TenantID)
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			apiErr(w, 404, "not_found", "device not found or already revoked")
			return
		}
		if _, e = tx.ExecContext(r.Context(), "UPDATE rules SET enabled=0,version=version+1,status='pending',updated_at=? WHERE device_id=?", now(), did); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if _, e = tx.ExecContext(r.Context(), "UPDATE resource_claims c JOIN rules r ON r.id=c.rule_id SET c.release_at=GREATEST(COALESCE(c.release_at,?),?) WHERE r.device_id=? AND r.deleting=1", now().Add(s.cfg.SnapshotTTL+2*time.Second), now().Add(s.cfg.SnapshotTTL+2*time.Second), did); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if e = tx.Commit(); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		s.audit(r.Context(), p.User.ID, p.User.TenantID, "device.revoke", "device", did)
		s.notify(r.Context())
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if !requireMethod(w, r, "PATCH") {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if e := readJSON(w, r, &in); e != nil || strings.TrimSpace(in.Name) == "" || len(in.Name) > 255 {
		apiErr(w, 400, "invalid_name", "name required (maximum 255 bytes)")
		return
	}
	if _, e := s.store(r.Context()).ExecContext(r.Context(), "UPDATE devices SET name=? WHERE id=? AND tenant_id=?", in.Name, did, p.User.TenantID); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	var d model.Device
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT id,tenant_id,name,public_key,revoked,generation FROM devices WHERE id=? AND tenant_id=?", did, p.User.TenantID).Scan(&d.ID, &d.TenantID, &d.Name, &d.PublicKey, &d.Revoked, &d.Generation); e != nil {
		apiErr(w, 404, "not_found", "device not found")
		return
	}
	s.notify(r.Context())
	writeJSON(w, 200, d)
}
func (s *Server) clientBind(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	if !s.allowRequest(r, "bind", 10) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, 429, "rate_limited", "too many binding requests")
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
	if len(in.Name) > 255 {
		apiErr(w, 400, "invalid_name", "device name too long")
		return
	}
	code := strings.ToUpper(randomToken(6))
	poll := randomToken(32)
	b := model.BindResponse{ID: id(), UserCode: code, PollToken: poll, VerificationURI: "/console/bind/" + code, ExpiresAt: now().Add(s.cfg.BindTTL), Status: "pending"}
	if _, e := s.store(r.Context()).ExecContext(r.Context(), "INSERT INTO bindings(id,user_code,poll_hash,name,public_key,status,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)", b.ID, code, hashToken(poll), in.Name, in.PublicKey, "pending", b.ExpiresAt, now()); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	writeJSON(w, 201, b)
}
func (s *Server) bindConfirm(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	var in struct {
		UserCode string `json:"user_code"`
		Name     string `json:"name"`
	}
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if len(in.Name) > 255 {
		apiErr(w, 400, "invalid_name", "name too long")
		return
	}
	tx, e := s.beginTx(r.Context(), nil)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	defer tx.Rollback()
	var bid, name, pub, status string
	var exp time.Time
	if e = tx.QueryRowContext(r.Context(), "SELECT id,name,public_key,status,expires_at FROM bindings WHERE user_code=? FOR UPDATE", strings.ToUpper(strings.TrimSpace(in.UserCode))).Scan(&bid, &name, &pub, &status, &exp); e != nil || status != "pending" || !now().Before(exp) {
		apiErr(w, 404, "binding_expired", "binding not found or expired")
		return
	}
	if in.Name != "" {
		name = in.Name
	}
	if e = requireResourceCapacity(r.Context(), tx, tenant(r), resourceDelta{"devices", 1}); e != nil {
		if !writeResourceQuotaError(w, e) {
			apiErr(w, 503, "database_unavailable", "could not check device resource quota")
		}
		return
	}
	did := id()
	if name == "" {
		name = "device-" + did[:8]
	}
	if _, e = tx.ExecContext(r.Context(), "INSERT INTO devices(id,tenant_id,name,public_key,capabilities,created_at) VALUES(?,?,?,?,?,?)", did, tenant(r), name, pub, "[]", now()); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if _, e = tx.ExecContext(r.Context(), "UPDATE bindings SET status='approved',tenant_id=?,device_id=? WHERE id=?", tenant(r), did, bid); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if e = tx.Commit(); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	p := r.Context().Value(pkey{}).(*principal)
	s.audit(r.Context(), p.User.ID, tenant(r), "device.bind", "device", did)
	s.notify(r.Context())
	writeJSON(w, 200, map[string]any{"device_id": did, "ok": true})
}
func (s *Server) clientBindPoll(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	if !s.allowRequest(r, "bind-poll", 120) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, 429, "rate_limited", "too many binding polls")
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
	var did sql.NullString
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT id,user_code,status,expires_at,device_id FROM bindings WHERE id=? AND poll_hash=?", in.ID, hashToken(in.PollToken)).Scan(&b.ID, &b.UserCode, &b.Status, &b.ExpiresAt, &did); e != nil {
		apiErr(w, 404, "binding_not_found", "binding not found")
		return
	}
	if !now().Before(b.ExpiresAt) {
		b.Status = "expired"
	} else if b.Status == "approved" {
		b.DeviceID = did.String
	}
	writeJSON(w, 200, b)
}
func (s *Server) bindInspect(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	code := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/bind/")))
	var name, pub, status string
	var expires time.Time
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT name,public_key,status,expires_at FROM bindings WHERE user_code=?", code).Scan(&name, &pub, &status, &expires); e != nil {
		apiErr(w, 404, "binding_not_found", "binding not found")
		return
	}
	if !now().Before(expires) {
		status = "expired"
	}
	writeJSON(w, 200, map[string]any{"user_code": code, "name": name, "public_key_fingerprint": hashToken(pub), "status": status, "expires_at": expires})
}
func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		items, e := s.listRules(r, tenant(r), "")
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
		return
	}
	if !requireMethod(w, r, "POST") {
		return
	}
	var in model.Rule
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	in.ID = id()
	in.TenantID = tenant(r)
	in.Version = 1
	in.AppliedVersion = 0
	in.Status = "pending"
	in.LastError = ""
	in.Deleting = false
	if e := s.persistRule(r, &in, nil); e != nil {
		if !writeResourceQuotaError(w, e) {
			apiErr(w, 409, "invalid_rule", e.Error())
		}
		return
	}
	p := r.Context().Value(pkey{}).(*principal)
	s.audit(r.Context(), p.User.ID, tenant(r), "rule.create", "rule", in.ID)
	s.notify(r.Context())
	writeJSON(w, 201, in)
}
func (s *Server) rule(w http.ResponseWriter, r *http.Request) {
	rid := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	items, e := s.listRules(r, tenant(r), rid)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if len(items) == 0 {
		apiErr(w, 404, "not_found", "rule not found")
		return
	}
	old := items[0]
	switch r.Method {
	case "GET":
		writeJSON(w, 200, old)
	case "DELETE":
		tx, e := s.beginTx(r.Context(), nil)
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(r.Context(), "UPDATE rules SET deleting=1,enabled=0,version=version+1,status='deleting',updated_at=? WHERE id=? AND tenant_id=? AND deleting=0", now(), rid, tenant(r)); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if _, e = tx.ExecContext(r.Context(), "UPDATE resource_claims SET release_at=COALESCE(release_at,?) WHERE rule_id=?", now().Add(s.cfg.SnapshotTTL+2*time.Second), rid); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if e = tx.Commit(); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		s.notify(r.Context())
		writeJSON(w, 200, map[string]any{"ok": true})
	case "PUT":
		var in model.Rule
		if e := readJSON(w, r, &in); e != nil {
			apiErr(w, 400, "invalid_json", e.Error())
			return
		}
		if in.Version != old.Version || old.Deleting {
			apiErr(w, 409, "version_conflict", "rule changed or is deleting")
			return
		}
		in.ID = rid
		in.TenantID = tenant(r)
		in.Deleting = false
		in.AppliedVersion = old.AppliedVersion
		in.Status = "pending"
		in.LastError = ""
		if e := s.persistRule(r, &in, &old); e != nil {
			if writeResourceQuotaError(w, e) {
				return
			}
			apiErr(w, 409, "invalid_rule", e.Error())
			return
		}
		s.notify(r.Context())
		writeJSON(w, 200, in)
	default:
		apiErr(w, 405, "method_not_allowed", "method not allowed")
	}
}
func (s *Server) persistRule(r *http.Request, in *model.Rule, old *model.Rule) error {
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = 30
	}
	in.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Domain), "."))
	if e := validateRule(*in); e != nil {
		return e
	}
	tx, e := s.beginTx(r.Context(), nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if old != nil {
		var version uint64
		var deleting bool
		if e = tx.QueryRowContext(r.Context(), "SELECT version,deleting FROM rules WHERE id=? AND tenant_id=? FOR UPDATE", in.ID, in.TenantID).Scan(&version, &deleting); e != nil || deleting || version != old.Version {
			return errVersion
		}
	}
	// Serialize resource mutations for an edge, including endpoint changes.
	var raw string
	var edge model.Edge
	if e = tx.QueryRowContext(r.Context(), "SELECT id,endpoints,http_port,https_port,port_min,port_max FROM edges WHERE id=? FOR UPDATE", in.EdgeID).Scan(&edge.ID, &raw, &edge.HTTPPort, &edge.HTTPSPort, &edge.PortMin, &edge.PortMax); e != nil {
		return errors.New("edge not found")
	}
	decodeJSON(raw, &edge.Endpoints)
	if in.Transport != "auto" {
		required := "tls"
		if in.Transport == "quic_only" {
			required = "quic"
		}
		available := false
		for _, ep := range edge.Endpoints {
			if ep.Transport == required {
				available = true
			}
		}
		if !available {
			return errors.New("capability_missing: edge has no endpoint for the required transport")
		}
	}
	var n int
	var deviceID string
	var capabilities string
	var leaseUntil sql.NullTime
	if e = tx.QueryRowContext(r.Context(), "SELECT id,capabilities,lease_until FROM devices WHERE id=? AND tenant_id=? AND revoked=0 FOR SHARE", in.DeviceID, in.TenantID).Scan(&deviceID, &capabilities, &leaseUntil); e != nil {
		return errors.New("device not found in this tenant")
	}
	if in.SourceMode == "native" {
		var caps []string
		decodeJSON(capabilities, &caps)
		found := false
		for _, c := range caps {
			found = found || c == "native_"+in.Protocol+"_ipv4_ip_port"
		}
		if !found || !leaseUntil.Valid || !now().Before(leaseUntil.Time) {
			return errors.New("capability_missing: an active Linux IPv4 transparent source probe is required")
		}
	}
	isSite := in.Protocol == "http" || in.Protocol == "https"
	if isSite {
		var owned string
		if e = tx.QueryRowContext(r.Context(), "SELECT d.id FROM domains d JOIN domain_ownership o ON o.domain=d.domain AND o.tenant_id=d.tenant_id WHERE d.tenant_id=? AND d.domain=? AND d.status='verified' FOR SHARE", in.TenantID, in.Domain).Scan(&owned); e != nil {
			return errors.New("domain_unverified: verify domain ownership before publishing a site")
		}
		in.PublicPort = edge.HTTPPort
		if in.Protocol == "https" {
			in.PublicPort = edge.HTTPSPort
		}
		if in.PublicPort < 1 {
			return errors.New("edge has no matching HTTP(S) listener")
		}
		if in.Protocol == "https" {
			var certPEM string
			var exp time.Time
			if e = tx.QueryRowContext(r.Context(), "SELECT cert_pem,expires_at FROM certificates WHERE id=? AND tenant_id=? FOR SHARE", in.CertificateID, in.TenantID).Scan(&certPEM, &exp); e != nil {
				return errors.New("certificate not found in this tenant")
			}
			if e = verifyCertificateDomain(certPEM, in.Domain); e != nil {
				return e
			}
		}
	} else {
		if in.PublicPort == 0 {
			for port := edge.PortMin; port <= edge.PortMax; port++ {
				if in.Protocol == "tcp" && (port == edge.HTTPPort || port == edge.HTTPSPort) {
					continue
				}
				busy := false
				for _, ep := range edge.Endpoints {
					_, p, _ := net.SplitHostPort(ep.Address)
					if strconv.Itoa(port) == p && ((ep.Transport == "tls" && in.Protocol == "tcp") || (ep.Transport == "quic" && in.Protocol == "udp")) {
						busy = true
						break
					}
				}
				if busy {
					continue
				}
				if e = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM resource_claims WHERE edge_id=? AND resource_key=? AND (release_at IS NULL OR release_at>?)", in.EdgeID, fmt.Sprintf("%s/%d", in.Protocol, port), now()).Scan(&n); e != nil {
					return e
				}
				if n == 0 {
					in.PublicPort = port
					break
				}
			}
			if in.PublicPort == 0 {
				return errors.New("edge business port pool is exhausted")
			}
		}
		if in.PublicPort < edge.PortMin || in.PublicPort > edge.PortMax {
			return errors.New("port is outside the edge business pool")
		}
		if in.Protocol == "tcp" && (in.PublicPort == edge.HTTPPort || in.PublicPort == edge.HTTPSPort) {
			return errors.New("port is occupied by HTTP(S)")
		}
		for _, ep := range edge.Endpoints {
			_, p, _ := net.SplitHostPort(ep.Address)
			port, _ := strconv.Atoi(p)
			if port == in.PublicPort && ((ep.Transport == "tls" && in.Protocol == "tcp") || (ep.Transport == "quic" && in.Protocol == "udp")) {
				return errors.New("port is occupied by a carrier endpoint")
			}
		}
		if in.ACLTemplateID == "" && in.ACL == nil && old == nil {
			var tid string
			e = tx.QueryRowContext(r.Context(), "SELECT id FROM acl_templates WHERE default_flag=1 AND published IS NOT NULL LIMIT 1").Scan(&tid)
			if e == nil {
				in.ACLTemplateID = tid
			} else if e != sql.ErrNoRows {
				return e
			}
		}
		if in.ACLTemplateID != "" {
			var p sql.NullString
			if e = tx.QueryRowContext(r.Context(), "SELECT published FROM acl_templates WHERE id=? FOR SHARE", in.ACLTemplateID).Scan(&p); e != nil || !p.Valid {
				return errors.New("ACL template is missing or unpublished")
			}
		}
	}
	key := resourceKey(*in)
	if e = s.reapResources(r.Context()); e != nil {
		return e
	}
	var owner string
	e = tx.QueryRowContext(r.Context(), "SELECT rule_id FROM resource_claims WHERE edge_id=? AND resource_key=?", in.EdgeID, key).Scan(&owner)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if e == nil && owner != in.ID {
		return errors.New("public resource is occupied or awaiting revocation acknowledgement")
	}
	changes := []resourceDelta{}
	if old == nil {
		changes = append(changes, resourceDelta{"rules", 1})
	}
	if !isSite && e == sql.ErrNoRows {
		changes = append(changes, resourceDelta{"ports", 1})
	}
	if len(changes) != 0 {
		if e = requireResourceCapacity(r.Context(), tx, in.TenantID, changes...); e != nil {
			return e
		}
	}
	if old != nil && (old.EdgeID != in.EdgeID || resourceKey(*old) != key) {
		if _, e = tx.ExecContext(r.Context(), "UPDATE resource_claims SET release_at=? WHERE edge_id=? AND resource_key=? AND rule_id=?", now().Add(s.cfg.SnapshotTTL+2*time.Second), old.EdgeID, resourceKey(*old), in.ID); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(r.Context(), "INSERT INTO resource_claims(edge_id,resource_key,rule_id,tenant_id) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE release_at=NULL,tenant_id=VALUES(tenant_id)", in.EdgeID, key, in.ID, in.TenantID); e != nil {
		return e
	}
	ac := encodeJSON(in.ACL)
	if old == nil {
		_, e = tx.ExecContext(r.Context(), "INSERT INTO rules(id,tenant_id,name,protocol,device_id,edge_id,public_port,domain,target,host,server_name,certificate_id,source_mode,transport,acl_template_id,acl,enabled,version,status,timeout_seconds,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", in.ID, in.TenantID, in.Name, in.Protocol, in.DeviceID, in.EdgeID, in.PublicPort, in.Domain, in.Target, in.Host, in.ServerName, in.CertificateID, in.SourceMode, in.Transport, in.ACLTemplateID, ac, in.Enabled, in.Version, in.Status, in.TimeoutSeconds, now(), now())
	} else {
		var res sql.Result
		res, e = tx.ExecContext(r.Context(), "UPDATE rules SET name=?,protocol=?,device_id=?,edge_id=?,public_port=?,domain=?,target=?,host=?,server_name=?,certificate_id=?,source_mode=?,transport=?,acl_template_id=?,acl=?,enabled=?,timeout_seconds=?,version=version+1,status='pending',last_error='',updated_at=? WHERE id=? AND tenant_id=? AND version=?", in.Name, in.Protocol, in.DeviceID, in.EdgeID, in.PublicPort, in.Domain, in.Target, in.Host, in.ServerName, in.CertificateID, in.SourceMode, in.Transport, in.ACLTemplateID, ac, in.Enabled, in.TimeoutSeconds, now(), in.ID, in.TenantID, in.Version)
		if e == nil {
			n, _ := res.RowsAffected()
			if n != 1 {
				return errors.New("rule version changed")
			}
		}
		in.Version++
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}
func resourceKey(r model.Rule) string {
	if r.Protocol == "http" || r.Protocol == "https" {
		return "site/" + r.Domain
	}
	return fmt.Sprintf("%s/%d", r.Protocol, r.PublicPort)
}
func validTarget(proto, target string) bool {
	if proto == "tcp" || proto == "udp" {
		h, p, e := net.SplitHostPort(target)
		port, pe := strconv.Atoi(p)
		return e == nil && pe == nil && h != "" && port > 0 && port <= 65535
	}
	u, e := url.Parse(target)
	return e == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.RawQuery == ""
}
func validateRule(r model.Rule) error {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 255 {
		return errors.New("name required (maximum 255 bytes)")
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "http" && r.Protocol != "https" {
		return errors.New("invalid protocol")
	}
	if !validTarget(r.Protocol, r.Target) || len(r.Target) > 512 {
		return errors.New("invalid target")
	}
	if r.Protocol == "http" || r.Protocol == "https" {
		if r.SourceMode != "forwarded_headers" {
			return errors.New("HTTP(S) requires forwarded_headers")
		}
		if !validDomain(r.Domain) {
			return errors.New("invalid domain")
		}
		if r.ACLTemplateID != "" || r.ACL != nil {
			return errors.New("HTTP(S) does not use TCP/UDP ACL")
		}
	} else {
		if r.SourceMode != "socket" && r.SourceMode != "native" {
			return errors.New("TCP/UDP requires socket or native source mode")
		}
		if r.SourceMode == "native" {
			host, _, _ := net.SplitHostPort(r.Target)
			if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
				return errors.New("capability_missing: native IPv6 source identity is not verified")
			}
		}
		if r.PublicPort < 0 || r.PublicPort > 65535 {
			return errors.New("invalid public_port")
		}
		if r.ACL != nil {
			if _, e := acl.Compile(*r.ACL); e != nil {
				return e
			}
		}
	}
	if r.Transport != "auto" && r.Transport != "quic_only" && r.Transport != "tls_only" {
		return errors.New("invalid transport")
	}
	if r.TimeoutSeconds < 1 || r.TimeoutSeconds > 3600 {
		return errors.New("timeout_seconds must be 1..3600")
	}
	if strings.ContainsAny(r.Host+r.ServerName, "\r\n\t /\\") {
		return errors.New("invalid Host or SNI")
	}
	return nil
}
func validDomain(v string) bool {
	if v == "" || len(v) > 253 || net.ParseIP(v) != nil {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

var _ = json.Valid
