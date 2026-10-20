package cloud

import (
	"crypto/ed25519"
	"database/sql"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

func (s *Server) edgeSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	token := parseBasicBearer(r)
	if token == "" {
		apiErr(w, 401, "unauthorized", "edge bearer token required")
		return
	}
	var eid string
	var edge model.Edge
	var eps string
	var ca, ph, lh, boot sql.NullString
	var last sql.NullTime
	e := s.db.QueryRowContext(r.Context(), "SELECT id,name,endpoints,ca_cert,public_host,listen_host,http_port,https_port,port_min,port_max,max_carriers,capacity_bps,boot_id,last_seen,applied_revision FROM edges WHERE token_hash=?", hashToken(token)).Scan(&edge.ID, &edge.Name, &eps, &ca, &ph, &lh, &edge.HTTPPort, &edge.HTTPSPort, &edge.PortMin, &edge.PortMax, &edge.MaxCarriers, &edge.CapacityBPS, &boot, &last, &edge.AppliedRevision)
	if e != nil {
		apiErr(w, 401, "unauthorized", "invalid edge token")
		return
	}
	eid = edge.ID
	decodeJSON(eps, &edge.Endpoints)
	edge.CACert = ca.String
	edge.PublicHost = ph.String
	edge.ListenHost = lh.String
	edge.BootID = boot.String
	if last.Valid {
		edge.LastSeen = last.Time
	}
	var in model.EdgeSyncRequest
	if e = readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if in.EdgeID != "" && in.EdgeID != eid {
		apiErr(w, 403, "edge_mismatch", "edge id mismatch")
		return
	}
	if in.BootID == "" {
		in.BootID = protocol.ID()
	}
	_, _ = s.db.ExecContext(r.Context(), "UPDATE edges SET boot_id=?,last_seen=?,applied_revision=? WHERE id=?", in.BootID, now(), in.AppliedRevision, eid)
	edge.BootID = in.BootID
	edge.LastSeen = now()
	rules, e := s.rulesForEdge(r, eid)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	devs, e := s.devicesForRules(r, rules)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	grants, e := s.grantsForEdge(r, eid, in.BootID, devs)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	if e = s.recordUsage(r, in.Usage); e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	snap := model.EdgeSnapshot{Revision: revision(r), ExpiresAt: now().Add(s.cfg.SnapshotTTL), Edge: edge, Devices: devs, Rules: rules, Grants: grants}
	writeJSON(w, 200, snap)
}
func (s *Server) revision(r *http.Request) uint64 {
	var v uint64
	_ = s.db.QueryRowContext(r.Context(), "SELECT COALESCE(UNIX_TIMESTAMP(MAX(updated_at)),0) FROM rules").Scan(&v)
	return v
}
func (s *Server) rulesForEdge(r *http.Request, eid string) ([]model.Rule, error) {
	rows, e := s.db.QueryContext(r.Context(), "SELECT id,tenant_id,name,protocol,device_id,edge_id,public_port,domain,target,host,server_name,certificate_id,source_mode,transport,acl_template_id,acl,enabled,deleting,version,status,last_error,applied_version,timeout_seconds FROM rules WHERE edge_id=? AND deleting=0", eid)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Rule{}
	for rows.Next() {
		var x model.Rule
		var dom, host, sn, cert, tid, last sql.NullString
		var ac string
		_ = rows.Scan(&x.ID, &x.TenantID, &x.Name, &x.Protocol, &x.DeviceID, &x.EdgeID, &x.PublicPort, &dom, &x.Target, &host, &sn, &cert, &x.SourceMode, &x.Transport, &tid, &ac, &x.Enabled, &x.Deleting, &x.Version, &x.Status, &last, &x.AppliedVersion, &x.TimeoutSeconds)
		x.Domain = dom.String
		x.Host = host.String
		x.ServerName = sn.String
		x.CertificateID = cert.String
		x.ACLTemplateID = tid.String
		x.LastError = last.String
		decodeJSON(ac, &x.ACL)
		out = append(out, x)
	}
	return out, nil
}
func (s *Server) devicesForRules(r *http.Request, rules []model.Rule) ([]model.DeviceGrant, error) {
	seen := map[string]bool{}
	out := []model.DeviceGrant{}
	for _, x := range rules {
		if seen[x.DeviceID] {
			continue
		}
		seen[x.DeviceID] = true
		var d model.DeviceGrant
		var exp time.Time
		var pub string
		var sid sql.NullString
		var gen uint64
		e := s.db.QueryRowContext(r.Context(), "SELECT id,tenant_id,public_key,session_id,generation FROM devices WHERE id=? AND revoked=0", x.DeviceID).Scan(&d.DeviceID, &d.TenantID, &pub, &sid, &gen)
		if e != nil {
			continue
		}
		d.PublicKey = pub
		d.SessionID = sid.String
		d.Generation = gen
		d.ExpiresAt = expOr(time.Now().Add(s.cfg.SnapshotTTL))
		out = append(out, d)
	}
	return out, nil
}
func expOr(t time.Time) time.Time { return t }
func (s *Server) grantsForEdge(r *http.Request, eid, boot string, devs []model.DeviceGrant) ([]model.Grant, error) {
	seen := map[string]bool{}
	out := []model.Grant{}
	for _, d := range devs {
		if seen[d.TenantID] {
			continue
		}
		seen[d.TenantID] = true
		var g model.Grant
		var reserved, used int64
		var closed bool
		e := s.db.QueryRowContext(r.Context(), "SELECT id,tenant_id,edge_id,boot_id,expires_at,bytes,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,reserved,used,closed FROM grants_table WHERE tenant_id=? AND edge_id=? AND boot_id=? AND closed=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1", d.TenantID, eid, boot, now()).Scan(&g.ID, &g.TenantID, &g.EdgeID, &g.BootID, &g.ExpiresAt, &g.Bytes, &g.BaseBPS, &g.PeakBPS, &g.BurstBytes, &g.MaxConnections, &g.NewFlowsPerSecond, &reserved, &used, &closed)
		if e == nil {
			out = append(out, g)
			continue
		}
		var q model.Quota
		_ = s.db.QueryRowContext(r.Context(), "SELECT tenant_id,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,period_bytes,used_bytes,reserved_bytes,version FROM quotas WHERE tenant_id=?", d.TenantID).Scan(&q.TenantID, &q.BaseBPS, &q.PeakBPS, &q.BurstBytes, &q.MaxConnections, &q.NewFlowsPerSecond, &q.PeriodBytes, &q.UsedBytes, &q.ReservedBytes, &q.Version)
		bytes := q.PeriodBytes
		if bytes <= 0 {
			bytes = 64 << 20
		}
		if q.PeriodBytes > 0 && q.UsedBytes+q.ReservedBytes >= q.PeriodBytes {
			continue
		}
		if q.PeriodBytes > 0 && bytes > q.PeriodBytes-q.UsedBytes-q.ReservedBytes {
			bytes = q.PeriodBytes - q.UsedBytes - q.ReservedBytes
		}
		g = model.Grant{ID: id(), TenantID: d.TenantID, EdgeID: eid, BootID: boot, ExpiresAt: now().Add(s.cfg.SnapshotTTL), Bytes: bytes, BaseBPS: q.BaseBPS, PeakBPS: q.PeakBPS, BurstBytes: q.BurstBytes, MaxConnections: q.MaxConnections, NewFlowsPerSecond: q.NewFlowsPerSecond}
		tx, e := s.db.BeginTx(r.Context(), nil)
		if e != nil {
			return nil, e
		}
		_, e = tx.ExecContext(r.Context(), "INSERT INTO grants_table(id,tenant_id,edge_id,boot_id,expires_at,bytes,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,reserved,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", g.ID, g.TenantID, g.EdgeID, g.BootID, g.ExpiresAt, g.Bytes, g.BaseBPS, g.PeakBPS, g.BurstBytes, g.MaxConnections, g.NewFlowsPerSecond, g.Bytes, now())
		if e == nil {
			_, e = tx.ExecContext(r.Context(), "INSERT INTO quotas(tenant_id,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,period_bytes,used_bytes,reserved_bytes,version,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE reserved_bytes=reserved_bytes+VALUES(reserved_bytes),version=version+1,updated_at=VALUES(updated_at)", d.TenantID, q.BaseBPS, q.PeakBPS, q.BurstBytes, q.MaxConnections, q.NewFlowsPerSecond, q.PeriodBytes, q.UsedBytes, g.Bytes, q.Version, now())
		}
		if e != nil {
			tx.Rollback()
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
		out = append(out, g)
	}
	return out, nil
}
func (s *Server) recordUsage(r *http.Request, us []model.Usage) error {
	for _, u := range us {
		if u.GrantID == "" {
			continue
		}
		var old int64
		var seq uint64
		var tenant, edge, boot string
		var closed bool
		e := s.db.QueryRowContext(r.Context(), "SELECT sequence_no,upload_bytes+download_bytes,tenant_id,edge_id,boot_id,closed FROM usage_table WHERE grant_id=?", u.GrantID).Scan(&seq, &old, &tenant, &edge, &boot, &closed)
		if e == nil && u.Sequence <= seq {
			continue
		}
		if e == nil {
			delta := u.UploadBytes + u.DownloadBytes - old
			if delta < 0 {
				delta = 0
			}
			_, _ = s.db.ExecContext(r.Context(), "UPDATE usage_table SET sequence_no=?,upload_bytes=?,download_bytes=?,closed=?,observed_at=? WHERE grant_id=?", u.Sequence, u.UploadBytes, u.DownloadBytes, u.Closed, now(), u.GrantID)
			_, _ = s.db.ExecContext(r.Context(), "UPDATE grants_table SET used=used+?,closed=? WHERE id=?", delta, u.Closed, u.GrantID)
			_, _ = s.db.ExecContext(r.Context(), "UPDATE quotas SET used_bytes=used_bytes+?,reserved_bytes=GREATEST(0,reserved_bytes-?),version=version+1 WHERE tenant_id=?", delta, delta, tenant)
		} else {
			_, e = s.db.ExecContext(r.Context(), "INSERT INTO usage_table(grant_id,tenant_id,edge_id,boot_id,sequence_no,upload_bytes,download_bytes,closed,observed_at) VALUES(?,?,?,?,?,?,?,?,?)", u.GrantID, edge, edge, boot, u.Sequence, u.UploadBytes, u.DownloadBytes, u.Closed, now())
			if e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Server) clientSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var in model.ClientSyncRequest
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if abs(time.Now().Unix()-in.Timestamp) > 60 {
		apiErr(w, 401, "clock_skew", "timestamp outside 60 seconds")
		return
	}
	pub, session, gen, tenantID, name := ",", "", uint64(0), "", ""
	var pkey string
	var revoked bool
	e := s.db.QueryRowContext(r.Context(), "SELECT public_key,session_id,generation,tenant_id,revoked,name FROM devices WHERE id=?", in.DeviceID).Scan(&pkey, &session, &gen, &tenantID, &revoked, &name)
	if e != nil || revoked || session != in.SessionID {
		apiErr(w, 401, "device_session", "device session invalid")
		return
	}
	pk, e := verifyPub(pkey)
	sig, e2 := base64.StdEncoding.DecodeString(in.Signature)
	if e != nil || e2 != nil || !ed25519.Verify(pk, model.SyncPayload(in.DeviceID, in.SessionID, in.Timestamp), sig) {
		apiErr(w, 401, "bad_signature", "invalid signature")
		return
	}
	_, _ = s.db.ExecContext(r.Context(), "UPDATE devices SET last_seen=?,capabilities=?,applied_revision=? WHERE id=?", now(), encodeJSON(in.Capabilities), in.AppliedRevision, in.DeviceID)
	rows, e := s.db.QueryContext(r.Context(), "SELECT id,name,endpoints,ca_cert,public_host,listen_host,http_port,https_port,port_min,port_max,max_carriers,capacity_bps,boot_id,last_seen,applied_revision FROM edges")
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	defer rows.Close()
	edges := []model.Edge{}
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
		edges = append(edges, x)
	}
	rules, e := s.rulesForDevice(r, in.DeviceID)
	if e != nil {
		apiErr(w, 500, "database", e.Error())
		return
	}
	d := model.DeviceGrant{DeviceID: in.DeviceID, TenantID: tenantID, PublicKey: pkey, SessionID: session, Generation: gen, ExpiresAt: now().Add(s.cfg.SnapshotTTL)}
	writeJSON(w, 200, model.ClientSnapshot{Revision: revision(r), ExpiresAt: now().Add(s.cfg.SnapshotTTL), Device: d, Edges: edges, Rules: rules})
	_ = name
}
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
func (s *Server) rulesForDevice(r *http.Request, did string) ([]model.Rule, error) {
	var tenant string
	_ = s.db.QueryRowContext(r.Context(), "SELECT tenant_id FROM devices WHERE id=?", did).Scan(&tenant)
	return s.listRules(r, tenant, "")
}

var _ = errors.New
var _ = strings.TrimSpace
var _ = protocol.ProtocolVersion
var _ = ed25519.PrivateKeySize
