package cloud

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) edges(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		items, e := s.loadEdges(r.Context(), "")
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if !isAdmin(r) {
			q, err := readQuota(r.Context(), s.store(r.Context()), tenant(r), false)
			if err != nil {
				apiErr(w, 503, "database_unavailable", err.Error())
				return
			}
			filtered := []model.Edge{}
			for _, edge := range items {
				if edgeAllowed(q, edge.ID) {
					filtered = append(filtered, edge)
				}
			}
			items = filtered
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
		return
	}
	if !isAdmin(r) {
		apiErr(w, 403, "forbidden", "administrator role required")
		return
	}
	if !requireMethod(w, r, "POST") {
		return
	}
	var in struct {
		model.Edge
		Token string `json:"token"`
	}
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if len(in.Token) < 24 || len(in.Token) > 1024 {
		apiErr(w, 400, "invalid_token", "supply a random edge token of at least 24 characters")
		return
	}
	if e := validateEdge(in.Edge); e != nil {
		apiErr(w, 400, "invalid_edge", e.Error())
		return
	}
	in.ID = id()
	in.BootID = ""
	in.LastSeen = time.Time{}
	in.AppliedRevision = 0
	if _, e := s.store(r.Context()).ExecContext(r.Context(), "INSERT INTO edges(id,name,endpoints,ca_cert,public_host,listen_host,http_port,https_port,port_min,port_max,max_carriers,capacity_bps,token_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", in.ID, in.Name, encodeJSON(in.Endpoints), in.CACert, in.PublicHost, in.ListenHost, in.HTTPPort, in.HTTPSPort, in.PortMin, in.PortMax, in.MaxCarriers, in.CapacityBPS, hashToken(in.Token), now()); e != nil {
		apiErr(w, 409, "resource_conflict", "edge or token already exists")
		return
	}
	s.notify(r.Context())
	writeJSON(w, 201, in.Edge)
}
func validateEdge(e model.Edge) error {
	if e.Name == "" || len(e.Name) > 255 || e.PublicHost == "" {
		return errors.New("name and public_host are required")
	}
	if e.PortMin < 1024 || e.PortMax > 65535 || e.PortMax < e.PortMin {
		return errors.New("business port pool must be within 1024..65535")
	}
	if e.MaxCarriers < 1 || e.MaxCarriers > 1024 || e.CapacityBPS < -1 {
		return errors.New("invalid carrier or capacity limit")
	}
	if e.HTTPPort < 0 || e.HTTPPort > 65535 || e.HTTPSPort < 0 || e.HTTPSPort > 65535 || e.HTTPPort > 0 && e.HTTPPort == e.HTTPSPort {
		return errors.New("invalid shared HTTP(S) ports")
	}
	if len(e.Endpoints) != 2 {
		return errors.New("configure one QUIC/UDP endpoint and one TLS/TCP endpoint; use DNS for dual-stack addresses")
	}
	seen := map[string]bool{}
	for _, ep := range e.Endpoints {
		h, p, err := net.SplitHostPort(ep.Address)
		port, pe := strconv.Atoi(p)
		if err != nil || pe != nil || h == "" || port < 1 || port > 65535 || ep.ServerName == "" {
			return errors.New("endpoint requires host:port and TLS server_name")
		}
		if ep.Transport != "quic" && ep.Transport != "tls" {
			return errors.New("endpoint transport must be quic or tls")
		}
		key := ep.Transport
		if seen[key] {
			return errors.New("duplicate carrier port")
		}
		seen[key] = true
		if ep.Transport == "tls" && (port == e.HTTPPort || port == e.HTTPSPort) {
			return errors.New("carrier conflicts with HTTP(S) listener")
		}
	}
	return nil
}
func (s *Server) edge(w http.ResponseWriter, r *http.Request) {
	eid := strings.TrimPrefix(r.URL.Path, "/api/v1/edges/")
	if r.Method == "GET" {
		items, e := s.loadEdges(r.Context(), eid)
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if len(items) == 0 {
			apiErr(w, 404, "not_found", "edge not found")
			return
		}
		writeJSON(w, 200, items[0])
		return
	}
	tx, e := s.beginTx(r.Context(), nil)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	defer tx.Rollback()
	if r.Method == "DELETE" {
		if _, err := lockPlanSettings(r.Context(), tx); err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
	}
	var found string
	if e = tx.QueryRowContext(r.Context(), "SELECT id FROM edges WHERE id=? FOR UPDATE", eid).Scan(&found); e != nil {
		apiErr(w, 404, "not_found", "edge not found")
		return
	}
	var n int
	if e = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM rules WHERE edge_id=?", eid).Scan(&n); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if n > 0 {
		apiErr(w, 409, "edge_in_use", "remove rules and wait for revocation before editing or deleting edge listeners")
		return
	}
	if e = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM resource_claims WHERE edge_id=? AND (release_at IS NULL OR release_at>?)", eid, now()).Scan(&n); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if n > 0 {
		apiErr(w, 409, "edge_in_use", "old edge authorization is awaiting revocation or lease expiry")
		return
	}
	switch r.Method {
	case "DELETE":
		if e = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM plan_edges WHERE edge_id=?", eid).Scan(&n); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if n > 0 {
			apiErr(w, 409, "edge_in_use", "出口节点已包含在套餐中")
			return
		}
		if e = s.prepareEdgeDeletion(r.Context(), tx, eid); e != nil {
			if errors.Is(e, errEdgeLeases) {
				apiErr(w, 409, "edge_in_use", e.Error())
			} else {
				apiErr(w, 503, "database_unavailable", e.Error())
			}
			return
		}
		_, e = tx.ExecContext(r.Context(), "DELETE FROM edges WHERE id=?", eid)
	case "PUT":
		var in model.Edge
		if e = readJSON(w, r, &in); e != nil {
			apiErr(w, 400, "invalid_json", e.Error())
			return
		}
		if e = validateEdge(in); e != nil {
			apiErr(w, 400, "invalid_edge", e.Error())
			return
		}
		_, e = tx.ExecContext(r.Context(), "UPDATE edges SET name=?,endpoints=?,ca_cert=?,public_host=?,listen_host=?,http_port=?,https_port=?,port_min=?,port_max=?,max_carriers=?,capacity_bps=? WHERE id=?", in.Name, encodeJSON(in.Endpoints), in.CACert, in.PublicHost, in.ListenHost, in.HTTPPort, in.HTTPSPort, in.PortMin, in.PortMax, in.MaxCarriers, in.CapacityBPS, eid)
	default:
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if e = tx.Commit(); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	s.notify(r.Context())
	if r.Method == "DELETE" {
		writeJSON(w, 200, map[string]any{"ok": true})
	} else {
		items, _ := s.loadEdges(r.Context(), eid)
		writeJSON(w, 200, items[0])
	}
}
func (s *Server) loadTemplates(r *http.Request) ([]model.ACLTemplate, error) {
	rows, e := s.store(r.Context()).QueryContext(r.Context(), "SELECT id,name,policy,published,version,default_flag,mandatory FROM acl_templates ORDER BY name")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.ACLTemplate{}
	for rows.Next() {
		var x model.ACLTemplate
		var raw string
		var pub sql.NullString
		if e = rows.Scan(&x.ID, &x.Name, &raw, &pub, &x.Version, &x.Default, &x.Mandatory); e != nil {
			return nil, e
		}
		decodeJSON(raw, &x.Policy)
		if pub.Valid {
			decodeJSON(pub.String, &x.Published)
		}
		if !isAdmin(r) {
			if x.Published == nil {
				continue
			}
			x.Policy = *x.Published
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Server) templates(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		items, e := s.loadTemplates(r)
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
		return
	}
	if !isAdmin(r) {
		apiErr(w, 403, "forbidden", "administrator role required")
		return
	}
	if !requireMethod(w, r, "POST") {
		return
	}
	var x model.ACLTemplate
	if e := readJSON(w, r, &x); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if x.Name == "" || len(x.Name) > 255 || len(x.Policy.Entries) != 0 || x.Default || x.Mandatory {
		apiErr(w, 400, "invalid_template", "create a named empty draft before selecting default or mandatory policy")
		return
	}
	if _, e := compileDraft(x.Policy); e != nil {
		apiErr(w, 400, "invalid_acl", e.Error())
		return
	}
	x.ID = id()
	x.Version = 1
	x.Policy.Version = 0
	x.Published = nil
	if _, e := s.store(r.Context()).ExecContext(r.Context(), "INSERT INTO acl_templates(id,name,policy,version,updated_at) VALUES(?,?,?,?,?)", x.ID, x.Name, encodeJSON(x.Policy), x.Version, now()); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	s.notify(r.Context())
	writeJSON(w, 201, x)
}
func (s *Server) template(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		apiErr(w, 403, "forbidden", "administrator role required")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/acl-templates/"), "/")
	tid := parts[0]
	tx, e := s.beginTx(r.Context(), nil)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	defer tx.Rollback()
	var x model.ACLTemplate
	var raw string
	var pub sql.NullString
	if e = tx.QueryRowContext(r.Context(), "SELECT id,name,policy,published,version,default_flag,mandatory FROM acl_templates WHERE id=? FOR UPDATE", tid).Scan(&x.ID, &x.Name, &raw, &pub, &x.Version, &x.Default, &x.Mandatory); e != nil {
		apiErr(w, 404, "not_found", "template not found")
		return
	}
	decodeJSON(raw, &x.Policy)
	if pub.Valid {
		decodeJSON(pub.String, &x.Published)
	}
	if len(parts) == 2 && parts[1] == "publish" {
		if !requireMethod(w, r, "POST") {
			return
		}
		if r.ContentLength != 0 {
			var in struct {
				Version uint64 `json:"version"`
			}
			if e = readJSON(w, r, &in); e != nil {
				apiErr(w, 400, "invalid_json", e.Error())
				return
			}
			if in.Version != x.Version {
				apiErr(w, 409, "version_conflict", "template changed")
				return
			}
		}
		if _, e = acl.Compile(x.Policy); e != nil {
			apiErr(w, 400, "invalid_acl", e.Error())
			return
		}
		x.Version++
		x.Policy.Version = x.Version
		p := x.Policy
		x.Published = &p
		_, e = tx.ExecContext(r.Context(), "UPDATE acl_templates SET published=?,version=?,updated_at=? WHERE id=?", encodeJSON(p), x.Version, now(), tid)
		if e == nil {
			_, e = tx.ExecContext(r.Context(), "INSERT INTO acl_template_versions(template_id,version,policy,created_at) VALUES(?,?,?,?)", tid, x.Version, encodeJSON(p), now())
		}
		if e == nil {
			_, e = tx.ExecContext(r.Context(), "UPDATE rules SET version=version+1,status='pending',updated_at=? WHERE deleting=0 AND (acl_template_id=? OR (?=1 AND protocol IN ('tcp','udp')))", now(), tid, x.Mandatory)
		}
	} else if len(parts) != 1 {
		apiErr(w, 404, "not_found", "unknown template action")
		return
	} else if r.Method == "PUT" {
		var in model.ACLTemplate
		if e = readJSON(w, r, &in); e != nil {
			apiErr(w, 400, "invalid_json", e.Error())
			return
		}
		if in.Version != x.Version {
			apiErr(w, 409, "version_conflict", "template changed")
			return
		}
		if _, e = compileDraft(in.Policy); e != nil {
			apiErr(w, 400, "invalid_acl", e.Error())
			return
		}
		if in.Name == "" || len(in.Name) > 255 {
			apiErr(w, 400, "invalid_name", "name required")
			return
		}
		if (in.Default || in.Mandatory) && x.Published == nil {
			apiErr(w, 400, "unpublished_policy", "publish before setting default or mandatory")
			return
		}
		if in.Default {
			if _, e = tx.ExecContext(r.Context(), "UPDATE acl_templates SET default_flag=0 WHERE id<>?", tid); e != nil {
				apiErr(w, 503, "database_unavailable", e.Error())
				return
			}
		}
		x.Name = in.Name
		x.Policy = in.Policy
		x.Default = in.Default
		forceChanged := x.Mandatory != in.Mandatory
		x.Mandatory = in.Mandatory
		x.Version++
		_, e = tx.ExecContext(r.Context(), "UPDATE acl_templates SET name=?,policy=?,default_flag=?,mandatory=?,version=?,updated_at=? WHERE id=?", x.Name, encodeJSON(x.Policy), x.Default, x.Mandatory, x.Version, now(), tid)
		if e == nil && forceChanged {
			_, e = tx.ExecContext(r.Context(), "UPDATE rules SET version=version+1,status='pending',updated_at=? WHERE protocol IN ('tcp','udp') AND deleting=0", now())
		}
	} else if r.Method == "DELETE" {
		var n int
		if e = tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM rules WHERE acl_template_id=?", tid).Scan(&n); e != nil || n > 0 || x.Mandatory || x.Default {
			apiErr(w, 409, "template_in_use", "remove bindings, default and mandatory flags before deletion")
			return
		}
		_, e = tx.ExecContext(r.Context(), "DELETE FROM acl_templates WHERE id=?", tid)
	} else {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if e = tx.Commit(); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	s.notify(r.Context())
	if r.Method == "DELETE" {
		writeJSON(w, 200, map[string]any{"ok": true})
	} else {
		writeJSON(w, 200, x)
	}
}
func verifyCertificateDomain(certPEM, domain string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("invalid certificate PEM")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return e
	}
	if now().Before(cert.NotBefore) || !now().Before(cert.NotAfter) {
		return errors.New("certificate is not currently valid")
	}
	return cert.VerifyHostname(domain)
}
func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, e := s.store(r.Context()).QueryContext(r.Context(), "SELECT id,name,domains,expires_at FROM certificates WHERE tenant_id=?", tenant(r))
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		defer rows.Close()
		out := []model.Certificate{}
		for rows.Next() {
			var c model.Certificate
			var dom string
			if e = rows.Scan(&c.ID, &c.Name, &dom, &c.ExpiresAt); e != nil {
				apiErr(w, 503, "database_unavailable", e.Error())
				return
			}
			c.TenantID = tenant(r)
			decodeJSON(dom, &c.Domains)
			out = append(out, c)
		}
		writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
		return
	}
	if !requireMethod(w, r, "POST") {
		return
	}
	var c model.Certificate
	if e := readJSON(w, r, &c); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if strings.TrimSpace(c.Name) == "" || len(c.Name) > 255 {
		apiErr(w, 400, "invalid_name", "certificate name required (maximum 255 bytes)")
		return
	}
	pair, e := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
	if e != nil || len(pair.Certificate) == 0 {
		apiErr(w, 400, "invalid_certificate", "certificate and private key must be a matching PEM pair")
		return
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || now().Before(leaf.NotBefore) || !now().Before(leaf.NotAfter) || leaf.IsCA {
		apiErr(w, 400, "invalid_certificate", "supply a valid, unexpired leaf certificate")
		return
	}
	c.Domains = leaf.DNSNames
	c.ExpiresAt = leaf.NotAfter
	c.ID = id()
	c.TenantID = tenant(r)
	enc, e := encrypt(s.key, c.KeyPEM)
	if e != nil {
		apiErr(w, 500, "encryption", e.Error())
		return
	}
	if _, e = s.store(r.Context()).ExecContext(r.Context(), "INSERT INTO certificates(id,tenant_id,name,domains,cert_pem,key_enc,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)", c.ID, c.TenantID, c.Name, encodeJSON(c.Domains), c.CertPEM, enc, c.ExpiresAt, now()); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	c.KeyPEM = ""
	s.notify(r.Context())
	writeJSON(w, 201, c)
}
func (s *Server) certificate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "DELETE") {
		return
	}
	cid := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	var found string
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT id FROM certificates WHERE id=? AND tenant_id=? FOR UPDATE", cid, tenant(r)).Scan(&found); e != nil {
		apiErr(w, 404, "not_found", "certificate not found")
		return
	}
	var n int
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT COUNT(*) FROM rules WHERE certificate_id=?", cid).Scan(&n); e != nil || n > 0 {
		apiErr(w, 409, "certificate_in_use", "certificate is referenced by a rule")
		return
	}
	res, e := s.store(r.Context()).ExecContext(r.Context(), "DELETE FROM certificates WHERE id=? AND tenant_id=?", cid, tenant(r))
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	n64, _ := res.RowsAffected()
	if n64 == 0 {
		apiErr(w, 404, "not_found", "certificate not found")
		return
	}
	s.notify(r.Context())
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) quotas(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	query := "SELECT tenant_id FROM quotas"
	args := []any{}
	if !isAdmin(r) {
		query += " WHERE tenant_id=?"
		args = append(args, tenant(r))
	}
	rows, e := s.store(r.Context()).QueryContext(r.Context(), query, args...)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	out := []model.Quota{}
	for _, id := range ids {
		q, e := s.quotaSnapshot(r.Context(), id)
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		out = append(out, q)
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}
func (s *Server) quota(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "PUT") {
		return
	}
	tid := strings.TrimPrefix(r.URL.Path, "/api/v1/quotas/")
	// New limits are optional on updates from older consoles. Omitting one
	// preserves its saved value; zero explicitly denies additional resources.
	var in struct {
		model.Quota
		MaxDevices *int `json:"max_devices"`
		MaxRules   *int `json:"max_rules"`
		MaxPorts   *int `json:"max_ports"`
		MaxDomains *int `json:"max_domains"`
	}
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	q := in.Quota
	for _, limit := range []*int{in.MaxDevices, in.MaxRules, in.MaxPorts, in.MaxDomains} {
		if limit != nil && (*limit < -1 || *limit > 1000000) {
			apiErr(w, 400, "invalid_quota", "configuration resource limits must be -1 or 0..1000000")
			return
		}
	}
	if q.BaseBPS < -1 || q.PeakBPS < -1 || q.BurstBytes < 0 || q.MaxConnections < -1 || q.NewFlowsPerSecond < -1 || q.PeriodBytes < -1 || q.BaseBPS > 1<<50 || q.PeakBPS > 1<<50 || q.BurstBytes > 1<<50 || q.PeriodBytes > 1<<60 || q.BaseBPS >= 0 && q.PeakBPS >= 0 && q.PeakBPS < q.BaseBPS || q.PeriodSeconds < 0 || q.PeriodSeconds > 366*86400 || q.PeriodSeconds > 0 && q.PeriodSeconds < 60 {
		apiErr(w, 400, "invalid_quota", "use -1 for unlimited and 0 for deny; peak must be at least base; period_seconds is 0 or 60..31622400")
		return
	}
	tx, e := s.beginTx(r.Context(), nil)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	defer tx.Rollback()
	var found string
	if e = tx.QueryRowContext(r.Context(), "SELECT tenant_id FROM quotas WHERE tenant_id=?", tid).Scan(&found); e != nil {
		apiErr(w, 404, "not_found", "tenant quota not found")
		return
	}
	old, e := s.currentQuota(r.Context(), tx, tid)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if q.Version != old.Version {
		apiErr(w, 409, "version_conflict", "quota changed")
		return
	}
	if old.PlanID != "" {
		p, err := readPlan(r.Context(), tx, old.PlanID)
		if err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
		if !p.Legacy {
			apiErr(w, 409, "plan_managed", "资源权限由套餐管理")
			return
		}
	}
	q.PlanID, q.AllowedEdgeIDs, q.MaxSites = old.PlanID, old.AllowedEdgeIDs, old.MaxSites
	q.MaxDevices, q.MaxRules, q.MaxPorts, q.MaxDomains = old.MaxDevices, old.MaxRules, old.MaxPorts, old.MaxDomains
	for _, item := range []struct {
		value *int
		dst   *int
	}{
		{in.MaxDevices, &q.MaxDevices}, {in.MaxRules, &q.MaxRules}, {in.MaxPorts, &q.MaxPorts}, {in.MaxDomains, &q.MaxDomains},
	} {
		if item.value != nil {
			*item.dst = *item.value
		}
	}
	q.TenantID = tid
	q.PeriodID = old.PeriodID
	q.PeriodStartedAt = old.PeriodStartedAt
	q.PeriodEndsAt = old.PeriodEndsAt
	q.UsedBytes = old.UsedBytes
	q.ReservedBytes = old.ReservedBytes
	if q.PeriodSeconds != old.PeriodSeconds {
		q.PeriodStartedAt = now()
		q.PeriodEndsAt = time.Time{}
		if q.PeriodSeconds > 0 {
			q.PeriodEndsAt = q.PeriodStartedAt.Add(time.Duration(q.PeriodSeconds) * time.Second)
			var oldLease sql.NullTime
			if e = tx.QueryRowContext(r.Context(), "SELECT MAX(expires_at) FROM grants_table WHERE tenant_id=? AND closed=0", tid).Scan(&oldLease); e != nil {
				apiErr(w, 503, "database_unavailable", e.Error())
				return
			}
			// A scheduling change cannot retroactively shorten authority already
			// held by an offline edge. The first new boundary waits for those leases.
			if oldLease.Valid && oldLease.Time.After(q.PeriodEndsAt) {
				q.PeriodEndsAt = oldLease.Time
			}
		}
	}
	_, e = tx.ExecContext(r.Context(), "UPDATE quotas SET base_bps=?,peak_bps=?,burst_bytes=?,max_connections=?,new_flows_per_second=?,period_bytes=?,period_seconds=?,period_started_at=?,period_ends_at=?,max_devices=?,max_rules=?,max_ports=?,max_domains=?,version=version+1,updated_at=? WHERE tenant_id=? AND version=?", q.BaseBPS, q.PeakBPS, q.BurstBytes, q.MaxConnections, q.NewFlowsPerSecond, q.PeriodBytes, q.PeriodSeconds, q.PeriodStartedAt, sqlTime(q.PeriodEndsAt), q.MaxDevices, q.MaxRules, q.MaxPorts, q.MaxDomains, now(), tid, q.Version)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if _, e = tx.ExecContext(r.Context(), "UPDATE quota_periods SET started_at=?,ends_at=? WHERE tenant_id=? AND period_id=?", q.PeriodStartedAt, sqlTime(q.PeriodEndsAt), tid, q.PeriodID); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	q.Resources, e = resourceUsage(r.Context(), tx, tid)
	if e != nil {
		apiErr(w, 503, "database_unavailable", "could not read configuration resource usage")
		return
	}
	if e = tx.Commit(); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	q.Version++
	s.notify(r.Context())
	writeJSON(w, 200, q)
}
func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, e := s.store(r.Context()).QueryContext(r.Context(), "SELECT u.id,u.tenant_id,u.username,u.role,u.disabled,u.created_at,COALESCE(q.plan_id,''),COALESCE(p.name,'') FROM users u LEFT JOIN quotas q ON q.tenant_id=u.tenant_id LEFT JOIN plans p ON p.id=q.plan_id ORDER BY u.username")
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		defer rows.Close()
		out := []model.User{}
		for rows.Next() {
			var u model.User
			if e = rows.Scan(&u.ID, &u.TenantID, &u.Username, &u.Role, &u.Disabled, &u.CreatedAt, &u.PlanID, &u.PlanName); e != nil {
				apiErr(w, 503, "database_unavailable", e.Error())
				return
			}
			out = append(out, u)
		}
		writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
		return
	}
	if !requireMethod(w, r, "POST") {
		return
	}
	var in struct {
		Username string  `json:"username"`
		Password string  `json:"password"`
		Role     string  `json:"role"`
		TenantID string  `json:"tenant_id"`
		PlanID   *string `json:"plan_id"`
	}
	if e := readJSON(w, r, &in); e != nil || strings.TrimSpace(in.Username) == "" || len(in.Username) > 255 || len(in.Password) < 10 || len(in.Password) > 72 || !validRole(in.Role) {
		apiErr(w, 400, "invalid_user", "username, role, and a 10..72 byte password are required")
		return
	}
	pw, e := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if e != nil {
		apiErr(w, 400, "invalid_password", e.Error())
		return
	}
	tx, e := s.beginTx(r.Context(), nil)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	defer tx.Rollback()
	tid := in.TenantID
	if tid == "" {
		tid = id()
		if _, e = tx.ExecContext(r.Context(), "INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)", tid, in.Username, now()); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if _, e = tx.ExecContext(r.Context(), "INSERT INTO quotas(tenant_id,updated_at) VALUES(?,?)", tid, now()); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if e = initializeAccountPlan(r.Context(), tx, tid, in.PlanID); e != nil {
			apiErr(w, 400, "invalid_plan", "套餐不存在或无法分配")
			return
		}
	} else if in.PlanID != nil {
		apiErr(w, 400, "shared_plan", "共享空间的套餐由空间统一分配")
		return
	}
	u := model.User{ID: id(), TenantID: tid, Username: in.Username, Role: in.Role}
	if _, e = tx.ExecContext(r.Context(), "INSERT INTO users(id,tenant_id,username,password_hash,role,created_at) VALUES(?,?,?,?,?,?)", u.ID, tid, u.Username, string(pw), u.Role, now()); e != nil {
		apiErr(w, 409, "user_conflict", "username exists or tenant is invalid")
		return
	}
	if e = tx.Commit(); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	s.notify(r.Context())
	writeJSON(w, 201, u)
}
func (s *Server) usage(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	rows, e := s.store(r.Context()).QueryContext(r.Context(), "SELECT u.grant_id,g.issued_edge_id,g.boot_id,u.sequence_no,u.upload_bytes,u.download_bytes,u.closed,u.observed_at FROM usage_table u JOIN grants_table g ON g.id=u.grant_id WHERE g.tenant_id=? ORDER BY u.observed_at DESC LIMIT 1000", tenant(r))
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, edge, boot string
		var seq uint64
		var up, down int64
		var closed bool
		var at time.Time
		if e = rows.Scan(&id, &edge, &boot, &seq, &up, &down, &closed, &at); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		out = append(out, map[string]any{"grant_id": id, "tenant_id": tenant(r), "edge_id": edge, "boot_id": boot, "sequence": seq, "upload_bytes": up, "download_bytes": down, "closed": closed, "observed_at": at})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}
func (s *Server) auditAPI(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	rows, e := s.store(r.Context()).QueryContext(r.Context(), "SELECT id,actor_id,tenant_id,action,resource_id,created_at FROM audit ORDER BY created_at DESC LIMIT 1000")
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, a, t, action, res string
		var at time.Time
		if e = rows.Scan(&id, &a, &t, &action, &res, &at); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		out = append(out, map[string]any{"id": id, "actor": a, "tenant_id": t, "action": action, "resource_id": res, "created_at": at})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}
func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	mysql := "healthy"
	if e := s.db.PingContext(r.Context()); e != nil {
		mysql = "unhealthy"
	}
	writeJSON(w, 200, map[string]any{"mysql": mysql, "cache": s.tmp.Stats(), "build_id": s.cfg.BuildID, "started_at": s.started})
}
