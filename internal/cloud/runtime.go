package cloud

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"drafrp/internal/model"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) revision(r *http.Request) uint64 {
	var v uint64
	_ = s.store(r.Context()).QueryRowContext(r.Context(), "SELECT revision FROM config_revision WHERE id=1").Scan(&v)
	return v
}
func (s *Server) edgeSync(w http.ResponseWriter, r *http.Request) {
	s.runtimeMutation(w, r, s.edgeSyncInTransaction)
}
func (s *Server) edgeSyncInTransaction(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	var in model.EdgeSyncRequest
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if in.BootID == "" || len(in.BootID) > 96 {
		apiErr(w, 400, "invalid_boot_id", "fresh boot_id is required")
		return
	}
	var eid string
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT id FROM edges WHERE token_hash=?", hashToken(parseBasicBearer(r))).Scan(&eid); e != nil {
		if e != sql.ErrNoRows {
			apiErr(w, 503, "database_unavailable", "could not validate edge")
			return
		}
		apiErr(w, 401, "unauthorized", "invalid edge token")
		return
	}
	if in.EdgeID != eid {
		apiErr(w, 403, "edge_mismatch", "edge id mismatch")
		return
	}
	if len(in.Usage) > 4096 || len(in.Statuses) > 4096 {
		apiErr(w, 400, "report_too_large", "report exceeds limits")
		return
	}
	var current sql.NullString
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT boot_id FROM edges WHERE id=? FOR UPDATE", eid).Scan(&current); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	var retired bool
	e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT retired FROM edge_boots WHERE edge_id=? AND boot_id=?", eid, in.BootID).Scan(&retired)
	if e != nil && e != sql.ErrNoRows {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if retired {
		apiErr(w, 409, "stale_boot", "edge boot was retired; restart with a new boot identity")
		return
	}
	if current.String != in.BootID {
		if _, e = s.store(r.Context()).ExecContext(r.Context(), "UPDATE edge_boots SET retired=1 WHERE edge_id=?", eid); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if current.Valid && current.String != "" {
			if _, e = s.store(r.Context()).ExecContext(r.Context(), "INSERT IGNORE INTO edge_boots(edge_id,boot_id,retired,created_at) VALUES(?,?,1,?)", eid, current.String, now()); e != nil {
				apiErr(w, 503, "database_unavailable", e.Error())
				return
			}
		}
		if _, e = s.store(r.Context()).ExecContext(r.Context(), "INSERT INTO edge_boots(edge_id,boot_id,created_at) VALUES(?,?,?)", eid, in.BootID, now()); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
	}
	if e = s.reapResources(r.Context()); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if e := s.recordUsage(r, in.Usage, eid, in.BootID); e != nil {
		apiErr(w, 400, "invalid_usage", e.Error())
		return
	}
	if e := s.recordACLReport(r.Context(), eid, in.BootID, in.ACL); e != nil {
		if errors.Is(e, errACLReport) {
			apiErr(w, 400, "invalid_acl_report", "ACL report exceeds bounds or contains invalid identities, counters or timestamps")
		} else {
			apiErr(w, 503, "database_unavailable", "could not persist ACL report")
		}
		return
	}
	var runtimeJSON any
	if in.Runtime != nil {
		if len(in.Runtime.Endpoints) > 16 || len(in.Runtime.Sites) > 2 || in.Runtime.ActiveFlows < 0 || in.Runtime.ActiveCarriers < 0 || in.Runtime.QUICCarriers < 0 || in.Runtime.TLSCarriers < 0 || in.Runtime.UDPMappings < 0 {
			apiErr(w, 400, "invalid_runtime", "invalid edge runtime counters")
			return
		}
		for _, ep := range append(append([]model.EndpointRuntime(nil), in.Runtime.Endpoints...), in.Runtime.Sites...) {
			if len(ep.Bindings) > 8 {
				apiErr(w, 400, "invalid_runtime", "too many listener bindings")
				return
			}
			for _, b := range ep.Bindings {
				addr, err := netip.ParseAddrPort(b.Address)
				if err != nil || addr.Port() == 0 || addr.Addr().Is4In6() || addr.Addr().Zone() != "" || len(b.Error) > 2048 || (b.Network != "tcp4" && b.Network != "tcp6" && b.Network != "udp4" && b.Network != "udp6") || strings.HasSuffix(b.Network, "4") != addr.Addr().Is4() {
					apiErr(w, 400, "invalid_runtime", "invalid listener binding")
					return
				}
			}
		}
		runtimeJSON = encodeJSON(in.Runtime)
	}
	if _, e := s.store(r.Context()).ExecContext(r.Context(), "UPDATE edges SET boot_id=?,last_seen=?,applied_revision=?,runtime=? WHERE id=?", in.BootID, now(), in.AppliedRevision, runtimeJSON, eid); e != nil {
		apiErr(w, 503, "database_unavailable", "could not update edge")
		return
	}
	for _, st := range in.Statuses {
		switch st.Status {
		case "ready", "listening", "waiting_for_agent", "error", "disabled", "deleted", "quota_exhausted":
		default:
			continue
		}
		if st.Status == "deleted" {
			tx, e := s.beginTx(r.Context(), nil)
			if e != nil {
				continue
			}
			res, e := tx.ExecContext(r.Context(), "DELETE FROM rules WHERE id=? AND edge_id=? AND version=? AND deleting=1", st.ID, eid, st.Version)
			if e == nil {
				n, _ := res.RowsAffected()
				if n > 0 {
					_, e = tx.ExecContext(r.Context(), "DELETE FROM resource_claims WHERE rule_id=? AND edge_id=?", st.ID, eid)
				}
			}
			if e != nil {
				tx.Rollback()
			} else {
				_ = tx.Commit()
			}
			continue
		}
		_, _ = s.store(r.Context()).ExecContext(r.Context(), "UPDATE rules SET status=?,last_error=?,applied_version=? WHERE id=? AND edge_id=? AND version=? AND deleting=0", st.Status, st.Error, st.Version, st.ID, eid, st.Version)
	}
	edges, e := s.loadEdges(r.Context(), eid)
	if e != nil || len(edges) != 1 {
		apiErr(w, 503, "database_unavailable", "could not read edge")
		return
	}
	edge := edges[0]
	rules, e := s.rulesForEdge(r, eid)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	mandatory, e := s.effectiveACLs(r.Context(), rules)
	if e != nil {
		apiErr(w, 503, "invalid_policy", e.Error())
		return
	}
	devs, e := s.devicesForRules(r, rules)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	grants, e := s.grantsForEdge(r, eid, in.BootID, devs)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	certs, e := s.certificatesForRules(r.Context(), rules)
	if e != nil {
		apiErr(w, 503, "certificate_unavailable", e.Error())
		return
	}
	writeJSON(w, 200, model.EdgeSnapshot{Revision: s.revision(r), ExpiresAt: now().Add(s.cfg.SnapshotTTL), Edge: edge, Devices: devs, Rules: rules, Grants: grants, Certificates: certs, MandatoryACLs: mandatory})
}
func (s *Server) loadEdges(ctx context.Context, eid string) ([]model.Edge, error) {
	// Runtime and browser mutation transactions always read MySQL directly;
	// only a read-only presentation view can be served from disposable cache.
	if _, transaction := ctx.Value(mutationKey{}).(*mutation); transaction || s.tmp == nil {
		return s.queryEdges(ctx, eid)
	}
	b, e := s.tmp.GetOrLoad(ctx, "edges/"+eid, 3*time.Second, func(ctx context.Context) ([]byte, error) {
		items, e := s.queryEdges(ctx, eid)
		if e != nil {
			return nil, e
		}
		return json.Marshal(items)
	})
	if e != nil {
		return nil, e
	}
	var items []model.Edge
	if e = json.Unmarshal(b, &items); e != nil {
		return s.queryEdges(ctx, eid)
	}
	return items, nil
}
func (s *Server) queryEdges(ctx context.Context, eid string) ([]model.Edge, error) {
	q := "SELECT id,name,endpoints,ca_cert,public_host,listen_host,http_port,https_port,port_min,port_max,max_carriers,capacity_bps,boot_id,last_seen,applied_revision,runtime FROM edges"
	args := []any{}
	if eid != "" {
		q += " WHERE id=?"
		args = append(args, eid)
	}
	rows, e := s.store(ctx).QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Edge{}
	for rows.Next() {
		var x model.Edge
		var ep, ca, ph, lh, boot, runtimeJSON sql.NullString
		var last sql.NullTime
		if e = rows.Scan(&x.ID, &x.Name, &ep, &ca, &ph, &lh, &x.HTTPPort, &x.HTTPSPort, &x.PortMin, &x.PortMax, &x.MaxCarriers, &x.CapacityBPS, &boot, &last, &x.AppliedRevision, &runtimeJSON); e != nil {
			return nil, e
		}
		decodeJSON(ep.String, &x.Endpoints)
		x.CACert = ca.String
		x.PublicHost = ph.String
		x.ListenHost = lh.String
		x.BootID = boot.String
		if runtimeJSON.Valid {
			decodeJSON(runtimeJSON.String, &x.Runtime)
		}
		if last.Valid {
			x.LastSeen = last.Time
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Server) rulesForEdge(r *http.Request, eid string) ([]model.Rule, error) {
	rules, err := s.queryRules(r.Context(), " WHERE edge_id=?", eid)
	if err != nil {
		return nil, err
	}
	return s.restrictPlanRules(r.Context(), rules)
}
func (s *Server) devicesForRules(r *http.Request, rules []model.Rule) ([]model.DeviceGrant, error) {
	seen := map[string]bool{}
	out := []model.DeviceGrant{}
	for _, x := range rules {
		if !x.Enabled || x.Deleting || seen[x.DeviceID] {
			continue
		}
		seen[x.DeviceID] = true
		var d model.DeviceGrant
		var sid sql.NullString
		var capabilities string
		var exp sql.NullTime
		e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT id,tenant_id,public_key,session_id,generation,lease_until,capabilities FROM devices WHERE id=? AND tenant_id=? AND revoked=0", x.DeviceID, x.TenantID).Scan(&d.DeviceID, &d.TenantID, &d.PublicKey, &sid, &d.Generation, &exp, &capabilities)
		if e == sql.ErrNoRows {
			continue
		}
		if e != nil {
			return nil, e
		}
		if !exp.Valid || !now().Before(exp.Time) || sid.String == "" {
			continue
		}
		d.SessionID = sid.String
		decodeJSON(capabilities, &d.Capabilities)
		d.ExpiresAt = exp.Time
		out = append(out, d)
	}
	return out, nil
}
func (s *Server) clientSync(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	var in model.ClientSyncRequest
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if in.Timestamp < time.Now().Unix()-60 || in.Timestamp > time.Now().Unix()+60 {
		apiErr(w, 401, "clock_skew", "timestamp outside 60 seconds")
		return
	}
	if len(in.SessionID) < 16 || len(in.SessionID) > 96 || len(in.Nonce) < 16 || len(in.Nonce) > 64 || len(in.Capabilities) > 32 {
		apiErr(w, 400, "invalid_session", "session_id and nonce are required")
		return
	}
	tx, e := s.beginTx(r.Context(), nil)
	if e != nil {
		apiErr(w, 503, "database_unavailable", "could not begin session")
		return
	}
	defer tx.Rollback()
	var d model.DeviceGrant
	var revoked bool
	var session sql.NullString
	var exp sql.NullTime
	e = tx.QueryRowContext(r.Context(), "SELECT id,tenant_id,public_key,session_id,generation,lease_until,revoked FROM devices WHERE id=? FOR UPDATE", in.DeviceID).Scan(&d.DeviceID, &d.TenantID, &d.PublicKey, &session, &d.Generation, &exp, &revoked)
	if e != nil && e != sql.ErrNoRows {
		apiErr(w, 503, "database_unavailable", "could not validate device")
		return
	}
	if e != nil || revoked {
		apiErr(w, 401, "device_revoked", "device unavailable")
		return
	}
	pk, pe := verifyPub(d.PublicKey)
	sig, se := base64.StdEncoding.DecodeString(in.Signature)
	if pe != nil || se != nil || !ed25519.Verify(pk, model.ClientSyncPayload(in), sig) {
		apiErr(w, 401, "bad_signature", "invalid signature")
		return
	}
	if !validDeviceRuntime(in.Runtime, now()) {
		apiErr(w, 400, "invalid_runtime", "invalid or excessive device runtime observations")
		return
	}
	if session.String != in.SessionID {
		if exp.Valid && now().Before(exp.Time) {
			apiErr(w, 409, "identity_conflict", "another process has an active device session; bind a separate device or wait for its lease to expire")
			return
		}
		d.Generation++
	}
	if _, e = tx.ExecContext(r.Context(), "INSERT INTO runtime_nonces(device_id,nonce,expires_at) VALUES(?,?,?)", in.DeviceID, in.Nonce, now().Add(2*time.Minute)); e != nil {
		apiErr(w, 409, "replayed_request", "request nonce already used")
		return
	}
	d.SessionID = in.SessionID
	d.Capabilities = append([]string(nil), in.Capabilities...)
	d.ExpiresAt = now().Add(s.cfg.SnapshotTTL)
	var runtimeJSON any
	if in.Runtime != nil {
		if e = scopeDeviceRuntime(r.Context(), tx, d.DeviceID, in.Runtime); e != nil {
			apiErr(w, 503, "database_unavailable", "could not scope device observations")
			return
		}
		in.Runtime.SessionID, in.Runtime.Generation, in.Runtime.ReceivedAt = d.SessionID, d.Generation, now()
		runtimeJSON = encodeJSON(in.Runtime)
	}
	if _, e = tx.ExecContext(r.Context(), "UPDATE devices SET session_id=?,generation=?,lease_until=?,last_seen=?,capabilities=?,applied_revision=?,runtime=? WHERE id=?", d.SessionID, d.Generation, d.ExpiresAt, now(), encodeJSON(in.Capabilities), in.AppliedRevision, runtimeJSON, d.DeviceID); e != nil {
		apiErr(w, 503, "database_unavailable", "session update failed")
		return
	}
	if e = tx.Commit(); e != nil {
		apiErr(w, 503, "database_unavailable", "session commit failed")
		return
	}
	_, _ = s.store(r.Context()).ExecContext(r.Context(), "DELETE FROM runtime_nonces WHERE expires_at<? LIMIT 1000", now())
	rules, e := s.rulesForDevice(r, in.DeviceID)
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	// Resolve templates here as well, but never send other devices' rules or keys.
	if _, e = s.effectiveACLs(r.Context(), rules); e != nil {
		apiErr(w, 503, "invalid_policy", e.Error())
		return
	}
	used := map[string]bool{}
	for _, x := range rules {
		if x.Enabled && !x.Deleting {
			used[x.EdgeID] = true
		}
	}
	all, e := s.loadEdges(r.Context(), "")
	if e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	edges := []model.Edge{}
	for _, x := range all {
		if used[x.ID] {
			edges = append(edges, x)
		}
	}
	writeJSON(w, 200, model.ClientSnapshot{Revision: s.revision(r), ExpiresAt: d.ExpiresAt, Device: d, Edges: edges, Rules: rules})
}

func validDeviceRuntime(runtime *model.DeviceRuntime, at time.Time) bool {
	if runtime == nil {
		return true
	}
	if len(runtime.Platform) > 32 || strings.ContainsAny(runtime.Platform, "\x00\r\n") {
		return false
	}
	switch runtime.NetworkMode {
	case "", "socket": // Empty fields remain valid for older clients.
	case "tun", "transparent":
		if runtime.Platform != "linux" {
			return false
		}
	default:
		return false
	}
	if runtime.SessionID != "" || runtime.Generation != 0 || !runtime.ReceivedAt.IsZero() ||
		runtime.ReportedAt.Before(at.Add(-2*time.Minute)) || runtime.ReportedAt.After(at.Add(time.Minute)) ||
		len(runtime.Carriers) > model.MaxDeviceRuntimeEntries || len(runtime.Endpoints) > model.MaxDeviceRuntimeEntries ||
		runtime.ActiveFlows < 0 || runtime.ActiveFlows > 1_000_000 || runtime.ActiveCarriers < 0 || runtime.ActiveCarriers > 100_000 ||
		runtime.QUICCarriers < 0 || runtime.TLSCarriers < 0 || runtime.QUICCarriers+runtime.TLSCarriers != runtime.ActiveCarriers {
		return false
	}
	if runtime.PreferredTransport != "auto" && runtime.PreferredTransport != "quic_only" && runtime.PreferredTransport != "tls_only" {
		return false
	}
	validEndpoint := func(edgeID, transport, address, serverName string) bool {
		return edgeID != "" && len(edgeID) <= 64 && (transport == "quic" || transport == "tls") && len(address) > 0 && len(address) <= 512 && len(serverName) > 0 && len(serverName) <= 253
	}
	validHandshake := func(ms float64) bool { return !math.IsNaN(ms) && !math.IsInf(ms, 0) && ms >= 0 && ms <= 60_000 }
	validPast := func(value time.Time) bool { return value.IsZero() || !value.After(at.Add(time.Minute)) }
	flows, quic, tls := 0, 0, 0
	for _, c := range runtime.Carriers {
		if !validEndpoint(c.EdgeID, c.Transport, c.Address, c.ServerName) || !validRemoteAddress(c.Address, c.RemoteAddress) || !validHandshake(c.HandshakeMS) || c.ActiveFlows < 0 || c.ActiveFlows > 1_000_000 || c.EstablishedAt.IsZero() || !validPast(c.EstablishedAt) || !validCarrierQuality(c, runtime.ReportedAt) {
			return false
		}
		flows += c.ActiveFlows
		if c.Transport == "quic" {
			quic++
		} else {
			tls++
		}
	}
	if runtime.Truncated {
		if runtime.ActiveCarriers < len(runtime.Carriers) || runtime.ActiveFlows < flows || runtime.QUICCarriers < quic || runtime.TLSCarriers < tls {
			return false
		}
	} else if runtime.ActiveCarriers != len(runtime.Carriers) || runtime.ActiveFlows != flows || runtime.QUICCarriers != quic || runtime.TLSCarriers != tls {
		return false
	}
	if len(runtime.Carriers) > 0 && (runtime.SnapshotExpiresAt.IsZero() || runtime.SnapshotExpiresAt.Before(runtime.ReportedAt)) {
		return false
	}
	seen := make(map[string]bool, len(runtime.Endpoints))
	for _, ep := range runtime.Endpoints {
		key := deviceEndpointKey(ep.EdgeID, ep.Transport, ep.Address, ep.ServerName) + "\x00" + ep.RemoteAddress
		if !validEndpoint(ep.EdgeID, ep.Transport, ep.Address, ep.ServerName) || !validRemoteAddress(ep.Address, ep.RemoteAddress) || !validHandshake(ep.HandshakeMS) || ep.RecentFailures > 32 || !validPast(ep.LastAttempt) || !validPast(ep.LastSuccess) || ep.RetryAt.After(at.Add(2*time.Minute)) || seen[key] {
			return false
		}
		seen[key] = true
		switch ep.ErrorCode {
		case "", "authorization_rejected", "tls_identity_failed", "race_not_selected", "path_timeout", "connection_failed", "carrier_closed":
		default:
			return false
		}
	}
	return true
}

// RemoteAddress is an observation of a configured authority, not a new grant.
// Older reports may omit it; new reports must use a unicast IP and the same port.
func validRemoteAddress(configured, remote string) bool {
	if remote == "" {
		return true
	}
	_, port, err := net.SplitHostPort(configured)
	p, pe := strconv.Atoi(port)
	addr, ae := netip.ParseAddrPort(remote)
	return err == nil && pe == nil && ae == nil && addr.Port() != 0 && int(addr.Port()) == p && !addr.Addr().IsUnspecified() && !addr.Addr().IsMulticast() && !addr.Addr().Is4In6() && addr.Addr().Zone() == ""
}

func deviceEndpointKey(edgeID, transport, address, serverName string) string {
	return edgeID + "\x00" + transport + "\x00" + address + "\x00" + serverName
}

// A rule can disappear while the signed report is in flight. Remove obsolete
// observations without blocking the Agent from obtaining its next snapshot.
// Claims about another device's edge/endpoint are never displayed as this
// device's connection, and this report cannot create any grant or resource.
func scopeDeviceRuntime(ctx context.Context, tx sqlStore, deviceID string, runtime *model.DeviceRuntime) error {
	if len(runtime.Carriers) == 0 && len(runtime.Endpoints) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT e.id,e.endpoints FROM edges e JOIN rules r ON r.edge_id=e.id WHERE r.device_id=? AND r.enabled=1 AND r.deleting=0", deviceID)
	if err != nil {
		return err
	}
	allowed := make(map[string]bool)
	for rows.Next() {
		var edgeID, raw string
		if err = rows.Scan(&edgeID, &raw); err != nil {
			break
		}
		var endpoints []model.Endpoint
		if err = json.Unmarshal([]byte(raw), &endpoints); err != nil {
			break
		}
		for _, ep := range endpoints {
			allowed[deviceEndpointKey(edgeID, ep.Transport, ep.Address, ep.ServerName)] = true
		}
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	carriers := make([]model.DeviceCarrierRuntime, 0, len(runtime.Carriers))
	removed := false
	for _, carrier := range runtime.Carriers {
		if allowed[deviceEndpointKey(carrier.EdgeID, carrier.Transport, carrier.Address, carrier.ServerName)] {
			carriers = append(carriers, carrier)
		} else {
			removed = true
		}
	}
	if removed {
		runtime.ActiveFlows, runtime.ActiveCarriers, runtime.QUICCarriers, runtime.TLSCarriers = 0, len(carriers), 0, 0
		for _, c := range carriers {
			runtime.ActiveFlows += c.ActiveFlows
			if c.Transport == "quic" {
				runtime.QUICCarriers++
			} else {
				runtime.TLSCarriers++
			}
		}
		runtime.Truncated = true
	}
	runtime.Carriers = carriers
	endpoints := make([]model.DeviceEndpointRuntime, 0, len(runtime.Endpoints))
	for _, ep := range runtime.Endpoints {
		if allowed[deviceEndpointKey(ep.EdgeID, ep.Transport, ep.Address, ep.ServerName)] {
			endpoints = append(endpoints, ep)
		} else {
			runtime.Truncated = true
		}
	}
	runtime.Endpoints = endpoints
	return nil
}
func (s *Server) rulesForDevice(r *http.Request, did string) ([]model.Rule, error) {
	rules, err := s.queryRules(r.Context(), " WHERE device_id=? AND deleting=0", did)
	if err != nil {
		return nil, err
	}
	return s.restrictPlanRules(r.Context(), rules)
}

// Grants are serialized by the durable tenant quota row. Expired, unreported
// reservations are conservatively spent; they never become free credit.
func (s *Server) grantsForEdge(r *http.Request, eid, boot string, devs []model.DeviceGrant) ([]model.Grant, error) {
	tenants := map[string]bool{}
	for _, d := range devs {
		tenants[d.TenantID] = true
	}
	keys := []string{}
	for k := range tenants {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []model.Grant{}
	for _, tid := range keys {
		g, e := s.allocateGrant(r.Context(), tid, eid, boot)
		if e != nil {
			return nil, e
		}
		if g.ID != "" {
			out = append(out, g)
		}
	}
	return out, nil
}
func (s *Server) allocateGrant(ctx context.Context, tid, eid, boot string) (model.Grant, error) {
	tx, e := s.beginTx(ctx, nil)
	if e != nil {
		return model.Grant{}, e
	}
	defer tx.Rollback()
	q, e := s.currentQuota(ctx, tx, tid)
	if e != nil {
		return model.Grant{}, e
	}
	if !edgeAllowed(q, eid) {
		return model.Grant{}, nil
	}
	waitForCredit := q.PeriodBytes < 0 || q.OverageAction == "throttle" && q.OverageBPS > 0
	overage := q.PeriodBytes >= 0 && waitForCredit && q.UsedBytes >= q.PeriodBytes
	base, peak, burst := q.BaseBPS, q.PeakBPS, q.BurstBytes
	if overage {
		base, peak, burst = q.OverageBPS, q.OverageBPS, 0
	} else if q.PeriodBytes >= 0 && q.UsedBytes >= q.PeriodBytes {
		base, peak, burst = 0, 0, 0
	}
	rows, e := tx.QueryContext(ctx, "SELECT id,tenant_id,COALESCE(edge_id,''),boot_id,expires_at,bytes,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,policy_version,period_id,used FROM grants_table WHERE tenant_id=? AND closed=0", tid)
	if e != nil {
		return model.Grant{}, e
	}
	live := []model.Grant{}
	used := map[string]int64{}
	for rows.Next() {
		var g model.Grant
		var n int64
		if e = rows.Scan(&g.ID, &g.TenantID, &g.EdgeID, &g.BootID, &g.ExpiresAt, &g.Bytes, &g.BaseBPS, &g.PeakBPS, &g.BurstBytes, &g.MaxConnections, &g.NewFlowsPerSecond, &g.PolicyVersion, &g.PeriodID, &n); e != nil {
			rows.Close()
			return model.Grant{}, e
		}
		live = append(live, g)
		used[g.ID] = n
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return model.Grant{}, e
	}
	edgeRows, e := tx.QueryContext(ctx, "SELECT DISTINCT edge_id FROM rules WHERE tenant_id=? AND enabled=1 AND deleting=0 ORDER BY edge_id", tid)
	if e != nil {
		return model.Grant{}, e
	}
	edgeIDs := []string{}
	for edgeRows.Next() {
		var edgeID string
		if e = edgeRows.Scan(&edgeID); e != nil {
			edgeRows.Close()
			return model.Grant{}, e
		}
		if edgeAllowed(q, edgeID) {
			edgeIDs = append(edgeIDs, edgeID)
		}
	}
	e = edgeRows.Err()
	edgeRows.Close()
	if e != nil {
		return model.Grant{}, e
	}
	if len(edgeIDs) == 0 {
		edgeIDs = []string{eid}
	}
	desired := func(total int64) int64 {
		if total < 0 {
			return -1
		}
		for i, edgeID := range edgeIDs {
			if edgeID == eid {
				n := total / int64(len(edgeIDs))
				if int64(i) < total%int64(len(edgeIDs)) {
					n++
				}
				return n
			}
		}
		return 0
	}
	share := func(total int64, except string, rate bool, which func(model.Grant) int64) int64 {
		if total < 0 {
			return -1
		}
		left := total
		for _, other := range live {
			if other.ID == except {
				continue
			}
			// A fully consumed lease cannot transmit. At the traffic boundary it
			// must not reserve its old high rate against the new reduced rate.
			if rate && other.Bytes <= used[other.ID] {
				continue
			}
			v := which(other)
			if v < 0 {
				return 0
			}
			left -= v
		}
		return max(0, min(left, desired(total)))
	}
	for _, g := range live {
		if g.EdgeID == eid && g.BootID == boot {
			if g.PeriodID != q.PeriodID {
				return model.Grant{}, errors.New("unexpired grant crosses accounting period")
			}
			// Existing credit remains cumulative. Limits are updated in place so an
			// online edge tightens immediately without resetting buckets or active
			// permits. Other live leases (including unlimited old policies) remain
			// reserved until they are updated, settled or expire.
			g.BaseBPS = share(base, g.ID, true, func(g model.Grant) int64 { return g.BaseBPS })
			g.PeakBPS = share(peak, g.ID, true, func(g model.Grant) int64 { return g.PeakBPS })
			g.BurstBytes = share(burst, g.ID, true, func(g model.Grant) int64 { return g.BurstBytes })
			g.MaxConnections = int(share(int64(q.MaxConnections), g.ID, false, func(g model.Grant) int64 { return int64(g.MaxConnections) }))
			g.NewFlowsPerSecond = int(share(int64(q.NewFlowsPerSecond), g.ID, false, func(g model.Grant) int64 { return int64(g.NewFlowsPerSecond) }))
			g.WaitForCredit = waitForCredit
			g.PolicyVersion = q.Version
			extra := int64(0)
			if g.Bytes-used[g.ID] < 16<<20 {
				extra = 64 << 20
				if q.PeriodBytes >= 0 && !overage {
					extra = min(extra, max(0, q.PeriodBytes-q.UsedBytes-q.ReservedBytes))
				}
			}
			g.Bytes += extra
			if q.PeriodBytes < 0 || overage || q.UsedBytes+q.ReservedBytes <= q.PeriodBytes {
				g.ExpiresAt = grantExpiry(q, s.cfg.SnapshotTTL)
			}
			if _, e = tx.ExecContext(ctx, "UPDATE grants_table SET bytes=?,reserved=reserved+?,expires_at=?,base_bps=?,peak_bps=?,burst_bytes=?,max_connections=?,new_flows_per_second=?,policy_version=? WHERE id=?", g.Bytes, extra, g.ExpiresAt, g.BaseBPS, g.PeakBPS, g.BurstBytes, g.MaxConnections, g.NewFlowsPerSecond, g.PolicyVersion, g.ID); e != nil {
				return model.Grant{}, e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE quotas SET reserved_bytes=reserved_bytes+? WHERE tenant_id=?", extra, tid); e != nil {
				return model.Grant{}, e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE quota_periods SET reserved_bytes=reserved_bytes+? WHERE tenant_id=? AND period_id=?", extra, tid, g.PeriodID); e != nil {
				return model.Grant{}, e
			}
			if e = tx.Commit(); e != nil {
				return model.Grant{}, e
			}
			return g, nil
		}
	}
	// Divide the policy across all configured edges. Existing unexpired leases,
	// including a previous boot, retain their shares until settlement or expiry.
	bytes := int64(64 << 20)
	if q.PeriodBytes >= 0 && !overage {
		bytes = min(bytes, max(0, q.PeriodBytes-q.UsedBytes-q.ReservedBytes))
	}
	g := model.Grant{ID: id(), TenantID: tid, EdgeID: eid, BootID: boot, ExpiresAt: grantExpiry(q, s.cfg.SnapshotTTL), Bytes: bytes, PolicyVersion: q.Version, PeriodID: q.PeriodID, WaitForCredit: waitForCredit,
		BaseBPS: share(base, "", true, func(g model.Grant) int64 { return g.BaseBPS }), PeakBPS: share(peak, "", true, func(g model.Grant) int64 { return g.PeakBPS }), BurstBytes: share(burst, "", true, func(g model.Grant) int64 { return g.BurstBytes }), MaxConnections: int(share(int64(q.MaxConnections), "", false, func(g model.Grant) int64 { return int64(g.MaxConnections) })), NewFlowsPerSecond: int(share(int64(q.NewFlowsPerSecond), "", false, func(g model.Grant) int64 { return int64(g.NewFlowsPerSecond) }))}
	if _, e = tx.ExecContext(ctx, "INSERT INTO grants_table(id,tenant_id,edge_id,issued_edge_id,boot_id,expires_at,bytes,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,policy_version,period_id,reserved,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", g.ID, tid, eid, eid, boot, g.ExpiresAt, bytes, g.BaseBPS, g.PeakBPS, g.BurstBytes, g.MaxConnections, g.NewFlowsPerSecond, g.PolicyVersion, g.PeriodID, bytes, now()); e != nil {
		return model.Grant{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE quotas SET reserved_bytes=reserved_bytes+? WHERE tenant_id=?", bytes, tid); e != nil {
		return model.Grant{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE quota_periods SET reserved_bytes=reserved_bytes+? WHERE tenant_id=? AND period_id=?", bytes, tid, g.PeriodID); e != nil {
		return model.Grant{}, e
	}
	if e = tx.Commit(); e != nil {
		return model.Grant{}, e
	}
	return g, nil
}
func (s *Server) recordUsage(r *http.Request, reports []model.Usage, eid, boot string) error {
	for _, u := range reports {
		if u.UploadBytes < 0 || u.DownloadBytes < 0 || u.Sequence == 0 || u.UploadBytes > 1<<60 || u.DownloadBytes > 1<<60 {
			return errors.New("invalid usage values")
		}
		if e := s.settleUsage(r.Context(), u, eid, boot); e != nil {
			return e
		}
	}
	return nil
}
func (s *Server) settleUsage(ctx context.Context, u model.Usage, eid, boot string) error {
	// Read identity first, then lock quota before grant, matching allocation order.
	var tid string
	if e := s.store(ctx).QueryRowContext(ctx, "SELECT tenant_id FROM grants_table WHERE id=? AND edge_id=? AND boot_id=?", u.GrantID, eid, boot).Scan(&tid); e != nil {
		return errors.New("grant does not belong to this edge boot")
	}
	tx, e := s.beginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var dummy string
	if e = tx.QueryRowContext(ctx, "SELECT tenant_id FROM quotas WHERE tenant_id=? FOR UPDATE", tid).Scan(&dummy); e != nil {
		return e
	}
	var credit, spent int64
	var period string
	var stopped bool
	if e = tx.QueryRowContext(ctx, "SELECT bytes,used,closed,period_id FROM grants_table WHERE id=? FOR UPDATE", u.GrantID).Scan(&credit, &spent, &stopped, &period); e != nil {
		return e
	}
	var seq uint64
	var up, down int64
	var wasClosed bool
	e = tx.QueryRowContext(ctx, "SELECT sequence_no,upload_bytes,download_bytes,closed FROM usage_table WHERE grant_id=?", u.GrantID).Scan(&seq, &up, &down, &wasClosed)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if u.Sequence <= seq {
		if u.Sequence == seq && (u.UploadBytes != up || u.DownloadBytes != down || u.Closed != wasClosed) {
			return errors.New("usage sequence was reused with different values")
		}
		return nil
	}
	if u.UploadBytes < up || u.DownloadBytes < down || u.UploadBytes+u.DownloadBytes > credit {
		return errors.New("usage is nonmonotonic or exceeds credit")
	}
	if wasClosed && !u.Closed {
		return errors.New("closed grant cannot reopen")
	}
	if wasClosed && (u.UploadBytes != up || u.DownloadBytes != down) {
		return errors.New("closed grant totals cannot change")
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO usage_table(grant_id,sequence_no,upload_bytes,download_bytes,closed,observed_at) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE sequence_no=VALUES(sequence_no),upload_bytes=VALUES(upload_bytes),download_bytes=VALUES(download_bytes),closed=VALUES(closed),observed_at=VALUES(observed_at)", u.GrantID, u.Sequence, u.UploadBytes, u.DownloadBytes, u.Closed, now()); e != nil {
		return e
	}
	if e = recordTraffic(ctx, tx, u, u.UploadBytes-up, u.DownloadBytes-down, now()); e != nil {
		return e
	}
	if !stopped {
		total := u.UploadBytes + u.DownloadBytes
		delta := total - spent
		if delta < 0 {
			return errors.New("usage decreased")
		}
		release := delta
		if u.Closed {
			release = credit - spent
		}
		if _, e = tx.ExecContext(ctx, "UPDATE quotas SET used_bytes=used_bytes+?,reserved_bytes=GREATEST(0,reserved_bytes-?) WHERE tenant_id=? AND period_id=?", delta, release, tid, period); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE quota_periods SET used_bytes=used_bytes+?,reserved_bytes=GREATEST(0,reserved_bytes-?) WHERE tenant_id=? AND period_id=?", delta, release, tid, period); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE grants_table SET used=?,closed=? WHERE id=?", total, u.Closed, u.GrantID); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Server) effectiveACLs(ctx context.Context, rules []model.Rule) ([]model.ACLPolicy, error) {
	rows, e := s.store(ctx).QueryContext(ctx, "SELECT id,published,mandatory FROM acl_templates ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	pub := map[string]model.ACLPolicy{}
	mandatory := []model.ACLPolicy{}
	for rows.Next() {
		var id string
		var raw sql.NullString
		var force bool
		if e = rows.Scan(&id, &raw, &force); e != nil {
			return nil, e
		}
		if !raw.Valid {
			if force {
				return nil, fmt.Errorf("mandatory template %s has no published policy", id)
			}
			continue
		}
		var p model.ACLPolicy
		decodeJSON(raw.String, &p)
		p.TemplateID = id
		pub[id] = p
		if force {
			mandatory = append(mandatory, p)
		}
	}
	for i := range rules {
		if rules[i].Protocol != "tcp" && rules[i].Protocol != "udp" {
			continue
		}
		if id := rules[i].ACLTemplateID; id != "" {
			p, ok := pub[id]
			if !ok {
				return nil, fmt.Errorf("template %s has no published policy", id)
			}
			rules[i].ACL = &p
		} else if rules[i].ACL != nil {
			// Inline rules cannot claim an administrator template identity.
			copy := *rules[i].ACL
			copy.TemplateID = ""
			rules[i].ACL = &copy
		}
	}
	return mandatory, rows.Err()
}
func (s *Server) certificatesForRules(ctx context.Context, rules []model.Rule) ([]model.Certificate, error) {
	out := []model.Certificate{}
	seen := map[string]bool{}
	for _, r := range rules {
		if r.CertificateID == "" || !r.Enabled || r.Deleting || seen[r.CertificateID] {
			continue
		}
		seen[r.CertificateID] = true
		var c model.Certificate
		var domains, enc string
		if e := s.store(ctx).QueryRowContext(ctx, "SELECT id,tenant_id,name,domains,cert_pem,key_enc,expires_at FROM certificates WHERE id=? AND tenant_id=?", r.CertificateID, r.TenantID).Scan(&c.ID, &c.TenantID, &c.Name, &domains, &c.CertPEM, &enc, &c.ExpiresAt); e != nil {
			return nil, e
		}
		decodeJSON(domains, &c.Domains)
		key, e := decrypt(s.key, enc)
		if e != nil {
			return nil, e
		}
		c.KeyPEM = key
		out = append(out, c)
	}
	return out, nil
}
