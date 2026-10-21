package cloud

import (
	"context"
	"database/sql"
	"drafrp/internal/model"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

const planColumns = "p.id,name,bandwidth_bps,max_ports,max_sites,all_edges,COALESCE((SELECT JSON_ARRAYAGG(pe.edge_id) FROM plan_edges pe WHERE pe.plan_id=p.id),JSON_ARRAY()),version,legacy,burst_enabled,burst_bps,burst_seconds,traffic_metered,traffic_bytes,period_seconds,overage_action,overage_bps"

func readPlan(ctx context.Context, db sqlStore, pid string) (model.Plan, error) {
	return scanPlan(db.QueryRowContext(ctx, "SELECT "+planColumns+" FROM plans p WHERE p.id=?", pid))
}

func scanPlan(row interface{ Scan(...any) error }, extra ...any) (model.Plan, error) {
	var p model.Plan
	var edges string
	dest := []any{&p.ID, &p.Name, &p.BandwidthBPS, &p.MaxPorts, &p.MaxSites, &p.AllEdges, &edges, &p.Version, &p.Legacy, &p.BurstEnabled, &p.BurstBPS, &p.BurstSeconds, &p.TrafficMetered, &p.TrafficBytes, &p.PeriodSeconds, &p.OverageAction, &p.OverageBPS}
	err := row.Scan(append(dest, extra...)...)
	if err == nil {
		decodeJSON(edges, &p.EdgeIDs)
		slices.Sort(p.EdgeIDs)
	}
	return p, err
}

// Serialize package edits, default changes and assignments before tenant locks.
// Admissions/runtime need only the tenant lock and its effective policy copy.
func lockPlanSettings(ctx context.Context, db sqlStore) (string, error) {
	var pid string
	err := db.QueryRowContext(ctx, "SELECT COALESCE(default_plan_id,'') FROM plan_settings WHERE id=1 FOR UPDATE").Scan(&pid)
	return pid, err
}

func migratePlans(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = lockPlanSettings(ctx, tx); err != nil {
		return err
	}
	// NULL distinguishes untouched pre-package rows from explicitly unassigned
	// new accounts ([]). Preserve legacy rate/period settings without reapplying.
	_, err = tx.ExecContext(ctx, `INSERT IGNORE INTO plans(id,name,bandwidth_bps,max_ports,max_sites,all_edges,legacy,burst_enabled,burst_bps,burst_seconds,traffic_metered,traffic_bytes,period_seconds,overage_action,overage_bps,created_at,updated_at)
		SELECT SHA2(CONCAT('legacy-plan:',q.tenant_id),256),CONCAT('迁移套餐 · ',LEFT(t.name,64)),q.base_bps,q.max_ports,q.max_sites,1,1,q.base_bps>0 AND q.peak_bps>q.base_bps,q.peak_bps,IF(q.peak_bps>q.base_bps,GREATEST(1,CEIL(q.burst_bytes*8/(q.peak_bps-q.base_bps))),0),q.period_bytes>=0,GREATEST(0,q.period_bytes),q.period_seconds,q.overage_action,q.overage_bps,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
		FROM quotas q JOIN tenants t ON t.id=q.tenant_id WHERE COALESCE(q.plan_id,'')='' AND q.allowed_edge_ids IS NULL`)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE quotas SET plan_id=SHA2(CONCAT('legacy-plan:',tenant_id),256) WHERE COALESCE(plan_id,'')='' AND allowed_edge_ids IS NULL`); err != nil {
		return err
	}
	return tx.Commit()
}

func edgeAllowed(q model.Quota, eid string) bool {
	return q.AllowedEdgeIDs == nil || slices.Contains(q.AllowedEdgeIDs, eid)
}

func applyPlan(ctx context.Context, db sqlStore, tid string, p *model.Plan) error {
	pid, bandwidth, ports, sites := "", int64(0), 0, 0
	peak, burst, periodBytes, periodSeconds, overageBPS := int64(0), int64(0), int64(-1), int64(0), int64(0)
	action := "reject"
	var edges any = "[]"
	if p != nil {
		pid, bandwidth, ports, sites = p.ID, p.BandwidthBPS, p.MaxPorts, p.MaxSites
		peak = bandwidth
		if p.BurstEnabled {
			peak = p.BurstBPS
			burst = (peak - bandwidth) * p.BurstSeconds / 8
		}
		if p.TrafficMetered {
			periodBytes, periodSeconds, action, overageBPS = p.TrafficBytes, p.PeriodSeconds, p.OverageAction, p.OverageBPS
		}
		if p.AllEdges {
			edges = nil
		} else {
			edges = encodeJSON(p.EdgeIDs)
		}
	}
	q, err := readQuota(ctx, db, tid, true)
	if err != nil {
		return err
	}
	// Changing a package never resets metering or reissues spent credit. A new
	// schedule retains this period's balance and honors existing offline leases.
	if periodSeconds != q.PeriodSeconds || q.PeriodStartedAt.IsZero() {
		q.PeriodStartedAt, q.PeriodEndsAt = now(), time.Time{}
		if periodSeconds > 0 {
			q.PeriodEndsAt = q.PeriodStartedAt.Add(time.Duration(periodSeconds) * time.Second)
			var lease sql.NullTime
			if err = db.QueryRowContext(ctx, "SELECT MAX(expires_at) FROM grants_table WHERE tenant_id=? AND closed=0", tid).Scan(&lease); err != nil {
				return err
			}
			if lease.Valid && lease.Time.After(q.PeriodEndsAt) {
				q.PeriodEndsAt = lease.Time
			}
		}
	}
	_, err = db.ExecContext(ctx, "UPDATE quotas SET plan_id=NULLIF(?,''),allowed_edge_ids=?,base_bps=?,peak_bps=?,burst_bytes=?,max_ports=?,max_sites=?,max_devices=-1,max_rules=-1,max_domains=-1,max_connections=-1,new_flows_per_second=-1,period_bytes=?,period_seconds=?,period_started_at=?,period_ends_at=?,overage_action=?,overage_bps=?,version=version+1,updated_at=? WHERE tenant_id=?", pid, edges, bandwidth, peak, burst, ports, sites, periodBytes, periodSeconds, q.PeriodStartedAt, sqlTime(q.PeriodEndsAt), action, overageBPS, now(), tid)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "UPDATE quota_periods p JOIN quotas q ON q.tenant_id=p.tenant_id AND q.period_id=p.period_id SET p.ends_at=q.period_ends_at WHERE q.tenant_id=?", tid)
	return err
}

func initializeAccountPlan(ctx context.Context, db sqlStore, tid string, requested *string) error {
	pid, err := lockPlanSettings(ctx, db)
	if err != nil {
		return err
	}
	if requested != nil {
		pid = *requested
	}
	var p *model.Plan
	if pid != "" {
		value, e := readPlan(ctx, db, pid)
		if e != nil {
			return e
		}
		p = &value
	}
	if err = applyPlan(ctx, db, tid, p); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "UPDATE quotas SET version=1 WHERE tenant_id=?", tid)
	return err
}

func (s *Server) quotaForPlanUpdate(ctx context.Context, tid string) (model.Quota, error) {
	tx, err := s.beginTx(ctx, nil)
	if err != nil {
		return model.Quota{}, err
	}
	defer tx.Rollback()
	q, err := s.currentQuota(ctx, tx, tid)
	if err != nil {
		return q, err
	}
	return q, tx.Commit()
}

func validatePlan(ctx context.Context, db sqlStore, p *model.Plan) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 255 || p.BandwidthBPS < -1 || p.BandwidthBPS > 1<<50 || p.MaxPorts < -1 || p.MaxPorts > 1000000 || p.MaxSites < -1 || p.MaxSites > 1000000 || len(p.EdgeIDs) > 1024 {
		return errors.New("套餐名称必填；带宽和数量使用 -1 表示不限，0 表示不可用")
	}
	if p.BurstEnabled {
		if p.BandwidthBPS <= 0 || p.BurstBPS <= p.BandwidthBPS || p.BurstBPS > 1<<50 || p.BurstSeconds < 1 || p.BurstSeconds > 3600 {
			return errors.New("突发带宽须大于基础带宽，突发时长须为 1–3600 秒")
		}
	} else {
		p.BurstBPS, p.BurstSeconds = 0, 0
	}
	if p.OverageAction == "" {
		p.OverageAction = "reject"
	}
	if p.TrafficMetered {
		if p.TrafficBytes < 0 || p.TrafficBytes > 1<<60 || p.PeriodSeconds < 0 || p.PeriodSeconds > 366*86400 || p.PeriodSeconds > 0 && p.PeriodSeconds < 60 {
			return errors.New("流量额度须为非负字节数；周期为 0 或 60–31622400 秒")
		}
		if p.OverageAction != "reject" && p.OverageAction != "throttle" {
			return errors.New("超额策略须为拒绝连接或限速")
		}
		if p.OverageAction == "throttle" && (p.OverageBPS <= 0 || p.OverageBPS > 1<<50 || p.BandwidthBPS == 0 || p.BandwidthBPS > 0 && p.OverageBPS > p.BandwidthBPS) {
			return errors.New("超额速率须大于 0，且不超过基础带宽")
		}
	} else {
		p.TrafficBytes, p.PeriodSeconds, p.OverageAction = 0, 0, "reject"
	}
	if !p.TrafficMetered || p.OverageAction != "throttle" {
		p.OverageBPS = 0
	}
	if p.EdgeIDs == nil {
		p.EdgeIDs = []string{}
	}
	if p.AllEdges {
		p.EdgeIDs = []string{}
	}
	slices.Sort(p.EdgeIDs)
	p.EdgeIDs = slices.Compact(p.EdgeIDs)
	for _, eid := range p.EdgeIDs {
		var found string
		if err := db.QueryRowContext(ctx, "SELECT id FROM edges WHERE id=?", eid).Scan(&found); err != nil {
			return errors.New("出口节点不存在")
		}
	}
	return nil
}

func (s *Server) plans(w http.ResponseWriter, r *http.Request) {
	ctx, db := r.Context(), s.store(r.Context())
	if r.Method == "GET" {
		rows, err := db.QueryContext(ctx, "SELECT "+planColumns+",p.id=COALESCE(ps.default_plan_id,''),(SELECT COUNT(*) FROM quotas q WHERE q.plan_id=p.id) FROM plans p CROSS JOIN plan_settings ps WHERE ps.id=1 ORDER BY p.created_at,p.id")
		if err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
		out := []model.Plan{}
		for rows.Next() {
			var isDefault bool
			var members int
			p, scanErr := scanPlan(rows, &isDefault, &members)
			p.Default, p.Members = isDefault, members
			if err = scanErr; err != nil {
				break
			}
			out = append(out, p)
		}
		readErr := rows.Err()
		rows.Close()
		if err != nil || readErr != nil {
			apiErr(w, 503, "database_unavailable", "could not read plans")
			return
		}
		writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
		return
	}
	if !requireMethod(w, r, "POST") {
		return
	}
	var p model.Plan
	if err := readJSON(w, r, &p); err != nil {
		apiErr(w, 400, "invalid_json", err.Error())
		return
	}
	if _, err := lockPlanSettings(ctx, db); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	if err := validatePlan(ctx, db, &p); err != nil {
		apiErr(w, 400, "invalid_plan", err.Error())
		return
	}
	p.ID, p.Version, p.Legacy, p.Members = id(), 1, false, 0
	if _, err := db.ExecContext(ctx, "INSERT INTO plans(id,name,bandwidth_bps,max_ports,max_sites,all_edges,burst_enabled,burst_bps,burst_seconds,traffic_metered,traffic_bytes,period_seconds,overage_action,overage_bps,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", p.ID, p.Name, p.BandwidthBPS, p.MaxPorts, p.MaxSites, p.AllEdges, p.BurstEnabled, p.BurstBPS, p.BurstSeconds, p.TrafficMetered, p.TrafficBytes, p.PeriodSeconds, p.OverageAction, p.OverageBPS, now(), now()); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	if err := writePlanEdges(ctx, db, p.ID, p.EdgeIDs); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	if p.Default {
		if _, err := db.ExecContext(ctx, "UPDATE plan_settings SET default_plan_id=NULLIF(?,'') WHERE id=1", p.ID); err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
	}
	s.notify(ctx)
	writeJSON(w, 201, p)
}

func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" && r.Method != "DELETE" {
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	ctx, db := r.Context(), s.store(r.Context())
	def, err := lockPlanSettings(ctx, db)
	if err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	pid := strings.TrimPrefix(r.URL.Path, "/api/v1/plans/")
	old, err := readPlan(ctx, db, pid)
	if err != nil {
		apiErr(w, 404, "not_found", "套餐不存在")
		return
	}
	if r.Method == "DELETE" {
		var n int
		if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM quotas WHERE plan_id=?", pid).Scan(&n); err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
		if n > 0 || def == pid {
			apiErr(w, 409, "plan_in_use", "套餐已分配或设为默认")
			return
		}
		if _, err = db.ExecContext(ctx, "DELETE FROM plans p WHERE p.id=?", pid); err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
		s.notify(ctx)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var p model.Plan
	if err = readJSON(w, r, &p); err != nil {
		apiErr(w, 400, "invalid_json", err.Error())
		return
	}
	if p.Version != old.Version {
		apiErr(w, 409, "version_conflict", "套餐已变更")
		return
	}
	if err = validatePlan(ctx, db, &p); err != nil {
		apiErr(w, 400, "invalid_plan", err.Error())
		return
	}
	p.ID, p.Legacy, p.Version = pid, false, old.Version+1
	if _, err = db.ExecContext(ctx, "UPDATE plans SET name=?,bandwidth_bps=?,max_ports=?,max_sites=?,all_edges=?,burst_enabled=?,burst_bps=?,burst_seconds=?,traffic_metered=?,traffic_bytes=?,period_seconds=?,overage_action=?,overage_bps=?,legacy=0,version=version+1,updated_at=? WHERE id=?", p.Name, p.BandwidthBPS, p.MaxPorts, p.MaxSites, p.AllEdges, p.BurstEnabled, p.BurstBPS, p.BurstSeconds, p.TrafficMetered, p.TrafficBytes, p.PeriodSeconds, p.OverageAction, p.OverageBPS, now(), pid); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	if err = writePlanEdges(ctx, db, pid, p.EdgeIDs); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	if p.Default {
		def = pid
	} else if def == pid {
		def = ""
	}
	if _, err = db.ExecContext(ctx, "UPDATE plan_settings SET default_plan_id=NULLIF(?,'') WHERE id=1", def); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	rows, err := db.QueryContext(ctx, "SELECT tenant_id FROM quotas WHERE plan_id=? ORDER BY tenant_id FOR UPDATE", pid)
	if err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
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
	if err != nil || readErr != nil {
		apiErr(w, 503, "database_unavailable", "could not read assignments")
		return
	}
	for _, tid := range ids {
		// Settle an elapsed old cycle before changing its schedule or limits.
		if _, err = s.quotaForPlanUpdate(ctx, tid); err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
		if err = applyPlan(ctx, db, tid, &p); err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
	}
	p.Members = len(ids)
	s.notify(ctx)
	writeJSON(w, 200, p)
}

func (s *Server) assignUserPlan(w http.ResponseWriter, r *http.Request, uid string) {
	if !requireMethod(w, r, "PUT") {
		return
	}
	var in struct {
		PlanID  string `json:"plan_id"`
		Version uint64 `json:"version"`
	}
	if err := readJSON(w, r, &in); err != nil {
		apiErr(w, 400, "invalid_json", err.Error())
		return
	}
	ctx, db := r.Context(), s.store(r.Context())
	if _, err := lockPlanSettings(ctx, db); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	var tid string
	if err := db.QueryRowContext(ctx, "SELECT tenant_id FROM users WHERE id=?", uid).Scan(&tid); err != nil {
		apiErr(w, 404, "not_found", "用户不存在")
		return
	}
	var p *model.Plan
	if in.PlanID != "" {
		v, err := readPlan(ctx, db, in.PlanID)
		if err != nil {
			apiErr(w, 404, "not_found", "套餐不存在")
			return
		}
		p = &v
	}
	q, err := s.quotaForPlanUpdate(ctx, tid)
	if err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	if q.Version != in.Version {
		apiErr(w, 409, "version_conflict", "用户套餐已变更")
		return
	}
	if err = applyPlan(ctx, db, tid, p); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	actor := r.Context().Value(pkey{}).(*principal)
	s.audit(ctx, actor.User.ID, tid, "plan.assign", "user", uid)
	s.notify(ctx)
	q, err = readQuota(ctx, db, tid, false)
	if err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	writeJSON(w, 200, q)
}

// Runtime copies disable services outside the effective package. Configurations
// remain available for editing/deletion, and old offline authority expires with
// the existing bounded snapshot lease.
func (s *Server) restrictPlanRules(ctx context.Context, rules []model.Rule) ([]model.Rule, error) {
	policies := map[string]model.Quota{}
	tids := []string{}
	for _, rule := range rules {
		if _, ok := policies[rule.TenantID]; !ok {
			policies[rule.TenantID] = model.Quota{}
			tids = append(tids, rule.TenantID)
		}
	}
	slices.Sort(tids)
	_, locked := ctx.Value(mutationKey{}).(*mutation)
	for _, tid := range tids {
		q, err := readQuota(ctx, s.store(ctx), tid, locked)
		if err != nil {
			return nil, err
		}
		policies[tid] = q
	}
	for i := range rules {
		if !edgeAllowed(policies[rules[i].TenantID], rules[i].EdgeID) {
			rules[i].Enabled = false
			if !rules[i].Deleting {
				rules[i].Status = "plan_restricted"
			}
		}
	}
	return rules, nil
}
