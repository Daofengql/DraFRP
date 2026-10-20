package cloud

import (
	"context"
	"database/sql"
	"drafrp/internal/model"
	"time"
)

const quotaColumns = "tenant_id,base_bps,peak_bps,burst_bytes,max_connections,new_flows_per_second,period_bytes,used_bytes,reserved_bytes,version,period_id,period_seconds,period_started_at,period_ends_at,max_devices,max_rules,max_ports,max_domains"

func readQuota(ctx context.Context, db sqlStore, tid string, locked bool) (model.Quota, error) {
	q := model.Quota{}
	var start, end sql.NullTime
	suffix := ""
	if locked {
		suffix = " FOR UPDATE"
	}
	e := db.QueryRowContext(ctx, "SELECT "+quotaColumns+" FROM quotas WHERE tenant_id=?"+suffix, tid).Scan(&q.TenantID, &q.BaseBPS, &q.PeakBPS, &q.BurstBytes, &q.MaxConnections, &q.NewFlowsPerSecond, &q.PeriodBytes, &q.UsedBytes, &q.ReservedBytes, &q.Version, &q.PeriodID, &q.PeriodSeconds, &start, &end, &q.MaxDevices, &q.MaxRules, &q.MaxPorts, &q.MaxDomains)
	q.PeriodStartedAt = start.Time
	q.PeriodEndsAt = end.Time
	return q, e
}
func sqlTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// currentQuota holds the tenant lock before touching grants or period ledgers.
// Retiring a period conservatively charges outstanding credit to THAT period;
// no old report can subtract from, or spend, a new period's allocation.
func (s *Server) currentQuota(ctx context.Context, tx *businessTx, tid string) (model.Quota, error) {
	if _, e := tx.ExecContext(ctx, "INSERT IGNORE INTO quotas(tenant_id,updated_at) VALUES(?,?)", tid, now()); e != nil {
		return model.Quota{}, e
	}
	q, e := readQuota(ctx, tx, tid, true)
	if e != nil {
		return q, e
	}
	if q.PeriodStartedAt.IsZero() {
		q.PeriodStartedAt = now()
		if q.PeriodSeconds > 0 {
			q.PeriodEndsAt = q.PeriodStartedAt.Add(time.Duration(q.PeriodSeconds) * time.Second)
		}
		if _, e = tx.ExecContext(ctx, "UPDATE quotas SET period_started_at=?,period_ends_at=? WHERE tenant_id=?", q.PeriodStartedAt, sqlTime(q.PeriodEndsAt), tid); e != nil {
			return q, e
		}
	}
	if _, e = tx.ExecContext(ctx, "INSERT IGNORE INTO quota_periods(tenant_id,period_id,started_at,ends_at,used_bytes,reserved_bytes) VALUES(?,?,?,?,?,?)", tid, q.PeriodID, q.PeriodStartedAt, sqlTime(q.PeriodEndsAt), q.UsedBytes, q.ReservedBytes); e != nil {
		return q, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT period_id,COALESCE(SUM(reserved-used),0) FROM grants_table WHERE tenant_id=? AND closed=0 AND expires_at<=? GROUP BY period_id", tid, now())
	if e != nil {
		return q, e
	}
	lost := map[string]int64{}
	for rows.Next() {
		var period string
		var credit int64
		if e = rows.Scan(&period, &credit); e != nil {
			rows.Close()
			return q, e
		}
		lost[period] = credit
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return q, e
	}
	for period, credit := range lost {
		if _, e = tx.ExecContext(ctx, "UPDATE quota_periods SET used_bytes=used_bytes+?,reserved_bytes=GREATEST(0,reserved_bytes-?) WHERE tenant_id=? AND period_id=?", credit, credit, tid, period); e != nil {
			return q, e
		}
		if period == q.PeriodID {
			q.UsedBytes += credit
			q.ReservedBytes = max(0, q.ReservedBytes-credit)
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE grants_table SET closed=1 WHERE tenant_id=? AND closed=0 AND expires_at<=?", tid, now()); e != nil {
		return q, e
	}
	if q.PeriodSeconds > 0 && !now().Before(q.PeriodEndsAt) {
		step := time.Duration(q.PeriodSeconds) * time.Second
		n := now().Sub(q.PeriodEndsAt) / step
		q.PeriodStartedAt = q.PeriodEndsAt.Add(n * step)
		q.PeriodEndsAt = q.PeriodStartedAt.Add(step)
		q.PeriodID = id()
		q.UsedBytes = 0
		q.ReservedBytes = 0
		if _, e = tx.ExecContext(ctx, "INSERT INTO quota_periods(tenant_id,period_id,started_at,ends_at) VALUES(?,?,?,?)", tid, q.PeriodID, q.PeriodStartedAt, q.PeriodEndsAt); e != nil {
			return q, e
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE quotas SET period_id=?,period_started_at=?,period_ends_at=?,used_bytes=?,reserved_bytes=? WHERE tenant_id=?", q.PeriodID, q.PeriodStartedAt, sqlTime(q.PeriodEndsAt), q.UsedBytes, q.ReservedBytes, tid); e != nil {
		return q, e
	}
	return q, nil
}
func (s *Server) quotaSnapshot(ctx context.Context, tid string) (model.Quota, error) {
	tx, e := s.beginTx(ctx, nil)
	if e != nil {
		return model.Quota{}, e
	}
	defer tx.Rollback()
	q, e := s.currentQuota(ctx, tx, tid)
	if e != nil {
		return q, e
	}
	q.Resources, e = resourceUsage(ctx, tx, tid)
	if e != nil {
		return q, e
	}
	return q, tx.Commit()
}
func grantExpiry(q model.Quota, ttl time.Duration) time.Time {
	exp := now().Add(ttl)
	if !q.PeriodEndsAt.IsZero() && q.PeriodEndsAt.Before(exp) {
		exp = q.PeriodEndsAt
	}
	return exp
}
