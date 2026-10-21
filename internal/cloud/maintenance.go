package cloud

import (
	"context"
	"time"
)

func (s *Server) maintain(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			work, cancel := context.WithTimeout(ctx, 4*time.Second)
			// Only due periods are selected; accounting is serialized against live
			// reports by the same durable tenant lock used for grant allocation.
			rows, e := s.db.QueryContext(work, "SELECT tenant_id FROM quotas WHERE period_seconds>0 AND period_ends_at<=? LIMIT 256", now())
			if e == nil {
				ids := []string{}
				for rows.Next() {
					var id string
					if rows.Scan(&id) == nil {
						ids = append(ids, id)
					}
				}
				rows.Close()
				for _, id := range ids {
					if _, e = s.quotaSnapshot(work, id); e != nil {
						break
					}
				}
			}
			_, _ = s.db.ExecContext(work, "DELETE FROM runtime_nonces WHERE expires_at<? LIMIT 1000", now())
			_, _ = s.db.ExecContext(work, "DELETE FROM bindings WHERE expires_at<? LIMIT 1000", now().Add(-24*time.Hour))
			_, _ = s.db.ExecContext(work, "DELETE FROM sessions WHERE expires_at<? LIMIT 1000", now().Add(-24*time.Hour))
			_, _ = s.db.ExecContext(work, "DELETE FROM acl_observations WHERE received_at<? LIMIT 1000", now().Add(-7*24*time.Hour))
			_, _ = s.db.ExecContext(work, "DELETE FROM usage_history WHERE bucket_start<? LIMIT 1000", now().Truncate(time.Minute).Add(-trafficRetention))
			cancel()
		}
	}
}
