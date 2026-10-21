package cloud

import (
	"context"
	"database/sql"
	"drafrp/internal/model"
	"errors"
	"net/http"
	"net/url"
	"time"
)

const trafficRetention = 30 * 24 * time.Hour
const maxTrafficPoints = 1440

func migrateTraffic(ctx context.Context, db *sql.DB) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS usage_history(grant_id VARCHAR(64) NOT NULL,bucket_start DATETIME(6) NOT NULL,source VARCHAR(8) NOT NULL,tenant_id VARCHAR(64) NOT NULL,edge_id VARCHAR(64) NOT NULL,upload_bytes BIGINT NOT NULL DEFAULT 0,download_bytes BIGINT NOT NULL DEFAULT 0,samples BIGINT NOT NULL DEFAULT 0,received_at DATETIME(6) NOT NULL,PRIMARY KEY(grant_id,bucket_start,source),INDEX tenant_time(tenant_id,bucket_start,edge_id),INDEX time_edge(bucket_start,edge_id),INDEX edge_time(edge_id,bucket_start)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS traffic_settings(id INT PRIMARY KEY,started_at DATETIME(6) NOT NULL) ENGINE=InnoDB`,
		`INSERT IGNORE INTO traffic_settings(id,started_at) VALUES(1,UTC_TIMESTAMP(6))`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// Called under the same tenant/grant locks as cumulative accounting. Absolute
// minute counters survive lost responses and retries without double counting.
func recordTraffic(ctx context.Context, tx sqlStore, u model.Usage, tid, eid string, up, down int64, at time.Time) error {
	if len(u.Minutes) > model.MaxTrafficMinutes {
		return errors.New("too many traffic minutes")
	}
	cutoff := at.Truncate(time.Minute).Add(-trafficRetention)
	var first, last time.Time
	seen := make(map[time.Time]bool, len(u.Minutes))
	for _, m := range u.Minutes {
		start := m.Start.UTC()
		if start.IsZero() || !start.Equal(start.Truncate(time.Minute)) || start.After(at.Truncate(time.Minute)) || m.UploadBytes < 0 || m.DownloadBytes < 0 || m.UploadBytes > u.UploadBytes || m.DownloadBytes > u.DownloadBytes || seen[start] {
			return errors.New("invalid traffic minute")
		}
		seen[start] = true
		if first.IsZero() || start.Before(first) {
			first = start
		}
		if start.After(last) {
			last = start
		}
	}
	stored := map[time.Time]model.TrafficMinute{}
	if len(u.Minutes) > 0 {
		rows, err := tx.QueryContext(ctx, "SELECT bucket_start,upload_bytes,download_bytes FROM usage_history WHERE grant_id=? AND source='edge' AND bucket_start>=? AND bucket_start<=?", u.GrantID, first, last)
		if err != nil {
			return err
		}
		for rows.Next() {
			var m model.TrafficMinute
			if err = rows.Scan(&m.Start, &m.UploadBytes, &m.DownloadBytes); err != nil {
				rows.Close()
				return err
			}
			stored[m.Start.UTC()] = m
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	for _, m := range u.Minutes {
		m.Start = m.Start.UTC()
		if m.Start.Before(cutoff) {
			continue
		}
		prev := stored[m.Start]
		deltaUp, deltaDown := m.UploadBytes-prev.UploadBytes, m.DownloadBytes-prev.DownloadBytes
		if deltaUp < 0 || deltaDown < 0 || deltaUp > up || deltaDown > down {
			return errors.New("traffic minutes disagree with cumulative usage")
		}
		up, down = up-deltaUp, down-deltaDown
		if _, err := tx.ExecContext(ctx, `INSERT INTO usage_history(grant_id,bucket_start,source,tenant_id,edge_id,upload_bytes,download_bytes,samples,received_at) VALUES(?,?,'edge',?,?,?,?,1,?) ON DUPLICATE KEY UPDATE upload_bytes=VALUES(upload_bytes),download_bytes=VALUES(download_bytes),samples=samples+1,received_at=VALUES(received_at)`, u.GrantID, m.Start, tid, eid, m.UploadBytes, m.DownloadBytes, at); err != nil {
			return err
		}
	}
	// Old edges send cumulative usage only. Preserve those deltas too, but label
	// receipt-time data so it cannot be mistaken for original minute samples.
	if up > 0 || down > 0 || len(u.Minutes) == 0 {
		_, err := tx.ExecContext(ctx, `INSERT INTO usage_history(grant_id,bucket_start,source,tenant_id,edge_id,upload_bytes,download_bytes,samples,received_at) VALUES(?,?,'receipt',?,?,?,?,1,?) ON DUPLICATE KEY UPDATE upload_bytes=upload_bytes+VALUES(upload_bytes),download_bytes=download_bytes+VALUES(download_bytes),samples=samples+1,received_at=VALUES(received_at)`, u.GrantID, at.Truncate(time.Minute), tid, eid, up, down, at)
		return err
	}
	return nil
}

func statisticsScope(w http.ResponseWriter, r *http.Request) (string, bool) {
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "tenant"
	}
	if scope != "tenant" && scope != "platform" {
		apiErr(w, 400, "invalid_scope", "统计范围无效")
		return "", false
	}
	if scope == "platform" && !isAdmin(r) {
		apiErr(w, 403, "forbidden", "仅管理员可查看全平台统计")
		return "", false
	}
	return scope, true
}

type trafficRange struct {
	start, end time.Time
	interval   time.Duration
	edgeID     string
}

func ceilMinute(at time.Time) time.Time {
	return at.Add(time.Minute - time.Nanosecond).UTC().Truncate(time.Minute)
}

func parseTrafficRange(q url.Values, at time.Time) (trafficRange, error) {
	bad := errors.New("请选择最近 30 天内的有效时间范围；最小粒度 1 分钟，最多 1440 个数据点")
	for key, values := range q {
		if len(values) != 1 || (key != "start" && key != "end" && key != "interval" && key != "scope" && key != "edge_id") {
			return trafficRange{}, bad
		}
	}
	out := trafficRange{end: ceilMinute(at), edgeID: q.Get("edge_id")}
	out.start = out.end.Add(-24 * time.Hour)
	if q.Has("start") || q.Has("end") {
		start, err := time.Parse(time.RFC3339, q.Get("start"))
		if err != nil {
			return out, bad
		}
		end, err := time.Parse(time.RFC3339, q.Get("end"))
		if err != nil || !end.After(start) {
			return out, bad
		}
		out.start, out.end = start.UTC().Truncate(time.Minute), ceilMinute(end)
	}
	if len(out.edgeID) > 64 || !out.end.After(out.start) || out.start.Before(ceilMinute(at).Add(-trafficRetention)) || out.end.After(ceilMinute(at)) {
		return out, bad
	}
	duration := out.end.Sub(out.start)
	switch q.Get("interval") {
	case "", "auto":
		switch {
		case duration <= 6*time.Hour:
			out.interval = time.Minute
		case duration <= 2*24*time.Hour:
			out.interval = 5 * time.Minute
		case duration <= 14*24*time.Hour:
			out.interval = time.Hour
		default:
			out.interval = 24 * time.Hour
		}
	case "1m":
		out.interval = time.Minute
	case "5m":
		out.interval = 5 * time.Minute
	case "1h":
		out.interval = time.Hour
	case "1d":
		out.interval = 24 * time.Hour
	default:
		return out, bad
	}
	if (duration+out.interval-1)/out.interval > maxTrafficPoints {
		return out, bad
	}
	return out, nil
}

func (s *Server) usageHistory(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	scope, ok := statisticsScope(w, r)
	if !ok {
		return
	}
	at := now()
	window, err := parseTrafficRange(r.URL.Query(), at)
	if err != nil {
		apiErr(w, 400, "invalid_time_range", err.Error())
		return
	}
	out := model.TrafficHistory{Scope: scope, EdgeID: window.edgeID, Start: window.start, End: window.end, IntervalSeconds: int64(window.interval / time.Second), ObservedAt: at, Points: []model.TrafficPoint{}}
	if err = s.store(r.Context()).QueryRowContext(r.Context(), "SELECT started_at FROM traffic_settings WHERE id=1").Scan(&out.AvailableFrom); err != nil {
		apiErr(w, 503, "database_unavailable", "无法读取流量记录起点")
		return
	}
	out.AvailableFrom = out.AvailableFrom.Truncate(time.Minute)
	if cutoff := at.Truncate(time.Minute).Add(-trafficRetention); out.AvailableFrom.Before(cutoff) {
		out.AvailableFrom = cutoff
	}
	filter := "bucket_start>=? AND bucket_start<?"
	args := []any{window.start, out.IntervalSeconds, window.start, window.end}
	if scope == "tenant" {
		filter += " AND tenant_id=?"
		args = append(args, tenant(r))
	}
	if window.edgeID != "" {
		filter += " AND edge_id=?"
		args = append(args, window.edgeID)
	}
	rows, err := s.store(r.Context()).QueryContext(r.Context(), "SELECT TIMESTAMPDIFF(SECOND,?,bucket_start) DIV ? AS bucket_no,SUM(upload_bytes),SUM(download_bytes),SUM(samples),SUM(CASE WHEN source='receipt' THEN upload_bytes+download_bytes ELSE 0 END) FROM usage_history WHERE "+filter+" GROUP BY bucket_no ORDER BY bucket_no", args...)
	if err != nil {
		apiErr(w, 503, "database_unavailable", "无法读取流量历史")
		return
	}
	defer rows.Close()
	for start := window.start; start.Before(window.end); start = start.Add(window.interval) {
		out.Points = append(out.Points, model.TrafficPoint{Start: start, End: minTrafficTime(start.Add(window.interval), window.end)})
	}
	for rows.Next() {
		var index int
		var p model.TrafficPoint
		if err = rows.Scan(&index, &p.UploadBytes, &p.DownloadBytes, &p.Samples, &p.ReceiptBytes); err != nil {
			apiErr(w, 503, "database_unavailable", "无法读取流量历史")
			return
		}
		if index < 0 || index >= len(out.Points) {
			continue
		}
		p.Start, p.End = out.Points[index].Start, out.Points[index].End
		seconds := minTrafficTime(p.End, at).Sub(p.Start).Seconds()
		if seconds > 0 {
			p.UploadBPS, p.DownloadBPS = float64(p.UploadBytes)*8/seconds, float64(p.DownloadBytes)*8/seconds
		}
		out.Points[index] = p
		out.UploadBytes += p.UploadBytes
		out.DownloadBytes += p.DownloadBytes
		out.ReceiptBytes += p.ReceiptBytes
	}
	if err = rows.Err(); err != nil {
		apiErr(w, 503, "database_unavailable", "无法读取流量历史")
		return
	}
	writeJSON(w, 200, out)
}

func minTrafficTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
