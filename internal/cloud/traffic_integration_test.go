package cloud

import (
	"drafrp/internal/model"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func TestMySQLTrafficHistoryIsMinuteScopedAndIdempotent(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("traffic-history-user")
	d, key := f.bind(b, "traffic-history-client")
	e := f.edge("traffic-history-edge")
	f.createRule(b, d, e, 20001)
	f.syncClient(d, key, "traffic-history-session")
	snapshot := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(e, "traffic-history-boot", nil, nil), 200)
	if len(snapshot.Grants) != 1 {
		t.Fatal("expected one grant")
	}
	start := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	report := model.Usage{GrantID: snapshot.Grants[0].ID, Sequence: 1, UploadBytes: 100, DownloadBytes: 200, Minutes: []model.TrafficMinute{{Start: start, UploadBytes: 100, DownloadBytes: 200}}}
	if w := f.syncEdge(e, "traffic-history-boot", nil, []model.Usage{report}); w.Code != 200 {
		t.Fatalf("minute report failed: %d %s", w.Code, w.Body.String())
	}
	// Replaying the exact cumulative sequence must not add another minute.
	if w := f.syncEdge(e, "traffic-history-boot", nil, []model.Usage{report}); w.Code != 200 {
		t.Fatalf("replayed report failed: %d %s", w.Code, w.Body.String())
	}
	query := url.Values{"start": {start.Format(time.RFC3339)}, "end": {start.Add(time.Minute).Format(time.RFC3339)}, "interval": {"1m"}}
	history := decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?"+query.Encode(), nil, b, nil), 200)
	if history.UploadBytes != 100 || history.DownloadBytes != 200 || len(history.Points) != 1 || history.Points[0].UploadBytes != 100 || history.Points[0].DownloadBytes != 200 {
		t.Fatalf("unexpected persisted history: %+v", history)
	}
	if history.Points[0].UploadBPS != float64(100)*8/60 || history.Points[0].DownloadBPS != float64(200)*8/60 || history.Points[0].Samples != 1 {
		t.Fatal("bandwidth conversion or replay sample count is wrong", history.Points)
	}
	adminHistory := decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?scope=platform&"+query.Encode(), nil, f.admin, nil), 200)
	if adminHistory.Scope != "platform" || adminHistory.UploadBytes != 100 {
		t.Fatalf("platform history did not include tenant report: %+v", adminHistory)
	}
	// Admins default to their own space; users cannot select platform or another
	// space, including by guessing an otherwise valid edge identifier.
	adminOwn := decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?"+query.Encode(), nil, f.admin, nil), 200)
	if adminOwn.UploadBytes != 0 || adminOwn.Points[0].Samples != 0 {
		t.Fatal("tenant history leaked into administrator's own space", adminOwn)
	}
	other := f.createUser("traffic-history-other")
	otherHistory := decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?edge_id="+e.ID+"&"+query.Encode(), nil, other, nil), 200)
	if otherHistory.UploadBytes != 0 || otherHistory.DownloadBytes != 0 || otherHistory.Points[0].Samples != 0 {
		t.Fatal("guessed edge leaked tenant history", otherHistory)
	}
	for _, path := range []string{"/api/v1/usage-history?scope=platform", "/api/v1/usage-summary?scope=platform"} {
		if w := f.request("GET", path, nil, b, nil); w.Code != 403 {
			t.Fatal("user could read platform statistics", path, w.Code)
		}
	}
	if w := f.request("GET", "/api/v1/usage-history", nil, nil, nil); w.Code != 401 {
		t.Fatal("unauthenticated history was allowed", w.Code)
	}
	if w := f.request("GET", "/api/v1/usage-history?tenant_id="+b.user.TenantID, nil, other, nil); w.Code != 400 {
		t.Fatal("tenant override was accepted", w.Code)
	}
	query.Set("edge_id", "unknown-edge")
	empty := decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?"+query.Encode(), nil, b, nil), 200)
	if empty.UploadBytes != 0 || empty.Points[0].Samples != 0 {
		t.Fatal("edge filter was ignored", empty)
	}
	query.Del("edge_id")
	// New absolute counters add only their increment, including a second minute.
	report.Sequence++
	report.UploadBytes, report.DownloadBytes = 180, 250
	report.Minutes = []model.TrafficMinute{{Start: start, UploadBytes: 120, DownloadBytes: 200}, {Start: start.Add(time.Minute), UploadBytes: 60, DownloadBytes: 50}}
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(e, "traffic-history-boot", nil, []model.Usage{report}), 200)
	query.Set("end", start.Add(2*time.Minute).Format(time.RFC3339))
	history = decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?"+query.Encode(), nil, b, nil), 200)
	if history.UploadBytes != 180 || history.DownloadBytes != 250 || history.ReceiptBytes != 0 || len(history.Points) != 2 || history.Points[1].UploadBytes != 60 {
		t.Fatal("minute increments were lost or double counted", history)
	}
	query.Set("interval", "5m")
	aggregated := decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?"+query.Encode(), nil, b, nil), 200)
	if aggregated.UploadBytes != 180 || len(aggregated.Points) != 1 || aggregated.Points[0].UploadBPS != float64(180)*8/120 {
		t.Fatal("partial aggregate used the wrong denominator", aggregated)
	}
	// An invalid telemetry report rolls back cumulative accounting too.
	bad := report
	bad.Sequence++
	bad.UploadBytes++
	bad.Minutes = []model.TrafficMinute{{Start: start, UploadBytes: 0}}
	if w := f.syncEdge(e, "traffic-history-boot", nil, []model.Usage{bad}); w.Code != 400 {
		t.Fatal("decreasing minute counters accepted", w.Code)
	}
	var total int64
	if err := f.s.db.QueryRow("SELECT upload_bytes FROM usage_table WHERE grant_id=?", report.GrantID).Scan(&total); err != nil || total != 180 {
		t.Fatal("invalid report left partial accounting", total, err)
	}
	// Old nodes (or a full memory window) use receipt-time deltas, visibly labelled.
	report.Sequence++
	report.UploadBytes += 5
	report.Minutes = nil
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(e, "traffic-history-boot", nil, []model.Usage{report}), 200)
	query.Set("end", ceilMinute(time.Now().UTC()).Format(time.RFC3339))
	fallback := decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?"+query.Encode(), nil, b, nil), 200)
	if fallback.UploadBytes != 185 || fallback.ReceiptBytes != 5 {
		t.Fatal("receipt-time fallback was lost or unlabelled", fallback)
	}
	if err := migrateTraffic(t.Context(), f.s.db); err != nil {
		t.Fatal("repeat migration failed", err)
	}
	after := decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?"+query.Encode(), nil, b, nil), 200)
	if !reflect.DeepEqual(fallback.AvailableFrom, after.AvailableFrom) || after.UploadBytes != 185 {
		t.Fatal("migration reset the recording start or history", after)
	}
}

func TestMySQLTrafficHistoryNodeFilterKeepsTenantAndPlatformTotalsSeparate(t *testing.T) {
	f := newCloudFixture(t)
	owner, other := f.createUser("traffic-filter-owner"), f.createUser("traffic-filter-other")
	d, key := f.bind(owner, "traffic-filter-client")
	d2, key2 := f.bind(other, "traffic-filter-other-client")
	e1, e2 := f.edge("traffic-filter-first"), f.edge("traffic-filter-second")
	f.createRule(owner, d, e1, 20001)
	f.createRule(owner, d, e2, 20001)
	f.createRule(other, d2, e1, 20002)
	f.syncClient(d, key, "traffic-filter-session")
	f.syncClient(d2, key2, "traffic-filter-other-session")
	start := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	for _, edge := range []model.Edge{e1, e2} {
		snapshot := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "traffic-filter-boot", nil, nil), 200)
		var reports []model.Usage
		for _, grant := range snapshot.Grants {
			up, down := int64(120), int64(180)
			if edge.ID == e2.ID {
				up, down = 240, 60
			}
			if grant.TenantID == other.user.TenantID {
				up, down = 600, 300
			}
			reports = append(reports, model.Usage{GrantID: grant.ID, Sequence: 1, UploadBytes: up, DownloadBytes: down, Minutes: []model.TrafficMinute{{Start: start, UploadBytes: up, DownloadBytes: down}}})
		}
		decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "traffic-filter-boot", nil, reports), 200)
	}
	for _, tc := range []struct {
		name, scope, edge string
		viewer            *browser
		up, down          int64
	}{
		{"own all nodes", "tenant", "", owner, 360, 240},
		{"own first node", "tenant", e1.ID, owner, 120, 180},
		{"own second node", "tenant", e2.ID, owner, 240, 60},
		{"other cannot see second node", "tenant", e2.ID, other, 0, 0},
		{"platform all nodes", "platform", "", f.admin, 960, 540},
		{"platform first node", "platform", e1.ID, f.admin, 720, 480},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := url.Values{"scope": {tc.scope}, "start": {start.Format(time.RFC3339)}, "end": {start.Add(time.Minute).Format(time.RFC3339)}, "interval": {"1m"}}
			if tc.edge != "" {
				query.Set("edge_id", tc.edge)
			}
			h := decodeResponse[model.TrafficHistory](t, f.request("GET", "/api/v1/usage-history?"+query.Encode(), nil, tc.viewer, nil), 200)
			if h.UploadBytes != tc.up || h.DownloadBytes != tc.down || len(h.Points) != 1 || h.Points[0].UploadBPS != float64(tc.up)*8/60 || h.Points[0].DownloadBPS != float64(tc.down)*8/60 {
				t.Fatalf("node filter mixed scope or bandwidth: %+v", h)
			}
		})
	}
}
