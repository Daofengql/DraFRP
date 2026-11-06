package cloud

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"math"
	"strings"
	"testing"
	"time"

	"drafrp/internal/model"
)

func runtimeReport(at time.Time, edgeID string) *model.DeviceRuntime {
	return &model.DeviceRuntime{ReportedAt: at, SnapshotExpiresAt: at.Add(30 * time.Second), PreferredTransport: "auto", ActiveFlows: 2, ActiveCarriers: 1, TLSCarriers: 1,
		Carriers:  []model.DeviceCarrierRuntime{{EdgeID: edgeID, Transport: "tls", Address: "edge.example:8443", ServerName: "edge.example", ActiveFlows: 2, EstablishedAt: at.Add(-time.Second), HandshakeMS: 12.5}},
		Endpoints: []model.DeviceEndpointRuntime{{EdgeID: edgeID, Transport: "quic", Address: "edge.example:8443", ServerName: "edge.example", RecentFailures: 1, LastAttempt: at.Add(-time.Second), RetryAt: at.Add(2 * time.Second), ErrorCode: "path_timeout"}}}
}

func TestDualStackRemoteObservationsRemainDistinct(t *testing.T) {
	at := time.Now()
	r := runtimeReport(at, "edge")
	r.Endpoints[0].RemoteAddress = "192.0.2.1:8443"
	other := r.Endpoints[0]
	other.RemoteAddress = "[2001:db8::1]:8443"
	r.Endpoints = append(r.Endpoints, other)
	r.Carriers[0].RemoteAddress = other.RemoteAddress
	if !validDeviceRuntime(r, at) {
		t.Fatal("IPv4/IPv6 observations of the same authorized DNS endpoint were conflated")
	}
}

func TestDeviceRuntimeValidation(t *testing.T) {
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if !validDeviceRuntime(nil, at) || !validDeviceRuntime(runtimeReport(at, "edge"), at) {
		t.Fatal("valid/legacy reports rejected")
	}
	for _, tc := range []struct {
		name string
		edit func(*model.DeviceRuntime)
	}{
		{"server_session", func(x *model.DeviceRuntime) { x.SessionID = "spoofed" }},
		{"server_generation", func(x *model.DeviceRuntime) { x.Generation = 1 }},
		{"server_received_at", func(x *model.DeviceRuntime) { x.ReceivedAt = at }},
		{"stale_report", func(x *model.DeviceRuntime) { x.ReportedAt = at.Add(-2*time.Minute - time.Nanosecond) }},
		{"future_report", func(x *model.DeviceRuntime) { x.ReportedAt = at.Add(time.Minute + time.Nanosecond) }},
		{"invalid_preference", func(x *model.DeviceRuntime) { x.PreferredTransport = "fastest" }},
		{"oversized_platform", func(x *model.DeviceRuntime) { x.Platform = strings.Repeat("x", 33) }},
		{"invalid_network_mode", func(x *model.DeviceRuntime) { x.NetworkMode = "wintun" }},
		{"windows_tun", func(x *model.DeviceRuntime) { x.Platform = "windows"; x.NetworkMode = "tun" }},
		{"negative_counter", func(x *model.DeviceRuntime) { x.ActiveFlows = -1 }},
		{"excessive_counter", func(x *model.DeviceRuntime) { x.ActiveCarriers = 100001 }},
		{"inconsistent_transport_counter", func(x *model.DeviceRuntime) { x.QUICCarriers++ }},
		{"inconsistent_flow_counter", func(x *model.DeviceRuntime) { x.ActiveFlows++ }},
		{"invalid_carrier_transport", func(x *model.DeviceRuntime) { x.Carriers[0].Transport = "tcp" }},
		{"missing_server_name", func(x *model.DeviceRuntime) { x.Carriers[0].ServerName = "" }},
		{"oversized_address", func(x *model.DeviceRuntime) { x.Carriers[0].Address = strings.Repeat("x", 513) }},
		{"nan_handshake", func(x *model.DeviceRuntime) { x.Carriers[0].HandshakeMS = math.NaN() }},
		{"infinite_handshake", func(x *model.DeviceRuntime) { x.Endpoints[0].HandshakeMS = math.Inf(1) }},
		{"negative_handshake", func(x *model.DeviceRuntime) { x.Carriers[0].HandshakeMS = -1 }},
		{"excessive_handshake", func(x *model.DeviceRuntime) { x.Endpoints[0].HandshakeMS = 60001 }},
		{"future_establishment", func(x *model.DeviceRuntime) { x.Carriers[0].EstablishedAt = at.Add(time.Minute + time.Second) }},
		{"missing_establishment", func(x *model.DeviceRuntime) { x.Carriers[0].EstablishedAt = time.Time{} }},
		{"expired_snapshot", func(x *model.DeviceRuntime) { x.SnapshotExpiresAt = at.Add(-time.Second) }},
		{"excessive_failures", func(x *model.DeviceRuntime) { x.Endpoints[0].RecentFailures = 33 }},
		{"unclassified_error", func(x *model.DeviceRuntime) { x.Endpoints[0].ErrorCode = "secret-local-CA-path" }},
		{"future_attempt", func(x *model.DeviceRuntime) { x.Endpoints[0].LastAttempt = at.Add(time.Minute + time.Second) }},
		{"excessive_retry", func(x *model.DeviceRuntime) { x.Endpoints[0].RetryAt = at.Add(2*time.Minute + time.Second) }},
		{"duplicate_endpoint", func(x *model.DeviceRuntime) { x.Endpoints = append(x.Endpoints, x.Endpoints[0]) }},
		{"remote_port_not_granted", func(x *model.DeviceRuntime) { x.Endpoints[0].RemoteAddress = "[::1]:9999" }},
		{"remote_unspecified", func(x *model.DeviceRuntime) { x.Carriers[0].RemoteAddress = "[::]:8443" }},
		{"remote_not_ip", func(x *model.DeviceRuntime) { x.Carriers[0].RemoteAddress = "other.test:8443" }},
		{"excessive_carriers", func(x *model.DeviceRuntime) {
			for len(x.Carriers) <= model.MaxDeviceRuntimeEntries {
				x.Carriers = append(x.Carriers, x.Carriers[0])
			}
		}},
		{"excessive_endpoints", func(x *model.DeviceRuntime) {
			for len(x.Endpoints) <= model.MaxDeviceRuntimeEntries {
				x.Endpoints = append(x.Endpoints, x.Endpoints[0])
			}
		}},
		{"truncated_counters_below_sample", func(x *model.DeviceRuntime) { x.Truncated = true; x.ActiveFlows = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := runtimeReport(at, "edge")
			tc.edit(x)
			if validDeviceRuntime(x, at) {
				t.Fatal("invalid runtime accepted")
			}
		})
	}
	x := runtimeReport(at, "edge")
	x.Truncated = true
	x.ActiveCarriers, x.TLSCarriers, x.ActiveFlows = 2, 2, 3
	if !validDeviceRuntime(x, at) {
		t.Fatal("truncated report rejected aggregate counters beyond its sample")
	}
}

func TestMySQLDeviceRuntimeSignatureSessionScopeAndRevocation(t *testing.T) {
	f := newCloudFixture(t)
	owner, outsider := f.createUser("runtime-owner"), f.createUser("runtime-outsider")
	d, key := f.bind(owner, "runtime-device")
	edge := f.edge("device-runtime-edge")
	rule := f.createRule(owner, d, edge, 0)
	const session = "runtime-process-session-one"
	send := func(report *model.DeviceRuntime, sessionID string, mutateAfterSign func(*model.ClientSyncRequest), status int) model.ClientSnapshot {
		t.Helper()
		in := model.ClientSyncRequest{DeviceID: d.ID, SessionID: sessionID, Timestamp: time.Now().Unix(), Nonce: randomToken(24), Runtime: report}
		in.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, model.ClientSyncPayload(in)))
		if mutateAfterSign != nil {
			mutateAfterSign(&in)
		}
		w := f.request("POST", "/api/v1/runtime/client/sync", in, nil, nil)
		if status != 200 {
			if w.Code != status {
				t.Fatalf("sync status %d want %d: %s", w.Code, status, w.Body.String())
			}
			return model.ClientSnapshot{}
		}
		return decodeResponse[model.ClientSnapshot](t, w, 200)
	}
	listed := func() model.Device {
		t.Helper()
		x := decodeResponse[struct {
			Items []model.Device `json:"items"`
		}](t, f.request("GET", "/api/v1/devices", nil, owner, nil), 200)
		if len(x.Items) != 1 {
			t.Fatalf("device listing %+v", x)
		}
		return x.Items[0]
	}
	initial := qualityReport(now())
	initial.Carriers[0].EdgeID, initial.Endpoints[0].EdgeID = edge.ID, edge.ID
	snapshot := send(initial, session, nil, 200)
	got := listed()
	if got.Runtime == nil || got.Runtime.ActiveFlows != 2 || len(got.Runtime.Carriers) != 1 || len(got.Runtime.Endpoints) != 1 || got.Runtime.Generation != snapshot.Device.Generation || got.Runtime.SessionID != session || got.Runtime.ReceivedAt.IsZero() || got.Runtime.ReceivedAt.Before(got.Runtime.ReportedAt) {
		t.Fatal("signed observations or cloud-owned metadata did not survive persistence", got)
	}
	if q := got.Runtime.Carriers[0].Quality; q == nil || q.Source != "carrier_probe_v1" || q.Timeouts != 1 || q.LatestRTTMS != 20 {
		t.Fatal("signed probe quality did not survive MySQL persistence", q)
	}
	send(initial, session, func(in *model.ClientSyncRequest) { in.Runtime.Carriers[0].Quality.Timeouts++ }, 401)
	if w := f.request("GET", "/api/v1/devices", nil, outsider, nil); strings.Contains(w.Body.String(), d.ID) || strings.Contains(w.Body.String(), session) {
		t.Fatal("another tenant can read device telemetry", w.Body.String())
	}
	send(runtimeReport(now(), edge.ID), session, func(in *model.ClientSyncRequest) { in.Runtime.Carriers[0].HandshakeMS++ }, 401)
	bad := runtimeReport(now(), edge.ID)
	bad.SessionID = "client-cannot-assign"
	send(bad, session, nil, 400)
	send(runtimeReport(now(), edge.ID), "runtime-process-session-two", nil, 409)
	if after := listed(); after.Runtime == nil || after.Runtime.ReceivedAt != got.Runtime.ReceivedAt || after.Generation != got.Generation {
		t.Fatal("rejected request changed the accepted runtime/session", after)
	}
	// Endpoint claims must match a currently referenced edge and all TLS identity
	// fields; accepting a report never authorizes a new connection.
	foreign := f.edge("foreign-runtime-edge")
	foreignDevice, _ := f.bind(outsider, "outsider-device")
	f.createRule(outsider, foreignDevice, foreign, 0)
	report := runtimeReport(now(), edge.ID)
	report.Carriers = append(report.Carriers, report.Carriers[0])
	report.Carriers[1].EdgeID = foreign.ID
	report.ActiveCarriers, report.TLSCarriers, report.ActiveFlows = 2, 2, 4
	wrongSNI := report.Endpoints[0]
	wrongSNI.ServerName = "wrong.example"
	report.Endpoints = append(report.Endpoints, wrongSNI)
	send(report, session, nil, 200)
	if scoped := listed().Runtime; scoped == nil || !scoped.Truncated || len(scoped.Carriers) != 1 || len(scoped.Endpoints) != 1 || scoped.ActiveFlows != 2 || scoped.ActiveCarriers != 1 || scoped.Carriers[0].EdgeID != edge.ID {
		t.Fatal("unauthorized edge/identity survived report scoping", scoped)
	}
	// Deleting a rule while a report is in flight must let the Agent renew its
	// lease and receive the new authorization, while discarding old observations.
	decodeResponse[map[string]any](t, f.request("DELETE", "/api/v1/rules/"+rule.ID, nil, owner, nil), 200)
	send(runtimeReport(now(), edge.ID), session, nil, 200)
	if removed := listed().Runtime; removed == nil || !removed.Truncated || removed.ActiveCarriers != 0 || removed.ActiveFlows != 0 || len(removed.Endpoints) != 0 {
		t.Fatal("deleted rule still exposes an authorized path", removed)
	}
	// Expired sessions must stop displaying their runtime before any cleanup job.
	if _, err := f.s.db.Exec("UPDATE devices SET lease_until=? WHERE id=?", now().Add(-time.Second), d.ID); err != nil {
		t.Fatal(err)
	}
	if expired := listed(); expired.Runtime != nil {
		t.Fatal("expired session retained visible observations", expired)
	}
	newSession := f.syncClient(d, key, "runtime-process-session-two")
	if newSession.Device.Generation != snapshot.Device.Generation+1 || listed().Runtime != nil {
		t.Fatal("new legacy process retained prior process telemetry")
	}
	var stored sql.NullString
	if err := f.s.db.QueryRow("SELECT runtime FROM devices WHERE id=?", d.ID).Scan(&stored); err != nil || stored.Valid {
		t.Fatalf("legacy runtime did not clear old data: %+v %v", stored, err)
	}
	send(&model.DeviceRuntime{ReportedAt: now(), PreferredTransport: "auto"}, "runtime-process-session-two", nil, 200)
	if listed().Runtime == nil {
		t.Fatal("empty but fresh runtime report was discarded")
	}
	decodeResponse[map[string]any](t, f.request("DELETE", "/api/v1/devices/"+d.ID, nil, owner, nil), 200)
	if revoked := listed(); !revoked.Revoked || revoked.Runtime != nil {
		t.Fatal("revoked device retained visible runtime", revoked)
	}
	if err := f.s.db.QueryRow("SELECT runtime FROM devices WHERE id=?", d.ID).Scan(&stored); err != nil || stored.Valid {
		t.Fatalf("revoke did not erase persisted runtime: %+v %v", stored, err)
	}
	send(&model.DeviceRuntime{ReportedAt: now(), PreferredTransport: "auto"}, "runtime-process-session-two", nil, 401)
}
