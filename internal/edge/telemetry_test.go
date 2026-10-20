package edge

import (
	"context"
	"drafrp/internal/geoip"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTelemetryRequiresActualListenerAndDropsStoppedListener(t *testing.T) {
	r := New(Config{EdgeID: "edge"})
	t.Cleanup(r.Close)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ep := model.Endpoint{Transport: "tls", Address: l.Addr().String(), ServerName: "edge.test"}
	key := "carrier/tls/" + ep.Address
	r.mu.Lock()
	r.snap.Edge.Endpoints = []model.Endpoint{ep, {Transport: "quic", Address: "edge.test:9999", ServerName: "edge.test"}}
	r.snap.ExpiresAt = time.Now().Add(time.Minute)
	r.listenerErrors["carrier/quic/edge.test:9999"] = "address already in use"
	r.mu.Unlock()
	before := r.RuntimeStatus()
	if before.Endpoints[0].Listening || before.Endpoints[1].Listening {
		t.Fatal("configuration was mistaken for live listening")
	}
	if before.Endpoints[1].Error != "address already in use" {
		t.Fatal("missing listener error")
	}
	r.mu.Lock()
	r.listeners[key] = listenerState{closer: l, kind: "carrier", address: l.Addr().String()}
	r.mu.Unlock()
	if !r.RuntimeStatus().Endpoints[0].Listening {
		t.Fatal("real listener missing")
	}
	_ = l.Close()
	r.listenerStopped(key, l, errors.New("listener stopped"))
	after := r.RuntimeStatus()
	if after.Endpoints[0].Listening || after.Endpoints[0].Error != "listener stopped" {
		t.Fatal("closed listener remained ready")
	}
	if after.CapacityEnforcement != "payload" {
		t.Fatal("unverified wire shaping advertised")
	}
	if after.GeoIPState != "unconfigured" || after.GeoIPVersion != "" {
		t.Fatal("unconfigured GeoIP presented as available")
	}
	db, err := geoip.Parse([]byte(`{"version":"administrator-version","records":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.geoDB = db
	r.mu.Unlock()
	if status := r.RuntimeStatus(); status.GeoIPState != "ready" || status.GeoIPVersion != "administrator-version" {
		t.Fatalf("GeoIP version not observed: %+v", status)
	}
	r.mu.Lock()
	r.geoDB, r.geoError = nil, "invalid database"
	r.mu.Unlock()
	if status := r.RuntimeStatus(); status.GeoIPState != "error" || status.GeoIPVersion != "" || status.GeoIPError != "invalid database" {
		t.Fatalf("failed GeoIP load was hidden: %+v", status)
	}
}

func TestSyncReportsLiveCarrierFlowAndSnapshot(t *testing.T) {
	f := fixture(t, model.Rule{ID: "tcp-telemetry", Protocol: "tcp"})
	started := make(chan struct{})
	f.agent(t, func(stream protocol.Stream, _ protocol.Flow) {
		_ = protocol.WriteJSON(stream, protocol.Result{})
		close(started)
		<-f.ctx.Done()
	})
	c, err := net.Dial("tcp", f.address(0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("flow did not open")
	}
	samples := make(chan *model.EdgeRuntime, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var input model.EdgeSyncRequest
		if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
			t.Error(err)
			http.Error(w, "bad", 400)
			return
		}
		samples <- input.Runtime
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.s)
	}))
	defer server.Close()
	f.r.cfg.CloudURL, f.r.cfg.Token = server.URL, strings.Repeat("a", 32)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	sampled := <-samples
	if sampled == nil || sampled.ActiveCarriers != 1 || sampled.TLSCarriers != 1 || sampled.QUICCarriers != 0 || sampled.ActiveFlows != 1 {
		t.Fatalf("not live runtime counts: %+v", sampled)
	}
	if !sampled.SnapshotExpiresAt.Equal(f.s.ExpiresAt) || time.Since(sampled.ReportedAt) > 3*time.Second {
		t.Fatal("wrong observation or snapshot time")
	}
	_ = f.c.Close()
	eventually(t, func() bool { return f.r.RuntimeStatus().ActiveCarriers == 0 })
}
