package systemtest

import (
	"bytes"
	"context"
	"drafrp/internal/client"
	"drafrp/internal/edge"
	"drafrp/internal/model"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPlanTrafficThrottleRejectAndCycle(t *testing.T) {
	s, browser := testCloudWithTTL(t, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	certFile, keyFile, certificate := certFiles(t)
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	carrier, business := freePort(t), freePort(t)
	for business == carrier {
		business = freePort(t)
	}
	token := strings.Repeat("plan-traffic-edge-", 3)
	var node model.Edge
	browser.api("POST", "/api/v1/edges", map[string]any{"name": "metered-exit", "token": token, "public_host": "127.0.0.1", "listen_host": "127.0.0.1", "endpoints": []model.Endpoint{{Transport: "tls", Address: address(carrier), ServerName: "edge.test"}}, "ca_cert": certificate, "http_port": 0, "https_port": 0, "port_min": business, "port_max": business, "max_carriers": 4, "capacity_bps": -1}, &node, 201)
	runtime := edge.New(edge.Config{CloudURL: browser.url, EdgeID: node.ID, Token: token, CertFile: certFile, KeyFile: keyFile, ListenHost: "127.0.0.1"})
	t.Cleanup(runtime.Close)
	agent, err := client.New(client.Config{CloudURL: browser.url, StateDir: t.TempDir(), Transport: "tls_only"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(agent.Close)
	binding, err := agent.Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	browser.api("POST", "/api/v1/bind/confirm", map[string]string{"user_code": binding.UserCode}, nil, 200)
	bound, err := agent.PollBind(ctx, binding.ID, binding.PollToken)
	if err != nil || bound.Status != "approved" {
		t.Fatal(bound, err)
	}
	var qs struct {
		Items []model.Quota `json:"items"`
	}
	browser.api("GET", "/api/v1/quotas", nil, &qs, 200)
	quota := qs.Items[0]
	var plan model.Plan
	browser.api("POST", "/api/v1/plans", model.Plan{Name: "metered", BandwidthBPS: 8000000, BurstEnabled: true, BurstBPS: 16000000, BurstSeconds: 1, TrafficMetered: true, TrafficBytes: 4096, PeriodSeconds: 60, OverageAction: "throttle", OverageBPS: 8192, MaxPorts: 1, EdgeIDs: []string{node.ID}}, &plan, 201)
	browser.api("PUT", "/api/v1/users/"+browser.user.ID+"/plan", map[string]any{"plan_id": plan.ID, "version": quota.Version}, &quota, 200)
	browser.api("POST", "/api/v1/rules", model.Rule{Name: "metered-tcp", DeviceID: bound.DeviceID, EdgeID: node.ID, Protocol: "tcp", Target: origin.Addr().String(), PublicPort: business, SourceMode: "socket", Transport: "tls_only", Enabled: true, TimeoutSeconds: 10}, nil, 201)
	if _, err = agent.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err = agent.ConnectEdge(ctx, node); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", address(business), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte{7}, 2048)
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, out); err != nil || !bytes.Equal(payload, out) {
		t.Fatal("included traffic failed", err)
	}
	// This same stream reaches the boundary and waits for authoritative renewal.
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var probe [1]byte
	if n, err := conn.Read(probe[:]); n != 0 || err == nil {
		t.Fatal("unacknowledged excess forwarded")
	}
	if runtime.FlowCount() != 1 {
		t.Fatal("included boundary closed active stream")
	}
	if err = runtime.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	grant := runtime.Snapshot().Grants[0]
	if grant.BaseBPS != 8192 || grant.PeakBPS != 8192 || grant.BurstBytes != 0 {
		t.Fatal("excess policy not applied", grant)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	started := time.Now()
	if _, err = io.ReadFull(conn, out); err != nil || !bytes.Equal(payload, out) {
		t.Fatal("active stream failed after excess renewal", err)
	}
	if elapsed := time.Since(started); elapsed < 1500*time.Millisecond {
		t.Fatal("excess traffic bypassed reduced rate", elapsed)
	}
	if err = runtime.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	browser.api("GET", "/api/v1/quotas", nil, &qs, 200)
	if qs.Items[0].UsedBytes != 8192 {
		t.Fatal("bidirectional excess missing from ledger", qs.Items[0])
	}
	plan.OverageAction = "reject"
	browser.api("PUT", "/api/v1/plans/"+plan.ID, plan, &plan, 200)
	if err = runtime.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = conn.Read(probe[:]); err == nil {
		t.Fatal("reject policy kept active stream")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("active stream did not close after reject policy")
	}
	denied, err := net.DialTimeout("tcp", address(business), time.Second)
	if err == nil {
		_ = denied.SetDeadline(time.Now().Add(time.Second))
		_, _ = denied.Write([]byte("blocked"))
		_, err = denied.Read(probe[:])
		_ = denied.Close()
		if err == nil {
			t.Fatal("new connection bypassed reject policy")
		}
	}
	// Advance the isolated database to a new cycle, honoring old lease expiry.
	boundary := time.Now().UTC().Add(-time.Second)
	if _, err = s.DB().Exec("UPDATE grants_table SET expires_at=? WHERE tenant_id=?", boundary, quota.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB().Exec("UPDATE quotas SET period_ends_at=? WHERE tenant_id=?", boundary, quota.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err = agent.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	grant = runtime.Snapshot().Grants[0]
	if grant.BaseBPS != plan.BandwidthBPS || grant.Bytes != plan.TrafficBytes || grant.PeriodID == quota.PeriodID {
		t.Fatal("cycle did not restore included policy", grant)
	}
	restored, err := net.DialTimeout("tcp", address(business), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	_ = restored.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = restored.Write([]byte("restored")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("restored"))
	if _, err = io.ReadFull(restored, echo); err != nil || string(echo) != "restored" {
		t.Fatal("new cycle failed to forward", err)
	}
	t.Log("real TLS client/exit: ongoing stream crossed traffic cap, reduced rate measured, rejection closed existing/new connections, cycle restored forwarding")
}
