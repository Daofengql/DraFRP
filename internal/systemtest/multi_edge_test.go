package systemtest

import (
	"bytes"
	"context"
	"drafrp/internal/client"
	"drafrp/internal/edge"
	"drafrp/internal/model"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Both edge processes obtain durable grants for the same tenant, then forward
// through separately bound real agents. This catches policies accidentally
// copied in full to each edge, beyond the single-edge multi-device scenario.
func TestMultiEdgeSharesAccountAuthority(t *testing.T) {
	// This test drives synchronization explicitly rather than running heartbeat
	// loops. Remote MySQL round trips under race instrumentation can outlast the
	// short lease used by expiry tests; keep authority live until policy revoke.
	s, browser := testCloudWithTTL(t, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	certFile, keyFile, certificate := certFiles(t)
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	type node struct {
		edge    model.Edge
		runtime *edge.Runtime
		agent   *client.Agent
		port    int
	}
	nodes := make([]node, 2)
	ports := map[int]bool{}
	port := func() int {
		for {
			p := freePort(t)
			if !ports[p] {
				ports[p] = true
				return p
			}
		}
	}
	for i := range nodes {
		carrier, business := port(), port()
		token := strings.Repeat(fmt.Sprintf("multi-edge-%d-", i), 3)
		browser.api("POST", "/api/v1/edges", map[string]any{"name": fmt.Sprintf("shared-edge-%d", i), "token": token, "public_host": "127.0.0.1", "listen_host": "127.0.0.1", "endpoints": []model.Endpoint{{Transport: "tls", Address: address(carrier), ServerName: "edge.test"}}, "ca_cert": certificate, "http_port": 0, "https_port": 0, "port_min": business, "port_max": business, "max_carriers": 8, "capacity_bps": -1}, &nodes[i].edge, 201)
		nodes[i].port = business
		nodes[i].runtime = edge.New(edge.Config{CloudURL: browser.url, EdgeID: nodes[i].edge.ID, Token: token, CertFile: certFile, KeyFile: keyFile, ListenHost: "127.0.0.1"})
		t.Cleanup(nodes[i].runtime.Close)
		agent, err := client.New(client.Config{CloudURL: browser.url, StateDir: t.TempDir(), Transport: "tls_only"})
		if err != nil {
			t.Fatal(err)
		}
		nodes[i].agent = agent
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
		browser.api("POST", "/api/v1/rules", model.Rule{Name: fmt.Sprintf("shared-device-%d", i), DeviceID: bound.DeviceID, EdgeID: nodes[i].edge.ID, Protocol: "tcp", Target: origin.Addr().String(), PublicPort: business, SourceMode: "socket", Transport: "tls_only", Enabled: true, TimeoutSeconds: 3}, nil, 201)
	}
	var quotas struct {
		Items []model.Quota `json:"items"`
	}
	browser.api("GET", "/api/v1/quotas", nil, &quotas, 200)
	quota := quotas.Items[0]
	quota.MaxConnections = 2
	quota.NewFlowsPerSecond = 20
	// The first edge may reserve 64MiB, leaving 32MiB for the second. Neither
	// receives a copied 96MiB account budget, and both must still forward.
	quota.PeriodBytes = 96 << 20
	browser.api("PUT", "/api/v1/quotas/"+quota.TenantID, quota, &quota, 200)
	for i := range nodes {
		if _, err = nodes[i].agent.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		if err = nodes[i].runtime.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		if err = nodes[i].agent.ConnectEdge(ctx, nodes[i].edge); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(reason string, fn func() bool) {
		t.Helper()
		until := time.Now().Add(3 * time.Second)
		for !fn() {
			if time.Now().After(until) {
				t.Fatal(reason)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait("both authenticated TLS carriers did not become live", func() bool {
		return nodes[0].runtime.RuntimeStatus().ActiveCarriers == 1 && nodes[1].runtime.RuntimeStatus().ActiveCarriers == 1
	})
	var bytesGranted int64
	var concurrencyGranted int
	for _, n := range nodes {
		grants := n.runtime.Snapshot().Grants
		if len(grants) != 1 || grants[0].TenantID != quota.TenantID || grants[0].Bytes <= 0 || grants[0].MaxConnections != 1 {
			t.Fatalf("invalid independent edge share: %+v", grants)
		}
		bytesGranted += grants[0].Bytes
		concurrencyGranted += grants[0].MaxConnections
	}
	if bytesGranted != quota.PeriodBytes || concurrencyGranted != quota.MaxConnections {
		t.Fatalf("account authority multiplied: bytes=%d/%d connections=%d/%d", bytesGranted, quota.PeriodBytes, concurrencyGranted, quota.MaxConnections)
	}
	if nodes[0].runtime.Config().BootID == nodes[1].runtime.Config().BootID {
		t.Fatal("test did not create independent edge boots")
	}
	active := make([]net.Conn, 2)
	var businessBytes int64
	for i, n := range nodes {
		conn, err := net.DialTimeout("tcp", address(n.port), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		active[i] = conn
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := bytes.Repeat([]byte{byte(i), 1, 254, 255}, 12<<10)
		if _, err = conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("edge %d echo mismatch: %v", i, err)
		}
		businessBytes += int64(len(payload) * 2)
	}
	for i, n := range nodes {
		denied, err := net.DialTimeout("tcp", address(n.port), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = denied.SetDeadline(time.Now().Add(time.Second))
		_, _ = denied.Write([]byte("extra"))
		var reply [5]byte
		_, err = io.ReadFull(denied, reply[:])
		_ = denied.Close()
		if err == nil {
			t.Fatalf("edge %d duplicated the account concurrency budget", i)
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("rejected account flow was left hanging")
		}
	}
	wait("two accepted flows were not counted independently", func() bool {
		return nodes[0].runtime.RuntimeStatus().ActiveFlows == 1 && nodes[1].runtime.RuntimeStatus().ActiveFlows == 1
	})
	for _, n := range nodes {
		if err = n.runtime.Sync(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var used, reserved, credit int64
	var maxConnections int
	if err = s.DB().QueryRow("SELECT used_bytes,reserved_bytes FROM quotas WHERE tenant_id=?", quota.TenantID).Scan(&used, &reserved); err != nil {
		t.Fatal(err)
	}
	if err = s.DB().QueryRow("SELECT COALESCE(SUM(bytes),0),COALESCE(SUM(max_connections),0) FROM grants_table WHERE tenant_id=? AND closed=0 AND expires_at>UTC_TIMESTAMP(6)", quota.TenantID).Scan(&credit, &maxConnections); err != nil {
		t.Fatal(err)
	}
	if used != businessBytes || reserved+used != quota.PeriodBytes || credit > quota.PeriodBytes || maxConnections > quota.MaxConnections {
		t.Fatalf("durable shared ledger: used=%d/%d reserved=%d credits=%d connections=%d", used, businessBytes, reserved, credit, maxConnections)
	}
	// Tightening a policy updates the existing IDs in place: no fresh grant,
	// carrier reconnect, or account bucket reset is required to revoke traffic.
	var before [2]string
	for i, n := range nodes {
		grants := n.runtime.Snapshot().Grants
		if len(grants) != 1 {
			t.Fatalf("edge %d lost authority before policy tightening: %+v", i, grants)
		}
		before[i] = grants[0].ID
	}
	quota.BaseBPS = 0
	browser.api("PUT", "/api/v1/quotas/"+quota.TenantID, quota, &quota, 200)
	for i, n := range nodes {
		if err = n.runtime.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		grants := n.runtime.Snapshot().Grants
		if len(grants) != 1 {
			t.Fatalf("edge %d lost authority during policy tightening: %+v", i, grants)
		}
		grant := grants[0]
		if grant.ID != before[i] || grant.BaseBPS != 0 {
			t.Fatalf("online tightening replaced or failed to tighten grant: %+v", grant)
		}
		_ = active[i].SetReadDeadline(time.Now().Add(time.Second))
		var payload [1]byte
		_, err = active[i].Read(payload[:])
		if err == nil {
			t.Fatalf("edge %d kept an active stream after zero-bandwidth update", i)
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatalf("edge %d did not close tightened stream", i)
		}
	}
	wait("tightened account still has active flows", func() bool {
		return nodes[0].runtime.RuntimeStatus().ActiveFlows+nodes[1].runtime.RuntimeStatus().ActiveFlows == 0
	})
	t.Logf("2 real edges/boots + 2 bound agents: shared concurrency=2, finite credit=%dB, persisted bidirectional payload=%dB, online zero-rate revocation passed", credit, used)
}
