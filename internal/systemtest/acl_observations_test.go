package systemtest

import (
	"context"
	"drafrp/internal/client"
	"drafrp/internal/edge"
	"drafrp/internal/model"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Exercises real TCP accepts and UDP packets through an authenticated carrier,
// two cloud synchronization round trips and the durable MySQL read API.
func TestACLObservationFullSystem(t *testing.T) {
	_, b := testCloudWithTTL(t, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	certFile, keyFile, cert := certFiles(t)
	carrierPort, businessPort, httpPort, httpsPort := freePort(t), freePort(t), freePort(t), freePort(t)
	token := strings.Repeat("acl-system-token-", 3)
	var edgeInfo model.Edge
	b.api("POST", "/api/v1/edges", map[string]any{"name": "acl-system-edge", "token": token, "public_host": "127.0.0.1", "listen_host": "127.0.0.1", "endpoints": carrierEndpoints(carrierPort), "ca_cert": cert, "http_port": httpPort, "https_port": httpsPort, "port_min": businessPort, "port_max": businessPort, "max_carriers": 8, "capacity_bps": -1}, &edgeInfo, 201)
	r := edge.New(edge.Config{CloudURL: b.url, EdgeID: edgeInfo.ID, Token: token, CertFile: certFile, KeyFile: keyFile, ListenHost: "127.0.0.1", UDPIdleTimeout: 200 * time.Millisecond})
	defer r.Close()
	agent, err := client.New(client.Config{CloudURL: b.url, StateDir: t.TempDir(), Transport: "tls_only"})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	bind, err := agent.Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b.api("POST", "/api/v1/bind/confirm", map[string]string{"user_code": bind.UserCode}, nil, 200)
	bound, err := agent.PollBind(ctx, bind.ID, bind.PollToken)
	if err != nil {
		t.Fatal(err)
	}
	targetTCP, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetTCP.Close()
	go func() {
		for {
			c, e := targetTCP.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	targetUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetUDP.Close()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, e := targetUDP.ReadFrom(buffer)
			if e != nil {
				return
			}
			_, _ = targetUDP.WriteTo(buffer[:n], peer)
		}
	}()
	var template model.ACLTemplate
	b.api("POST", "/api/v1/acl-templates", model.ACLTemplate{Name: "real-traffic-template"}, &template, 201)
	template.Policy = model.ACLPolicy{DefaultAction: "deny", Entries: []model.ACLEntry{{ID: "loopback-entry", Action: "allow", CIDRs: []string{"127.0.0.0/8"}}}}
	b.api("PUT", "/api/v1/acl-templates/"+template.ID, template, &template, 200)
	b.api("POST", "/api/v1/acl-templates/"+template.ID+"/publish", map[string]uint64{"version": template.Version}, &template, 200)
	var tcpRule, udpRule model.Rule
	for _, item := range []struct {
		protocol, target string
		out              *model.Rule
	}{{"tcp", targetTCP.Addr().String(), &tcpRule}, {"udp", targetUDP.LocalAddr().String(), &udpRule}} {
		b.api("POST", "/api/v1/rules", model.Rule{Name: "acl-" + item.protocol, Protocol: item.protocol, DeviceID: bound.DeviceID, EdgeID: edgeInfo.ID, PublicPort: businessPort, Target: item.target, SourceMode: "socket", Transport: "tls_only", Enabled: true, ACLTemplateID: template.ID}, item.out, 201)
	}
	if _, err = agent.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err = r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err = agent.ConnectEdge(ctx, edgeInfo); err != nil {
		t.Fatal(err)
	}
	var tcp net.Conn
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		tcp, err = net.Dial("tcp4", address(businessPort))
		if err == nil {
			_ = tcp.SetDeadline(time.Now().Add(300 * time.Millisecond))
			_, err = tcp.Write([]byte("x"))
			var got [1]byte
			if err == nil {
				_, err = io.ReadFull(tcp, got[:])
			}
			if err == nil && got[0] == 'x' {
				break
			}
			_ = tcp.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("TCP carrier never ready", err)
	}
	defer tcp.Close()
	udp, err := net.Dial("udp4", address(businessPort))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	for range 3 {
		_ = udp.SetDeadline(time.Now().Add(time.Second))
		_, _ = udp.Write([]byte("y"))
		var got [1]byte
		if _, err = udp.Read(got[:]); err != nil || got[0] != 'y' {
			t.Fatal("UDP allowed traffic failed", err)
		}
	}
	if err = r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	type observed struct {
		Items []struct {
			model.ACLHit
			Current    bool      `json:"current"`
			BootID     string    `json:"boot_id"`
			ObservedAt time.Time `json:"observed_at"`
		} `json:"items"`
		Application struct {
			State     string            `json:"state"`
			BootID    string            `json:"boot_id"`
			ACKBootID string            `json:"ack_boot_id"`
			ACK       *model.ACLApplied `json:"ack"`
		} `json:"application"`
	}
	get := func(rule model.Rule) observed {
		var out observed
		b.api("GET", "/api/v1/acl/observations?rule_id="+rule.ID, nil, &out, 200)
		return out
	}
	assertCounts := func(got observed, version uint64, allowed, denied uint64) {
		t.Helper()
		var a, d uint64
		for _, row := range got.Items {
			if row.Kind == "rule_total" && row.RuleVersion == version {
				a += row.Allowed
				d += row.Denied
			}
		}
		if a < allowed || d != denied {
			t.Fatalf("real traffic totals got %d/%d want >=%d/%d %+v", a, d, allowed, denied, got)
		}
	}
	assertCounts(get(tcpRule), tcpRule.Version, 1, 0)
	assertCounts(get(udpRule), udpRule.Version, 3, 0)
	if got := get(tcpRule); got.Application.State != "applied" {
		t.Fatal("successful apply ACK missing", got)
	}
	template.Policy = model.ACLPolicy{DefaultAction: "deny"}
	b.api("PUT", "/api/v1/acl-templates/"+template.ID, template, &template, 200)
	b.api("POST", "/api/v1/acl-templates/"+template.ID+"/publish", map[string]uint64{"version": template.Version}, &template, 200)
	b.api("GET", "/api/v1/rules/"+tcpRule.ID, nil, &tcpRule, 200)
	b.api("GET", "/api/v1/rules/"+udpRule.ID, nil, &udpRule, 200)
	if err = r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := get(tcpRule); got.Application.State != "pending" {
		t.Fatal("new version treated as applied before real ACK", got)
	}
	// A new default-deny policy closes the old admitted flow before reporting.
	_ = tcp.SetDeadline(time.Now().Add(time.Second))
	var buffer [1]byte
	if _, err = tcp.Read(buffer[:]); err == nil {
		t.Fatal("old admitted flow survived new deny")
	}
	deniedTCP, err := net.Dial("tcp4", address(businessPort))
	if err != nil {
		t.Fatal(err)
	}
	_ = deniedTCP.SetDeadline(time.Now().Add(time.Second))
	_, _ = deniedTCP.Write([]byte("z"))
	if _, err = deniedTCP.Read(buffer[:]); err == nil {
		t.Fatal("denied TCP reached target")
	}
	_ = deniedTCP.Close()
	_ = udp.SetDeadline(time.Now().Add(150 * time.Millisecond))
	_, _ = udp.Write([]byte("z"))
	if _, err = udp.Read(buffer[:]); err == nil {
		t.Fatal("denied UDP reached target")
	}
	if err = r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	tcpObservation, udpObservation := get(tcpRule), get(udpRule)
	assertCounts(tcpObservation, tcpRule.Version, 0, 1)
	assertCounts(udpObservation, udpRule.Version, 0, 1)
	for _, got := range []observed{tcpObservation, udpObservation} {
		if got.Application.State != "applied" {
			t.Fatal("new application ACK missing", got)
		}
		found := false
		for _, row := range got.Items {
			if row.Current && row.Kind == "policy" && row.UsedDefault && row.Denied == 1 {
				found = true
			}
		}
		if !found {
			t.Fatal("actual default deny evidence missing", got)
		}
	}
	if path := os.Getenv("DRAFRP_ACL_EVIDENCE"); path != "" {
		evidence := map[string]any{"status": "passed", "observed_at": time.Now().UTC(), "test": "TestACLObservationFullSystem", "database": "real MySQL", "carrier": "authenticated TLS/yamux", "tcp_allowed_before_publish": true, "udp_allowed_packets": 3, "tcp_denied_after_publish": true, "udp_denied_after_publish": true, "old_flow_stopped": true, "unacknowledged_publish_pending": true, "actual_apply_ack_confirmed": true, "default_deny_hits_persisted": true, "tcp_observation": tcpObservation, "udp_observation": udpObservation}
		data, e := json.MarshalIndent(evidence, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, append(data, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
}
