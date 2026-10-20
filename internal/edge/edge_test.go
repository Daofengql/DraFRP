package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type edgeFixture struct {
	r      *Runtime
	s      model.EdgeSnapshot
	key    ed25519.PrivateKey
	c      *protocol.Carrier
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func fixture(t *testing.T, rules ...model.Rule) *edgeFixture {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	r := New(Config{EdgeID: "edge", ListenHost: "127.0.0.1", UDPIdleTimeout: 300 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	f := &edgeFixture{r: r, key: key, ctx: ctx, cancel: cancel}
	exp := time.Now().Add(time.Minute)
	for i := range rules {
		rules[i].EdgeID = "edge"
		rules[i].TenantID = "tenant"
		rules[i].DeviceID = "device"
		rules[i].Version = 1
		rules[i].Enabled = true
		rules[i].Transport = "auto"
		rules[i].TimeoutSeconds = 2
		if rules[i].SourceMode == "" {
			rules[i].SourceMode = "socket"
		}
		if rules[i].PublicPort == 0 {
			rules[i].PublicPort = freePort(t)
		}
	}
	f.s = model.EdgeSnapshot{Revision: 1, ExpiresAt: exp, Edge: model.Edge{ID: "edge", BootID: r.cfg.BootID, CapacityBPS: -1, MaxCarriers: 16}, Devices: []model.DeviceGrant{{DeviceID: "device", TenantID: "tenant", PublicKey: base64.StdEncoding.EncodeToString(pub), SessionID: "session-unique-123", Generation: 1, ExpiresAt: exp}}, Rules: rules, Grants: []model.Grant{{ID: "grant", TenantID: "tenant", EdgeID: "edge", BootID: r.cfg.BootID, ExpiresAt: exp, Bytes: 64 << 20, BaseBPS: -1, PeakBPS: -1, MaxConnections: 64, NewFlowsPerSecond: 1000}}}
	if e = r.apply(f.s); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		f.cancel()
		if f.c != nil {
			_ = f.c.Close()
		}
		f.r.Close()
		f.wg.Wait()
	})
	return f
}
func (f *edgeFixture) agent(t *testing.T, handler func(protocol.Stream, protocol.Flow)) {
	t.Helper()
	a, b := net.Pipe()
	server, e := protocol.WrapTLS(a, true, "edge")
	if e != nil {
		t.Fatal(e)
	}
	client, e := protocol.WrapTLS(b, false, "edge")
	if e != nil {
		t.Fatal(e)
	}
	f.c = client
	f.r.ServeCarrier(f.ctx, server)
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	if e = protocol.AuthenticateClient(ctx, client, f.s.Devices[0], f.key); e != nil {
		t.Fatal(e)
	}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			st, e := client.Accept(f.ctx)
			if e != nil {
				return
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer st.Close()
				var flow protocol.Flow
				_ = st.SetDeadline(time.Now().Add(5 * time.Second))
				if protocol.ReadJSON(st, &flow) != nil {
					return
				}
				_ = st.SetDeadline(time.Time{})
				handler(st, flow)
			}()
		}
	}()
	eventually(t, func() bool { f.r.mu.RLock(); defer f.r.mu.RUnlock(); return len(f.r.carriers) == 1 })
}
func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not converge")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func (f *edgeFixture) address(i int) string {
	return fmt.Sprintf("127.0.0.1:%d", f.s.Rules[i].PublicPort)
}
func TestTCPPayloadAndHalfClose(t *testing.T) {
	f := fixture(t, model.Rule{ID: "tcp", Protocol: "tcp"})
	f.agent(t, func(s protocol.Stream, flow protocol.Flow) {
		if flow.Generation != 1 || flow.ID == 0 || flow.Protocol != "tcp" {
			return
		}
		_ = protocol.WriteJSON(s, protocol.Result{})
		payload, e := io.ReadAll(s)
		if e == nil {
			_ = protocol.WriteFull(s, append([]byte("reply:"), payload...))
		}
	})
	c, e := net.Dial("tcp", f.address(0))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	payload := bytes.Repeat([]byte{0, 1, 4, 127, 255}, 20000)
	if e = protocol.WriteFull(c, payload); e != nil {
		t.Fatal(e)
	}
	if e = c.(*net.TCPConn).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	out, e := io.ReadAll(c)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(out, append([]byte("reply:"), payload...)) {
		t.Fatalf("payload or handshake leaked: got %d bytes", len(out))
	}
	eventually(t, func() bool { return f.r.FlowCount() == 0 })
	report := f.r.history["grant"].report()
	if report.UploadBytes != int64(len(payload)) || report.DownloadBytes != int64(len(out)) {
		t.Fatalf("wrong payload accounting: %+v", report)
	}
}
func TestACLExpiryClosesOnlyAffectedFlow(t *testing.T) {
	expires := time.Now().Add(400 * time.Millisecond)
	policy := &model.ACLPolicy{DefaultAction: "deny", Entries: []model.ACLEntry{{ID: "temporary", Priority: 1, Action: "allow", CIDRs: []string{"127.0.0.0/8"}, ExpiresAt: &expires}}}
	f := fixture(t, model.Rule{ID: "temporary", Protocol: "tcp", ACL: policy}, model.Rule{ID: "other", Protocol: "tcp"})
	f.agent(t, func(s protocol.Stream, _ protocol.Flow) {
		_ = protocol.WriteJSON(s, protocol.Result{})
		_, _ = io.Copy(s, s)
	})
	c1, e := net.Dial("tcp", f.address(0))
	if e != nil {
		t.Fatal(e)
	}
	defer c1.Close()
	c2, e := net.Dial("tcp", f.address(1))
	if e != nil {
		t.Fatal(e)
	}
	defer c2.Close()
	for _, c := range []net.Conn{c1, c2} {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Write([]byte("x"))
		b := make([]byte, 1)
		if _, e = io.ReadFull(c, b); e != nil {
			t.Fatal(e)
		}
	}
	eventually(t, func() bool { return f.r.FlowCount() == 1 })
	b := make([]byte, 1)
	if _, e = c1.Read(b); e == nil {
		t.Fatal("expired ACL kept a flow alive")
	}
	_, _ = c2.Write([]byte("z"))
	if _, e = io.ReadFull(c2, b); e != nil || b[0] != 'z' {
		t.Fatalf("unrelated flow was disrupted: %v", e)
	}
}
func TestUDPMappingIsPerSourceAndPreservesBoundaries(t *testing.T) {
	f := fixture(t, model.Rule{ID: "udp", Protocol: "udp"})
	var created atomic.Int64
	f.agent(t, func(s protocol.Stream, flow protocol.Flow) {
		created.Add(1)
		if flow.Datagram {
			return
		}
		_ = protocol.WriteJSON(s, protocol.Result{})
		for {
			b, e := protocol.ReadPacket(s)
			if e != nil {
				return
			}
			if protocol.WritePacket(s, b) != nil {
				return
			}
		}
	})
	c1, e := net.Dial("udp", f.address(0))
	if e != nil {
		t.Fatal(e)
	}
	defer c1.Close()
	c2, e := net.Dial("udp", f.address(0))
	if e != nil {
		t.Fatal(e)
	}
	defer c2.Close()
	send := func(c net.Conn, p []byte) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, e = c.Write(p); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, protocol.MaxPacket)
		n, e := c.Read(b)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(b[:n], p) {
			t.Fatal("UDP packet changed or crossed source mapping")
		}
	}
	send(c1, []byte("one"))
	send(c1, bytes.Repeat([]byte("a"), 8000))
	send(c2, []byte("two"))
	send(c1, []byte{})
	if created.Load() != 2 {
		t.Fatalf("got %d maps instead of 2", created.Load())
	}
	eventually(t, func() bool { return f.r.FlowCount() == 0 })
}
func TestAuthorizationExpiryStopsListenersAndFlows(t *testing.T) {
	f := fixture(t, model.Rule{ID: "tcp", Protocol: "tcp"})
	f.agent(t, func(s protocol.Stream, _ protocol.Flow) {
		_ = protocol.WriteJSON(s, protocol.Result{})
		_, _ = io.Copy(s, s)
	})
	c, e := net.Dial("tcp", f.address(0))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_, _ = c.Write([]byte("x"))
	var b [1]byte
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = io.ReadFull(c, b[:]); e != nil {
		t.Fatal(e)
	}
	f.s.ExpiresAt = time.Now().Add(150 * time.Millisecond)
	f.s.Revision++
	if e = f.r.apply(f.s); e != nil {
		t.Fatal(e)
	}
	eventually(t, func() bool { return !f.r.Ready() && f.r.FlowCount() == 0 })
	if _, e = c.Read(b[:]); e == nil {
		t.Fatal("expired flow still reads")
	}
	l, e := net.Listen("tcp", f.address(0))
	if e != nil {
		t.Fatalf("expired listener retained socket: %v", e)
	}
	_ = l.Close()
}
func TestGrantRenewalDoesNotRefillCreditOrConnections(t *testing.T) {
	f := fixture(t, model.Rule{ID: "tcp", Protocol: "tcp"})
	b := f.r.budgets["tenant"]
	n, e := b.reserve(25, true)
	if e != nil {
		t.Fatal(e)
	}
	b.complete(n, 25, true)
	if !b.acquire() {
		t.Fatal("admission failed")
	}
	f.s.Revision++
	f.s.Grants[0].Bytes += 50
	if e = f.r.apply(f.s); e != nil {
		t.Fatal(e)
	}
	if f.r.budgets["tenant"] != b {
		t.Fatal("renewal replaced the account budget")
	}
	if report := b.report(); report.UploadBytes != 25 {
		t.Fatalf("renewal reset cumulative usage: %+v", report)
	}
	if b.active != 1 {
		t.Fatal("renewal reset active permits")
	}
	b.release()
	before := f.r.Snapshot()
	bad := f.s
	bad.Revision++
	bad.Grants = append([]model.Grant(nil), bad.Grants...)
	bad.Grants[0].BootID = "wrong"
	if e = f.r.apply(bad); e == nil {
		t.Fatal("wrong-boot grant was accepted")
	}
	if f.r.Snapshot().Revision != before.Revision {
		t.Fatal("invalid snapshot partially replaced authority")
	}
}
func TestNativeSourceFailsClosed(t *testing.T) {
	f := fixture(t, model.Rule{ID: "native", Protocol: "tcp", SourceMode: "native"})
	if st := f.r.Statuses()[0]; st.Status != "error" || !strings.Contains(st.Error, "capability_missing") {
		t.Fatalf("unsupported native mode was misreported: %+v", st)
	}
	l, e := net.Listen("tcp", f.address(0))
	if e != nil {
		t.Fatal("unsupported native rule opened a socket")
	}
	_ = l.Close()
}

func TestGeoIPReloadAndMissingCapability(t *testing.T) {
	policy := &model.ACLPolicy{DefaultAction: "deny", Entries: []model.ACLEntry{{ID: "regional", Priority: 1, Action: "allow", Countries: []string{"AA"}, GeoUnknownAction: "deny"}}}
	f := fixture(t, model.Rule{ID: "geo", Protocol: "tcp", ACL: policy})
	if st := f.r.Statuses()[0]; st.Status != "error" || !strings.Contains(st.Error, "capability_missing") {
		t.Fatal(st)
	}
	path := filepath.Join(t.TempDir(), "geo.json")
	f.r.cfg.GeoIPFile = path
	write := func(country string) {
		t.Helper()
		if e := os.WriteFile(path, []byte(fmt.Sprintf(`{"version":"test","records":[{"cidr":"203.0.113.0/24","country":%q}]}`, country)), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("AA")
	if e := f.r.apply(f.s); e != nil {
		t.Fatal(e)
	}
	f.agent(t, func(s protocol.Stream, _ protocol.Flow) { _ = protocol.WriteJSON(s, protocol.Result{}) })
	flow, e := f.r.beginFlow(f.ctx, "geo", "203.0.113.7:54321")
	if e != nil {
		t.Fatal(e)
	}
	defer f.r.finishFlow(flow)
	write("BB")
	if e = f.r.apply(f.s); e != nil {
		t.Fatal(e)
	}
	select {
	case <-flow.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("geographic database update did not revoke previously allowed flow")
	}
	if e = os.WriteFile(path, []byte(`{"corrupt":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e = f.r.apply(f.s); e != nil {
		t.Fatal(e)
	}
	if st := f.r.Statuses()[0]; st.Status != "error" || !strings.Contains(st.Error, "capability_missing") {
		t.Fatal("corrupt geographic database left rule available", st)
	}
}
func TestAgentCannotOpenReverseTarget(t *testing.T) {
	f := fixture(t, model.Rule{ID: "tcp", Protocol: "tcp"})
	f.agent(t, func(protocol.Stream, protocol.Flow) {})
	s, e := f.c.Open(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer protocol.Abort(s)
	_ = s.SetDeadline(time.Now().Add(time.Second))
	_ = protocol.WriteJSON(s, protocol.Flow{RuleID: "tcp", Version: 1, Protocol: "tcp"})
	var result protocol.Result
	if protocol.ReadJSON(s, &result) == nil {
		t.Fatal("agent-originated business stream was served by edge")
	}
}
func TestHTTPErrorsAndInterruptedUpload(t *testing.T) {
	port := freePort(t)
	f := fixture(t, model.Rule{ID: "site", Protocol: "http", SourceMode: "forwarded_headers", Domain: "app.test", PublicPort: port})
	f.s.Edge.HTTPPort = port
	f.s.Revision++
	if e := f.r.apply(f.s); e != nil {
		t.Fatal(e)
	}
	c, e := net.Dial("tcp", f.address(0))
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
	resp, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		t.Fatal(e)
	}
	if resp.StatusCode != 503 || resp.Header.Get("X-DraFRP-Error") != "agent_offline" {
		t.Fatalf("wrong offline result: %s", resp.Status)
	}
	_ = resp.Body.Close()
	_ = c.Close()
	f.agent(t, func(s protocol.Stream, _ protocol.Flow) {
		req, e := http.ReadRequest(bufio.NewReader(s))
		if e != nil {
			return
		}
		_ = req
		_ = protocol.WriteJSON(s, protocol.Result{Code: "target_timeout", Error: "test origin timed out"})
	})
	c, e = net.Dial("tcp", f.address(0))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprint(c, "POST / HTTP/1.1\r\nHost: app.test\r\nContent-Length: 1048576\r\n\r\nx")
	resp, e = http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		t.Fatalf("early failure left upload blocked: %v", e)
	}
	if resp.StatusCode != 504 {
		t.Fatalf("got %s", resp.Status)
	}
	_ = resp.Body.Close()
	eventually(t, func() bool { return f.r.FlowCount() == 0 })
}
func TestHTTPStreamingAndUpgrade(t *testing.T) {
	port := freePort(t)
	f := fixture(t, model.Rule{ID: "site", Protocol: "http", SourceMode: "forwarded_headers", Domain: "app.test", PublicPort: port})
	f.s.Edge.HTTPPort = port
	f.s.Revision++
	if e := f.r.apply(f.s); e != nil {
		t.Fatal(e)
	}
	f.agent(t, func(s protocol.Stream, flow protocol.Flow) {
		reader := bufio.NewReader(s)
		req, e := http.ReadRequest(reader)
		if e != nil {
			return
		}
		if req.Header.Get("X-Forwarded-For") != "" || flow.Host != "app.test" || flow.IngressPort != port {
			return
		}
		_ = protocol.WriteJSON(s, protocol.Result{})
		if req.Header.Get("Upgrade") == "echo" {
			_, _ = fmt.Fprint(s, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
			_, _ = io.Copy(s, reader)
			return
		}
		body, _ := io.ReadAll(req.Body)
		resp := &http.Response{StatusCode: 201, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"X-Origin": []string{"test"}}, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
		_ = resp.Write(s)
	})
	payload := strings.Repeat("payload", 12000)
	req, e := http.NewRequest("POST", "http://"+f.address(0)+"/test", strings.NewReader(payload))
	if e != nil {
		t.Fatal(e)
	}
	req.Host = "app.test"
	req.Header.Set("X-Forwarded-For", "forged")
	hc := &http.Client{Timeout: 4 * time.Second}
	resp, e := hc.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if e != nil || resp.StatusCode != 201 || string(body) != payload {
		t.Fatalf("HTTP payload mismatch: status=%d len=%d err=%v", resp.StatusCode, len(body), e)
	}
	c, e := net.Dial("tcp", f.address(0))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprint(c, "GET /socket HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	reader := bufio.NewReader(c)
	resp, e = http.ReadResponse(reader, nil)
	if e != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade failed: %v %+v", e, resp)
	}
	_, _ = c.Write([]byte("after-upgrade"))
	b := make([]byte, len("after-upgrade"))
	if _, e = io.ReadFull(reader, b); e != nil || string(b) != "after-upgrade" {
		t.Fatalf("upgrade byte relay failed: %v", e)
	}
}
