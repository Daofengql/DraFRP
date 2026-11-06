package client

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
)

func TestIPv6RecoveryPreservesExistingIPv4Flow(t *testing.T) {
	v6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	defer v6.Close()
	port := v6.Addr().(*net.TCPAddr).Port
	v4, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		c, err := origin.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	a, err := New(Config{CloudURL: "http://127.0.0.1", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cert, ca := certificate(t, "edge.test")
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}
	d := model.DeviceGrant{DeviceID: "device", TenantID: "tenant", PublicKey: base64.StdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey)), SessionID: a.st.SessionID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}
	e := model.Edge{ID: "edge", CACert: ca, MaxCarriers: 2, Endpoints: []model.Endpoint{{Transport: "tls", Address: fmt.Sprintf("edge.test:%d", port), ServerName: "edge.test"}}}
	r := model.Rule{ID: "rule", Version: 1, TenantID: d.TenantID, DeviceID: d.DeviceID, EdgeID: e.ID, Protocol: "tcp", SourceMode: "socket", Target: origin.Addr().String(), Transport: "tls_only", Enabled: true}
	a.mu.Lock()
	a.snap = model.ClientSnapshot{Device: d, Edges: []model.Edge{e}, Rules: []model.Rule{r}, ExpiresAt: d.ExpiresAt}
	a.mu.Unlock()
	a.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	var recovered atomic.Bool
	accepted := make(chan *protocol.Carrier, 4)
	for _, ln := range []net.Listener{v6, v4} {
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				if ln == v6 && !recovered.Load() {
					conn.Close()
					continue
				}
				go func() {
					c, err := protocol.WrapTLS(tls.Server(conn, tc), true, e.ID)
					if err != nil {
						conn.Close()
						return
					}
					defer c.Close()
					if err := protocol.AuthenticateEdge(ctx, c, func(id string) (model.DeviceGrant, bool) { return d, id == d.DeviceID }); err != nil {
						return
					}
					accepted <- c
					for {
						st, err := c.Accept(ctx)
						if err != nil {
							return
						}
						c.HandleProbe(ctx, st, func() bool { return true })
					}
				}()
			}
		}()
	}
	c, err := a.dialEdge(ctx, e, "tls_only")
	if err != nil {
		t.Fatal(err)
	}
	if netip.MustParseAddrPort(c.RemoteAddress).Addr().Is6() {
		t.Fatal("failed IPv6 path selected")
	}
	// Age only the unpublished fixture. No published carrier state is mutated.
	c.EstablishedAt = time.Now().Add(-endpointStableWindow - time.Second)
	a.mu.Lock()
	a.carriers["existing"], a.carrierEdges["existing"] = c, e
	a.wg.Add(1)
	a.mu.Unlock()
	go a.acceptCarrier(a.ctx, "existing", c)
	var edgeCarrier *protocol.Carrier
	select {
	case edgeCarrier = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	stream := openFlow(t, edgeCarrier, r, 123, false)
	result(t, stream)
	echo := func(message string) {
		t.Helper()
		if err := protocol.WriteFull(stream, []byte(message)); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, len(message))
		if _, err := io.ReadFull(stream, data); err != nil || string(data) != message {
			t.Fatalf("existing flow lost: %q %v", data, err)
		}
	}
	echo("before-v6-recovery")
	recovered.Store(true)
	a.mu.Lock()
	for k, health := range a.pathHealth {
		if k.RemoteAddress == fmt.Sprintf("[::1]:%d", port) {
			health.RetryAt = time.Time{}
		}
	}
	a.mu.Unlock()
	if err := a.ConnectEdge(ctx, e); err != nil {
		t.Fatal(err)
	}
	status := a.TransportStatus()
	if len(status) != 2 {
		t.Fatalf("recovery did not use spare carrier budget: %+v", status)
	}
	hasIPv6 := false
	for _, path := range status {
		hasIPv6 = hasIPv6 || netip.MustParseAddrPort(path["remote_address"].(string)).Addr().Is6()
	}
	if !hasIPv6 {
		t.Fatalf("maintenance duplicated IPv4 instead of recovering IPv6: %+v", status)
	}
	echo("same-v4-flow-after-v6-recovery")
}
