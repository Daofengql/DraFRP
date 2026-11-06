package client

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"github.com/quic-go/quic-go"
)

func TestDualStackCarrierRaces(t *testing.T) {
	for _, tc := range []struct {
		name, mode, wantTransport, wantHost string
		quic4, quic6, tls4, tls6            bool
	}{
		{"ipv6_first", "auto", "quic", "::1", true, true, true, true},
		{"ipv6_udp_blackhole_keeps_ipv4_quic", "auto", "quic", "127.0.0.1", true, false, true, true},
		{"all_udp_blackhole_uses_ipv6_tls", "auto", "tls", "::1", false, false, true, true},
		{"tls_only_ipv6", "tls_only", "tls", "::1", true, true, true, true},
		{"tls6_handshake_blackhole_uses_ipv4", "tls_only", "tls", "127.0.0.1", false, false, true, false},
		{"quic_only_ipv6_blackhole", "quic_only", "quic", "127.0.0.1", true, false, true, true},
		{"quic_only_does_not_use_available_tls", "quic_only", "", "", false, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v6, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Skipf("IPv6 loopback unavailable: %v", err)
			}
			v6.Close()
			a, err := New(Config{CloudURL: "http://127.0.0.1", StateDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(a.Close)
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			t.Cleanup(cancel)
			cert, ca := certificate(t, "edge.test")
			tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{protocol.ALPN}}
			ln4, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln4.Close() })
			port := ln4.Addr().(*net.TCPAddr).Port
			ln6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln6.Close() })
			d := model.DeviceGrant{DeviceID: "device", TenantID: "tenant", SessionID: a.st.SessionID, Generation: 1, PublicKey: base64.StdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey)), ExpiresAt: time.Now().Add(time.Minute)}
			edge := model.Edge{ID: "edge", CACert: ca, Endpoints: []model.Endpoint{{Transport: "quic", Address: fmt.Sprintf("edge.test:%d", port), ServerName: "edge.test"}, {Transport: "tls", Address: fmt.Sprintf("edge.test:%d", port), ServerName: "edge.test"}}}
			a.mu.Lock()
			a.snap = model.ClientSnapshot{Device: d, Edges: []model.Edge{edge}, ExpiresAt: d.ExpiresAt}
			a.mu.Unlock()
			lookups := 0
			a.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
				lookups++
				return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, nil
			}
			admit := func(c *protocol.Carrier) {
				defer c.Close()
				if protocol.AuthenticateEdge(ctx, c, func(id string) (model.DeviceGrant, bool) { return d, id == d.DeviceID }) == nil {
					<-ctx.Done()
				}
			}
			for _, listener := range []struct {
				ln    net.Listener
				serve bool
			}{{ln4, tc.tls4}, {ln6, tc.tls6}} {
				go func() {
					conn, err := listener.ln.Accept()
					if err != nil {
						return
					}
					if !listener.serve {
						defer conn.Close()
						<-ctx.Done()
						return
					}
					c, err := protocol.WrapTLS(tls.Server(conn, tlsConfig), true, edge.ID)
					if err == nil {
						admit(c)
					} else {
						conn.Close()
					}
				}()
			}
			for _, udp := range []struct {
				network, host string
				serve         bool
			}{{"udp4", "127.0.0.1", tc.quic4}, {"udp6", "::1", tc.quic6}} {
				packet, err := net.ListenPacket(udp.network, net.JoinHostPort(udp.host, fmt.Sprint(port)))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { packet.Close() })
				if !udp.serve {
					continue
				} // A bound socket that never reads is a real UDP blackhole.
				transport := &quic.Transport{Conn: packet}
				listener, err := transport.Listen(tlsConfig, protocol.QUICConfig())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close(); transport.Close() })
				go func() {
					q, err := listener.Accept(ctx)
					if err == nil {
						admit(protocol.WrapQUIC(q, edge.ID))
					}
				}()
			}
			started := time.Now()
			carrier, err := a.dialEdge(ctx, edge, tc.mode)
			if tc.wantTransport == "" {
				if err == nil {
					carrier.Close()
					t.Fatal("quic_only silently fell back to TLS")
				}
				if time.Since(started) > 3*time.Second {
					t.Fatalf("failed race exceeded deadline: %v", time.Since(started))
				}
				for _, status := range a.EndpointStatus() {
					if status.Transport != "quic" {
						t.Fatal("quic_only probed TLS")
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer carrier.Close()
			actual := netip.MustParseAddrPort(carrier.RemoteAddress)
			if carrier.Transport != tc.wantTransport || actual.Addr().String() != tc.wantHost || time.Since(started) > 2*time.Second {
				t.Fatalf("unexpected selected path after %v: %s %s", time.Since(started), carrier.Transport, carrier.RemoteAddress)
			}
			if lookups != 1 || carrier.Endpoint.Address != edge.Endpoints[0].Address {
				t.Fatalf("DNS not shared or configured authority replaced: lookups=%d endpoint=%s", lookups, carrier.Endpoint.Address)
			}
			if tc.mode == "tls_only" {
				for _, status := range a.EndpointStatus() {
					if status.Transport == "quic" {
						t.Fatal("tls_only probed QUIC")
					}
				}
			}
		})
	}
}

func TestIPv4BusinessTargetsAndIPv6HTTPIdentity(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Origin-Connection", req.RemoteAddr)
		fmt.Fprint(w, req.Header.Get("X-Forwarded-For")+"|"+req.Header.Get("X-Real-IP")+"|"+req.Header.Get("Forwarded"))
	}))
	defer target.Close()
	a, c, r := connected(t, "tls", model.Rule{Protocol: "http", SourceMode: "forwarded_headers", Domain: "public.example", Target: target.URL})
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), time.Second)
	defer cancelProbe()
	if !c.ReverseProbeSupported() {
		t.Fatal("reverse control probe was not negotiated")
	}
	if err := c.Probe(probeCtx); err != nil {
		t.Fatalf("server could not observe path RTT: %v", err)
	}
	if c.Active() != 0 || a.RuntimeStatus().ActiveFlows != 0 {
		t.Fatal("control probe consumed business flows")
	}
	for _, network := range []string{"tcp", "udp"} {
		if conn, err := a.dialTarget(context.Background(), network, "[::1]:1234"); err == nil || !strings.Contains(err.Error(), "address_family_unsupported") {
			if conn != nil {
				conn.Close()
			}
			t.Fatalf("IPv6 %s target accepted: %v", network, err)
		}
	}
	var pooled string
	for i, peer := range []string{"[2001:db8::123]:1234", "198.51.100.17:9876"} {
		st, err := c.Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer protocol.Abort(st)
		st.SetDeadline(time.Now().Add(3 * time.Second))
		flow := protocol.Flow{ID: uint64(i + 1), RuleID: r.ID, Version: r.Version, Generation: c.Device.Generation, Protocol: r.Protocol, Peer: peer, Host: r.Domain, Scheme: "https", IngressPort: 443}
		if err := protocol.WriteJSON(st, flow); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", "http://public.example/", nil)
		req.Header.Set("X-Forwarded-For", "forged")
		req.Header.Set("X-Real-IP", "forged")
		req.Header.Set("Forwarded", "for=forged")
		written := make(chan error, 1)
		go func() { written <- req.Write(st) }()
		result(t, st)
		resp, err := http.ReadResponse(bufio.NewReader(st), req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		ip := netip.MustParseAddrPort(peer).Addr().String()
		if string(body) != ip+"|"+ip+"|" {
			t.Fatalf("request identity leaked or forged: %s", body)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		connection := resp.Header.Get("X-Origin-Connection")
		if pooled != "" && pooled != connection {
			t.Fatalf("HTTP did not reuse IPv4 origin socket: %s -> %s", pooled, connection)
		}
		pooled = connection
	}
	a.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::1")}, nil
	}
	if conn, err := a.dialTarget(context.Background(), "tcp", "aaaa-only.test:80"); err == nil || !strings.Contains(err.Error(), "address_family_unsupported") {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("AAAA-only business target accepted: %v", err)
	}
}

func TestIPv6BusinessPeerRejectedOnAuthenticatedCarrier(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			_, c, r := connected(t, "tls", model.Rule{Protocol: network, SourceMode: "socket", Target: "127.0.0.1:1"})
			st, err := c.Open(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer protocol.Abort(st)
			st.SetDeadline(time.Now().Add(time.Second))
			if err := protocol.WriteJSON(st, protocol.Flow{ID: 1, RuleID: r.ID, Version: r.Version, Generation: c.Device.Generation, Protocol: r.Protocol, Peer: "[2001:db8::1]:1234"}); err != nil {
				t.Fatal(err)
			}
			var result protocol.Result
			if err := protocol.ReadJSON(st, &result); err != nil || result.Code != "unauthorized_flow" {
				t.Fatalf("IPv6 peer reached target dial: %+v %v", result, err)
			}
		})
	}
}
