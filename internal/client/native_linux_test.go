//go:build linux

package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
)

func TestNativeAgentAuthorizedFlowAndRevocation(t *testing.T) {
	if os.Getenv("DRAFRP_NATIVE_TEST") != "1" {
		t.Skip("requires isolated NET_ADMIN namespace")
	}
	for index, transport := range []string{"tls", "quic"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(transport+"/"+network, func(t *testing.T) {
				peer := fmt.Sprintf("203.0.113.35:%d", 30000+os.Getpid()%20000+index)
				var target string
				if network == "tcp" {
					ln, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer ln.Close()
					target = ln.Addr().String()
					go func() {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						defer conn.Close()
						_, _ = io.WriteString(conn, conn.RemoteAddr().String()+"|")
						_, _ = io.Copy(conn, conn)
					}()
				} else {
					pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer pc.Close()
					target = pc.LocalAddr().String()
					go func() {
						data := make([]byte, 4096)
						for {
							n, source, err := pc.ReadFrom(data)
							if err != nil {
								return
							}
							_, _ = pc.WriteTo(append([]byte(source.String()+"|"), data[:n]...), source)
						}
					}()
				}
				a, c, r := connectedConfig(t, transport, model.Rule{Protocol: network, SourceMode: "native", Target: target}, Config{NetworkMode: "transparent", AllowedTargetCIDRs: []string{"127.0.0.1/32"}})
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				st, err := c.Open(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer protocol.Abort(st)
				_ = st.SetDeadline(time.Now().Add(4 * time.Second))
				if err = protocol.WriteJSON(st, protocol.Flow{RuleID: r.ID, Version: r.Version, ID: 123, Protocol: network, Peer: peer, Generation: c.Device.Generation}); err != nil {
					t.Fatal(err)
				}
				result(t, st)
				const payload = "native authorized payload"
				if network == "tcp" {
					_, err = io.WriteString(st, payload)
				} else {
					err = protocol.WritePacket(st, []byte(payload))
				}
				if err != nil {
					t.Fatal(err)
				}
				var got []byte
				if network == "tcp" {
					got = make([]byte, len(peer)+1+len(payload))
					_, err = io.ReadFull(st, got)
				} else {
					got, err = protocol.ReadPacket(st)
				}
				if err != nil || string(got) != peer+"|"+payload {
					t.Fatalf("native Agent source/payload %q %v", got, err)
				}
				a.mu.Lock()
				a.snap.Rules = nil
				a.reconcileLocked()
				a.mu.Unlock()
				var probe [1]byte
				if _, err = st.Read(probe[:]); err == nil {
					t.Fatal("revoked native flow remained active")
				}
				deadline := time.Now().Add(time.Second)
				for time.Now().Before(deadline) {
					a.mu.RLock()
					count := len(a.flows)
					a.mu.RUnlock()
					if count == 0 {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				// HTTP capabilities remain independent of native TCP/UDP readiness.
				if strings.Join(a.native.Capabilities(), ",") != "native_tcp_ipv4_ip_port,native_udp_ipv4_ip_port" {
					t.Fatal("verified capabilities missing")
				}
			})
		}
	}
}
