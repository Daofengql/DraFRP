//go:build linux

package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This opt-in suite is run in a disposable NET_ADMIN network namespace.
// Normal test runs never install host routes or firewall rules.
func TestTransparentSourceAndOwnedCleanup(t *testing.T) {
	if os.Getenv("DRAFRP_NATIVE_TEST") != "1" {
		t.Skip("requires an isolated NET_ADMIN namespace")
	}
	dir := t.TempDir()
	m, err := New(Config{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	if got := strings.Join(m.Capabilities(), ","); got != "native_tcp_ipv4_ip_port,native_udp_ipv4_ip_port" {
		t.Fatalf("source verification capabilities: %s", got)
	}
	targets := []string{"127.0.0.1"}
	if extra := os.Getenv("DRAFRP_NATIVE_LOCAL_IP"); extra != "" {
		targets = append(targets, extra)
	}
	for index, address := range targets {
		for protocolIndex, network := range []string{"tcp", "udp"} {
			t.Run(network+"/"+address, func(t *testing.T) {
				peer := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.12"), uint16(30000+os.Getpid()%20000+index*2+protocolIndex))
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var target netip.AddrPort
				if network == "tcp" {
					ln, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
					if err != nil {
						t.Fatal(err)
					}
					defer ln.Close()
					target = ln.Addr().(*net.TCPAddr).AddrPort()
					go func() {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
						_, _ = conn.Write([]byte(conn.RemoteAddr().String() + "\n"))
						_, _ = io.Copy(conn, conn)
					}()
				} else {
					pc, err := net.ListenPacket("udp4", net.JoinHostPort(address, "0"))
					if err != nil {
						t.Fatal(err)
					}
					defer pc.Close()
					target = pc.LocalAddr().(*net.UDPAddr).AddrPort()
					go func() {
						b := make([]byte, 64)
						n, source, err := pc.ReadFrom(b)
						if err != nil {
							return
						}
						_, _ = pc.WriteTo([]byte(source.String()+"\n"+string(b[:n])), source)
					}()
				}
				conn, err := m.Dial(ctx, network, target, peer)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = m.Dial(ctx, network, target, peer); !errors.Is(err, ErrTupleInUse) {
					t.Fatalf("source tuple collision was hidden: %v", err)
				}
				if _, err = conn.Write([]byte("payload")); err != nil {
					t.Fatal(err)
				}
				want := peer.String() + "\npayload"
				buf := make([]byte, len(want))
				if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != want {
					t.Fatalf("target observed/returned %q, %v", buf, err)
				}
			})
		}
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(ownershipPath(dir)); !os.IsNotExist(err) {
		t.Fatal("native ownership state not released")
	}
	listing, _ := run("iptables", "-t", "mangle", "-S")
	if strings.Contains(listing, m.owned.Chain) {
		t.Fatal("owned firewall state survived close")
	}
	rules, _ := run("ip", "-4", "rule", "show")
	if strings.Contains(rules, "lookup "+strconv.Itoa(m.owned.Table)) {
		t.Fatal("owned route rule survived close")
	}
}
func TestNativeManagersCannotShareKernelTuple(t *testing.T) {
	if os.Getenv("DRAFRP_NATIVE_TEST") != "1" {
		t.Skip("requires isolated NET_ADMIN namespace")
	}
	a, err := New(Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var target netip.AddrPort
			if network == "tcp" {
				ln, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				target = ln.Addr().(*net.TCPAddr).AddrPort()
				go func() {
					c, err := ln.Accept()
					if err == nil {
						defer c.Close()
						_, _ = io.Copy(c, c)
					}
				}()
			} else {
				pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				target = pc.LocalAddr().(*net.UDPAddr).AddrPort()
			}
			peer := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.25"), uint16(30000+os.Getpid()%20000))
			conn, err := a.Dial(context.Background(), network, target, peer)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if duplicate, err := b.Dial(context.Background(), network, target, peer); !errors.Is(err, ErrTupleInUse) {
				if duplicate != nil {
					duplicate.Close()
				}
				t.Fatalf("kernel tuple collision hidden: %v", err)
			}
		})
	}
}

func TestNativeCrashHelper(t *testing.T) {
	if os.Getenv("DRAFRP_NATIVE_CRASH_CHILD") == "" {
		t.Skip("crash subprocess helper")
	}
	m, err := New(Config{StateDir: os.Getenv("DRAFRP_NATIVE_CRASH_CHILD")})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	_, err = m.Dial(context.Background(), "udp", netip.MustParseAddrPort("127.0.0.1:9"), netip.MustParseAddrPort("203.0.113.45:53001"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("native-ready\n")
	select {}
}
func TestNativeCrashRecoveryRemovesOnlyOwnedObjects(t *testing.T) {
	if os.Getenv("DRAFRP_NATIVE_TEST") != "1" {
		t.Skip("requires isolated NET_ADMIN namespace")
	}
	dir := t.TempDir()
	// A foreign chain/rule is a canary against broad cleanup.
	chain := "DFRP_TEST_FOREIGN"
	if err := fw("-N", chain); err != nil {
		t.Fatal(err)
	}
	defer fw("-X", chain)
	cmd := exec.Command(os.Args[0], "-test.run=^TestNativeCrashHelper$")
	cmd.Env = append(os.Environ(), "DRAFRP_NATIVE_CRASH_CHILD="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "native-ready" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("crash child did not start")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("crash child startup timed out")
	}
	b, err := os.ReadFile(ownershipPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var old ownedNetwork
	if err = json.Unmarshal(b, &old); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	m, err := New(Config{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	listing, _ := run("iptables", "-t", "mangle", "-S")
	if strings.Contains(listing, old.Chain) || !strings.Contains(listing, chain) {
		t.Fatal("crash recovery removed foreign state or retained old state")
	}
	rules, _ := run("ip", "-4", "rule", "show")
	if strings.Contains(rules, "lookup "+strconv.Itoa(old.Table)) {
		t.Fatal("per-flow policy route survived process death")
	}
}

func TestNativePartialInstallationAndMissingOwnershipMarker(t *testing.T) {
	if os.Getenv("DRAFRP_NATIVE_TEST") != "1" {
		t.Skip("requires isolated NET_ADMIN namespace")
	}
	m, err := New(Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	o := m.owned
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fw("-N", o.Chain); err != nil {
		t.Fatal(err)
	}
	if err := removeNetwork(o); err != nil {
		t.Fatalf("empty chain from interrupted installation was not recovered: %v", err)
	}
	if err := ip("route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(o.Table)); err != nil {
		t.Fatal(err)
	}
	if err := removeNetwork(o); err == nil {
		t.Error("missing ownership chain silently accepted orphaned routing table")
	}
	routes, _ := run("ip", "-4", "route", "show", "table", strconv.Itoa(o.Table))
	if !strings.Contains(routes, "local default dev lo") {
		t.Error("unproven routing table was changed")
	}
	if err := ip("route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(o.Table)); err != nil {
		t.Fatal(err)
	}
	if err := ip("rule", "add", "priority", strconv.Itoa(o.Priority), "fwmark", "0xda000001", "lookup", strconv.Itoa(o.Table)); err != nil {
		t.Fatal(err)
	}
	if err := removeNetwork(o); err == nil {
		t.Error("missing ownership chain silently accepted orphaned policy rule")
	}
	if err := ip("rule", "del", "priority", strconv.Itoa(o.Priority), "lookup", strconv.Itoa(o.Table)); err != nil {
		t.Fatalf("unproven policy rule was changed: %v", err)
	}
	if err := removeNetwork(o); err != nil {
		t.Fatalf("already-clean interrupted installation failed: %v", err)
	}
}

func TestNativeUDPWrongSourceCannotBypassEdge(t *testing.T) {
	localIP := os.Getenv("DRAFRP_NATIVE_LOCAL_IP")
	if os.Getenv("DRAFRP_NATIVE_TEST") != "1" || localIP == "" {
		t.Skip("requires isolated NET_ADMIN namespace with an interface address")
	}
	m, err := New(Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	target := origin.LocalAddr().(*net.UDPAddr).AddrPort()
	peer := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.83"), uint16(30000+os.Getpid()%20000))
	conn, err := m.Dial(context.Background(), "udp", target, peer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Broad UDP return capture has one owner for each peer/target-port pair,
	// even when two local targets use different destination IP addresses.
	other := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), target.Port())
	if duplicate, err := m.Dial(context.Background(), "udp", other, peer); !errors.Is(err, ErrTupleInUse) {
		if duplicate != nil {
			duplicate.Close()
		}
		t.Fatalf("overlapping UDP capture accepted: %v", err)
	}
	second, err := New(Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if duplicate, err := second.Dial(context.Background(), "udp", other, peer); !errors.Is(err, ErrTupleInUse) {
		if duplicate != nil {
			duplicate.Close()
		}
		t.Fatalf("separate manager bypassed exclusive UDP source bind: %v", err)
	}
	competingRules, err := run("iptables", "-w", "2", "-t", "mangle", "-S", second.owned.Chain)
	if err != nil || strings.Contains(competingRules, "drafrp-flow:") || strings.Contains(competingRules, "drafrp-guard:") {
		t.Fatalf("failed competing bind installed return rules over live flow: %s %v", competingRules, err)
	}
	wrong, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(localIP), target.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err := wrong.WriteToUDPAddrPort([]byte("must-not-escape"), peer); err != nil && !errors.Is(err, syscall.EPERM) {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 64)); err == nil {
		t.Fatal("wrong target source was accepted")
	}
	listing, err := run("iptables", "-w", "2", "-t", "mangle", "-L", m.owned.Chain, "-v", "-n", "-x")
	if err != nil {
		t.Fatal(err)
	}
	dropped := false
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 2 && fields[2] == "DROP" && fields[0] == "1" {
			dropped = true
		}
	}
	if !dropped {
		t.Fatalf("wrong source escaped owned DROP rule: %s", listing)
	}
	if _, err := origin.WriteToUDPAddrPort([]byte("valid-reply"), peer); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	if err != nil || string(buffer[:n]) != "valid-reply" {
		t.Fatalf("valid reply failed after wrong-source packet: %q %v", buffer[:n], err)
	}
}

func TestNativeRemoteTarget(t *testing.T) {
	if os.Getenv("DRAFRP_NATIVE_TARGET") != "1" {
		t.Skip("LAN target helper")
	}
	bindIP := os.Getenv("DRAFRP_NATIVE_BIND")
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(bindIP, "38081"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pc, err := net.ListenPacket("udp4", net.JoinHostPort(bindIP, "38082"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if badSource := os.Getenv("DRAFRP_NATIVE_BAD_SOURCE"); badSource != "" {
		request, err := net.ListenPacket("udp4", "127.0.0.1:38083")
		if err != nil {
			t.Fatal(err)
		}
		defer request.Close()
		response, err := net.ListenPacket("udp4", net.JoinHostPort(badSource, "38083"))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Close()
		go func() {
			data := make([]byte, 128)
			for {
				n, peer, err := request.ReadFrom(data)
				if err != nil {
					return
				}
				_, _ = response.WriteTo(data[:n], peer)
				_, _ = os.Stdout.WriteString("wrong-source-reply-attempted\n")
			}
		}()
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.WriteString(conn, conn.RemoteAddr().String()+"|")
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	go func() {
		data := make([]byte, 65507)
		for {
			n, source, err := pc.ReadFrom(data)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte(source.String()+"|"), data[:n]...), source)
		}
	}()
	_, _ = os.Stdout.WriteString("target-ready\n")
	select {}
}
func TestNativeRemoteReturnPathAndUDPFragments(t *testing.T) {
	remote := os.Getenv("DRAFRP_NATIVE_REMOTE_IP")
	if os.Getenv("DRAFRP_NATIVE_TEST") != "1" || remote == "" {
		t.Skip("requires separate LAN target namespace and explicit return route")
	}
	m, err := New(Config{StateDir: t.TempDir(), ReturnCIDRs: []string{remote + "/32"}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for i, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			port := uint16(38081 + i)
			peer := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.65"), uint16(30000+os.Getpid()%20000))
			target := netip.AddrPortFrom(netip.MustParseAddr(remote), port)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := m.Dial(ctx, network, target, peer)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			payload := bytes.Repeat([]byte("native-LAN-UDP-fragmentation"), 2200)
			if _, err = conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			want := append([]byte(peer.String()+"|"), payload...)
			buf := make([]byte, len(want))
			if _, err = io.ReadFull(conn, buf); err != nil || !bytes.Equal(buf, want) {
				t.Fatalf("LAN peer tuple/payload incorrect: bytes=%d err=%v", len(buf), err)
			}
		})
	}
}

func TestTransparentRemoteRequiresExplicitReturnScope(t *testing.T) {
	if os.Getenv("DRAFRP_NATIVE_TEST") != "1" {
		t.Skip("requires an isolated NET_ADMIN namespace")
	}
	m, err := New(Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	_, err = m.Dial(context.Background(), "tcp", netip.MustParseAddrPort("192.0.2.10:80"), netip.MustParseAddrPort("203.0.113.1:50000"))
	if err == nil || !strings.Contains(err.Error(), "native_return_route_required") {
		t.Fatalf("undeclared remote return path accepted: %v", err)
	}
}
