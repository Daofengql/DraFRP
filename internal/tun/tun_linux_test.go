//go:build linux

package tun

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
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

func privileged(t *testing.T) {
	t.Helper()
	if os.Getenv("DRAFRP_TUN_TEST") != "1" {
		t.Skip("requires an explicitly isolated Linux TUN/NET_ADMIN namespace")
	}
}
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	m, e := New(Config{StateDir: dir})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Error(e)
		}
	})
	return m
}
func TestTUNKernelIdentityScopeAndTupleOwnership(t *testing.T) {
	privileged(t)
	m := newTestManager(t)
	if len(m.Capabilities()) != 4 {
		t.Fatal("capabilities were not verified")
	}
	peer := netip.MustParseAddrPort("203.0.113.65:39231")
	if _, e := m.Open("udp", netip.MustParseAddrPort("192.0.2.1:38082"), peer); e == nil || !strings.Contains(e.Error(), "tun_return_route_required") {
		t.Fatalf("undeclared LAN target accepted: %v", e)
	}
	addresses := []string{"127.0.0.1"}
	if extra := os.Getenv("DRAFRP_TUN_LOCAL_IP"); extra != "" {
		addresses = append(addresses, extra)
	}
	for _, address := range addresses {
		t.Run(address, func(t *testing.T) {
			origin, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(address)})
			if e != nil {
				t.Fatal(e)
			}
			defer origin.Close()
			target := origin.LocalAddr().(*net.UDPAddr).AddrPort()
			f, e := m.Open("udp", target, peer)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			if _, e = m.Open("udp", target, peer); e == nil {
				t.Fatal("duplicate tuple accepted")
			}
			other := newTestManager(t)
			if _, e = other.Open("udp", target, peer); e == nil || !strings.Contains(e.Error(), "tuple_conflict") {
				t.Fatalf("another process could steal the kernel tuple: %v", e)
			}
			for _, payload := range [][]byte{nil, []byte("payload"), bytes.Repeat([]byte("x"), 60000)} {
				if e = m.Inject(udpPacket(peer, target, payload)); e != nil {
					t.Fatal(e)
				}
				_ = origin.SetDeadline(time.Now().Add(2 * time.Second))
				b := make([]byte, MaxPacketSize)
				n, from, e := origin.ReadFromUDPAddrPort(b)
				if e != nil || from != peer || !bytes.Equal(b[:n], payload) {
					t.Fatalf("kernel source/payload mismatch: %v %v", from, e)
				}
				if _, e = origin.WriteToUDPAddrPort(b[:n], from); e != nil {
					t.Fatal(e)
				}
				select {
				case raw := <-f.Packets:
					p, e := Parse(raw)
					if e != nil || p.Source != target || p.Dest != peer || !bytes.Equal(raw[p.Header+p.Transport:], payload) {
						t.Fatalf("return mismatch: %v", e)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("return timed out")
				}
			}
		})
	}
	owned := m.owned
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(statePath(m.cfg.StateDir)); !os.IsNotExist(e) {
		t.Fatal("ownership record survived cleanup")
	}
	listing, _ := run("ip", "-4", "rule", "show")
	if strings.Contains(listing, "lookup "+strconv.Itoa(owned.Table)) {
		t.Fatal("policy rule survived cleanup")
	}
	if _, e := os.Stat("/sys/class/net/" + owned.Interface); !os.IsNotExist(e) {
		t.Fatal("TUN link survived cleanup")
	}
}
func TestTUNLinkFailureWithdrawsCapabilities(t *testing.T) {
	privileged(t)
	m := newTestManager(t)
	if _, e := run("ip", "link", "delete", "dev", m.owned.Interface); e != nil {
		t.Fatal(e)
	}
	select {
	case <-m.Failed():
	case <-time.After(time.Second):
		t.Fatal("link failure was not detected")
	}
	if len(m.Capabilities()) != 0 {
		t.Fatal("failed TUN still advertised")
	}
	if _, e := m.Open("udp", netip.MustParseAddrPort("127.0.0.1:80"), netip.MustParseAddrPort("203.0.113.1:30303")); e == nil {
		t.Fatal("failed path admitted flow")
	}
}
func TestTUNLinkDownWithdrawsCapabilities(t *testing.T) {
	privileged(t)
	m := newTestManager(t)
	if _, e := run("ip", "link", "set", "dev", m.owned.Interface, "down"); e != nil {
		t.Fatal(e)
	}
	select {
	case <-m.Failed():
	case <-time.After(time.Second):
		t.Fatal("down interface still advertised")
	}
}
func TestTUNReturnGuardDropsRoutingBypass(t *testing.T) {
	privileged(t)
	m := newTestManager(t)
	origin, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer origin.Close()
	peer := netip.MustParseAddrPort("203.0.113.44:39045")
	f, e := m.Open("udp", origin.LocalAddr().(*net.UDPAddr).AddrPort(), peer)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = ip(append([]string{"rule", "del"}, m.routeArgs(f.t)...)...); e != nil {
		t.Fatal(e)
	}
	if _, e = origin.WriteToUDPAddrPort([]byte("must-not-bypass-tun"), peer); e != nil && !errors.Is(e, unix.EPERM) {
		t.Fatal(e)
	}
	listing, e := run("iptables", "-t", "filter", "-nvxL", "OUTPUT")
	if e != nil {
		t.Fatal(e)
	}
	matched := false
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if strings.Contains(line, m.marker()) && len(fields) > 2 && fields[0] != "0" && fields[2] == "DROP" {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("return bypass was not dropped: %s", listing)
	}
}
func TestTUNMissingPrivilegesLeaveNoOwnedNetwork(t *testing.T) {
	privileged(t)
	if os.Getenv("DRAFRP_TUN_UNPRIVILEGED_CHILD") == "1" {
		m, e := New(Config{StateDir: os.Getenv("DRAFRP_TUN_UNPRIVILEGED_DIR")})
		if e == nil {
			m.Close()
			t.Fatal("unprivileged TUN unexpectedly succeeded")
		}
		return
	}
	dir, e := os.MkdirTemp("", "drafrp-tun-permission-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	if e = os.Chown(dir, 65534, 65534); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTUNMissingPrivilegesLeaveNoOwnedNetwork$")
	cmd.Env = append(os.Environ(), "DRAFRP_TUN_UNPRIVILEGED_CHILD=1", "DRAFRP_TUN_UNPRIVILEGED_DIR="+dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("unprivileged child: %s %v", b, e)
	}
	if _, e = os.Stat(statePath(dir)); !os.IsNotExist(e) {
		t.Fatal("unprivileged startup left a network ownership record")
	}
}
func TestTUNCrashRecoveryAndForeignObjects(t *testing.T) {
	privileged(t)
	if dir := os.Getenv("DRAFRP_TUN_CRASH_CHILD"); dir != "" {
		m, e := New(Config{StateDir: dir})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = m.Open("udp", netip.MustParseAddrPort("127.0.0.1:39191"), netip.MustParseAddrPort("203.0.113.9:39192")); e != nil {
			t.Fatal(e)
		}
		os.Exit(0) // Deliberate abrupt exit: no cleanup, like process death.
	}
	const canary = "drafrp_tun_qa_canary"
	if e := fw("filter", "-N", canary); e != nil {
		t.Fatal(e)
	}
	defer fw("filter", "-X", canary)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTUNCrashRecoveryAndForeignObjects$")
	cmd.Env = append(os.Environ(), "DRAFRP_TUN_CRASH_CHILD="+dir)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("crash child: %s %v", b, e)
	}
	var old ownership
	b, e := os.ReadFile(statePath(dir))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &old); e != nil {
		t.Fatal(e)
	}
	m, e := New(Config{StateDir: dir})
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	rules, _ := run("ip", "-4", "rule", "show")
	if strings.Contains(rules, "lookup "+strconv.Itoa(old.Table)) {
		t.Fatal("crashed process policy survived recovery")
	}
	if _, e = run("iptables", "-t", "filter", "-S", canary); e != nil {
		t.Fatal("unrelated canary was removed")
	}
}
