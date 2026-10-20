//go:build linux

package shaping

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOwnershipSignature(t *testing.T) {
	for s, want := range map[string]int64{"16000b/1": 16000, "64Kb/1": 65536, "1Mb/4": 1 << 20} {
		got, err := burstSize(s)
		if err != nil || got != want {
			t.Fatalf("%s: %d %v", s, got, err)
		}
	}
	o := ownership{Owner: "0001abcdef0123456789abcdef012345", Handle: "1:", Boot: "boot", Namespace: "net:[1]", Interface: "eth0", Index: 3, RateBPS: 8_000_000, BurstBytes: 16000, LatencyUS: 100000}
	if !validOwnership(o) {
		t.Fatal("valid canonical handle rejected")
	}
	q := qdisc{Kind: "tbf", Handle: "1:", Root: true, Options: json.RawMessage(`{"rate":1000000,"burst":"16000b/1","lat":100000}`)}
	if !matches(q, o) {
		t.Fatal("pending install cannot recover its exact intended qdisc")
	}
	q.Handle = "2:"
	if matches(q, o) {
		t.Fatal("foreign handle accepted")
	}
	q.Handle = "1:"
	q.Options = json.RawMessage(`{"rate":2000000,"burst":"16000b/1","lat":100000}`)
	if matches(q, o) {
		t.Fatal("changed rate accepted")
	}
}

// This opt-in test requires a disposable, dedicated network namespace. It never
// runs merely because the process has root privileges or an eth0 interface.
func TestLinuxWireLifecycleAndTraffic(t *testing.T) {
	iface := os.Getenv("DRAFRP_TEST_SHAPING_INTERFACE")
	if iface == "" {
		t.Skip("set DRAFRP_TEST_SHAPING_INTERFACE in an isolated NET_ADMIN namespace")
	}
	q, err := root(iface)
	if err != nil {
		t.Fatal(err)
	}
	if !kernelDefault(q) {
		t.Fatal("test requires a default root qdisc")
	}
	c := Config{Interface: iface, DedicatedInterface: true, StateDir: t.TempDir(), RateBPS: 8_000_000, BurstBytes: 16000, Latency: 100 * time.Millisecond}
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if _, err = New(c); err == nil {
		t.Fatal("concurrent state owner accepted")
	}
	if target := os.Getenv("DRAFRP_TEST_SHAPING_TARGET"); target != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		before := m.Status()
		b, err := exec.CommandContext(ctx, "iperf3", "-c", target, "-J", "-t", "5", "-O", "1", "-P", "2").CombinedOutput()
		if err != nil {
			t.Fatalf("iperf: %v %s", err, b)
		}
		var result struct {
			End struct {
				Sent struct {
					BPS float64 `json:"bits_per_second"`
				} `json:"sum_sent"`
			} `json:"end"`
		}
		if err = json.Unmarshal(b, &result); err != nil {
			t.Fatal(err)
		}
		if result.End.Sent.BPS > 9_500_000 || result.End.Sent.BPS < 4_000_000 {
			t.Fatalf("aggregate egress rate outside bounded 8Mbps window: %.0f", result.End.Sent.BPS)
		}
		m.refresh()
		after := m.Status()
		if after.TXBytes <= before.TXBytes || after.RXBytes <= before.RXBytes {
			t.Fatal("interface physical counters did not advance")
		}
		t.Logf("two TCP streams aggregate %.0f bit/s; interface tx delta %d bytes", result.End.Sent.BPS, after.TXBytes-before.TXBytes)
	}
	// Simulate process death: retain durable evidence and the qdisc, releasing
	// only the process-local monitor and advisory lock.
	close(m.stop)
	<-m.done
	_ = unix.Flock(int(m.lock.Fd()), unix.LOCK_UN)
	_ = m.lock.Close()
	m.once.Do(func() {})
	m, err = New(c)
	if err != nil {
		t.Fatalf("crash recovery: %v", err)
	}
	if !m.Status().Enforced {
		t.Fatal("recovered limiter not verified")
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(c.StateDir, "wire-shaping.json")); !os.IsNotExist(err) {
		t.Fatal("ownership state not cleared")
	}
	q, err = root(iface)
	if err != nil || !kernelDefault(q) {
		t.Fatalf("default qdisc not restored: %+v %v", q, err)
	}
	if _, err = tc("qdisc", "add", "dev", iface, "root", "handle", "baba:", "tbf", "rate", "16000000bit", "burst", "16000", "latency", "100ms"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = tc("qdisc", "del", "dev", iface, "root", "handle", "baba:") })
	if _, err = New(c); err == nil {
		t.Fatal("foreign root qdisc was overwritten")
	}
	q, err = root(iface)
	if err != nil || q.Handle != "baba:" {
		t.Fatal("foreign qdisc changed")
	}
	if _, err = tc("qdisc", "del", "dev", iface, "root", "handle", "baba:"); err != nil {
		t.Fatal(err)
	}
	m, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tc("qdisc", "del", "dev", iface, "root", "handle", m.owned.Handle); err != nil {
		t.Fatal(err)
	}
	if _, err = tc("qdisc", "add", "dev", iface, "root", "handle", "baba:", "tbf", "rate", "16000000bit", "burst", "16000", "latency", "100ms"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.Failed():
	case <-time.After(3 * time.Second):
		t.Fatal("qdisc tamper was not detected")
	}
	if m.Status().Enforced {
		t.Fatal("foreign replacement reported as wire enforced")
	}
	if m.Close() == nil {
		t.Fatal("cleanup accepted a foreign replacement")
	}
	q, err = root(iface)
	if err != nil || q.Handle != "baba:" {
		t.Fatal("cleanup removed foreign replacement")
	}
}
