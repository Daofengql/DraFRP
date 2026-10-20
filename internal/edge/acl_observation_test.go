package edge

import (
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func aclReportForTest(r *Runtime) *model.ACLReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aclReportLocked()
}

func TestACLObservationRealIngressCountsAndVersion(t *testing.T) {
	allow := &model.ACLPolicy{Version: 7, DefaultAction: "deny", Entries: []model.ACLEntry{{ID: "loopback-entry", Action: "allow", CIDRs: []string{"127.0.0.0/8"}}}}
	f := fixture(t, model.Rule{ID: "tcp", Protocol: "tcp", ACL: allow}, model.Rule{ID: "udp", Protocol: "udp", ACL: allow})
	f.agent(t, func(stream protocol.Stream, flow protocol.Flow) {
		if protocol.WriteJSON(stream, protocol.Result{}) != nil {
			return
		}
		if flow.Protocol == "udp" {
			for {
				packet, err := protocol.ReadPacket(stream)
				if err != nil {
					return
				}
				if protocol.WritePacket(stream, packet) != nil {
					return
				}
			}
		}
		_, _ = io.Copy(stream, stream)
	})
	tcp, err := net.Dial("tcp", f.address(0))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(time.Second))
	_, _ = tcp.Write([]byte("a"))
	var b [1]byte
	if _, err = io.ReadFull(tcp, b[:]); err != nil {
		t.Fatal(err)
	}
	udp, err := net.Dial("udp", f.address(1))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	for range 3 {
		_ = udp.SetDeadline(time.Now().Add(time.Second))
		_, _ = udp.Write([]byte("b"))
		if _, err = udp.Read(b[:]); err != nil {
			t.Fatal(err)
		}
	}
	report := aclReportForTest(f.r)
	check := func(report *model.ACLReport, version uint64, wantTCP, wantUDP, denyTCP, denyUDP uint64) {
		t.Helper()
		var ta, ua, td, ud uint64
		for _, row := range report.Rows {
			if row.RuleVersion != version {
				continue
			}
			if row.Kind == "rule_total" {
				if row.Protocol == "tcp" {
					ta += row.Allowed
					td += row.Denied
				} else {
					ua += row.Allowed
					ud += row.Denied
				}
			}
		}
		if ta != wantTCP || ua != wantUDP || td != denyTCP || ud != denyUDP {
			t.Fatalf("counts TCP %d/%d UDP %d/%d, report=%+v", ta, td, ua, ud, report)
		}
	}
	check(report, 1, 1, 3, 0, 0) // Creating a UDP mapping must not count its first packet twice.
	var entryHits uint64
	for _, row := range report.Rows {
		if row.Kind == "policy" {
			if row.EntryID != "loopback-entry" || row.UsedDefault || row.EntryHash != acl.Digest("loopback-entry") {
				t.Fatal(row)
			}
			entryHits += row.Allowed
		}
	}
	if entryHits != 4 {
		t.Fatal("entry counter differs", entryHits)
	}
	// Simulation and background reconciliation use the unobserved evaluator.
	f.r.mu.Lock()
	for _, rr := range f.r.rules {
		for range 5 {
			rr.allow(netip.MustParseAddrPort("127.0.0.1:50000"))
		}
	}
	f.r.reconcileLocked()
	f.r.mu.Unlock()
	check(aclReportForTest(f.r), 1, 1, 3, 0, 0)
	for i := range f.s.Rules {
		f.s.Rules[i].Version = 2
		f.s.Rules[i].ACL = &model.ACLPolicy{Version: 8, DefaultAction: "deny"}
	}
	f.s.Revision++
	if err = f.r.apply(f.s); err != nil {
		t.Fatal(err)
	}
	// Old TCP/UDP flows were canceled before the ACK was made available.
	eventually(t, func() bool { return f.r.FlowCount() == 0 })
	denied, err := net.Dial("tcp", f.address(0))
	if err != nil {
		t.Fatal(err)
	}
	_ = denied.SetDeadline(time.Now().Add(time.Second))
	_, _ = denied.Write([]byte("x"))
	if _, err = denied.Read(b[:]); err == nil {
		t.Fatal("denied TCP echoed")
	}
	_ = denied.Close()
	_ = udp.SetDeadline(time.Now().Add(120 * time.Millisecond))
	_, _ = udp.Write([]byte("x"))
	if _, err = udp.Read(b[:]); err == nil {
		t.Fatal("denied UDP echoed")
	}
	report = aclReportForTest(f.r)
	check(report, 2, 0, 0, 1, 1)
	defaults := 0
	for _, row := range report.Rows {
		if row.RuleVersion == 2 && row.Kind == "policy" {
			if !row.UsedDefault || row.Denied != 1 {
				t.Fatal(row)
			}
			defaults++
		}
	}
	if defaults != 2 {
		t.Fatal("default denials missing", report)
	}
	for _, ack := range report.ACKs {
		if ack.State != "applied" || ack.RuleVersion != 2 || ack.ActiveFlows != 0 {
			t.Fatal("ACK not actual current version", ack)
		}
	}
	f.r.mu.Lock()
	f.r.acknowledgeACLLocked(report)
	f.r.mu.Unlock()
	for _, row := range aclReportForTest(f.r).Rows {
		if row.RuleVersion == 1 {
			t.Fatal("retired acknowledged counters kept forever")
		}
	}
}

func TestACLObservationBoundedAndHTTPExcluded(t *testing.T) {
	r := New(Config{EdgeID: "test"})
	defer r.Close()
	r.aclMetrics = newACLMetrics()
	for i := 0; i < aclCounterCapacity+15; i++ {
		r.aclMetrics.add(model.ACLHit{RuleID: fmt.Sprint(i), Kind: "rule_total"}, true)
	}
	if len(r.aclMetrics.rows) != aclCounterCapacity || r.aclMetrics.dropped != 15 {
		t.Fatal("collector unbounded")
	}
	rr := &ruleRuntime{rule: model.Rule{ID: "http", Protocol: "http"}}
	_ = r.allowObservedACL(rr, netip.MustParseAddrPort("192.0.2.1:50000"))
	if r.aclMetrics.dropped != 15 {
		t.Fatal("HTTP polluted counters")
	}
	seen := map[string]bool{}
	for range 20 {
		report := aclReportForTest(r)
		if len(report.Rows) > 256 || len(report.ACKs) > 16 {
			t.Fatal("batch unbounded")
		}
		for _, row := range report.Rows {
			seen[row.RuleID] = true
		}
	}
	if len(seen) != aclCounterCapacity {
		t.Fatal("rotating batches starved labels", len(seen))
	}
	// A new Runtime has independent cumulative counters and report sequence.
	other := newACLMetrics()
	if len(other.rows) != 0 || other.sequence != 0 || other.dropped != 0 {
		t.Fatal("boot inherited counters")
	}
	snapshot := model.EdgeSnapshot{Revision: 99, ExpiresAt: time.Now().Add(time.Minute)}
	for i := 0; i < 5000; i++ {
		snapshot.Rules = append(snapshot.Rules, model.Rule{ID: fmt.Sprint(i), Protocol: "tcp", Version: 1})
	}
	r.failedACLApply(snapshot, errors.New("rejected snapshot"))
	if len(r.aclMetrics.acks) > aclCounterCapacity {
		t.Fatal("failure ACK map unbounded")
	}
	for _, ack := range aclReportForTest(r).ACKs {
		if ack.State != "error" || ack.Error == "" {
			t.Fatal("failed apply claimed success", ack)
		}
	}
}
