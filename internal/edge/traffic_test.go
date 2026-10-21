package edge

import (
	"context"
	"drafrp/internal/model"
	"testing"
	"time"
)

func TestTrafficCreditWaitRenewAndRevoke(t *testing.T) {
	g := model.Grant{ID: "budget", TenantID: "tenant", EdgeID: "edge", BootID: "boot", PeriodID: "period", Bytes: 1, BaseBPS: -1, PeakBPS: -1, MaxConnections: -1, NewFlowsPerSecond: -1, WaitForCredit: true, ExpiresAt: time.Now().Add(time.Minute)}
	b := newAccountBudget(g)
	n, err := b.reserve(1, false)
	if err != nil {
		t.Fatal(err)
	}
	b.complete(n, n, true)
	if !b.valid() || !b.acquire() {
		t.Fatal("included boundary closed renewable flow")
	}
	defer b.release()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		n, err := b.reserveContext(ctx, 2, false)
		if err == nil {
			b.complete(n, n, true)
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatal("invented local credit", err)
	case <-time.After(20 * time.Millisecond):
	}
	g.Bytes += 2
	g.BaseBPS, g.PeakBPS = 8000, 8000
	if err = b.update(g); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil || b.report().UploadBytes != 3 {
		t.Fatal("renewal failed to resume cumulative budget", err)
	}
	go func() { _, err := b.reserveContext(ctx, 1, false); done <- err }()
	b.retire()
	if err = <-done; err == nil || b.valid() {
		t.Fatal("retirement did not cancel pending credit", err)
	}
}

func TestTrafficMinuteReportKeepsPayloadBuckets(t *testing.T) {
	g := model.Grant{ID: "minute-grant", TenantID: "tenant", EdgeID: "edge", BootID: "boot", Bytes: 1 << 20, BaseBPS: -1, PeakBPS: -1, MaxConnections: -1, NewFlowsPerSecond: -1, ExpiresAt: time.Now().Add(time.Minute)}
	b := newAccountBudget(g)
	first := time.Date(2026, 10, 21, 8, 12, 20, 0, time.UTC)
	b.completeAt(10, 10, true, first)
	b.completeAt(5, 5, false, first.Add(20*time.Second))
	b.completeAt(7, 7, true, first.Add(time.Minute))
	u := b.reportAt(first.Add(time.Minute))
	if u.UploadBytes != 17 || u.DownloadBytes != 5 || len(u.Minutes) != 2 {
		t.Fatalf("unexpected cumulative minute report: %+v", u)
	}
	var firstBucket, secondBucket model.TrafficMinute
	for _, m := range u.Minutes {
		if m.UploadBytes == 10 {
			firstBucket = m
		}
		if m.UploadBytes == 7 {
			secondBucket = m
		}
	}
	if firstBucket.DownloadBytes != 5 || secondBucket.Start.IsZero() {
		t.Fatalf("minute counters were not grouped by UTC minute: %+v", u.Minutes)
	}
	if firstBucket.Start != first.Truncate(time.Minute) || secondBucket.Start != first.Add(time.Minute).Truncate(time.Minute) {
		t.Fatalf("unexpected bucket starts: %+v", u.Minutes)
	}
	// A lost response keeps both minutes. Additional payload stays cumulative.
	b.completeAt(3, 3, false, first.Add(time.Minute))
	u = b.reportAt(first.Add(time.Minute))
	if u.Minutes[1].DownloadBytes != 3 || u.DownloadBytes != 8 {
		t.Fatal("retry lost minute data", u)
	}
	b.acknowledgeMinutesAt(u, first.Add(time.Minute))
	if len(b.minutes) != 1 {
		t.Fatal("acknowledgement must remove past minutes and retain the current minute", b.minutes)
	}
	b.completeAt(4, 4, true, first.Add(time.Minute))
	u = b.reportAt(first.Add(2 * time.Minute))
	if u.Minutes[0].UploadBytes != 11 || u.Minutes[0].DownloadBytes != 3 {
		t.Fatal("current minute restarted after acknowledgement", u)
	}
	// Writes after a report must survive acknowledgement of that report.
	b.completeAt(2, 2, true, first.Add(time.Minute))
	b.acknowledgeMinutesAt(u, first.Add(2*time.Minute))
	if len(b.minutes) != 1 || b.minutes[first.Add(time.Minute).Truncate(time.Minute).Unix()].UploadBytes != 13 {
		t.Fatal("acknowledgement removed an in-flight increment", b.minutes)
	}
}

func TestTrafficMinuteMemoryIsBoundedWithoutLosingCumulativeAccounting(t *testing.T) {
	b := newAccountBudget(model.Grant{})
	start := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for i := 0; i < model.MaxTrafficMinutes+10; i++ {
		b.completeAt(1, 1, true, start.Add(time.Duration(i)*time.Minute))
	}
	u := b.reportAt(start.Add(2 * time.Hour))
	if len(u.Minutes) > model.MaxTrafficMinutes || u.UploadBytes != model.MaxTrafficMinutes+10 {
		t.Fatal("unbounded telemetry or lost accounting", u)
	}
}

func TestUDPExcessBoundaryPreservesWholePacket(t *testing.T) {
	f := fixture(t)
	f.s.Grants[0].ID = "packet-grant"
	f.s.Grants[0].Bytes = 3
	f.s.Grants[0].WaitForCredit = true
	if err := f.r.apply(f.s); err != nil {
		t.Fatal(err)
	}
	b := f.r.budgets["tenant"]
	flow := &flowState{ctx: f.ctx, budget: b, rule: model.Rule{TenantID: "tenant"}}
	sent := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- f.r.chargePacket(flow, []byte("one-packet"), true, func() error { sent <- struct{}{}; return nil })
	}()
	eventually(t, func() bool { return b.report().UploadBytes == 3 })
	select {
	case <-sent:
		t.Fatal("forwarded a packet without authority for its remainder")
	default:
	}
	f.s.Grants[0].Bytes += 100
	f.s.Grants[0].BaseBPS, f.s.Grants[0].PeakBPS = 8000, 8000
	if err := f.r.apply(f.s); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-sent:
	default:
		t.Fatal("renewal failed to send complete datagram")
	}
	if b.report().UploadBytes != int64(len("one-packet")) {
		t.Fatal("packet payload metered twice or lost")
	}
}
