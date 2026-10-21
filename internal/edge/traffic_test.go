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
