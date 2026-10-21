package limiter

import (
	"context"
	"drafrp/internal/model"
	"sync"
	"testing"
	"time"
)

func TestRatesCreditAndRenewal(t *testing.T) {
	g := model.Grant{BaseBPS: 8000, PeakBPS: -1, BurstBytes: 1000, ExpiresAt: time.Now().Add(time.Minute)}
	b := New(g)
	if !b.Allow(1000) || b.Allow(100) {
		t.Fatal("base allowance must be 1000 bytes, not 8000")
	}
	b.Update(g)
	if b.Allow(100) {
		t.Fatal("renewal refilled exhausted credit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if b.WaitContext(ctx, 500) {
		t.Fatal("large request ignored cancellation")
	}
	g.BaseBPS, g.PeakBPS = -1, 8000
	b = New(g)
	if b.Allow(20) || !b.Allow(10) {
		t.Fatal("peak pacing bucket was bypassed")
	}
	start := time.Now()
	if !b.WaitContext(context.Background(), 100) || time.Since(start) < 65*time.Millisecond {
		t.Fatal("peak did not pace emitted bytes")
	}
	for _, rate := range []int64{0, -1} {
		b = New(model.Grant{BaseBPS: rate, PeakBPS: rate})
		if got := b.Allow(1); got != (rate == -1) {
			t.Fatalf("rate %d allowed=%v", rate, got)
		}
	}
	b = New(model.Grant{BaseBPS: -1, PeakBPS: -1, ExpiresAt: time.Now().Add(-time.Second)})
	if b.Allow(1) {
		t.Fatal("expired unlimited grant remained usable")
	}
}

func TestSharedConcurrencyAndNoRenewalRefill(t *testing.T) {
	c := NewConnections(7)
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() { defer wg.Done(); c.Acquire() }()
	}
	wg.Wait()
	if c.Count() != 7 {
		t.Fatalf("active=%d", c.Count())
	}
	c.Update(2)
	if c.Acquire() {
		t.Fatal("lowering cap permitted another flow")
	}
	for range 7 {
		c.Release()
	}
	c.Update(0)
	if c.Acquire() {
		t.Fatal("zero cap allowed flow")
	}
	c.Update(-1)
	if !c.Acquire() {
		t.Fatal("unlimited cap denied flow")
	}
	f := NewFlows(2)
	if !f.Allow() || !f.Allow() || f.Allow() {
		t.Fatal("new flow rate not enforced")
	}
	f.Update(2)
	if f.Allow() {
		t.Fatal("renewal replenished new-flow bucket")
	}
	f.Update(0)
	if f.Allow() {
		t.Fatal("zero new-flow rate allowed flow")
	}
}

func TestAvailableByteAccountingAndPartialQuantum(t *testing.T) {
	b := &Bucket{rate: 1, peak: -1, capacity: 10, quantum: 10, tokens: 1.75, last: time.Now(), expires: time.Now().Add(time.Minute)}
	n, wait, ok := b.TakeAvailable(1000)
	if !ok || wait != 0 || n != 1 {
		t.Fatalf("whole available byte was unnecessarily blocked: %d %v %v", n, wait, ok)
	}
	b.mu.Lock()
	tokens := b.tokens
	b.mu.Unlock()
	if tokens < 0.74 || tokens > 0.85 {
		t.Fatalf("fractional token credit lost: %f", tokens)
	}
	if b.WaitContext(context.Background(), -1) {
		t.Fatal("negative byte request accepted")
	}
}

func TestBurstFallsBackToBaseAndCannotRenewCredit(t *testing.T) {
	g := model.Grant{BaseBPS: 8000, PeakBPS: 16000, BurstBytes: 1000, ExpiresAt: time.Now().Add(time.Minute)}
	b := New(g)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	start := time.Now()
	if !b.WaitContext(ctx, 2000) {
		t.Fatal("initial burst failed")
	}
	burstDuration := time.Since(start)
	if burstDuration < 850*time.Millisecond {
		t.Fatal("burst exceeded peak", burstDuration)
	}
	// Renewing the same authority must not refill its depleted burst bucket.
	b.Update(g)
	start = time.Now()
	if !b.WaitContext(ctx, 1000) {
		t.Fatal("base progress after burst failed")
	}
	if elapsed := time.Since(start); elapsed < 850*time.Millisecond {
		t.Fatal("renewal or peak bypassed sustainable base", elapsed)
	}
	g.PeakBPS, g.BurstBytes = g.BaseBPS, 0
	b = New(g)
	start = time.Now()
	if !b.WaitContext(ctx, 500) || time.Since(start) < 440*time.Millisecond {
		t.Fatal("disabled burst exceeded base bandwidth")
	}
}
