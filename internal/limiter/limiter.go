// Package limiter enforces renewable, shared edge-local resource budgets.
// Rates use bits/second at the API boundary; -1 means unlimited and 0 denies.
package limiter

import (
	"context"
	"drafrp/internal/model"
	"sync"
	"time"
)

// Bucket preserves credit across grant renewal. The base bucket bounds bytes
// by R*t+B, and a second bucket enforces the configured peak rate.
type Bucket struct {
	mu                                                sync.Mutex
	rate, peak, capacity, tokens, peakTokens, quantum float64
	last                                              time.Time
	expires                                           time.Time
}

func New(g model.Grant) *Bucket { b := &Bucket{last: time.Now()}; b.update(g, true); return b }
func (b *Bucket) refill(now time.Time) {
	dt := max(0, now.Sub(b.last).Seconds())
	b.last = now
	if b.rate > 0 {
		b.tokens = min(b.capacity, b.tokens+b.rate*dt)
	}
	if b.peak > 0 {
		b.peakTokens = min(b.quantum, b.peakTokens+b.peak*dt)
	}
}
func (b *Bucket) update(g model.Grant, initial bool) {
	b.refill(time.Now())
	b.rate = float64(g.BaseBPS) / 8
	b.peak = float64(g.PeakBPS) / 8
	b.capacity = float64(max(0, g.BurstBytes))
	b.quantum = 1024
	// A small packetization tolerance permits paced progress with zero burst.
	if b.rate > 0 {
		b.quantum = min(1024, max(1, b.rate/100))
		b.capacity = max(b.capacity, b.quantum)
	}
	if b.peak > 0 {
		b.quantum = min(b.quantum, max(1, b.peak/100))
	}
	if initial {
		b.tokens = b.capacity
		b.peakTokens = b.quantum
	} else {
		b.tokens = min(b.tokens, b.capacity)
		b.peakTokens = min(b.peakTokens, b.quantum)
	}
	b.expires = g.ExpiresAt
}
func (b *Bucket) Update(g model.Grant) { b.mu.Lock(); defer b.mu.Unlock(); b.update(g, false) }
func (b *Bucket) allowance(n int) (int, time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.refill(now)
	if n < 0 {
		return 0, 0, false
	}
	if n == 0 {
		return 0, 0, true
	}
	if (!b.expires.IsZero() && !now.Before(b.expires)) || b.rate == 0 || b.peak == 0 {
		return 0, 0, false
	}
	size := float64(n)
	if b.rate > 0 {
		size = min(size, b.capacity)
	}
	if b.peak > 0 {
		size = min(size, b.quantum)
	}
	// Count whole emitted bytes. Fractional pacing credit must not be debited
	// while the caller receives only the truncated integer byte count.
	size = float64(max(1, int(size)))
	available := size
	if b.rate > 0 {
		available = min(available, b.tokens)
	}
	if b.peak > 0 {
		available = min(available, b.peakTokens)
	}
	if available >= 1 {
		size = float64(int(available))
	} else {
		size = 1
	}
	delay := 0.0
	if b.rate > 0 && b.tokens < size {
		delay = max(delay, (size-b.tokens)/b.rate)
	}
	if b.peak > 0 && b.peakTokens < size {
		delay = max(delay, (size-b.peakTokens)/b.peak)
	}
	if delay > 0 {
		return 0, time.Duration(delay*float64(time.Second)) + time.Microsecond, true
	}
	if b.rate > 0 {
		b.tokens -= size
	}
	if b.peak > 0 {
		b.peakTokens -= size
	}
	return int(size), 0, true
}

// TakeAvailable reserves at most one pacing quantum without waiting. Shared
// schedulers can rotate accounts between quanta instead of blocking all other
// accounts behind one large request.
func (b *Bucket) TakeAvailable(n int) (int, time.Duration, bool) { return b.allowance(n) }
func (b *Bucket) WaitContext(ctx context.Context, n int) bool {
	if n < 0 {
		return false
	}
	for n > 0 {
		taken, delay, ok := b.allowance(n)
		if !ok {
			return false
		}
		n -= taken
		if delay > 0 {
			timer := time.NewTimer(min(delay, 100*time.Millisecond))
			select {
			case <-ctx.Done():
				timer.Stop()
				return false
			case <-timer.C:
			}
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
	}
	return true
}
func (b *Bucket) Allow(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.refill(now)
	if (!b.expires.IsZero() && !now.Before(b.expires)) || b.rate == 0 || b.peak == 0 {
		return false
	}
	v := float64(n)
	if n < 0 || (b.rate > 0 && b.tokens < v) || (b.peak > 0 && b.peakTokens < v) {
		return false
	}
	if b.rate > 0 {
		b.tokens -= v
	}
	if b.peak > 0 {
		b.peakTokens -= v
	}
	return true
}
func (b *Bucket) Wait(n int, deadline time.Time) bool {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	return b.WaitContext(ctx, n)
}

type Connections struct {
	mu     sync.Mutex
	max, n int
}

func NewConnections(maximum int) *Connections { return &Connections{max: maximum} }
func (c *Connections) Update(maximum int)     { c.mu.Lock(); c.max = maximum; c.mu.Unlock() }
func (c *Connections) Acquire() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max >= 0 && c.n >= c.max {
		return false
	}
	c.n++
	return true
}
func (c *Connections) Release() {
	c.mu.Lock()
	if c.n > 0 {
		c.n--
	}
	c.mu.Unlock()
}
func (c *Connections) Count() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

type Flows struct {
	mu     sync.Mutex
	rate   int
	tokens float64
	last   time.Time
}

func NewFlows(rate int) *Flows {
	return &Flows{rate: rate, tokens: float64(max(0, rate)), last: time.Now()}
}
func (f *Flows) Update(rate int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refill()
	f.rate = rate
	f.tokens = min(f.tokens, float64(max(0, rate)))
}
func (f *Flows) refill() {
	now := time.Now()
	f.tokens = min(float64(max(0, f.rate)), f.tokens+max(0, now.Sub(f.last).Seconds())*float64(max(0, f.rate)))
	f.last = now
}
func (f *Flows) Allow() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refill()
	if f.rate < 0 {
		return true
	}
	if f.tokens < 1 {
		return false
	}
	f.tokens--
	return true
}
