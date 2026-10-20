// Package limiter enforces account and edge-local resource grants.
package limiter

import (
	"drafrp/internal/model"
	"sync"
	"time"
)

// Bucket is a token bucket with a finite burst credit. Bytes are charged by
// the caller once per business payload (transport overhead is not charged).
type Bucket struct {
	mu                        sync.Mutex
	rate, peak, burst, tokens float64
	last                      time.Time
	expires                   time.Time
}

func New(g model.Grant) *Bucket {
	now := time.Now()
	burst := float64(g.BurstBytes)
	if burst < 0 {
		burst = 0
	}
	return &Bucket{rate: float64(g.BaseBPS) / 8, peak: float64(g.PeakBPS) / 8, burst: burst, tokens: burst, last: now, expires: g.ExpiresAt}
}
func (b *Bucket) Allow(n int) bool {
	if n <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	dt := now.Sub(b.last).Seconds()
	if dt < 0 {
		dt = 0
	}
	b.last = now
	if !b.expires.IsZero() && now.After(b.expires) {
		return false
	}
	if b.rate <= 0 {
		return true
	}
	max := b.rate
	if b.peak > max && b.tokens > 0 {
		max = b.peak
	}
	b.tokens += max * dt
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens >= float64(n) {
		b.tokens -= float64(n)
		return true
	}
	return false
}
func (b *Bucket) Wait(n int, deadline time.Time) bool {
	for {
		if b.Allow(n) {
			return true
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type Connections struct {
	mu  sync.Mutex
	max int
	n   int
}

func NewConnections(max int) *Connections { return &Connections{max: max} }
func (c *Connections) Acquire() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max > 0 && c.n >= c.max {
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
