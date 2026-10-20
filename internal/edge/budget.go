package edge

import (
	"context"
	"drafrp/internal/limiter"
	"drafrp/internal/model"
	"errors"
	"io"
	"sync"
	"time"
)

var errQuota = errors.New("account budget exhausted or expired")
var errCapacity = errors.New("edge capacity unavailable")

type accountBudget struct {
	mu                   sync.Mutex
	grant                model.Grant
	upload, download     int64
	held                 int64
	active               int
	retired              bool
	sequence             uint64
	upBucket, downBucket *limiter.Bucket
	conns                *limiter.Connections
	newFlows             *limiter.Flows
}

func newAccountBudget(g model.Grant) *accountBudget {
	return &accountBudget{grant: g, upBucket: limiter.New(g), downBucket: limiter.New(g), conns: limiter.NewConnections(g.MaxConnections), newFlows: limiter.NewFlows(g.NewFlowsPerSecond)}
}
func (b *accountBudget) id() string { b.mu.Lock(); defer b.mu.Unlock(); return b.grant.ID }
func (b *accountBudget) canUpdate(g model.Grant) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.renewable(g) {
		return errors.New("grant cannot be reset, shrunk or reopened")
	}
	return nil
}
func (b *accountBudget) update(g model.Grant) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.renewable(g) {
		return errors.New("grant cannot be reset, shrunk or reopened")
	}
	b.grant = g
	b.upBucket.Update(g)
	b.downBucket.Update(g)
	b.conns.Update(g.MaxConnections)
	b.newFlows.Update(g.NewFlowsPerSecond)
	return nil
}

// Called with mu held: an identifier may never be recycled across an account,
// edge process or accounting period, even when the amount of credit increases.
func (b *accountBudget) renewable(g model.Grant) bool {
	return !b.retired && g.ID == b.grant.ID && g.TenantID == b.grant.TenantID && g.EdgeID == b.grant.EdgeID && g.BootID == b.grant.BootID && g.PeriodID == b.grant.PeriodID && g.PolicyVersion >= b.grant.PolicyVersion && g.Bytes >= b.grant.Bytes
}
func (b *accountBudget) valid() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.retired && time.Now().Before(b.grant.ExpiresAt) && b.grant.Bytes > b.upload+b.download && b.grant.BaseBPS != 0 && b.grant.PeakBPS != 0
}
func (b *accountBudget) acquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.retired || !time.Now().Before(b.grant.ExpiresAt) || b.grant.Bytes <= b.upload+b.download+b.held || b.grant.BaseBPS == 0 || b.grant.PeakBPS == 0 || !b.newFlows.Allow() {
		return false
	}
	if !b.conns.Acquire() {
		return false
	}
	b.active++
	return true
}
func (b *accountBudget) release() {
	b.mu.Lock()
	if b.active > 0 {
		b.active--
		b.conns.Release()
	}
	b.mu.Unlock()
}
func (b *accountBudget) retire() { b.mu.Lock(); b.retired = true; b.mu.Unlock() }
func (b *accountBudget) reserve(n int, atomic bool) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.retired || !time.Now().Before(b.grant.ExpiresAt) {
		return 0, errQuota
	}
	left := b.grant.Bytes - b.upload - b.download - b.held
	if left <= 0 || atomic && left < int64(n) {
		return 0, errQuota
	}
	count := int(min(int64(n), left))
	b.held += int64(count)
	return count, nil
}
func (b *accountBudget) complete(reserved, written int, upload bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.held -= int64(reserved)
	if upload {
		b.upload += int64(written)
	} else {
		b.download += int64(written)
	}
}
func (b *accountBudget) report() model.Usage {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sequence++
	return model.Usage{GrantID: b.grant.ID, Sequence: b.sequence, UploadBytes: b.upload, DownloadBytes: b.download, Closed: b.retired && b.active == 0 && b.held == 0, ObservedAt: time.Now().UTC()}
}
func (b *accountBudget) isSettled(u model.Usage) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.retired && b.active == 0 && b.held == 0 && b.upload == u.UploadBytes && b.download == u.DownloadBytes
}
func (b *accountBudget) wait(ctx context.Context, n int, upload bool) bool {
	if upload {
		return b.upBucket.WaitContext(ctx, n)
	}
	return b.downBucket.WaitContext(ctx, n)
}

type meteredStream struct {
	r      *Runtime
	f      *flowState
	stream io.ReadWriteCloser
}

func (m *meteredStream) Read(p []byte) (int, error) {
	n, e := m.stream.Read(p)
	if n == 0 {
		return n, e
	}
	count, ce := m.charge(n, false, func(size int) (int, error) { return size, nil })
	if ce != nil {
		return count, ce
	}
	return count, e
}
func (m *meteredStream) Write(p []byte) (int, error) { return m.writePayload(p) }
func (m *meteredStream) charge(n int, upload bool, write func(int) (int, error)) (int, error) {
	total := 0
	for total < n {
		size := min(n-total, 16<<10)
		reserved, e := m.f.budget.reserve(size, false)
		if e != nil {
			return total, e
		}
		ctx, cancel := context.WithTimeout(m.f.ctx, 30*time.Second)
		ok := m.f.budget.wait(ctx, reserved, upload)
		if ok {
			ok = m.r.waitCapacity(ctx, m.f.rule.TenantID, reserved)
		}
		cancel()
		if !ok {
			m.f.budget.complete(reserved, 0, upload)
			return total, errQuota
		}
		var written int
		var we error
		written, we = write(reserved)
		if written < 0 || written > reserved {
			written = 0
			we = io.ErrShortWrite
		}
		m.f.budget.complete(reserved, written, upload)
		total += written
		if we != nil {
			return total, we
		}
		if written != reserved {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (m *meteredStream) Close() error {
	if s, ok := m.stream.(interface{ SetDeadline(time.Time) error }); ok {
		_ = s.SetDeadline(time.Now())
	}
	return m.stream.Close()
}
func (m *meteredStream) SetDeadline(t time.Time) error {
	if s, ok := m.stream.(interface{ SetDeadline(time.Time) error }); ok {
		return s.SetDeadline(t)
	}
	return nil
}
func (m *meteredStream) CloseWrite() error {
	if h, ok := m.stream.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	if h, ok := m.stream.(interface{ Close() error }); ok {
		return h.Close()
	}
	return nil
}

// Write metering must slice using the current offset, while the account and
// root scheduler continue sharing a single reservation for each emitted chunk.
func (m *meteredStream) writePayload(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		size := min(len(p), 16<<10)
		reserved, e := m.f.budget.reserve(size, false)
		if e != nil {
			return total, e
		}
		ctx, cancel := context.WithTimeout(m.f.ctx, 30*time.Second)
		ok := m.f.budget.wait(ctx, reserved, true)
		if ok {
			ok = m.r.waitCapacity(ctx, m.f.rule.TenantID, reserved)
		}
		cancel()
		if !ok {
			m.f.budget.complete(reserved, 0, true)
			return total, errQuota
		}
		n, e := m.stream.Write(p[:reserved])
		if n < 0 || n > reserved {
			n = 0
			e = io.ErrShortWrite
		}
		m.f.budget.complete(reserved, n, true)
		total += n
		p = p[n:]
		if e != nil {
			return total, e
		}
		if n != reserved {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (r *Runtime) chargePacket(f *flowState, b []byte, upload bool, send func() error) error {
	n, e := f.budget.reserve(len(b), true)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(f.ctx, time.Second)
	defer cancel()
	if !f.budget.wait(ctx, n, upload) || !r.waitCapacity(ctx, f.rule.TenantID, n) {
		f.budget.complete(n, 0, upload)
		return errQuota
	}
	e = send()
	written := 0
	if e == nil {
		written = n
	}
	f.budget.complete(n, written, upload)
	return e
}
