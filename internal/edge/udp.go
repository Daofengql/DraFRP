package edge

import (
	"context"
	"drafrp/internal/protocol"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

type udpMapping struct {
	key    string
	peer   net.Addr
	queue  chan []byte
	last   time.Time
	cancel context.CancelFunc
}

// Every map and queue is bounded. Reading a packet never allocates a new
// tunnel until ACL, global packet rate and session capacity have admitted it.
func (r *Runtime) acceptUDP(ruleID string, pc net.PacketConn) {
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	var mu sync.Mutex
	maps := map[string]*udpMapping{}
	var workers sync.WaitGroup
	defer workers.Wait()
	defer func() {
		mu.Lock()
		for _, m := range maps {
			m.cancel()
		}
		mu.Unlock()
	}()
	tickerDone := make(chan struct{})
	go func() {
		defer close(tickerDone)
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				mu.Lock()
				for key, m := range maps {
					if now.Sub(m.last) >= r.cfg.UDPIdleTimeout {
						m.cancel()
						delete(maps, key)
					}
				}
				mu.Unlock()
			}
		}
	}()
	defer func() { cancel(); <-tickerDone }()
	buf := make([]byte, protocol.MaxPacket+1)
	for {
		n, peer, e := pc.ReadFrom(buf)
		if e != nil {
			return
		}
		if n > protocol.MaxPacket || !r.packetRate.Allow() {
			continue
		}
		source, se := netip.ParseAddrPort(peer.String())
		if se != nil {
			continue
		}
		r.mu.RLock()
		rr := r.rules[ruleID]
		allowed := rr != nil && rr.policyError == "" && time.Now().Before(r.snap.ExpiresAt) && r.allowObservedACL(rr, source)
		r.mu.RUnlock()
		if !allowed {
			continue
		}
		key := peer.String()
		mu.Lock()
		m := maps[key]
		if m != nil {
			m.last = time.Now()
			select {
			case m.queue <- append([]byte(nil), buf[:n]...):
			default:
			}
			mu.Unlock()
			continue
		}
		if len(maps) >= r.cfg.MaxUDPSessions {
			mu.Unlock()
			continue
		}
		select {
		case r.udpSlots <- struct{}{}:
		default:
			mu.Unlock()
			continue
		}
		mctx, mcancel := context.WithCancel(ctx)
		m = &udpMapping{key: key, peer: peer, queue: make(chan []byte, 8), last: time.Now(), cancel: mcancel}
		m.queue <- append([]byte(nil), buf[:n]...)
		maps[key] = m
		workers.Add(1)
		mu.Unlock()
		go func(m *udpMapping, ctx context.Context) {
			defer func() { <-r.udpSlots }()
			defer workers.Done()
			defer m.cancel()
			defer func() {
				mu.Lock()
				if maps[m.key] == m {
					delete(maps, m.key)
				}
				mu.Unlock()
			}()
			r.forwardUDP(ctx, ruleID, pc, m, func() { mu.Lock(); m.last = time.Now(); mu.Unlock() })
		}(m, mctx)
	}
}
func (r *Runtime) forwardUDP(ctx context.Context, ruleID string, pc net.PacketConn, m *udpMapping, touch func()) {
	f, e := r.beginFlow(ctx, ruleID, m.peer.String())
	if e != nil {
		return
	}
	defer r.finishFlow(f)
	flowID := protocol.FlowID()
	datagram := f.carrier.Datagram()
	var incoming <-chan []byte
	unregister := func() {}
	if datagram {
		incoming, unregister, e = f.carrier.Register(flowID)
		if e != nil {
			return
		}
	}
	defer unregister()
	s, e := r.openStream(f, protocol.Flow{ID: flowID, Datagram: datagram})
	if e != nil {
		return
	}
	defer protocol.Abort(s)
	stop := context.AfterFunc(f.ctx, func() { protocol.Abort(s) })
	defer stop()
	if e = readResult(s); e != nil {
		r.markStatus(f.rule, "error", e)
		return
	}
	_ = s.SetDeadline(time.Time{})
	receive := make(chan []byte, 8)
	done := make(chan struct{})
	go func(receive chan []byte) {
		defer close(done)
		defer close(receive)
		if datagram {
			var b [1]byte
			_, _ = s.Read(b[:])
			return
		}
		for {
			b, e := protocol.ReadPacket(s)
			if e != nil {
				return
			}
			select {
			case receive <- b:
			case <-f.ctx.Done():
				return
			}
		}
	}(receive)
	defer func() { protocol.Abort(s); <-done }()
	if datagram {
		receive = nil
	}
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-done:
			return
		case b, ok := <-receive:
			if !ok {
				return
			}
			e = r.chargePacket(f, b, false, func() error { _, we := pc.WriteTo(b, m.peer); return we })
			if e != nil {
				return
			}
			touch()
			r.markStatus(f.rule, "ready", nil)
		case b := <-incoming:
			e = r.chargePacket(f, b, false, func() error { _, we := pc.WriteTo(b, m.peer); return we })
			if e != nil {
				return
			}
			touch()
			r.markStatus(f.rule, "ready", nil)
		case b := <-m.queue:
			e = r.chargePacket(f, b, true, func() error {
				if datagram {
					return f.carrier.SendPacket(flowID, b)
				}
				return protocol.WritePacket(s, b)
			})
			if e != nil {
				if errors.Is(e, errQuota) {
					return
				}
				if !errors.Is(e, io.EOF) {
					return
				}
			}
		}
	}
}
