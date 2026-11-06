package edge

import (
	"context"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

type admissionError struct {
	code    string
	status  int
	message string
}

func (e *admissionError) Error() string { return e.message }
func (r *Runtime) beginFlow(ctx context.Context, ruleID, peer string) (*flowState, error) {
	source, e := netip.ParseAddrPort(peer)
	if e != nil {
		return nil, &admissionError{"invalid_source", 400, "invalid visitor address"}
	}
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || !time.Now().Before(r.snap.ExpiresAt) {
		return nil, &admissionError{"authorization_expired", 503, "edge authorization is unavailable"}
	}
	rr := r.rules[ruleID]
	if rr == nil || rr.policyError != "" {
		return nil, &admissionError{"rule_unavailable", 503, "rule is unavailable"}
	}
	if (rr.rule.Protocol == "tcp" || rr.rule.Protocol == "udp") && !source.Addr().Is4() {
		return nil, &admissionError{"address_family_unsupported", 400, "TCP/UDP forwarding requires an IPv4 visitor"}
	}
	if r.snap.Edge.CapacityBPS == 0 {
		return nil, &admissionError{"edge_overloaded", 503, "edge payload capacity is disabled"}
	}
	if rr.rule.Protocol == "tcp" && !r.allowObservedACL(rr, source) || rr.rule.Protocol != "tcp" && !rr.allow(source) {
		return nil, &admissionError{"source_denied", 403, "source ACL denied the visitor"}
	}
	if rr.rule.SourceMode == "native" && !source.Addr().Is4() {
		return nil, &admissionError{"capability_missing", 503, "native source identity currently requires an IPv4 visitor"}
	}
	c := r.pickCarrierLocked(rr.rule)
	if c == nil {
		return nil, &admissionError{"agent_offline", 503, "agent is offline or its carrier is unavailable"}
	}
	b := r.budgets[rr.rule.TenantID]
	if b == nil || !b.valid() {
		return nil, &admissionError{"quota_exhausted", 403, "account credit is unavailable"}
	}
	if !r.rootConns.Acquire() {
		return nil, &admissionError{"edge_overloaded", 503, "edge active flow capacity reached"}
	}
	if !b.acquire() {
		r.rootConns.Release()
		return nil, &admissionError{"account_limit", 429, "account concurrency or new-flow rate reached"}
	}
	flowCtx, cancel := context.WithCancel(r.ctx)
	stop := context.AfterFunc(ctx, cancel)
	f := &flowState{id: protocol.ID(), rule: rr.rule, peer: source, generation: c.Device.Generation, grantID: b.id(), budget: b, carrier: c, ctx: flowCtx, cancel: func() { stop(); cancel() }}
	r.flows[f.id] = f
	c.AddActive(1)
	return f, nil
}
func (r *Runtime) finishFlow(f *flowState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f.finished {
		return
	}
	f.finished = true
	f.cancel()
	delete(r.flows, f.id)
	f.budget.release()
	r.rootConns.Release()
	f.carrier.AddActive(-1)
}
func (r *Runtime) openStream(f *flowState, flow protocol.Flow) (protocol.Stream, error) {
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	s, e := f.carrier.Open(ctx)
	if e != nil {
		return nil, e
	}
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	flow.RuleID = f.rule.ID
	flow.Version = f.rule.Version
	flow.Protocol = f.rule.Protocol
	flow.Generation = f.generation
	if flow.ID == 0 {
		flow.ID = protocol.FlowID()
	}
	flow.Peer = f.peer.String()
	if e = protocol.WriteJSON(s, flow); e != nil {
		protocol.Abort(s)
		return nil, e
	}
	return s, nil
}
func readResult(s protocol.Stream) error {
	var out protocol.Result
	if e := protocol.ReadJSON(s, &out); e != nil {
		return e
	}
	if out.Code != "" || out.Error != "" {
		return fmt.Errorf("%s: %s", out.Code, out.Error)
	}
	return nil
}
func (r *Runtime) acceptTCP(ruleID string, l net.Listener) {
	for {
		conn, e := l.Accept()
		if e != nil {
			return
		}
		f, e := r.beginFlow(r.ctx, ruleID, conn.RemoteAddr().String())
		if e != nil {
			_ = conn.Close()
			continue
		}
		r.mu.Lock()
		launched := r.launchLocked(func() { r.forwardTCP(f, conn) })
		r.mu.Unlock()
		if !launched {
			_ = conn.Close()
			r.finishFlow(f)
		}
	}
}
func (r *Runtime) forwardTCP(f *flowState, conn net.Conn) {
	defer conn.Close()
	defer r.finishFlow(f)
	stop := context.AfterFunc(f.ctx, func() { _ = conn.Close() })
	defer stop()
	s, e := r.openStream(f, protocol.Flow{})
	if e != nil {
		r.markStatus(f.rule, "error", e)
		return
	}
	defer protocol.Abort(s)
	if e = readResult(s); e != nil {
		r.markStatus(f.rule, "error", e)
		return
	}
	_ = s.SetDeadline(time.Time{})
	r.markStatus(f.rule, "ready", nil)
	metered := &meteredStream{r: r, f: f, stream: s}
	_ = protocol.Relay(f.ctx, metered, conn)
}
func (r *Runtime) FlowCount() int { r.mu.RLock(); defer r.mu.RUnlock(); return len(r.flows) }
func (r *Runtime) Statuses() []model.RuleStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshStatusesLocked()
	out := []model.RuleStatus{}
	for _, s := range r.statuses {
		out = append(out, s)
	}
	return out
}

var _ = errors.Is
