package client

import (
	"context"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

func parsePrefix(s string) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil {
		return p, e
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return p, errors.New("ambiguous mapped prefix")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}
func (a *Agent) dialTarget(ctx context.Context, network, address string) (net.Conn, error) {
	return a.dialTargetPeer(ctx, network, address, "")
}
func (a *Agent) dialTargetPeer(ctx context.Context, network, address, peer string) (net.Conn, error) {
	host, p, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	port, e := strconv.Atoi(p)
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid target port")
	}
	if a.cfg.AllowedTargetPorts != nil {
		ok := false
		for _, v := range a.cfg.AllowedTargetPorts {
			ok = ok || v == port
		}
		if !ok {
			return nil, errors.New("target_scope_denied: port is outside local allowlist")
		}
	}
	resolved, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil {
		return nil, e
	}
	var last error
	for _, ip := range resolved {
		ip = ip.Unmap()
		if ip.IsUnspecified() || ip.IsMulticast() {
			last = errors.New("target_scope_denied: target must be unicast")
			continue
		}
		allowed := a.cfg.AllowedTargetCIDRs == nil
		for _, s := range a.cfg.AllowedTargetCIDRs {
			prefix, _ := parsePrefix(s)
			allowed = allowed || prefix.Contains(ip)
		}
		if !allowed {
			last = errors.New("target_scope_denied: address is outside local allowlist")
			continue
		}
		var conn net.Conn
		if peer != "" {
			if a.native == nil {
				return nil, errors.New("native_source_unavailable")
			}
			from, err := netip.ParseAddrPort(peer)
			if err != nil {
				return nil, err
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			conn, e = a.native.Dial(ctx, network, netip.AddrPortFrom(ip, uint16(port)), from)
		} else {
			conn, e = (&net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), p))
		}
		if e == nil {
			return conn, nil
		}
		last = e
	}
	if last == nil {
		last = errors.New("no permitted target addresses")
	}
	return nil, last
}
func (a *Agent) serveStream(c *protocol.Carrier, st protocol.Stream) {
	// FIN preserves the final Result/HTTP bytes on QUIC. Only cancellation or
	// a broken flow resets the stream, because a reset can discard queued data.
	defer protocol.Finish(st)
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	var f protocol.Flow
	if e := protocol.ReadJSON(st, &f); e != nil {
		return
	}
	a.mu.Lock()
	var rule model.Rule
	for _, r := range a.snap.Rules {
		if r.ID == f.RuleID {
			rule = r
			break
		}
	}
	d := a.snap.Device
	edgeAllowed := false
	for _, edge := range a.snap.Edges {
		if edge.ID == c.EdgeID {
			edgeAllowed = true
			break
		}
	}
	sourceOK := rule.SourceMode == "socket" && (rule.Protocol == "tcp" || rule.Protocol == "udp") || rule.SourceMode == "forwarded_headers" && (rule.Protocol == "http" || rule.Protocol == "https")
	if rule.SourceMode == "native" && a.native != nil && (rule.Protocol == "tcp" || rule.Protocol == "udp") {
		peer, err := netip.ParseAddrPort(f.Peer)
		if err == nil && peer.Addr().Unmap().Is4() {
			for _, capability := range a.native.Capabilities() {
				if capability == "native_"+rule.Protocol+"_ipv4_ip_port" {
					sourceOK = true
					break
				}
			}
		}
	}
	valid := !a.closing && len(a.flows) < 1024 && edgeAllowed && time.Now().Before(a.snap.ExpiresAt) && time.Now().Before(d.ExpiresAt) && f.ID != 0 && rule.ID != "" && rule.Version == f.Version && rule.Enabled && !rule.Deleting && rule.DeviceID == d.DeviceID && rule.TenantID == d.TenantID && rule.EdgeID == c.EdgeID && c.Device.DeviceID == d.DeviceID && c.Device.TenantID == d.TenantID && c.Device.SessionID == d.SessionID && c.Device.Generation == d.Generation && f.Generation == d.Generation && f.Protocol == rule.Protocol && sourceOK
	select {
	case <-c.Done():
		valid = false
	default:
	}
	if rule.Transport == "quic_only" && c.Transport != "quic" || rule.Transport == "tls_only" && c.Transport != "tls" {
		valid = false
	}
	if peer, e := netip.ParseAddrPort(f.Peer); e != nil || peer.Addr().IsUnspecified() || peer.Addr().IsMulticast() || peer.Port() == 0 {
		valid = false
	}
	if (rule.Protocol == "http" || rule.Protocol == "https") && (f.Host != rule.Domain || f.Scheme != "http" && f.Scheme != "https" || f.IngressPort < 1 || f.IngressPort > 65535) {
		valid = false
	}
	if !valid {
		a.mu.Unlock()
		_ = protocol.WriteJSON(st, protocol.Result{Code: "unauthorized_flow", Error: "rule, device, session, edge or transport mismatch"})
		return
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.flows[st] = activeFlow{rule: rule, edgeID: c.EdgeID, generation: d.Generation, cancel: cancel, carrier: c}
	a.mu.Unlock()
	defer cancel()
	defer func() { a.mu.Lock(); delete(a.flows, st); a.mu.Unlock() }()
	stop := context.AfterFunc(ctx, func() { protocol.Abort(st) })
	defer stop()
	c.AddActive(1)
	defer c.AddActive(-1)
	switch rule.Protocol {
	case "tcp":
		a.serveTCP(ctx, st, rule, f)
	case "udp":
		a.serveUDP(ctx, c, st, rule, f)
	case "http", "https":
		a.serveHTTP(ctx, st, rule, f)
	}
}
func (a *Agent) serveTCP(ctx context.Context, st protocol.Stream, r model.Rule, f protocol.Flow) {
	dialCtx, cancel := context.WithTimeout(ctx, ruleTimeout(r))
	peer := ""
	if r.SourceMode == "native" {
		peer = f.Peer
	}
	target, e := a.dialTargetPeer(dialCtx, "tcp", r.Target, peer)
	cancel()
	if e != nil {
		_ = protocol.WriteJSON(st, protocol.Result{Code: "target_unreachable", Error: e.Error()})
		return
	}
	defer target.Close()
	if e = protocol.WriteJSON(st, protocol.Result{}); e != nil {
		return
	}
	_ = st.SetDeadline(time.Time{})
	_ = protocol.Relay(ctx, st, target)
}
func (a *Agent) serveUDP(ctx context.Context, c *protocol.Carrier, st protocol.Stream, r model.Rule, f protocol.Flow) {
	dialCtx, dialCancel := context.WithTimeout(ctx, ruleTimeout(r))
	peer := ""
	if r.SourceMode == "native" {
		peer = f.Peer
	}
	conn, e := a.dialTargetPeer(dialCtx, "udp", r.Target, peer)
	dialCancel()
	if e != nil {
		_ = protocol.WriteJSON(st, protocol.Result{Code: "target_unreachable", Error: e.Error()})
		return
	}
	defer conn.Close()
	var incoming <-chan []byte
	unregister := func() {}
	if f.Datagram {
		if !c.Datagram() {
			_ = protocol.WriteJSON(st, protocol.Result{Code: "capability_missing", Error: "DATAGRAM not available"})
			return
		}
		incoming, unregister, e = c.Register(f.ID)
		if e != nil {
			_ = protocol.WriteJSON(st, protocol.Result{Code: "flow_capacity", Error: e.Error()})
			return
		}
	}
	defer unregister()
	if e = protocol.WriteJSON(st, protocol.Result{}); e != nil {
		return
	}
	_ = st.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); _ = conn.Close(); protocol.Abort(st); workers.Wait() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); protocol.Abort(st) })
	defer stop()
	errs := make(chan error, 2)
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	workers.Add(2)
	go func() {
		defer workers.Done()
		buf := make([]byte, protocol.MaxPacket)
		for {
			n, e := conn.Read(buf)
			if e != nil {
				errs <- e
				return
			}
			last.Store(time.Now().UnixNano())
			if f.Datagram {
				e = c.SendPacket(f.ID, buf[:n])
			} else {
				e = protocol.WritePacket(st, buf[:n])
			}
			if e != nil {
				errs <- e
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		if f.Datagram {
			var b [1]byte
			_, e := st.Read(b[:])
			errs <- e
			return
		}
		for {
			b, e := protocol.ReadPacket(st)
			if e != nil {
				errs <- e
				return
			}
			if _, e = conn.Write(b); e != nil {
				errs <- e
				return
			}
			last.Store(time.Now().UnixNano())
		}
	}()
	idle := ruleTimeout(r)
	ticker := time.NewTicker(min(time.Second, idle/2))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-errs:
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, last.Load())) >= idle {
				return
			}
		case b := <-incoming:
			if _, e = conn.Write(b); e != nil {
				return
			}
			last.Store(time.Now().UnixNano())
		}
	}
}
