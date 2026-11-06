package client

import (
	"context"
	"crypto/tls"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"encoding/json"
	"errors"
	"github.com/quic-go/quic-go"
	"net"
	"time"
)

func (a *Agent) DialEdge(ctx context.Context, e model.Edge) (*protocol.Carrier, error) {
	return a.dialEdge(ctx, e, a.cfg.Transport)
}
func (a *Agent) dialEdge(ctx context.Context, e model.Edge, mode string) (*protocol.Carrier, error) {
	return a.dialEdgeFiltered(ctx, e, mode, false)
}
func (a *Agent) dialEdgeFiltered(ctx context.Context, e model.Edge, mode string, excludeActive bool) (*protocol.Carrier, error) {
	a.mu.RLock()
	grant := a.snap.Device
	allowed := false
	for _, x := range a.snap.Edges {
		if x.ID == e.ID {
			e = x
			allowed = true
			break
		}
	}
	valid := !a.closing && time.Now().Before(a.snap.ExpiresAt)
	grant.ExpiresAt = minTime(grant.ExpiresAt, a.snap.ExpiresAt)
	a.mu.RUnlock()
	if !allowed || !valid || !time.Now().Before(grant.ExpiresAt) {
		return nil, errors.New("edge is not authorized by an active snapshot")
	}
	candidates, earliestRetry, resolveErr := a.dialCandidates(ctx, e, grant, mode)
	if excludeActive {
		a.mu.RLock()
		filtered := candidates[:0]
		for _, candidate := range candidates {
			active := false
			for _, c := range a.carriers {
				active = active || c.EdgeID == e.ID && c.Transport == candidate.ep.Transport && c.RemoteAddress == candidate.key.RemoteAddress
			}
			if !active {
				filtered = append(filtered, candidate)
			}
		}
		candidates = filtered
		a.mu.RUnlock()
	}
	if resolveErr != nil && len(candidates) == 0 && earliestRetry.IsZero() {
		return nil, resolveErr
	}
	if len(candidates) == 0 {
		if !earliestRetry.IsZero() {
			return nil, &endpointCooldownError{RetryAt: earliestRetry}
		}
		return nil, errors.New("no compatible edge endpoint")
	}
	raceCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	type result struct {
		c *protocol.Carrier
		e error
	}
	results := make(chan result, len(candidates))
	counts := map[string]int{}
	for _, candidate := range candidates {
		counts[candidate.ep.Transport]++
	}
	indices := map[string]int{}
	for _, candidate := range candidates {
		i := indices[candidate.ep.Transport]
		indices[candidate.ep.Transport]++
		go func(i int, candidate dialCandidate) {
			delay := time.Duration(i) * 150 * time.Millisecond
			if mode == "auto" && candidate.ep.Transport == "tls" && counts["quic"] > 0 {
				delay += 250*time.Millisecond + time.Duration(counts["quic"]-1)*150*time.Millisecond
			}
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-raceCtx.Done():
				results <- result{e: raceCtx.Err()}
				return
			case <-timer.C:
			}
			select {
			case a.dialSlots <- struct{}{}:
				defer func() { <-a.dialSlots }()
			case <-raceCtx.Done():
				results <- result{e: raceCtx.Err()}
				return
			}
			started := time.Now()
			key := candidate.key
			if !a.beginEndpoint(key, started) {
				results <- result{e: &endpointCooldownError{RetryAt: time.Now().Add(time.Second)}}
				return
			}
			c, err := a.dialEndpointAddress(raceCtx, e, candidate.ep, key.RemoteAddress, grant)
			a.finishEndpoint(key, started, err, ctx.Err() != nil)
			results <- result{c, err}
		}(i, candidate)
	}
	var last error
	for i := 0; i < len(candidates); i++ {
		res := <-results
		if res.e == nil && res.c != nil {
			cancel()
			remaining := len(candidates) - i - 1
			go func() {
				for j := 0; j < remaining; j++ {
					x := <-results
					if x.c != nil {
						_ = x.c.Close()
					}
				}
			}()
			return res.c, nil
		}
		last = res.e
	}
	return nil, last
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (a *Agent) dialEndpoint(ctx context.Context, e model.Edge, ep model.Endpoint, d model.DeviceGrant) (*protocol.Carrier, error) {
	return a.dialEndpointAddress(ctx, e, ep, ep.Address, d)
}
func (a *Agent) dialEndpointAddress(ctx context.Context, e model.Edge, ep model.Endpoint, address string, d model.DeviceGrant) (*protocol.Carrier, error) {
	started := time.Now()
	tc, err := protocol.TLSClient(a.cfg.CAFile, e.CACert, ep.ServerName)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// Independent renewals can leave the edge's lease behind the Agent's lease.
	// A proof only needs to cover this admission attempt, so bound it by the
	// actual dial deadline instead of sending the Agent's newer full lease. The
	// edge still requires the proof to fit its own current device authorization;
	// both sides continue enforcing their renewable snapshots after admission.
	deadline, _ := dialCtx.Deadline()
	d.ExpiresAt = minTime(d.ExpiresAt, deadline)
	var c *protocol.Carrier
	switch ep.Transport {
	case "quic":
		q, err := quic.DialAddr(dialCtx, address, tc, protocol.QUICConfig())
		if err != nil {
			return nil, err
		}
		c = protocol.WrapQUIC(q, e.ID)
	case "tls":
		conn, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: tc}).DialContext(dialCtx, "tcp", address)
		if err != nil {
			return nil, err
		}
		tlsConn := conn.(*tls.Conn)
		if tlsConn.ConnectionState().NegotiatedProtocol != protocol.ALPN {
			_ = conn.Close()
			return nil, errors.New("edge ALPN mismatch")
		}
		c, err = protocol.WrapTLS(conn, false, e.ID)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	default:
		return nil, errors.New("unknown transport")
	}
	if err = protocol.AuthenticateClient(dialCtx, c, d, a.key); err != nil {
		_ = c.Close()
		return nil, err
	}
	if ctx.Err() != nil {
		_ = c.Close()
		return nil, ctx.Err()
	}
	c.Endpoint, c.EstablishedAt, c.HandshakeDuration = ep, time.Now(), time.Since(started)
	c.RemoteAddress = address
	return c, nil
}
func (a *Agent) ConnectEdge(ctx context.Context, e model.Edge) error {
	a.connectMu.Lock()
	defer a.connectMu.Unlock()
	a.mu.Lock()
	a.reconcileLocked()
	needed := map[string]bool{}
	for _, r := range a.snap.Rules {
		if r.EdgeID == e.ID && r.Enabled && !r.Deleting {
			mode := r.Transport
			if a.cfg.Transport != "auto" {
				if mode != "auto" && mode != a.cfg.Transport {
					a.mu.Unlock()
					return errors.New("local and rule transport policies conflict")
				}
				mode = a.cfg.Transport
			}
			needed[mode] = true
		}
	}
	a.mu.Unlock()
	// Allocate constrained modes before a generic auto carrier.
	var failures []error
	for _, mode := range []string{"quic_only", "tls_only", "auto"} {
		if !needed[mode] {
			continue
		}
		a.mu.RLock()
		count := 0
		usable := false
		hasQUIC := false
		var load int64
		for _, c := range a.carriers {
			if c.EdgeID != e.ID {
				continue
			}
			count++
			if mode == "quic_only" && c.Transport != "quic" || mode == "tls_only" && c.Transport != "tls" {
				continue
			}
			usable = true
			hasQUIC = hasQUIC || c.Transport == "quic"
			load += c.Active()
		}
		limit := a.cfg.MaxCarriersPerEdge
		for _, allowed := range a.snap.Edges {
			if allowed.ID == e.ID {
				e = allowed
				break
			}
		}
		if e.MaxCarriers > 0 {
			limit = min(limit, e.MaxCarriers)
		}
		closing := a.closing
		a.mu.RUnlock()
		if closing {
			return errors.New("agent closed")
		}
		dialMode := mode
		recoverQUIC := mode == "auto" && usable && !hasQUIC && count < limit
		recoveryMode := mode
		if mode == "auto" && hasQUIC {
			recoveryMode = "quic_only"
		}
		recoverFamily := usable && count < limit && a.familyRecovery(ctx, e, recoveryMode)
		if recoverQUIC {
			dialMode = "quic_only"
		} else if recoverFamily {
			dialMode = recoveryMode
		} else if usable && !recoverFamily && (load < int64(count*32) || count >= limit) {
			continue
		}
		if count >= limit {
			if usable {
				continue
			}
			failures = append(failures, errors.New("edge carrier limit cannot satisfy rule transport policies"))
			continue
		}
		c, err := a.dialEdgeFiltered(ctx, e, dialMode, recoverFamily || recoverQUIC)
		if err != nil {
			var cooldown *endpointCooldownError
			if !errors.As(err, &cooldown) && !recoverQUIC && !recoverFamily {
				failures = append(failures, err)
			}
			continue
		}
		a.mu.Lock()
		stillAllowed := false
		for _, edge := range a.snap.Edges {
			if edge.ID == e.ID && sameEdgeAuthority(e, edge) {
				stillAllowed = true
				break
			}
		}
		if a.closing || !stillAllowed || !time.Now().Before(a.snap.ExpiresAt) || c.Device.Generation != a.snap.Device.Generation || c.Device.SessionID != a.snap.Device.SessionID {
			a.mu.Unlock()
			_ = c.Close()
			return errors.New("agent closed")
		}
		key := e.ID + "/" + protocol.ID()
		a.carriers[key] = c
		a.carrierEdges[key] = e
		a.wg.Add(1)
		a.mu.Unlock()
		go a.acceptCarrier(a.ctx, key, c)
	}
	return errors.Join(failures...)
}
func (a *Agent) acceptCarrier(ctx context.Context, key string, c *protocol.Carrier) {
	defer a.wg.Done()
	defer c.Close()
	probeCtx, stopProbes := context.WithCancel(ctx)
	probesDone := make(chan struct{})
	go func() {
		defer close(probesDone)
		c.ObserveQuality(probeCtx, func() bool { return a.carrierProbeAuthorized(key, c) })
	}()
	defer func() { stopProbes(); <-probesDone }()
	defer func() {
		a.mu.Lock()
		if edge, ok := a.carrierEdges[key]; ok {
			a.disconnectedEndpointLocked(edge, c)
		}
		delete(a.carriers, key)
		delete(a.carrierEdges, key)
		for _, f := range a.flows {
			if f.carrier == c {
				f.cancel()
			}
		}
		a.mu.Unlock()
	}()
	for {
		st, e := c.Accept(ctx)
		if e != nil {
			return
		}
		a.mu.Lock()
		if a.closing || a.pendingStreams >= 1024 {
			a.mu.Unlock()
			protocol.Abort(st)
			continue
		}
		a.wg.Add(1)
		a.pendingStreams++
		a.mu.Unlock()
		go func() {
			defer a.wg.Done()
			defer func() { a.mu.Lock(); a.pendingStreams--; a.mu.Unlock() }()
			a.serveStream(c, st)
		}()
	}
}
func (a *Agent) TransportStatus() []map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := []map[string]any{}
	for _, c := range a.carriers {
		out = append(out, map[string]any{"edge_id": c.EdgeID, "transport": c.Transport, "active_flows": c.Active(), "endpoint": c.Endpoint.Address, "remote_address": c.RemoteAddress, "established_at": c.EstablishedAt, "handshake_ms": float64(c.HandshakeDuration) / float64(time.Millisecond), "quality": c.Quality()})
	}
	return out
}

func sameEdgeAuthority(a, b model.Edge) bool {
	return a.CACert == b.CACert && stringJSON(a.Endpoints) == stringJSON(b.Endpoints)
}
func stringJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
