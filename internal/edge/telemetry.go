package edge

import (
	"drafrp/internal/model"
	"io"
	"time"
)

// runtimeLocked samples only runtime-owned listener/carrier/flow state. The
// desired snapshot supplies endpoint identities, never their listening status.
// Caller must hold r.mu. Counts describe this edge, not a tenant or target.
func (r *Runtime) runtimeLocked() *model.EdgeRuntime {
	now := time.Now().UTC()
	out := &model.EdgeRuntime{
		ReportedAt:        now,
		SnapshotExpiresAt: r.snap.ExpiresAt,
		Endpoints:         make([]model.EndpointRuntime, 0, len(r.snap.Edge.Endpoints)),
		UDPMappings:       len(r.udpSlots),
		GeoIPState:        "unconfigured",
		GeoIPError:        r.geoError,
	}
	r.capacityRuntimeLocked(out)
	if r.geoError != "" {
		out.GeoIPState = "error"
	} else if r.geoDB != nil {
		out.GeoIPState = "ready"
		out.GeoIPVersion = r.geoDB.Version
	}
	for _, ep := range r.snap.Edge.Endpoints {
		key := "carrier/" + ep.Transport + "/" + ep.Address
		listener, exists := r.listeners[key]
		out.Endpoints = append(out.Endpoints, model.EndpointRuntime{
			Transport: ep.Transport,
			Address:   ep.Address,
			Listening: exists && listener.closer != nil && listener.kind == "carrier" && !r.closing,
			Error:     r.listenerErrors[key],
		})
	}
	for _, state := range r.carriers {
		if state.c == nil {
			continue
		}
		select {
		case <-state.c.Done():
			continue
		default:
		}
		out.ActiveCarriers++
		switch state.c.Transport {
		case "quic":
			out.QUICCarriers++
		case "tls":
			out.TLSCarriers++
		}
	}
	for _, flow := range r.flows {
		if flow == nil || flow.finished {
			continue
		}
		if flow.ctx != nil && flow.ctx.Err() != nil {
			continue
		}
		out.ActiveFlows++
	}
	return out
}

// RuntimeStatus is a detached, point-in-time sample for diagnostics and tests.
func (r *Runtime) RuntimeStatus() *model.EdgeRuntime {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.runtimeLocked()
}

// Remove failed accept loops from observed listener state. Desired config alone
// must never keep a dead listener reported as listening until a later snapshot.
func (r *Runtime) listenerStopped(key string, closer io.Closer, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.listeners[key]
	if !exists || current.closer != closer {
		return
	}
	delete(r.listeners, key)
	if !r.closing && err != nil {
		r.listenerErrors[key] = err.Error()
	}
}
