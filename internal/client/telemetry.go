package client

import (
	"drafrp/internal/model"
	"sort"
	"time"
)

// runtimeStatusLocked samples one process under the Agent lock. It deliberately
// sends only classified failure codes; raw transport errors may contain private
// local paths and are retained only in the local diagnostic API.
func (a *Agent) runtimeStatusLocked() *model.DeviceRuntime {
	at := time.Now().UTC()
	out := &model.DeviceRuntime{ReportedAt: at, PreferredTransport: a.cfg.Transport,
		Carriers: []model.DeviceCarrierRuntime{}, Endpoints: []model.DeviceEndpointRuntime{}}
	if a.closing || !at.Before(a.snap.ExpiresAt) || !at.Before(a.snap.Device.ExpiresAt) {
		return out
	}
	out.SnapshotExpiresAt = minTime(a.snap.ExpiresAt, a.snap.Device.ExpiresAt)
	for _, c := range a.carriers {
		select {
		case <-c.Done():
			continue
		default:
		}
		var authorized bool
		for _, edge := range a.snap.Edges {
			if edge.ID == c.EdgeID {
				authorized = a.endpointAuthorizedLocked(pathKey(edge, c.Endpoint, c.Device))
				break
			}
		}
		if !authorized {
			continue
		}
		x := model.DeviceCarrierRuntime{EdgeID: c.EdgeID, Transport: c.Transport, Address: c.Endpoint.Address,
			ServerName: c.Endpoint.ServerName, ActiveFlows: int(c.Active()), EstablishedAt: c.EstablishedAt,
			HandshakeMS: float64(c.HandshakeDuration) / float64(time.Millisecond), Quality: c.Quality()}
		out.ActiveCarriers++
		out.ActiveFlows += x.ActiveFlows
		if c.Transport == "quic" {
			out.QUICCarriers++
		} else if c.Transport == "tls" {
			out.TLSCarriers++
		}
		out.Carriers = append(out.Carriers, x)
	}
	for key, h := range a.pathHealth {
		if !a.endpointAuthorizedLocked(key) {
			continue
		}
		out.Endpoints = append(out.Endpoints, model.DeviceEndpointRuntime{EdgeID: key.EdgeID,
			Transport: key.Endpoint.Transport, Address: key.Endpoint.Address, ServerName: key.Endpoint.ServerName,
			RecentFailures: h.Failures, RetryAt: h.RetryAt, LastAttempt: h.LastAttempt, LastSuccess: h.LastSuccess,
			HandshakeMS: float64(h.Handshake) / float64(time.Millisecond), ErrorCode: h.ErrorCode, Probing: h.Probing})
	}
	// Stable ordering makes truncation deterministic and keeps repeated signed
	// reports reviewable when a device references a large endpoint plan.
	sort.Slice(out.Carriers, func(i, j int) bool {
		a, b := out.Carriers[i], out.Carriers[j]
		if a.EdgeID != b.EdgeID {
			return a.EdgeID < b.EdgeID
		}
		if a.Transport != b.Transport {
			return a.Transport < b.Transport
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.EstablishedAt.Before(b.EstablishedAt)
	})
	sort.Slice(out.Endpoints, func(i, j int) bool {
		a, b := out.Endpoints[i], out.Endpoints[j]
		if a.EdgeID != b.EdgeID {
			return a.EdgeID < b.EdgeID
		}
		if a.Transport != b.Transport {
			return a.Transport < b.Transport
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.ServerName < b.ServerName
	})
	if len(out.Carriers) > model.MaxDeviceRuntimeEntries {
		out.Truncated = true
		out.Carriers = out.Carriers[:model.MaxDeviceRuntimeEntries]
	}
	if len(out.Endpoints) > model.MaxDeviceRuntimeEntries {
		out.Truncated = true
		out.Endpoints = out.Endpoints[:model.MaxDeviceRuntimeEntries]
	}
	return out
}

func (a *Agent) RuntimeStatus() *model.DeviceRuntime {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.runtimeStatusLocked()
}
