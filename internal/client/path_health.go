package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
)

const endpointStableWindow = 30 * time.Second

type endpointKey struct {
	EdgeID, DeviceID, SessionID string
	Generation                  uint64
	Endpoint                    model.Endpoint
	CA                          [32]byte
	RemoteAddress               string
}
type endpointHealth struct {
	Failures    uint
	RetryAt     time.Time
	LastAttempt time.Time
	LastSuccess time.Time
	Handshake   time.Duration
	ErrorCode   string
	LastError   string
	Probing     bool
	RTT         time.Duration
	RTTAt       time.Time
}

// EndpointStatus describes bounded, local connection attempts. HandshakeMS
// includes carrier establishment and device admission; it is not steady RTT.
type EndpointStatus struct {
	EdgeID        string    `json:"edge_id"`
	Transport     string    `json:"transport"`
	Address       string    `json:"address"`
	RemoteAddress string    `json:"remote_address,omitempty"`
	Failures      uint      `json:"recent_failures"`
	RetryAt       time.Time `json:"retry_at,omitempty"`
	LastAttempt   time.Time `json:"last_attempt,omitempty"`
	LastSuccess   time.Time `json:"last_success,omitempty"`
	HandshakeMS   float64   `json:"handshake_ms"`
	ErrorCode     string    `json:"error_code,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Probing       bool      `json:"probing"`
}

type endpointCooldownError struct{ RetryAt time.Time }

func (e *endpointCooldownError) Error() string {
	return fmt.Sprintf("authorized endpoints are cooling down until %s", e.RetryAt.UTC().Format(time.RFC3339Nano))
}
func pathKey(edge model.Edge, ep model.Endpoint, d model.DeviceGrant) endpointKey {
	k := endpointKey{EdgeID: edge.ID, DeviceID: d.DeviceID, SessionID: d.SessionID, Generation: d.Generation, Endpoint: ep, CA: sha256.Sum256([]byte(edge.CACert))}
	if addr, err := netip.ParseAddrPort(ep.Address); err == nil {
		k.RemoteAddress = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()).String()
	}
	return k
}
func carrierPathKey(edge model.Edge, c *protocol.Carrier) endpointKey {
	k := pathKey(edge, c.Endpoint, c.Device)
	if c.RemoteAddress != "" {
		k.RemoteAddress = c.RemoteAddress
	}
	return k
}
func (a *Agent) endpointAuthorizedLocked(k endpointKey) bool {
	d := a.snap.Device
	if a.closing || !time.Now().Before(a.snap.ExpiresAt) || !time.Now().Before(d.ExpiresAt) || k.DeviceID != d.DeviceID || k.SessionID != d.SessionID || k.Generation != d.Generation {
		return false
	}
	for _, edge := range a.snap.Edges {
		if edge.ID != k.EdgeID || sha256.Sum256([]byte(edge.CACert)) != k.CA {
			continue
		}
		for _, ep := range edge.Endpoints {
			if ep == k.Endpoint {
				return true
			}
		}
	}
	return false
}
func (a *Agent) pruneEndpointHealthLocked() {
	active := make(map[endpointKey]bool, len(a.carriers))
	for id, c := range a.carriers {
		active[carrierPathKey(a.carrierEdges[id], c)] = true
	}
	for k, h := range a.pathHealth {
		// DNS rotation must not retain failed addresses forever. Active paths
		// refresh their observations when maintenance evaluates candidates.
		if !a.endpointAuthorizedLocked(k) || !h.Probing && !active[k] && time.Since(maxTime(h.LastAttempt, h.LastSuccess)) > 10*time.Minute {
			delete(a.pathHealth, k)
		}
	}
}
func (a *Agent) endpointEligible(k endpointKey, now time.Time) (bool, time.Time) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.endpointAuthorizedLocked(k) {
		return false, time.Time{}
	}
	h := a.pathHealth[k]
	if h == nil {
		return true, time.Time{}
	}
	return !h.Probing && !now.Before(h.RetryAt), h.RetryAt
}
func (a *Agent) beginEndpoint(k endpointKey, started time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.endpointAuthorizedLocked(k) {
		return false
	}
	h := a.pathHealth[k]
	if h == nil {
		a.pruneEndpointHealthLocked()
		if len(a.pathHealth) >= 2048 {
			return false
		}
		h = &endpointHealth{}
		a.pathHealth[k] = h
	}
	if h.Probing || started.Before(h.RetryAt) {
		return false
	}
	if h.ErrorCode == "" && !h.LastSuccess.IsZero() && started.Sub(h.LastSuccess) >= endpointStableWindow {
		h.Failures = 0
	}
	h.Probing, h.LastAttempt = true, started
	return true
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
func endpointBackoff(failures uint) time.Duration {
	// Two seconds to one minute, with 0..25% cryptographic jitter. The cap
	// includes jitter, so repeated calls cannot extend an unbounded cooldown.
	failures = max(1, failures)
	delay := 2 * time.Second * time.Duration(1<<min(failures-1, 5))
	var random [4]byte
	_, _ = rand.Read(random[:])
	jitter := time.Duration(binary.BigEndian.Uint32(random[:])%501) * time.Millisecond
	return min(delay+jitter, time.Minute)
}
func endpointErrorCode(err error) string {
	var admission *protocol.AdmissionError
	if errors.As(err, &admission) {
		return "authorization_rejected"
	}
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return "tls_identity_failed"
	}
	if errors.Is(err, context.Canceled) {
		return "race_not_selected"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return "path_timeout"
	}
	return "connection_failed"
}
func (a *Agent) finishEndpoint(k endpointKey, started time.Time, err error, callerCanceled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h := a.pathHealth[k]
	if h == nil || h.LastAttempt != started || !a.endpointAuthorizedLocked(k) {
		return
	}
	h.Probing = false
	if callerCanceled {
		return
	}
	if err == nil {
		h.Handshake = time.Since(started)
		h.LastSuccess = time.Now()
		h.RetryAt = h.LastSuccess.Add(endpointStableWindow)
		h.ErrorCode, h.LastError = "", ""
		return
	}
	h.Failures = min(h.Failures+1, 32)
	h.RetryAt = time.Now().Add(endpointBackoff(h.Failures))
	h.ErrorCode, h.LastError = endpointErrorCode(err), err.Error()
	if len(h.LastError) > 1024 {
		h.LastError = h.LastError[:1024]
	}
}
func (a *Agent) disconnectedEndpointLocked(edge model.Edge, c *protocol.Carrier) {
	k := carrierPathKey(edge, c)
	h := a.pathHealth[k]
	if h == nil || !a.endpointAuthorizedLocked(k) {
		return
	}
	if time.Since(c.EstablishedAt) >= endpointStableWindow {
		h.Failures = 0
	}
	h.Failures = min(h.Failures+1, 32)
	h.RetryAt = time.Now().Add(endpointBackoff(h.Failures))
	h.ErrorCode, h.LastError = "carrier_closed", "authenticated carrier disconnected"
}
func (a *Agent) EndpointStatus() []EndpointStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]EndpointStatus, 0, len(a.pathHealth))
	for k, h := range a.pathHealth {
		if a.endpointAuthorizedLocked(k) {
			out = append(out, EndpointStatus{EdgeID: k.EdgeID, Transport: k.Endpoint.Transport, Address: k.Endpoint.Address, RemoteAddress: k.RemoteAddress, Failures: h.Failures, RetryAt: h.RetryAt, LastAttempt: h.LastAttempt, LastSuccess: h.LastSuccess, HandshakeMS: float64(h.Handshake) / float64(time.Millisecond), ErrorCode: h.ErrorCode, LastError: h.LastError, Probing: h.Probing})
		}
	}
	return out
}
