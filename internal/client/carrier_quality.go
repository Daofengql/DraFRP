package client

import "drafrp/internal/protocol"

// Called only for a carrier already published under the Agent lock. Renewals
// retain the window; session/generation, CA or endpoint changes retire it.
func (a *Agent) carrierProbeAuthorized(key string, c *protocol.Carrier) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	edge, ok := a.carrierEdges[key]
	return ok && a.carriers[key] == c && a.endpointAuthorizedLocked(pathKey(edge, c.Endpoint, c.Device))
}
