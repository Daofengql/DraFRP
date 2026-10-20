package edge

import "drafrp/internal/model"

func (r *Runtime) capacityAvailable() bool {
	return r.cfg.WireShaping == nil || r.shaper != nil && r.shaper.Status().Enforced
}

// capacityRuntimeLocked uses cached, independently verified kernel observations;
// it never invokes tc or performs filesystem I/O while holding the edge lock.
func (r *Runtime) capacityRuntimeLocked(out *model.EdgeRuntime) {
	out.CapacityEnforcement = "payload"
	if r.cfg.WireShaping == nil {
		return
	}
	out.CapacityEnforcement = "wire_failed"
	if r.shaper == nil {
		out.CapacityError = "wire shaping initialization failed"
		return
	}
	status := r.shaper.Status()
	out.PhysicalInterface = status.Interface
	out.WireRateBPS = status.RateBPS
	out.PhysicalTXBytes = status.TXBytes
	out.PhysicalRXBytes = status.RXBytes
	out.PhysicalObservedAt = status.ObservedAt
	out.CapacityError = status.Error
	if status.Enforced {
		out.CapacityEnforcement = "wire"
	}
}
