// Package native implements explicitly enabled, verified source preserving
// sockets. It never changes source ports to hide a tuple conflict.
package native

import "errors"

type Config struct {
	StateDir string
	// Remote targets must have a return route to this Agent. The operator
	// explicitly declares the target networks for which that route exists.
	ReturnCIDRs []string
	MaxFlows    int
}

var ErrTupleInUse = errors.New("native_source_tuple_conflict")
