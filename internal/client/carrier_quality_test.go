package client

import (
	"context"
	"testing"
	"time"

	"drafrp/internal/model"
)

func TestCarrierQualityLifecycleAndSignedRuntime(t *testing.T) {
	for _, transport := range []string{"tls", "quic"} {
		t.Run(transport, func(t *testing.T) {
			a, edge, _ := connected(t, transport, model.Rule{Protocol: "tcp", Target: "127.0.0.1:9"})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				for {
					st, err := edge.Accept(ctx)
					if err != nil {
						return
					}
					edge.HandleProbe(ctx, st, func() bool { return true })
				}
			}()
			deadline := time.Now().Add(3 * time.Second)
			for {
				r := a.RuntimeStatus()
				if len(r.Carriers) == 1 && r.Carriers[0].Quality != nil {
					q := r.Carriers[0].Quality
					if q.Successes != 1 || q.Samples != 1 || r.ActiveFlows != 0 {
						t.Fatal("probe affected business or was not sampled", r)
					}
					if transport == "quic" && q.QUIC == nil {
						t.Fatal("QUIC statistics absent from signed runtime")
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("real probe did not reach Agent runtime", r)
				}
				time.Sleep(5 * time.Millisecond)
			}
			a.mu.Lock()
			for key, c := range a.carriers {
				if !a.endpointAuthorizedLocked(pathKey(a.carrierEdges[key], c.Endpoint, c.Device)) {
					t.Fatal("current carrier unauthorized")
				}
			}
			a.snap.Device.Generation++
			a.reconcileLocked()
			a.mu.Unlock()
			if r := a.RuntimeStatus(); len(r.Carriers) != 0 || r.ActiveFlows != 0 {
				t.Fatal("old process generation observations survived", r)
			}
		})
	}
}
