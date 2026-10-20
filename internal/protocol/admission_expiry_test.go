package protocol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"drafrp/internal/model"
)

func TestAdmissionPreservesLocalLeaseBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*model.DeviceGrant, *model.DeviceGrant) bool
	}{
		{"proof_outlives_edge", func(edge, proof *model.DeviceGrant) bool { edge.ExpiresAt = time.Now().Add(time.Second); return true }},
		{"edge_expired", func(edge, proof *model.DeviceGrant) bool { edge.ExpiresAt = time.Now().Add(-time.Second); return true }},
		{"proof_expired", func(edge, proof *model.DeviceGrant) bool { proof.ExpiresAt = time.Now().Add(-time.Second); return true }},
		{"old_generation", func(edge, proof *model.DeviceGrant) bool { edge.Generation++; return true }},
		{"revoked_device", func(edge, proof *model.DeviceGrant) bool { return false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, y := tlsPair(t)
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			edgeGrant := model.DeviceGrant{DeviceID: "device", TenantID: "tenant", PublicKey: base64.StdEncoding.EncodeToString(pub), SessionID: "session", Generation: 3, ExpiresAt: time.Now().Add(10 * time.Second)}
			proof := edgeGrant
			proof.ExpiresAt = time.Now().Add(2 * time.Second)
			available := tc.edit(&edgeGrant, &proof)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- AuthenticateEdge(ctx, y, func(string) (model.DeviceGrant, bool) { return edgeGrant, available })
			}()
			if err := AuthenticateClient(ctx, x, proof, key); err == nil {
				t.Fatal("invalid admission was accepted by client")
			}
			if err := <-done; err == nil {
				t.Fatal("invalid admission was accepted by edge")
			}
		})
	}
}
