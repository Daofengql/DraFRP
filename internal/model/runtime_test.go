package model

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestClientSyncLegacyPayloadCompatibility(t *testing.T) {
	in := ClientSyncRequest{DeviceID: "device", SessionID: "session", Timestamp: 123, Signature: "excluded", Capabilities: []string{"tcp"}, AppliedRevision: 7, Nonce: "nonce"}
	want := "drafrp-client-sync-v2\n" + `{"device_id":"device","session_id":"session","timestamp":123,"signature":"","capabilities":["tcp"],"applied_revision":7,"nonce":"nonce"}`
	if got := ClientSyncPayload(in); string(got) != want {
		t.Fatalf("legacy signature payload changed: %s", got)
	}
}

func TestClientSyncLegacyCarrierQualityOmission(t *testing.T) {
	const wire = `{"device_id":"device","session_id":"session","timestamp":123,"signature":"","capabilities":["tcp"],"applied_revision":7,"nonce":"nonce","runtime":{"reported_at":"2026-10-21T12:00:00Z","received_at":"0001-01-01T00:00:00Z","snapshot_expires_at":"2026-10-21T12:01:00Z","preferred_transport":"auto","active_flows":0,"active_carriers":1,"quic_carriers":0,"tls_carriers":1,"carriers":[{"edge_id":"edge","transport":"tls","address":"edge.example:443","server_name":"edge.example","active_flows":0,"established_at":"2026-10-21T11:59:00Z","handshake_ms":12.5}],"endpoints":[],"truncated":false}}`
	var in ClientSyncRequest
	if err := json.Unmarshal([]byte(wire), &in); err != nil {
		t.Fatal(err)
	}
	if got := string(ClientSyncPayload(in)); got != "drafrp-client-sync-v2\n"+wire {
		t.Fatalf("old runtime signature bytes changed: %s", got)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	in.Runtime.Carriers[0].Quality = &CarrierQualityRuntime{Source: "carrier_probe_v1", Samples: 1}
	sig := ed25519.Sign(key, ClientSyncPayload(in))
	in.Runtime.Carriers[0].Quality.Timeouts++
	if ed25519.Verify(pub, ClientSyncPayload(in), sig) {
		t.Fatal("probe report is outside the signature")
	}
}

func TestClientSyncSignatureCoversRuntime(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	in := ClientSyncRequest{DeviceID: "device", Runtime: &DeviceRuntime{ReportedAt: time.Now().UTC(), PreferredTransport: "auto"}}
	payload := ClientSyncPayload(in)
	if !bytes.Contains(payload, []byte(`"runtime":`)) {
		t.Fatal("runtime missing from signed payload")
	}
	sig := ed25519.Sign(key, payload)
	in.Runtime.PreferredTransport = "tls_only"
	if ed25519.Verify(pub, ClientSyncPayload(in), sig) {
		t.Fatal("runtime tampering retained a valid signature")
	}
	in.Runtime = nil
	if ed25519.Verify(pub, ClientSyncPayload(in), sig) {
		t.Fatal("removing runtime retained a valid signature")
	}
}
