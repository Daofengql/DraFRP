package systemtest

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"drafrp/internal/client"
	"drafrp/internal/edge"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"github.com/quic-go/quic-go"
)

// The production Agent and edge renew independently. In particular, admission
// must work when the Agent has just renewed a ten-second lease while the edge
// still holds the preceding, valid lease. Synchronizing the edge after every
// Agent renewal would hide this failure.
func TestShortTTLIndependentRenewalAdmission(t *testing.T) {
	for _, transport := range []string{"quic", "tls"} {
		t.Run(transport, func(t *testing.T) {
			_, browser := testCloudWithTTL(t, 10*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			certFile, keyFile, certificate := certFiles(t)
			carrierPort, businessPort := freePort(t), freePort(t)
			for businessPort == carrierPort {
				businessPort = freePort(t)
			}
			token := strings.Repeat("renewal-admission-", 3)
			var edgeConfig model.Edge
			browser.api("POST", "/api/v1/edges", map[string]any{"name": "renewal-edge", "token": token, "public_host": "127.0.0.1", "listen_host": "127.0.0.1", "endpoints": carrierEndpoints(carrierPort), "ca_cert": certificate, "http_port": 0, "https_port": 0, "port_min": businessPort, "port_max": businessPort, "max_carriers": 8, "capacity_bps": -1}, &edgeConfig, 201)
			runtime := edge.New(edge.Config{CloudURL: browser.url, EdgeID: edgeConfig.ID, Token: token, CertFile: certFile, KeyFile: keyFile, ListenHost: "127.0.0.1"})
			defer runtime.Close()
			stateDir := t.TempDir()
			agent, err := client.New(client.Config{CloudURL: browser.url, StateDir: stateDir, Transport: transport + "_only"})
			if err != nil {
				t.Fatal(err)
			}
			defer agent.Close()
			binding, err := agent.Bind(ctx)
			if err != nil {
				t.Fatal(err)
			}
			browser.api("POST", "/api/v1/bind/confirm", map[string]string{"user_code": binding.UserCode}, nil, 200)
			bound, err := agent.PollBind(ctx, binding.ID, binding.PollToken)
			if err != nil || bound.Status != "approved" {
				t.Fatal(bound, err)
			}
			origin, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			go func() {
				for {
					conn, err := origin.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
				}
			}()
			browser.api("POST", "/api/v1/rules", model.Rule{Name: "renewing-rule", DeviceID: bound.DeviceID, EdgeID: edgeConfig.ID, Protocol: "tcp", Target: origin.Addr().String(), PublicPort: businessPort, SourceMode: "socket", Transport: transport + "_only", Enabled: true, TimeoutSeconds: 3}, nil, 201)
			renewCtx, stopRenew := context.WithCancel(ctx)
			var renewals sync.WaitGroup
			var agentCount, edgeCount atomic.Int32
			renewalErrors := make(chan error, 2)
			loop := func(name string, phase time.Duration, count *atomic.Int32, sync func(context.Context) error) {
				defer renewals.Done()
				timer := time.NewTimer(phase)
				defer timer.Stop()
				for {
					select {
					case <-renewCtx.Done():
						return
					case <-timer.C:
					}
					if err := sync(renewCtx); err != nil {
						if renewCtx.Err() == nil {
							renewalErrors <- fmt.Errorf("%s renewal: %w", name, err)
						}
						return
					}
					count.Add(1)
					timer.Reset(time.Second)
				}
			}
			renewals.Add(2)
			go loop("agent", 0, &agentCount, func(ctx context.Context) error { _, err := agent.Sync(ctx); return err })
			go loop("edge", 350*time.Millisecond, &edgeCount, runtime.Sync)
			defer func() { stopRenew(); renewals.Wait() }()
			checkRenewals := func() {
				t.Helper()
				select {
				case err := <-renewalErrors:
					t.Fatal(err)
				default:
				}
			}
			// Observe a genuinely independent, older edge lease before dialing.
			// The assertion below fails immediately with the previous full-lease
			// proof, even if a later edge heartbeat could temporarily mask it.
			var agentExpiry, edgeExpiry time.Time
			for until := time.Now().Add(10 * time.Second); time.Now().Before(until); {
				checkRenewals()
				as, es := agent.Snapshot(), runtime.Snapshot()
				if agentCount.Load() >= 2 && len(es.Devices) == 1 && es.Devices[0].ExpiresAt.Before(as.Device.ExpiresAt) && time.Until(es.Devices[0].ExpiresAt) > 3*time.Second {
					agentExpiry, edgeExpiry = as.Device.ExpiresAt, es.Devices[0].ExpiresAt
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if edgeExpiry.IsZero() {
				t.Fatalf("independent renewals did not produce the lease ordering: agent=%+v edge=%+v", agent.Snapshot(), runtime.Snapshot())
			}
			if err := agent.ConnectEdge(ctx, edgeConfig); err != nil {
				t.Fatalf("valid older edge lease rejected a freshly renewed Agent: edge=%s agent=%s: %v", edgeExpiry, agentExpiry, err)
			}
			var conn net.Conn
			for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
				conn, err = net.DialTimeout("tcp", address(businessPort), time.Second)
				if err == nil && runtime.RuntimeStatus().ActiveCarriers == 1 {
					break
				}
				if conn != nil {
					_ = conn.Close()
					conn = nil
				}
				time.Sleep(10 * time.Millisecond)
			}
			if conn == nil {
				t.Fatal("admitted carrier never became available", err)
			}
			defer conn.Close()
			// Keep the same business stream alive beyond both the admission proof
			// and the original ten-second lease. Only renewed local authority can
			// sustain it, without reconnecting or extending proof validity.
			for until := time.Now().Add(11 * time.Second); ; {
				checkRenewals()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				payload := []byte("independently-renewed-" + transport)
				if _, err := conn.Write(payload); err != nil {
					t.Fatal("renewal closed the existing business flow", err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil || string(got) != string(payload) {
					t.Fatalf("renewing flow: %q %v", got, err)
				}
				if time.Now().After(until) {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if agentCount.Load() < 3 || edgeCount.Load() < 3 {
				t.Fatal("test did not renew both local snapshots repeatedly")
			}
			// Revoke through the real control API, then refresh only the edge. The
			// Agent deliberately keeps a still-live snapshot: it cannot override
			// the edge's newer revocation using a shorter admission proof.
			stopRenew()
			renewals.Wait()
			// The same authorized carrier collected multiple real control RTTs
			// across renewable snapshots while preserving this one business flow.
			local := agent.RuntimeStatus()
			if local.ActiveCarriers != 1 || local.ActiveFlows != 1 || len(local.Carriers) != 1 || local.Carriers[0].Quality == nil || local.Carriers[0].Quality.Successes < 2 || local.Carriers[0].Quality.Timeouts != 0 {
				t.Fatalf("continuous probe disrupted business or missed renewed carrier: %+v", local)
			}
			if _, err := agent.Sync(ctx); err != nil {
				t.Fatal("signed quality sync", err)
			}
			var listed struct {
				Items []model.Device `json:"items"`
			}
			browser.api("GET", "/api/v1/devices", nil, &listed, 200)
			if len(listed.Items) != 1 || listed.Items[0].Runtime == nil || len(listed.Items[0].Runtime.Carriers) != 1 {
				t.Fatal("quality missing from cloud device read", listed)
			}
			quality := listed.Items[0].Runtime.Carriers[0].Quality
			// A successful fast loopback round trip can span zero timer ticks on
			// Windows. Completed authenticated samples and their timestamps prove
			// observation; requiring a strictly positive duration would fabricate
			// a precision requirement the platform clock does not provide.
			if quality == nil || quality.Samples < 2 || quality.Successes < 2 || quality.Timeouts != 0 || quality.Errors != 0 || quality.LastSuccessAt.IsZero() || quality.Source != "carrier_probe_v1" {
				t.Fatalf("real round trips not persisted through signature: %+v", quality)
			}
			if (quality.QUIC != nil) != (transport == "quic") {
				t.Fatal("native QUIC source disagrees with actual transport", quality)
			}
			browser.api("DELETE", "/api/v1/devices/"+bound.DeviceID, nil, nil, 200)
			if err := runtime.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if _, err := conn.Read(one[:]); err == nil {
				t.Fatal("revoked device retained its admitted business flow")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("revocation failed to terminate the business flow")
			}
			// Bypass the Agent's successful-endpoint cooldown to perform an actual
			// second proof exchange using this isolated test identity. A cooldown
			// error would not establish that the edge enforced its new snapshot.
			var persisted struct {
				PrivateKey string `json:"private_key"`
			}
			data, err := os.ReadFile(filepath.Join(stateDir, "device.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &persisted); err != nil {
				t.Fatal(err)
			}
			key, err := base64.StdEncoding.DecodeString(persisted.PrivateKey)
			if err != nil || len(key) != ed25519.PrivateKeySize {
				t.Fatal("invalid isolated test identity")
			}
			proof := agent.Snapshot().Device
			if !time.Now().Before(proof.ExpiresAt) {
				t.Fatal("test did not retain a valid old Agent snapshot")
			}
			if until := time.Now().Add(2 * time.Second); until.Before(proof.ExpiresAt) {
				proof.ExpiresAt = until
			}
			tlsConfig, err := protocol.TLSClient("", certificate, "edge.test")
			if err != nil {
				t.Fatal(err)
			}
			admissionCtx, stopAdmission := context.WithTimeout(ctx, 2*time.Second)
			defer stopAdmission()
			var carrier *protocol.Carrier
			if transport == "quic" {
				q, err := quic.DialAddr(admissionCtx, address(carrierPort), tlsConfig, protocol.QUICConfig())
				if err != nil {
					t.Fatal(err)
				}
				carrier = protocol.WrapQUIC(q, edgeConfig.ID)
			} else {
				network, err := (&tls.Dialer{Config: tlsConfig}).DialContext(admissionCtx, "tcp", address(carrierPort))
				if err != nil {
					t.Fatal(err)
				}
				carrier, err = protocol.WrapTLS(network, false, edgeConfig.ID)
				if err != nil {
					_ = network.Close()
					t.Fatal(err)
				}
			}
			defer carrier.Close()
			admissionErr := protocol.AuthenticateClient(admissionCtx, carrier, proof, ed25519.PrivateKey(key))
			var denied *protocol.AdmissionError
			var remoteClose *quic.ApplicationError
			explicitlyDenied := errors.As(admissionErr, &denied) && denied.Code == "unauthorized"
			// QUIC connection close can overtake the unauthorized Result. It is
			// still a rejection if the peer explicitly closes this new carrier;
			// unlike net.ErrClosed, this typed remote error cannot be a timeout or
			// the local context's cancellation of an otherwise pending admission.
			remotelyClosed := transport == "quic" && errors.As(admissionErr, &remoteClose) && remoteClose.Remote && remoteClose.ErrorCode == 0
			if admissionCtx.Err() != nil || !explicitlyDenied && !remotelyClosed {
				t.Fatalf("revoked device admission was not rejected promptly: %v", admissionErr)
			}
			if remotelyClosed {
				t.Log("QUIC peer rejected admission by closing the connection before its reason Result arrived")
			}
			select {
			case <-carrier.Done():
			case <-time.After(time.Second):
				t.Fatal("rejected carrier remained open")
			}
			if observed := runtime.RuntimeStatus(); observed.ActiveCarriers != 0 || observed.ActiveFlows != 0 {
				t.Fatalf("revoked identity retained an active carrier or flow: %+v", observed)
			}
		})
	}
}
