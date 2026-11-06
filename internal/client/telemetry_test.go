package client

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	goRuntime "runtime"
	"strings"
	"testing"
	"time"

	"drafrp/internal/model"
)

func TestRuntimeSamplesAuthenticatedCarriersAndFlows(t *testing.T) {
	for _, transport := range []string{"tls", "quic"} {
		t.Run(transport, func(t *testing.T) {
			origin, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = origin.Close() })
			go func() {
				conn, err := origin.Accept()
				if err == nil {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}
			}()
			a, edgeCarrier, rule := connected(t, transport, model.Rule{Protocol: "tcp", Target: origin.Addr().String()})
			stream := openFlow(t, edgeCarrier, rule, 419, false)
			result(t, stream)
			if _, err := stream.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var echoed [4]byte
			if _, err := io.ReadFull(stream, echoed[:]); err != nil || string(echoed[:]) != "ping" {
				t.Fatalf("real flow failed: %q %v", echoed, err)
			}
			a.mu.Lock()
			for _, health := range a.pathHealth {
				health.LastError = "secret-local-CA-path"
			}
			a.mu.Unlock()
			runtime := a.RuntimeStatus()
			if runtime.Platform != goRuntime.GOOS || runtime.NetworkMode != "socket" {
				t.Fatal("client platform/network mode missing", runtime)
			}
			if runtime.ActiveCarriers != 1 || runtime.ActiveFlows != 1 || len(runtime.Carriers) != 1 || len(runtime.Endpoints) != 1 || runtime.Truncated {
				t.Fatalf("real carrier/flow was not sampled: %+v", runtime)
			}
			carrier, endpoint := runtime.Carriers[0], runtime.Endpoints[0]
			if carrier.Transport != transport || carrier.ActiveFlows != 1 || carrier.HandshakeMS <= 0 || carrier.EstablishedAt.IsZero() || carrier.Address != endpoint.Address || endpoint.ServerName != "edge.test" || endpoint.LastSuccess.IsZero() || endpoint.HandshakeMS <= 0 {
				t.Fatalf("missing handshake or endpoint observations: %+v / %+v", carrier, endpoint)
			}
			if transport == "quic" && (runtime.QUICCarriers != 1 || runtime.TLSCarriers != 0) || transport == "tls" && (runtime.TLSCarriers != 1 || runtime.QUICCarriers != 0) {
				t.Fatal("transport counters do not match the real carrier", runtime)
			}
			encoded, err := json.Marshal(runtime)
			if err != nil || strings.Contains(string(encoded), "secret-local-CA-path") || !runtime.ReceivedAt.IsZero() || runtime.SessionID != "" || runtime.Generation != 0 {
				t.Fatalf("client supplied private diagnostics or server metadata: %s %v", encoded, err)
			}
			a.mu.Lock()
			a.snap.ExpiresAt = time.Now().Add(-time.Second)
			a.mu.Unlock()
			expired := a.RuntimeStatus()
			if expired.ActiveCarriers != 0 || expired.ActiveFlows != 0 || len(expired.Carriers) != 0 || len(expired.Endpoints) != 0 || !expired.SnapshotExpiresAt.IsZero() {
				t.Fatal("expired authorization retained live observations", expired)
			}
		})
	}
}

func TestRuntimeBoundsAndScopesEndpointObservations(t *testing.T) {
	at := time.Now().UTC()
	d := model.DeviceGrant{DeviceID: "device", SessionID: "process-session", Generation: 3, ExpiresAt: at.Add(time.Minute)}
	a := &Agent{cfg: Config{Transport: "auto"}, snap: model.ClientSnapshot{ExpiresAt: d.ExpiresAt, Device: d}, pathHealth: map[endpointKey]*endpointHealth{}}
	for i := 0; i < model.MaxDeviceRuntimeEntries+17; i++ {
		ep := model.Endpoint{Transport: "tls", Address: fmt.Sprintf("edge-%03d.example:443", i), ServerName: "edge.example"}
		e := model.Edge{ID: fmt.Sprintf("edge-%03d", i), CACert: "current CA", Endpoints: []model.Endpoint{ep}}
		a.snap.Edges = append(a.snap.Edges, e)
		a.pathHealth[pathKey(e, ep, d)] = &endpointHealth{LastAttempt: at, Failures: 2, ErrorCode: "path_timeout"}
	}
	e := a.snap.Edges[0]
	for _, mutation := range []func(*endpointKey){
		func(k *endpointKey) { k.DeviceID = "another-device" },
		func(k *endpointKey) { k.SessionID = "old-session" },
		func(k *endpointKey) { k.Generation-- },
		func(k *endpointKey) { k.CA[0]++ },
		func(k *endpointKey) { k.Endpoint.ServerName = "untrusted.example" },
	} {
		key := pathKey(e, e.Endpoints[0], d)
		mutation(&key)
		a.pathHealth[key] = &endpointHealth{LastError: "must be omitted", ErrorCode: "connection_failed"}
	}
	first, second := a.RuntimeStatus(), a.RuntimeStatus()
	if !first.Truncated || len(first.Endpoints) != model.MaxDeviceRuntimeEntries || first.Endpoints[0].EdgeID != "edge-000" || first.Endpoints[len(first.Endpoints)-1].EdgeID != "edge-127" || !reflect.DeepEqual(first.Endpoints, second.Endpoints) {
		t.Fatalf("endpoint ordering or bound is unstable: %+v", first)
	}
	for _, ep := range first.Endpoints {
		if ep.ErrorCode != "path_timeout" {
			t.Fatal("unauthorized endpoint appeared in report", ep)
		}
	}
	a.snap.Edges = nil
	if got := a.RuntimeStatus(); len(got.Endpoints) != 0 || got.Truncated {
		t.Fatal("removed endpoints retained observations", got)
	}
}

func TestSyncSendsSignedRuntime(t *testing.T) {
	a, err := New(Config{CloudURL: "http://127.0.0.1", StateDir: t.TempDir(), Transport: "tls_only"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	a.mu.Lock()
	a.st.DeviceID = "bound-device"
	a.mu.Unlock()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in model.ClientSyncRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		pub := a.key.Public().(ed25519.PublicKey)
		sig, _ := base64.StdEncoding.DecodeString(in.Signature)
		if in.Runtime == nil || in.Runtime.PreferredTransport != "tls_only" || in.Runtime.ReportedAt.IsZero() || !ed25519.Verify(pub, model.ClientSyncPayload(in), sig) {
			t.Error("sync omitted runtime or did not sign it", in.Runtime)
		}
		_ = json.NewEncoder(w).Encode(model.ClientSnapshot{Revision: 1, ExpiresAt: time.Now().Add(time.Minute), Device: model.DeviceGrant{DeviceID: in.DeviceID, TenantID: "tenant", SessionID: in.SessionID, Generation: 1, PublicKey: base64.StdEncoding.EncodeToString(pub), ExpiresAt: time.Now().Add(time.Minute)}})
	}))
	defer srv.Close()
	a.cfg.CloudURL = srv.URL
	if _, err := a.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
}
