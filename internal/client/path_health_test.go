package client

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"github.com/quic-go/quic-go"
)

func TestAutoFallbackCooldownAndQUICRecoveryPreservesExistingFlow(t *testing.T) {
	a, err := New(Config{CloudURL: "http://127.0.0.1", StateDir: t.TempDir(), MaxCarriersPerEdge: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		c, err := origin.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	cert, ca := certificate(t, "edge.test")
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{protocol.ALPN}}
	tcp, err := tls.Listen("tcp4", "127.0.0.1:0", tc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blackhole.Close() })
	quicAddress := blackhole.LocalAddr().String()
	d := model.DeviceGrant{DeviceID: "device", TenantID: "tenant", PublicKey: base64.StdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey)), SessionID: a.st.SessionID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}
	e := model.Edge{ID: "edge", CACert: ca, MaxCarriers: 2, Endpoints: []model.Endpoint{{Transport: "quic", Address: quicAddress, ServerName: "edge.test"}, {Transport: "tls", Address: tcp.Addr().String(), ServerName: "edge.test"}}}
	r := model.Rule{ID: "rule", Version: 1, TenantID: d.TenantID, DeviceID: d.DeviceID, EdgeID: e.ID, Protocol: "tcp", SourceMode: "socket", Target: origin.Addr().String(), Transport: "auto", Enabled: true}
	a.mu.Lock()
	a.st.DeviceID = d.DeviceID
	a.snap = model.ClientSnapshot{Revision: 1, ExpiresAt: d.ExpiresAt, Device: d, Rules: []model.Rule{r}, Edges: []model.Edge{e}}
	a.mu.Unlock()
	acceptedTLS := make(chan *protocol.Carrier, 1)
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			return
		}
		c, err := protocol.WrapTLS(conn, true, e.ID)
		if err == nil {
			err = protocol.AuthenticateEdge(ctx, c, func(id string) (model.DeviceGrant, bool) { return d, id == d.DeviceID })
		}
		if err != nil {
			if c != nil {
				c.Close()
			}
			return
		}
		acceptedTLS <- c
	}()
	started := time.Now()
	if err := a.ConnectEdge(ctx, e); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("UDP blackhole delayed TLS fallback for %v", elapsed)
	}
	var tlsCarrier *protocol.Carrier
	select {
	case tlsCarrier = <-acceptedTLS:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { tlsCarrier.Close() })
	stream := openFlow(t, tlsCarrier, r, 101, false)
	result(t, stream)
	echo := func(payload string) {
		t.Helper()
		_ = stream.SetDeadline(time.Now().Add(time.Second))
		if err := protocol.WriteFull(stream, []byte(payload)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, buffer); err != nil || string(buffer) != payload {
			t.Fatalf("existing TLS flow %q, %v", buffer, err)
		}
	}
	echo("before-quic-recovery")
	key := pathKey(e, e.Endpoints[0], d)
	var firstAttempt time.Time
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		a.mu.RLock()
		h := a.pathHealth[key]
		if h != nil && !h.Probing && h.Failures > 0 {
			firstAttempt = h.LastAttempt
		}
		a.mu.RUnlock()
		if !firstAttempt.IsZero() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if firstAttempt.IsZero() {
		t.Fatal("losing QUIC probe did not enter cooldown")
	}
	for i := 0; i < 10; i++ {
		if err := a.ConnectEdge(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	a.mu.RLock()
	unchanged := a.pathHealth[key].LastAttempt == firstAttempt
	a.mu.RUnlock()
	if !unchanged {
		t.Fatal("maintenance bypassed endpoint cooldown")
	}
	_ = blackhole.Close()
	udp, err := quic.ListenAddr(quicAddress, tc, protocol.QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	acceptedQUIC := make(chan *protocol.Carrier, 1)
	go func() {
		q, err := udp.Accept(ctx)
		if err != nil {
			return
		}
		c := protocol.WrapQUIC(q, e.ID)
		if protocol.AuthenticateEdge(ctx, c, func(id string) (model.DeviceGrant, bool) { return d, id == d.DeviceID }) != nil {
			c.Close()
			return
		}
		acceptedQUIC <- c
	}()
	a.mu.Lock()
	a.snap.Edges[0].MaxCarriers = 1
	retryAt := a.pathHealth[key].RetryAt
	a.mu.Unlock()
	for time.Now().Before(retryAt.Add(30 * time.Millisecond)) {
		if err := a.ConnectEdge(ctx, e); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.mu.Lock()
	unchanged = a.pathHealth[key].LastAttempt == firstAttempt
	a.snap.Edges[0].MaxCarriers = 2
	a.mu.Unlock()
	if !unchanged || len(a.TransportStatus()) != 1 {
		t.Fatal("background QUIC probe exceeded approved single-carrier budget")
	}
	var quicCarrier *protocol.Carrier
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && quicCarrier == nil; {
		if err := a.ConnectEdge(ctx, e); err != nil {
			t.Fatal(err)
		}
		select {
		case quicCarrier = <-acceptedQUIC:
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	if quicCarrier == nil {
		t.Fatal("available QUIC path was not recovered after cooldown")
	}
	t.Cleanup(func() { quicCarrier.Close() })
	status := a.TransportStatus()
	if len(status) != 2 {
		t.Fatalf("recovery exceeded or discarded the approved carrier budget: %+v", status)
	}
	echo("same-tls-flow-after-quic-recovery")
	for _, s := range a.EndpointStatus() {
		if s.Transport == "quic" && (s.HandshakeMS < 0 || s.LastSuccess.IsZero() || s.ErrorCode != "") {
			t.Fatalf("recovered path lacks real handshake observation: %+v", s)
		}
	}
}

func TestEndpointObservationsAreScopedToCurrentAuthority(t *testing.T) {
	a, _, _ := connected(t, "tls", model.Rule{Protocol: "tcp", Target: "127.0.0.1:1"})
	if len(a.EndpointStatus()) != 1 {
		t.Fatal("authenticated TLS attempt was not recorded")
	}
	a.mu.Lock()
	a.snap.Edges[0].CACert = "replaced certificate authority"
	a.reconcileLocked()
	remaining := len(a.pathHealth)
	a.mu.Unlock()
	if remaining != 0 || len(a.EndpointStatus()) != 0 {
		t.Fatal("old authority retained health or cooldown state")
	}
}

func TestTLSOnlyNeverProbesQUIC(t *testing.T) {
	a, _, _ := connected(t, "tls", model.Rule{Protocol: "tcp", Target: "127.0.0.1:1"})
	a.mu.Lock()
	e := a.snap.Edges[0]
	e.Endpoints = append(e.Endpoints, model.Endpoint{Transport: "quic", Address: "127.0.0.1:1", ServerName: "edge.test"})
	a.snap.Edges[0] = e
	// The endpoint remains authorized; only the local/rule TLS preference
	// must prevent a UDP probe, without relying on endpoint unavailability.
	for key := range a.carrierEdges {
		a.carrierEdges[key] = e
	}
	a.mu.Unlock()
	if err := a.ConnectEdge(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	for _, status := range a.EndpointStatus() {
		if status.Transport != "tls" {
			t.Fatalf("tls_only sent an unsolicited QUIC probe: %+v", status)
		}
	}
}

func TestEndpointFailureClassificationAndBoundedBackoff(t *testing.T) {
	for _, testcase := range []struct {
		err  error
		code string
	}{{&protocol.AdmissionError{Code: "unauthorized", Message: "invalid grant"}, "authorization_rejected"}, {x509.UnknownAuthorityError{}, "tls_identity_failed"}, {context.DeadlineExceeded, "path_timeout"}, {context.Canceled, "race_not_selected"}, {errors.New("connection refused"), "connection_failed"}} {
		if got := endpointErrorCode(testcase.err); got != testcase.code {
			t.Errorf("%v classified as %s, want %s", testcase.err, got, testcase.code)
		}
	}
	for failures := uint(1); failures <= 32; failures++ {
		if delay := endpointBackoff(failures); delay < 2*time.Second || delay > time.Minute {
			t.Fatalf("unbounded reconnect delay %v at failure %d", delay, failures)
		}
	}
}

func TestOldSuccessDoesNotResetNewFailureBackoff(t *testing.T) {
	a, _, _ := connected(t, "tls", model.Rule{Protocol: "tcp", Target: "127.0.0.1:1"})
	a.mu.Lock()
	e, d := a.snap.Edges[0], a.snap.Device
	key := pathKey(e, e.Endpoints[0], d)
	h := a.pathHealth[key]
	h.LastSuccess = time.Now().Add(-time.Hour)
	h.Failures, h.ErrorCode, h.RetryAt = 3, "connection_failed", time.Time{}
	a.mu.Unlock()
	started := time.Now()
	if !a.beginEndpoint(key, started) {
		t.Fatal("eligible retry was not started")
	}
	a.finishEndpoint(key, started, errors.New("still unavailable"), false)
	a.mu.RLock()
	failures, retry := a.pathHealth[key].Failures, a.pathHealth[key].RetryAt
	a.mu.RUnlock()
	if failures != 4 || retry.Sub(started) < 16*time.Second {
		t.Fatalf("old successful handshake reset new failure streak: failures=%d retry=%v", failures, retry)
	}
}
