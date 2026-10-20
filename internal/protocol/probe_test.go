package protocol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"drafrp/internal/model"
	"github.com/quic-go/quic-go"
)

// Both branches use actual encrypted loopback sockets, not a fabricated RTT or
// a library-presence assertion. Authentication negotiates the probe capability.
func networkProbePair(t *testing.T, transport string) (*Carrier, *Carrier) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"edge.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}, ServerName: "edge.test", RootCAs: roots}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		c   *Carrier
		err error
	}
	accepted := make(chan result, 1)
	var client *Carrier
	if transport == "quic" {
		listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, QUICConfig())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			q, err := listener.Accept(ctx)
			if err != nil {
				accepted <- result{err: err}
				return
			}
			accepted <- result{c: WrapQUIC(q, "edge")}
		}()
		q, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, QUICConfig())
		if err != nil {
			t.Fatal(err)
		}
		client = WrapQUIC(q, "edge")
	} else {
		listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				accepted <- result{err: err}
				return
			}
			c, err := WrapTLS(conn, true, "edge")
			accepted <- result{c, err}
		}()
		conn, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		client, err = WrapTLS(conn, false, "edge")
		if err != nil {
			t.Fatal(err)
		}
	}
	server := <-accepted
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.c.Close() })
	d := model.DeviceGrant{DeviceID: "device", TenantID: "tenant", PublicKey: base64.StdEncoding.EncodeToString(pub), SessionID: "session", Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}
	authenticated := make(chan error, 1)
	go func() {
		authenticated <- AuthenticateEdge(ctx, server.c, func(string) (model.DeviceGrant, bool) { return d, true })
	}()
	if err = AuthenticateClient(ctx, client, d, key); err != nil {
		t.Fatal(err)
	}
	if err = <-authenticated; err != nil {
		t.Fatal(err)
	}
	client.EstablishedAt = time.Now()
	return client, server.c
}

func TestProbeRealEncryptedCarriersAndBusinessIsolation(t *testing.T) {
	for _, transport := range []string{"tls", "quic"} {
		t.Run(transport, func(t *testing.T) {
			client, edge := networkProbePair(t, transport)
			client.HandshakeDuration = 10 * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			handled := make(chan struct{})
			go func() {
				defer close(handled)
				st, err := edge.Accept(ctx)
				if err == nil {
					time.Sleep(25 * time.Millisecond)
					edge.HandleProbe(ctx, st, func() bool { return true })
				}
			}()
			if err := client.Probe(ctx); err != nil {
				t.Fatal(err)
			}
			<-handled
			q := client.Quality()
			if q == nil || q.Source != "carrier_probe_v1" || q.Samples != 1 || q.Successes != 1 || q.Timeouts != 0 || q.LatestRTTMS < 20 || q.LatestRTTMS >= 2000 || client.Active() != 0 || edge.Active() != 0 {
				t.Fatalf("invalid real probe observation: %+v", q)
			}
			if transport == "quic" {
				if q.QUIC == nil || q.QUIC.Source != "quic_go_rfc9002" || q.QUIC.PacketsSent == 0 || q.QUIC.PacketsReceived == 0 || q.QUIC.LatestRTTMS <= 0 {
					t.Fatalf("missing native QUIC observation: %+v", q.QUIC)
				}
			} else if q.QUIC != nil {
				t.Fatal("TLS fabricated QUIC packet statistics")
			}
			if err := client.Probe(ctx); !errors.Is(err, errProbeUnavailable) || client.Quality().Samples != 1 {
				t.Fatal("probe frequency bound bypassed", err)
			}
			// An edge-initiated application stream still works after the probe.
			written := make(chan error, 1)
			go func() {
				st, err := edge.Open(ctx)
				if err == nil {
					err = WriteFull(st, []byte("live"))
					Finish(st)
				}
				written <- err
			}()
			st, err := client.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var body [4]byte
			_, err = io.ReadFull(st, body[:])
			Abort(st)
			if err != nil || string(body[:]) != "live" || <-written != nil {
				t.Fatalf("business affected: %q %v", body, err)
			}
			_ = client.Close()
			if client.Quality() != nil {
				t.Fatal("closed carrier exposed its old window")
			}
		})
	}
}

func TestProbeTimeoutCancellationAndUnauthorizedEcho(t *testing.T) {
	for _, transport := range []string{"tls", "quic"} {
		for _, scenario := range []string{"timeout", "cancel", "unauthorized", "invalid_echo"} {
			t.Run(transport+"/"+scenario, func(t *testing.T) {
				client, edge := networkProbePair(t, transport)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				accepted := make(chan struct{})
				go func() {
					st, err := edge.Accept(ctx)
					if err != nil {
						close(accepted)
						return
					}
					defer Abort(st)
					close(accepted)
					if scenario == "unauthorized" {
						edge.HandleProbe(ctx, st, func() bool { return false })
						return
					}
					var request [24]byte
					_ = st.SetDeadline(time.Now().Add(3 * time.Second))
					_, _ = io.ReadFull(st, request[:])
					if scenario == "invalid_echo" {
						request[23] ^= 1
						_ = WriteFull(st, request[:])
						Finish(st)
						return
					}
					<-ctx.Done()
				}()
				if scenario == "cancel" {
					go func() { <-accepted; time.Sleep(20 * time.Millisecond); cancel() }()
				}
				started := time.Now()
				if err := client.Probe(ctx); err == nil {
					t.Fatal("unexpected probe success")
				}
				q := client.Quality()
				if scenario == "cancel" {
					if q != nil || time.Since(started) > time.Second {
						t.Fatal("local cancellation counted as a network failure", q)
					}
				} else if q == nil || q.Samples != 1 || q.Successes != 0 || q.LatestRTTMS != 0 || q.QUIC != nil || (scenario == "timeout" && q.Timeouts != 1) || (scenario != "timeout" && q.Errors != 1) {
					t.Fatalf("wrong failure window: %+v", q)
				}
				if time.Since(started) > ProbeTimeout+time.Second {
					t.Fatal("probe exceeded duration bound")
				}
				select {
				case <-client.Done():
					t.Fatal("failed probe closed business carrier")
				default:
				}
			})
		}
	}
}

func TestProbeLegacyNegotiationAndPreauthentication(t *testing.T) {
	for _, side := range []string{"legacy_client", "legacy_edge"} {
		t.Run(side, func(t *testing.T) {
			client, edge := tlsPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := client.Probe(ctx); !errors.Is(err, errProbeUnavailable) {
				t.Fatal("probe before admission", err)
			}
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			d := model.DeviceGrant{DeviceID: "device", SessionID: "session", Generation: 1, PublicKey: base64.StdEncoding.EncodeToString(pub), ExpiresAt: time.Now().Add(time.Minute)}
			done := make(chan error, 1)
			if side == "legacy_client" {
				go func() { done <- AuthenticateEdge(ctx, edge, func(string) (model.DeviceGrant, bool) { return d, true }) }()
				st, err := client.Open(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				_ = WriteJSON(st, admissionHello{Version: 1})
				var ch Challenge
				if err = ReadJSON(st, &ch); err != nil {
					t.Fatal(err)
				}
				if ch.ProbeVersion != 0 {
					t.Fatal("capability guessed for old Agent")
				}
				p := Proof{DeviceID: d.DeviceID, SessionID: d.SessionID, Generation: d.Generation, ExpiresAt: d.ExpiresAt}
				p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, ProofPayload(ch, p)))
				_ = WriteJSON(st, p)
				var result Result
				if err = ReadJSON(st, &result); err != nil || result.Code != "" {
					t.Fatal(result, err)
				}
			} else {
				go func() {
					st, err := edge.Accept(ctx)
					if err != nil {
						done <- err
						return
					}
					defer st.Close()
					var hello admissionHello
					_ = ReadJSON(st, &hello)
					_ = WriteJSON(st, Challenge{Version: 1, EdgeID: "edge", Nonce: ID()})
					var proof Proof
					_ = ReadJSON(st, &proof)
					done <- WriteJSON(st, Result{})
				}()
				if err := AuthenticateClient(ctx, client, d, key); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if client.ProbeSupported() || edge.ProbeSupported() || client.Quality() != nil {
				t.Fatal("old peer unexpectedly probed")
			}
			written := make(chan error, 1)
			go func() {
				st, err := edge.Open(ctx)
				if err == nil {
					err = WriteFull(st, []byte("legacy-business"))
					Finish(st)
				}
				written <- err
			}()
			st, err := client.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(st)
			Abort(st)
			if err != nil || string(payload) != "legacy-business" || <-written != nil {
				t.Fatal("legacy business stream no longer works", string(payload), err)
			}
		})
	}
}

func TestProbeWindowExpiresAndSnapshotIsDetached(t *testing.T) {
	c, _ := tlsPair(t)
	c.probe.enabled.Store(true)
	at := time.Now()
	c.probe.count = ProbeWindowLimit
	for i := range c.probe.samples {
		c.probe.samples[i] = probeSample{started: at.Add(-time.Duration(ProbeWindowLimit-i) * ProbeInterval), finished: at.Add(-time.Duration(ProbeWindowLimit-i)*ProbeInterval + time.Millisecond), rtt: time.Millisecond}
	}
	c.probe.samples[0].started = at.Add(-probeWindowAge - time.Second)
	q := c.Quality()
	if q == nil || q.Samples != ProbeWindowLimit-1 || q.Successes != q.Samples || q.MeanRTTMS != 1 {
		t.Fatal("window age/aggregate", q)
	}
	q.Successes = 999
	if c.Quality().Successes == 999 {
		t.Fatal("snapshot aliases carrier state")
	}
	c.clearProbeSamples()
	if c.Quality() != nil {
		t.Fatal("retired session retained observation")
	}
}

func TestProbeSingleInflightAndResponderRechecksAuthority(t *testing.T) {
	for _, scenario := range []string{"single_inflight", "revoked_during_read", "slow_sender"} {
		t.Run(scenario, func(t *testing.T) {
			client, edge := tlsPair(t)
			client.probe.enabled.Store(true)
			edge.probe.enabled.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			accepted := make(chan struct{})
			handled := make(chan struct{})
			var checks atomic.Int32
			go func() {
				defer close(handled)
				st, err := edge.Accept(ctx)
				if err != nil {
					close(accepted)
					return
				}
				close(accepted)
				if scenario == "single_inflight" {
					time.Sleep(40 * time.Millisecond)
				}
				edge.HandleProbe(ctx, st, func() bool { return checks.Add(1) == 1 || scenario != "revoked_during_read" })
			}()
			if scenario == "slow_sender" {
				st, err := client.Open(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer Abort(st)
				start := time.Now()
				_ = WriteFull(st, probeMagic[:1])
				<-handled
				if time.Since(start) > ProbeTimeout+500*time.Millisecond {
					t.Fatal("slow control read escaped deadline")
				}
				if client.Active() != 0 || edge.Active() != 0 {
					t.Fatal("control stream reserved business capacity")
				}
				return
			}
			result := make(chan error, 1)
			go func() { result <- client.Probe(ctx) }()
			<-accepted
			if scenario == "single_inflight" {
				if err := client.Probe(ctx); !errors.Is(err, errProbeUnavailable) {
					t.Fatal("parallel probe accepted", err)
				}
				if err := <-result; err != nil {
					t.Fatal(err)
				}
				if q := client.Quality(); q == nil || q.Samples != 1 {
					t.Fatal("concurrent request altered sample count", q)
				}
			} else {
				if err := <-result; err == nil || checks.Load() != 2 {
					t.Fatal("revoked authorization still echoed control data", err, checks.Load())
				}
			}
			<-handled
		})
	}
}

func TestProbeNativeStatsRejectUnmeasuredLibraryDefaults(t *testing.T) {
	stats := quic.ConnectionStats{MinRTT: 100 * time.Millisecond, LatestRTT: 100 * time.Millisecond, SmoothedRTT: 100 * time.Millisecond, PacketsReceived: 10}
	if measuredQUICStats(stats) {
		t.Fatal("library initial/path-migration RTT became an observation")
	}
	stats.MeanDeviation = 50 * time.Millisecond
	if !measuredQUICStats(stats) {
		t.Fatal("a real measured 100 ms RTT was mistaken for a default")
	}
}

func TestProbeObservedZeroTimerTicksRemainSuccessful(t *testing.T) {
	c, _ := tlsPair(t)
	c.probe.enabled.Store(true)
	at := time.Now()
	c.probe.count, c.probe.next = 2, 2
	c.probe.samples[0] = probeSample{started: at.Add(-6 * time.Second), finished: at.Add(-6*time.Second + 1039600*time.Nanosecond), rtt: 1039600 * time.Nanosecond}
	c.probe.samples[1] = probeSample{started: at.Add(-time.Second), finished: at.Add(-time.Second), rtt: 0}
	q := c.Quality()
	if q == nil || q.Samples != 2 || q.Successes != 2 || q.Timeouts != 0 || q.Errors != 0 || q.LastSuccessAt.IsZero() || q.LatestRTTMS != 0 || q.MinRTTMS != 0 || q.MaxRTTMS != 1.0396 || q.MeanRTTMS != .5198 {
		t.Fatalf("real timer zero was converted to missing data or altered: %+v", q)
	}
}

func TestProbeSchedulingUsesActualAttemptBoundary(t *testing.T) {
	c, _ := tlsPair(t)
	base := time.Now()
	actualStart := base.Add(time.Microsecond)
	c.probe.lastAttempt = actualStart
	for _, tc := range []struct {
		name string
		at   time.Time
		want time.Duration
	}{
		{"old_ticker_one_microsecond_early", base.Add(ProbeInterval), time.Microsecond},
		{"exact_cooldown_boundary", actualStart.Add(ProbeInterval), 0},
		{"after_cooldown", actualStart.Add(ProbeInterval + time.Second), 0},
		{"slow_reply_does_not_add_an_extra_interval", actualStart.Add(ProbeTimeout), ProbeInterval - ProbeTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.nextProbeDelay(tc.at); got != tc.want {
				t.Fatalf("next wait %s, want %s", got, tc.want)
			}
		})
	}
}

func TestProbeObserverGetsTwoRealSamplesWithinSixSeconds(t *testing.T) {
	for _, transport := range []string{"tls", "quic"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			c, edge := networkProbePair(t, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			responded := make(chan struct{})
			go func() {
				defer close(responded)
				for {
					st, err := edge.Accept(ctx)
					if err != nil {
						return
					}
					edge.HandleProbe(ctx, st, func() bool { return true })
				}
			}()
			observed := make(chan struct{})
			var checks atomic.Int32
			go func() {
				defer close(observed)
				c.ObserveQuality(ctx, func() bool {
					// Any fixed ticker constructed before authorization is now
					// guaranteed to fire before the actual 5-second cooldown.
					if checks.Add(1) == 1 {
						time.Sleep(150 * time.Millisecond)
					}
					return true
				})
			}()
			defer func() { cancel(); <-observed; <-responded }()
			poll := time.NewTicker(5 * time.Millisecond)
			defer poll.Stop()
			for {
				select {
				case <-ctx.Done():
					t.Fatal("cadence skipped a valid attempt before six seconds")
				case <-poll.C:
					q := c.Quality()
					if q == nil || q.Successes < 2 {
						continue
					}
					if q.Samples != 2 || q.Timeouts != 0 || q.Errors != 0 || c.Active() != 0 || edge.Active() != 0 {
						t.Fatal("probe cadence changed business or outcomes", q)
					}
					c.probe.mu.Lock()
					gap := c.probe.samples[1].started.Sub(c.probe.samples[0].started)
					c.probe.mu.Unlock()
					if gap < ProbeInterval {
						t.Fatalf("external minimum interval bypassed: %s", gap)
					}
					return
				}
			}
		})
	}
}
