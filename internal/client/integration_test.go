package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"github.com/quic-go/quic-go"
)

func certificate(t *testing.T, name string) (tls.Certificate, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// This exercises the real authenticated TLS/yamux or QUIC carrier, instead of
// treating library availability as proof that the Agent data path works.
func connected(t *testing.T, transport string, r model.Rule) (*Agent, *protocol.Carrier, model.Rule) {
	return connectedConfig(t, transport, r, Config{})
}
func connectedConfig(t *testing.T, transport string, r model.Rule, cfg Config) (*Agent, *protocol.Carrier, model.Rule) {
	t.Helper()
	cfg.CloudURL = "http://127.0.0.1"
	cfg.StateDir = t.TempDir()
	cfg.Transport = transport + "_only"
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	r.ID = "rule"
	r.Version = 1
	r.TenantID = "tenant"
	r.DeviceID = "device"
	r.EdgeID = "edge"
	r.Enabled = true
	r.Transport = transport + "_only"
	if r.TimeoutSeconds == 0 {
		r.TimeoutSeconds = 3
	}
	if r.SourceMode == "" {
		r.SourceMode = "socket"
	}
	cert, ca := certificate(t, "edge.test")
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{protocol.ALPN}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	accepted := make(chan struct {
		c   *protocol.Carrier
		err error
	}, 1)
	d := model.DeviceGrant{DeviceID: r.DeviceID, TenantID: r.TenantID, PublicKey: base64.StdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey)), SessionID: a.st.SessionID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}
	var address string
	admit := func(c *protocol.Carrier, err error) {
		if err == nil {
			err = protocol.AuthenticateEdge(ctx, c, func(id string) (model.DeviceGrant, bool) { return d, id == d.DeviceID })
		}
		accepted <- struct {
			c   *protocol.Carrier
			err error
		}{c, err}
	}
	if transport == "quic" {
		ln, err := quic.ListenAddr("127.0.0.1:0", tc, protocol.QUICConfig())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		address = ln.Addr().String()
		go func() {
			q, err := ln.Accept(ctx)
			if err != nil {
				admit(nil, err)
				return
			}
			admit(protocol.WrapQUIC(q, "edge"), nil)
		}()
	} else {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", tc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		address = ln.Addr().String()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				admit(nil, err)
				return
			}
			c, err := protocol.WrapTLS(conn, true, "edge")
			admit(c, err)
		}()
	}
	e := model.Edge{ID: "edge", CACert: ca, MaxCarriers: 2, Endpoints: []model.Endpoint{{Transport: transport, Address: address, ServerName: "edge.test"}}}
	a.mu.Lock()
	a.st.DeviceID = d.DeviceID
	a.snap = model.ClientSnapshot{Revision: 1, ExpiresAt: d.ExpiresAt, Device: d, Rules: []model.Rule{r}, Edges: []model.Edge{e}}
	a.mu.Unlock()
	if err = a.ConnectEdge(ctx, e); err != nil {
		t.Fatal(err)
	}
	got := <-accepted
	if got.err != nil {
		t.Fatal(got.err)
	}
	t.Cleanup(func() { _ = got.c.Close() })
	return a, got.c, r
}
func openFlow(t *testing.T, c *protocol.Carrier, r model.Rule, id uint64, datagram bool) protocol.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := c.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { protocol.Abort(st) })
	_ = st.SetDeadline(time.Now().Add(4 * time.Second))
	if err = protocol.WriteJSON(st, protocol.Flow{ID: id, RuleID: r.ID, Version: r.Version, Generation: c.Device.Generation, Protocol: r.Protocol, Peer: "203.0.113.10:10000", Datagram: datagram, Host: r.Domain, Scheme: "https", IngressPort: 443}); err != nil {
		t.Fatal(err)
	}
	return st
}
func result(t *testing.T, st protocol.Stream) {
	t.Helper()
	var res protocol.Result
	if err := protocol.ReadJSON(st, &res); err != nil || res.Code != "" || res.Error != "" {
		t.Fatalf("flow result %+v %v", res, err)
	}
}

func TestTCPResultAndHalfCloseOnRealCarriers(t *testing.T) {
	for _, transport := range []string{"tls", "quic"} {
		t.Run(transport, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			seen := make(chan string, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				body, _ := io.ReadAll(conn)
				seen <- string(body)
				_, _ = conn.Write([]byte("reply:" + string(body)))
			}()
			_, c, r := connected(t, transport, model.Rule{Protocol: "tcp", Target: ln.Addr().String()})
			st := openFlow(t, c, r, 1, false)
			result(t, st)
			if _, err = st.Write([]byte("business")); err != nil {
				t.Fatal(err)
			}
			protocol.HalfClose(st)
			body, err := io.ReadAll(st)
			if err != nil || string(body) != "reply:business" {
				t.Fatalf("half-close reply %q %v", body, err)
			}
			if got := <-seen; got != "business" {
				t.Fatalf("protocol handshake polluted target bytes: %q", got)
			}
		})
	}
}
func TestUDPIndependentPersistentMappingsAndLargePackets(t *testing.T) {
	for _, transport := range []string{"tls", "quic"} {
		t.Run(transport, func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			go func() {
				p := make([]byte, protocol.MaxPacket)
				for {
					n, addr, err := pc.ReadFrom(p)
					if err != nil {
						return
					}
					_, _ = pc.WriteTo(append([]byte(addr.String()+"|"), p[:n]...), addr)
				}
			}()
			a, c, r := connected(t, transport, model.Rule{Protocol: "udp", Target: pc.LocalAddr().String()})
			ids := []uint64{30, 31}
			streams := make([]protocol.Stream, 2)
			packets := make([]<-chan []byte, 2)
			for i, id := range ids {
				if transport == "quic" {
					ch, unreg, err := c.Register(id)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(unreg)
					packets[i] = ch
				}
				streams[i] = openFlow(t, c, r, id, transport == "quic")
				result(t, streams[i])
			}
			exchange := func(i int, p []byte) []byte {
				t.Helper()
				var err error
				if transport == "quic" {
					err = c.SendPacket(ids[i], p)
				} else {
					err = protocol.WritePacket(streams[i], p)
				}
				if err != nil {
					t.Fatal(err)
				}
				if transport == "quic" {
					select {
					case b := <-packets[i]:
						return b
					case <-time.After(3 * time.Second):
						t.Fatal("DATAGRAM reply timed out")
					}
				}
				b, err := protocol.ReadPacket(streams[i])
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			one := bytes.SplitN(exchange(0, []byte("a")), []byte("|"), 2)
			two := bytes.SplitN(exchange(1, []byte("b")), []byte("|"), 2)
			three := bytes.SplitN(exchange(0, []byte("c")), []byte("|"), 2)
			if len(one) != 2 || len(two) != 2 || len(three) != 2 || !bytes.Equal(one[0], three[0]) || bytes.Equal(one[0], two[0]) || string(one[1])+string(two[1])+string(three[1]) != "abc" {
				t.Fatal("UDP target sockets were replaced or shared")
			}
			payload := bytes.Repeat([]byte("fragment-preservation"), 2900)
			large := bytes.SplitN(exchange(0, payload), []byte("|"), 2)
			if len(large) != 2 || !bytes.Equal(large[1], payload) {
				t.Fatal("large UDP packet changed or truncated")
			}
			zero := bytes.SplitN(exchange(0, nil), []byte("|"), 2)
			if len(zero) != 2 || len(zero[1]) != 0 {
				t.Fatal("zero length UDP datagram lost")
			}
			a.mu.Lock()
			a.snap.Rules = nil
			a.reconcileLocked()
			a.mu.Unlock()
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				a.mu.RLock()
				active := len(a.flows)
				a.mu.RUnlock()
				if active == 0 {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("revoked UDP mappings survived")
		})
	}
}

func httpExchange(t *testing.T, c *protocol.Carrier, r model.Rule, id uint64, request *http.Request) (*http.Response, protocol.Stream) {
	t.Helper()
	st := openFlow(t, c, r, id, false)
	written := make(chan error, 1)
	go func() { written <- request.Write(st) }()
	result(t, st)
	resp, err := http.ReadResponse(bufio.NewReader(st), request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request upload did not complete")
	}
	return resp, st
}
func TestHTTPSourceHeadersHostPathsAndPoolIsolation(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Host != "origin.internal" || r.URL.EscapedPath() != "/base/a%2Fb" || r.URL.RawQuery != "q=value" {
			t.Errorf("origin routing: %s %s", r.Host, r.URL)
		}
		for k, want := range map[string]string{"X-Forwarded-For": "203.0.113.10", "X-Real-Ip": "203.0.113.10", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "public.example", "X-Forwarded-Port": "443"} {
			if vs := r.Header.Values(k); len(vs) != 1 || vs[0] != want {
				t.Errorf("untrusted identity %s=%q", k, vs)
			}
		}
		if r.Header.Get("Forwarded") != "" || r.Header.Get("True-Client-IP") != "" || r.Header.Get("X-Strip") != "" {
			t.Error("untrusted/hop headers reached origin")
		}
		w.Header().Set("Connection", "X-Origin-Hop")
		w.Header().Set("X-Origin-Hop", "private")
		w.WriteHeader(418)
		_, _ = w.Write(body)
	}))
	defer target.Close()
	a, c, r := connected(t, "tls", model.Rule{Protocol: "http", SourceMode: "forwarded_headers", Domain: "public.example", Target: target.URL + "/base", Host: "origin.internal"})
	for id := uint64(1); id <= 3; id++ {
		req, _ := http.NewRequest("POST", "http://forged.invalid/a%2Fb?q=value", strings.NewReader("streamed body"))
		req.Header = http.Header{"X-Forwarded-For": {"spoof"}, "x-forwarded-for": {"second-spoof"}, "Forwarded": {"for=spoof"}, "True-Client-IP": {"spoof"}, "Connection": {"X-Strip, X-Forwarded-For"}, "X-Strip": {"secret"}}
		resp, _ := httpExchange(t, c, r, id, req)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 418 || string(body) != "streamed body" || resp.Header.Get("X-Origin-Hop") != "" {
			t.Fatalf("normal origin status/body %s %q %v", resp.Status, body, err)
		}
	}
	a.mu.Lock()
	n := len(a.transports)
	a.snap.ExpiresAt = time.Now().Add(-time.Second)
	a.reconcileLocked()
	remaining := len(a.transports)
	a.mu.Unlock()
	if n != 1 || remaining != 0 {
		t.Fatalf("pool lifetime %d -> %d", n, remaining)
	}
}
func TestHTTPSOriginCAAndSNIValidation(t *testing.T) {
	cert, ca := certificate(t, "origin.test")
	seen := make(chan string, 4)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("verified TLS")) }))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) { seen <- ch.ServerName; return nil, nil }}
	origin.StartTLS()
	defer origin.Close()
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			a, c, r := connected(t, "tls", model.Rule{Protocol: "https", Domain: "public.example", SourceMode: "forwarded_headers", Target: origin.URL, ServerName: "origin.test"})
			if trusted {
				path := filepath.Join(t.TempDir(), "origin-ca.pem")
				if err := os.WriteFile(path, []byte(ca), 0600); err != nil {
					t.Fatal(err)
				}
				a.mu.Lock()
				a.cfg.OriginCAFile = path
				a.mu.Unlock()
			}
			st := openFlow(t, c, r, 90, false)
			req, _ := http.NewRequest("GET", "http://public.example/", nil)
			go func() { _ = req.Write(st) }()
			var res protocol.Result
			if err := protocol.ReadJSON(st, &res); err != nil {
				t.Fatal(err)
			}
			if trusted {
				if res.Error != "" {
					t.Fatal(res.Error)
				}
				resp, err := http.ReadResponse(bufio.NewReader(st), req)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(b) != "verified TLS" {
					t.Fatal("TLS response missing")
				}
			} else if res.Code != "target_unreachable" {
				t.Fatalf("unknown origin CA accepted: %+v", res)
			}
			select {
			case name := <-seen:
				if name != "origin.test" {
					t.Fatalf("origin SNI %q", name)
				}
			case <-time.After(time.Second):
				t.Fatal("origin handshake missing")
			}
		})
	}
}

func TestWebSocketUpgradePreservesBufferedBytes(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := w.(http.Hijacker)
		if !ok {
			t.Error("missing hijacker")
			return
		}
		conn, rw, err := h.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	}))
	defer origin.Close()
	_, c, r := connected(t, "quic", model.Rule{Protocol: "http", Domain: "public.example", SourceMode: "forwarded_headers", Target: origin.URL})
	st := openFlow(t, c, r, 91, false)
	go func() {
		_, _ = io.WriteString(st, "GET / HTTP/1.1\r\nHost: public.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nearly")
	}()
	result(t, st)
	br := bufio.NewReader(st)
	req, _ := http.NewRequest("GET", "http://public.example/", nil)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("upgrade %+v", resp)
	}
	buf := make([]byte, 5)
	if _, err = io.ReadFull(br, buf); err != nil || string(buf) != "early" {
		t.Fatalf("upgrade lost buffered request data: %q %v", buf, err)
	}
	_, _ = st.Write([]byte("later"))
	if _, err = io.ReadFull(br, buf); err != nil || string(buf) != "later" {
		t.Fatalf("upgrade stopped relaying: %q %v", buf, err)
	}
}

func TestEarlyOriginFailureCancelsUnfinishedUpload(t *testing.T) {
	for _, transport := range []string{"tls", "quic"} {
		t.Run(transport, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := ln.Addr().String()
			_ = ln.Close()
			_, c, r := connected(t, transport, model.Rule{Protocol: "http", Domain: "public.example", SourceMode: "forwarded_headers", Target: "http://" + address})
			st := openFlow(t, c, r, 99, false)
			written := make(chan error, 1)
			go func() {
				_, err := io.Copy(st, io.MultiReader(strings.NewReader("POST / HTTP/1.1\r\nHost: public.example\r\nContent-Length: 1000000000\r\n\r\n"), io.LimitReader(zeroReader{}, 1000000000)))
				written <- err
			}()
			var res protocol.Result
			if err = protocol.ReadJSON(st, &res); err != nil || res.Code != "target_unreachable" {
				t.Fatalf("origin failure %+v %v", res, err)
			}
			// The edge owns its upload goroutine and cancels it after consuming
			// the failure Result. yamux FIN alone intentionally preserves TCP
			// half-close, so it cannot signal an independent read cancellation.
			protocol.Abort(st)
			select {
			case err := <-written:
				if err == nil {
					t.Fatal("oversized upload was not stopped")
				}
			case <-time.After(time.Second):
				t.Fatal("origin failure left upload blocked")
			}
		})
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
