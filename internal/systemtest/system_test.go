// Package systemtest validates the public control API together with the real
// authenticated network carriers. MySQL databases are isolated per test run.
package systemtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"drafrp/internal/client"
	"drafrp/internal/cloud"
	"drafrp/internal/edge"
	"drafrp/internal/model"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

type browser struct {
	t         *testing.T
	client    *http.Client
	url, csrf string
	user      model.User
}

func (b *browser) api(method, path string, in, out any, want int) {
	b.t.Helper()
	raw, _ := json.Marshal(in)
	req, e := http.NewRequest(method, b.url+path, bytes.NewReader(raw))
	if e != nil {
		b.t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", b.csrf)
	res, e := b.client.Do(req)
	if e != nil {
		b.t.Fatal(e)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		b.t.Fatalf("%s %s: HTTP %d want %d: %s", method, path, res.StatusCode, want, data)
	}
	if out != nil {
		if e = json.Unmarshal(data, out); e != nil {
			b.t.Fatal(e)
		}
	}
}
func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func address(p int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(p)) }

func testCloud(t *testing.T) (*cloud.Server, *browser) {
	t.Helper()
	return testCloudWithTTL(t, 10*time.Second)
}

func testCloudWithTTL(t *testing.T, ttl time.Duration) (*cloud.Server, *browser) {
	t.Helper()
	dsn := os.Getenv("DRAFRP_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set DRAFRP_TEST_MYSQL_DSN to run real cloud/edge/agent integration")
	}
	cfg, e := mysql.ParseDSN(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.DBName = ""
	db, e := sql.Open("mysql", cfg.FormatDSN())
	if e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("drafrp_system_test_%d", time.Now().UnixNano())
	if _, e = db.Exec("CREATE DATABASE " + name); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = db.Exec("DROP DATABASE " + name); _ = db.Close() })
	cfg.DBName = name
	s, e := cloud.New(context.Background(), cloud.Config{MySQLDSN: cfg.FormatDSN(), StorageKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), AdminUsername: "admin", AdminPassword: "drafrp-system-test", SnapshotTTL: ttl, CaptchaDisabled: true})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	h := httptest.NewServer(s.Handler())
	t.Cleanup(h.Close)
	jar, _ := cookiejar.New(nil)
	b := &browser{t: t, client: &http.Client{Jar: jar, Timeout: 8 * time.Second}, url: h.URL}
	var login struct {
		User model.User `json:"user"`
		CSRF string     `json:"csrf_token"`
	}
	b.api("POST", "/auth/login", map[string]string{"username": "admin", "password": "drafrp-system-test"}, &login, 200)
	b.csrf, b.user = login.CSRF, login.User
	return s, b
}

func certFiles(t *testing.T) (string, string, string) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge.test"}, DNSNames: []string{"edge.test", "app.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: false, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	d := t.TempDir()
	cf, kf := filepath.Join(d, "cert.pem"), filepath.Join(d, "key.pem")
	if e = os.WriteFile(cf, cert, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(kf, private, 0600); e != nil {
		t.Fatal(e)
	}
	return cf, kf, string(cert)
}

func TestFullSystem(t *testing.T) {
	for _, transport := range []string{"quic", "tls"} {
		t.Run(transport, func(t *testing.T) {
			// This feature test advances synchronization explicitly. Keep leases
			// live across control API round trips under full race-test load;
			// the independent-renewal test exercises the short ten-second TTL.
			s, b := testCloudWithTTL(t, time.Minute)
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			certFile, keyFile, cert := certFiles(t)
			carrierPort, httpPort, httpsPort, businessPort, secondPort := freePort(t), freePort(t), freePort(t), freePort(t), freePort(t)
			var e model.Edge
			b.api("POST", "/api/v1/edges", map[string]any{"name": "system-edge", "token": strings.Repeat("system-test-token-", 3), "public_host": "127.0.0.1", "listen_host": "127.0.0.1", "endpoints": []model.Endpoint{{Transport: transport, Address: address(carrierPort), ServerName: "edge.test"}}, "ca_cert": cert, "http_port": httpPort, "https_port": httpsPort, "port_min": min(businessPort, secondPort), "port_max": max(businessPort, secondPort), "max_carriers": 8, "capacity_bps": -1}, &e, 201)
			r := edge.New(edge.Config{CloudURL: b.url, EdgeID: e.ID, Token: strings.Repeat("system-test-token-", 3), CertFile: certFile, KeyFile: keyFile, ListenHost: "127.0.0.1", UDPIdleTimeout: 300 * time.Millisecond})
			defer r.Close()
			a, err := client.New(client.Config{CloudURL: b.url, StateDir: t.TempDir(), Transport: transport + "_only"})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			bind, err := a.Bind(ctx)
			if err != nil {
				t.Fatal(err)
			}
			b.api("GET", "/api/v1/bind/"+bind.UserCode, nil, nil, 200)
			b.api("POST", "/api/v1/bind/confirm", map[string]string{"user_code": bind.UserCode}, nil, 200)
			bound, err := a.PollBind(ctx, bind.ID, bind.PollToken)
			if err != nil || bound.Status != "approved" {
				t.Fatal(bound, err)
			}
			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			go func() {
				for {
					c, err := tcp.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
				}
			}()
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go func() {
				buf := make([]byte, 65535)
				for {
					n, p, err := udp.ReadFrom(buf)
					if err != nil {
						return
					}
					_, _ = udp.WriteTo(buf[:n], p)
				}
			}()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				_ = http.NewResponseController(w).EnableFullDuplex()
				w.Header().Set("X-Origin-XFF", req.Header.Get("X-Forwarded-For"))
				w.Header().Set("X-Origin-Host", req.Host)
				w.Header().Set("X-Origin-Proto", req.Header.Get("X-Forwarded-Proto"))
				_, _ = io.Copy(w, req.Body)
			}))
			defer origin.Close()
			create := func(proto, target string, port int, domain, certID string) model.Rule {
				var out model.Rule
				mode := "socket"
				if proto == "http" || proto == "https" {
					mode = "forwarded_headers"
				}
				b.api("POST", "/api/v1/rules", model.Rule{Name: "system-" + proto, DeviceID: bound.DeviceID, EdgeID: e.ID, Protocol: proto, Target: target, PublicPort: port, Domain: domain, CertificateID: certID, Host: "origin.internal", SourceMode: mode, Transport: transport + "_only", Enabled: true, TimeoutSeconds: 3}, &out, 201)
				return out
			}
			tcpRule := create("tcp", tcp.Addr().String(), businessPort, "", "")
			_ = create("udp", udp.LocalAddr().String(), businessPort, "", "")
			// Domain ownership is provisioned inside this isolated test database only;
			// the public API must require its DNS TXT ownership challenge.
			if _, err = s.DB().Exec("INSERT INTO domains(id,tenant_id,domain,status,challenge,verified_at,created_at) VALUES(?,?,?,'verified',?,?,?)", "system-domain", b.user.TenantID, "app.test", "test", time.Now(), time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err = s.DB().Exec("INSERT INTO domain_ownership(domain,tenant_id) VALUES(?,?)", "app.test", b.user.TenantID); err != nil {
				t.Fatal(err)
			}
			keyBytes, _ := os.ReadFile(keyFile)
			var siteCert model.Certificate
			b.api("POST", "/api/v1/certificates", map[string]string{"name": "system-site", "cert_pem": cert, "key_pem": string(keyBytes)}, &siteCert, 201)
			_ = create("https", origin.URL, 0, "app.test", siteCert.ID)
			if _, err = a.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			if err = r.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			if err = a.ConnectEdge(ctx, e); err != nil {
				t.Fatal(err)
			}
			var conn net.Conn
			for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
				conn, err = net.DialTimeout("tcp", address(businessPort), time.Second)
				if err == nil {
					_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
					_, err = conn.Write([]byte("ready"))
					var got [5]byte
					if err == nil {
						_, err = io.ReadFull(conn, got[:])
					}
					if err == nil && string(got[:]) == "ready" {
						break
					}
					_ = conn.Close()
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil {
				t.Fatal("carrier never became ready", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			payload := bytes.Repeat([]byte{0, 1, 2, 3, 254, 255}, 16000)
			writeDone := make(chan error, 1)
			go func() {
				_, e := conn.Write(payload)
				if e == nil {
					e = conn.(*net.TCPConn).CloseWrite()
				}
				writeDone <- e
			}()
			got, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("TCP bytes %d/%d err=%v", len(got), len(payload), err)
			}
			if err = <-writeDone; err != nil {
				t.Fatal(err)
			}
			u, err := net.Dial("udp", address(businessPort))
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			_ = u.SetDeadline(time.Now().Add(5 * time.Second))
			for _, data := range [][]byte{[]byte("udp"), bytes.Repeat([]byte{42}, 48000), {}} {
				if _, err = u.Write(data); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 65535)
				n, err := u.Read(buf)
				if err != nil || !bytes.Equal(buf[:n], data) {
					t.Fatalf("UDP %d/%d: %v", n, len(data), err)
				}
			}
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM([]byte(cert))
			web := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "app.test"}}, Timeout: 5 * time.Second}
			defer web.CloseIdleConnections()
			req, _ := http.NewRequest("POST", "https://"+address(httpsPort)+"/escaped%2Fpath?q=a%26b", bytes.NewReader(payload))
			req.Host = "app.test"
			req.Header.Set("X-Forwarded-For", "forged")
			res, err := web.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(res.Body)
			_ = res.Body.Close()
			if err != nil || res.StatusCode != 200 || !bytes.Equal(got, payload) || res.Header.Get("X-Origin-XFF") != "127.0.0.1" || res.Header.Get("X-Origin-Host") != "origin.internal" || res.Header.Get("X-Origin-Proto") != "https" {
				t.Fatalf("site HTTP %d bytes=%d headers=%v err=%v", res.StatusCode, len(got), res.Header, err)
			}
			if err = r.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			var actual model.Rule
			b.api("GET", "/api/v1/rules/"+tcpRule.ID, nil, &actual, 200)
			if actual.Status != "ready" {
				t.Fatalf("observed rule status=%s: %s", actual.Status, actual.LastError)
			}
			var usage int64
			if err = s.DB().QueryRow("SELECT COALESCE(SUM(upload_bytes+download_bytes),0) FROM usage_table u JOIN grants_table g ON g.id=u.grant_id WHERE g.tenant_id=?", b.user.TenantID).Scan(&usage); err != nil || usage < int64(len(payload)*4) {
				t.Fatalf("durable usage=%d err=%v", usage, err)
			}
			// Two independently bound devices must draw from the same account cap.
			// A UDP socket close is not signalled over the network: its edge
			// mapping still consumes concurrency until the idle timeout. Finish
			// that preceding scenario before setting the shared limit to one.
			_ = u.Close()
			idleDeadline := time.Now().Add(4 * time.Second)
			for r.RuntimeStatus().ActiveFlows != 0 {
				if time.Now().After(idleDeadline) {
					t.Fatalf("preceding flows did not drain: %+v", r.RuntimeStatus())
				}
				time.Sleep(20 * time.Millisecond)
			}
			a2, err := client.New(client.Config{CloudURL: b.url, StateDir: t.TempDir(), Transport: transport + "_only"})
			if err != nil {
				t.Fatal(err)
			}
			defer a2.Close()
			bind2, err := a2.Bind(ctx)
			if err != nil {
				t.Fatal(err)
			}
			b.api("POST", "/api/v1/bind/confirm", map[string]string{"user_code": bind2.UserCode}, nil, 200)
			bound2, err := a2.PollBind(ctx, bind2.ID, bind2.PollToken)
			if err != nil {
				t.Fatal(err)
			}
			var secondRule model.Rule
			b.api("POST", "/api/v1/rules", model.Rule{Name: "second-device", DeviceID: bound2.DeviceID, EdgeID: e.ID, Protocol: "tcp", Target: tcp.Addr().String(), PublicPort: secondPort, SourceMode: "socket", Transport: transport + "_only", Enabled: true}, &secondRule, 201)
			var quotas struct {
				Items []model.Quota `json:"items"`
			}
			b.api("GET", "/api/v1/quotas", nil, &quotas, 200)
			q := quotas.Items[0]
			q.MaxConnections = 1
			b.api("PUT", "/api/v1/quotas/"+q.TenantID, q, &q, 200)
			if _, err = a.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = a2.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			if err = r.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			// Production maintains every Agent's carrier after authorization
			// renewals. Do the same for the original and newly bound devices.
			if err = a.ConnectEdge(ctx, e); err != nil {
				t.Fatal(err)
			}
			if err = a2.ConnectEdge(ctx, e); err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(2 * time.Second); r.RuntimeStatus().ActiveCarriers != 2; {
				if time.Now().After(deadline) {
					t.Fatalf("both devices did not become available before testing the shared cap: %+v", r.RuntimeStatus())
				}
				time.Sleep(10 * time.Millisecond)
			}
			first, err := net.Dial("tcp", address(businessPort))
			if err != nil {
				t.Fatal(err)
			}
			_ = first.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = first.Write([]byte("one"))
			var one [3]byte
			if _, err = io.ReadFull(first, one[:]); err != nil {
				t.Fatalf("first device flow failed: %v; agent=%+v edge=%+v statuses=%+v", err, a.RuntimeStatus(), r.RuntimeStatus(), r.Statuses())
			}
			second, err := net.Dial("tcp", address(secondPort))
			if err != nil {
				t.Fatal(err)
			}
			_ = second.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = second.Write([]byte("two"))
			var two [3]byte
			_, err = io.ReadFull(second, two[:])
			_ = second.Close()
			if err == nil {
				t.Fatal("second device multiplied the shared concurrency cap")
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("denied account flow was left hanging")
			}
			q.BaseBPS = 0
			b.api("PUT", "/api/v1/quotas/"+q.TenantID, q, &q, 200)
			if err = r.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			// Control API/database work may outlast the earlier echo deadline,
			// especially under race instrumentation. Start the closure assertion's
			// own deadline after the revocation has actually been applied.
			_ = first.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, err = first.Read(one[:])
			_ = first.Close()
			if err == nil {
				t.Fatal("zero bandwidth did not revoke active flow")
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("zero bandwidth did not close active flow")
			}
			q.BaseBPS = -1
			q.MaxConnections = -1
			b.api("PUT", "/api/v1/quotas/"+q.TenantID, q, &q, 200)
			if err = r.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			// Revocation must interrupt an already established bidirectional stream.
			live, err := net.Dial("tcp", address(businessPort))
			if err != nil {
				t.Fatal(err)
			}
			defer live.Close()
			_ = live.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = live.Write([]byte("alive"))
			var alive [5]byte
			if _, err = io.ReadFull(live, alive[:]); err != nil {
				t.Fatal(err)
			}
			b.api("DELETE", "/api/v1/devices/"+bound.DeviceID, nil, nil, 200)
			if err = r.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			_ = live.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, err = live.Read(alive[:])
			if err == nil {
				t.Fatal("revoked flow stayed open")
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("revocation did not close active flow")
			}
			if _, err = a.Sync(ctx); err == nil {
				t.Fatal("revoked device synchronized")
			}
			t.Logf("%s cloud+MySQL+edge+agent: TCP, UDP, HTTPS, source headers, persisted status/usage and active-flow revocation passed (%d bytes)", transport, usage)
		})
	}
}
