package cloud

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"drafrp/internal/model"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

type cloudFixture struct {
	s     *Server
	t     *testing.T
	h     http.Handler
	admin *browser
}
type browser struct {
	f      *cloudFixture
	cookie *http.Cookie
	csrf   string
	user   model.User
}

func newCloudFixture(t *testing.T) *cloudFixture {
	t.Helper()
	dsn := os.Getenv("DRAFRP_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set DRAFRP_TEST_MYSQL_DSN for isolated MySQL integration tests")
	}
	cfg, e := mysql.ParseDSN(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ParseTime = true
	base, e := sql.Open("mysql", cfg.FormatDSN())
	if e != nil {
		t.Fatal(e)
	}
	dbname := "drafrp_cloud_test_" + strings.ReplaceAll(id(), "-", "")
	if _, e = base.Exec("CREATE DATABASE `" + dbname + "`"); e != nil {
		base.Close()
		t.Fatal(e)
	}
	cfg.DBName = dbname
	ctx, cancel := context.WithCancel(context.Background())
	s, e := New(ctx, Config{MySQLDSN: cfg.FormatDSN(), StorageKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)), AdminUsername: "admin", AdminPassword: "a-strong-test-password", SnapshotTTL: 30 * time.Second, CaptchaDisabled: true})
	if e != nil {
		_, _ = base.Exec("DROP DATABASE `" + dbname + "`")
		base.Close()
		cancel()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cancel()
		s.Close()
		_, e := base.Exec("DROP DATABASE `" + dbname + "`")
		if e != nil {
			t.Error(e)
		}
		base.Close()
	})
	f := &cloudFixture{s: s, t: t, h: s.Handler()}
	f.admin = f.login("admin", "a-strong-test-password")
	// Existing transport/accounting tests exercise the pre-package policy API.
	// Keep their fixture on a migrated package; package tests assign new plans.
	p := decodeResponse[model.Plan](t, f.request("POST", "/api/v1/plans", model.Plan{Name: "Legacy test package", BandwidthBPS: -1, MaxPorts: -1, MaxSites: -1, AllEdges: true, Default: true}, f.admin, nil), 201)
	if _, err := s.db.Exec("UPDATE plans SET legacy=1 WHERE id=?", p.ID); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *cloudFixture) request(method, path string, body any, b *browser, headers map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	var raw []byte
	switch v := body.(type) {
	case []byte:
		raw = v
	case nil:
	default:
		var e error
		raw, e = json.Marshal(v)
		if e != nil {
			f.t.Fatal(e)
		}
	}
	r := httptest.NewRequest(method, "https://cloud.example"+path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if b != nil {
		r.AddCookie(b.cookie)
		r.Header.Set("X-CSRF-Token", b.csrf)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}
func decodeResponse[T any](t *testing.T, w *httptest.ResponseRecorder, status int) T {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d want %d: %s", w.Code, status, w.Body.String())
	}
	var out T
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func (f *cloudFixture) login(name, password string) *browser {
	f.t.Helper()
	w := f.request("POST", "/auth/login", map[string]any{"username": name, "password": password}, nil, nil)
	x := decodeResponse[struct {
		User model.User `json:"user"`
		CSRF string     `json:"csrf_token"`
	}](f.t, w, 200)
	return &browser{f: f, cookie: w.Result().Cookies()[0], csrf: x.CSRF, user: x.User}
}
func (f *cloudFixture) createUser(name string) *browser {
	f.t.Helper()
	decodeResponse[model.User](f.t, f.request("POST", "/api/v1/users", map[string]any{"username": name, "password": "user-test-password", "role": "user"}, f.admin, nil), 201)
	return f.login(name, "user-test-password")
}
func (f *cloudFixture) bind(b *browser, name string) (model.Device, ed25519.PrivateKey) {
	f.t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	res := decodeResponse[model.BindResponse](f.t, f.request("POST", "/api/v1/runtime/client/bind", model.BindRequest{Name: name, PublicKey: base64.StdEncoding.EncodeToString(pub)}, nil, nil), 201)
	decodeResponse[map[string]any](f.t, f.request("GET", "/api/v1/bind/"+res.UserCode, nil, b, nil), 200)
	confirmed := decodeResponse[struct {
		DeviceID string `json:"device_id"`
	}](f.t, f.request("POST", "/api/v1/bind/confirm", map[string]string{"user_code": res.UserCode}, b, nil), 200)
	poll := decodeResponse[model.BindResponse](f.t, f.request("POST", "/api/v1/runtime/client/bind/poll", map[string]string{"id": res.ID, "poll_token": res.PollToken}, nil, nil), 200)
	if poll.DeviceID != confirmed.DeviceID || poll.Status != "approved" {
		f.t.Fatal("poll did not return consumed binding")
	}
	return model.Device{ID: poll.DeviceID, TenantID: b.user.TenantID, Name: name}, key
}
func (f *cloudFixture) edge(name string) model.Edge {
	f.t.Helper()
	e := model.Edge{Name: name, PublicHost: "edge.example", Endpoints: []model.Endpoint{{Transport: "tls", Address: "edge.example:8443", ServerName: "edge.example"}, {Transport: "quic", Address: "edge.example:8443", ServerName: "edge.example"}}, HTTPPort: 18080, HTTPSPort: 18443, PortMin: 20000, PortMax: 20010, MaxCarriers: 4, CapacityBPS: -1}
	encoded, _ := json.Marshal(e)
	var in map[string]any
	_ = json.Unmarshal(encoded, &in)
	in["token"] = strings.Repeat(name, 24)
	return decodeResponse[model.Edge](f.t, f.request("POST", "/api/v1/edges", in, f.admin, nil), 201)
}
func (f *cloudFixture) createRule(b *browser, d model.Device, e model.Edge, port int) model.Rule {
	f.t.Helper()
	r := model.Rule{Name: "test-rule", DeviceID: d.ID, EdgeID: e.ID, Protocol: "tcp", PublicPort: port, Target: "127.0.0.1:8080", SourceMode: "socket", Transport: "auto", Enabled: true}
	return decodeResponse[model.Rule](f.t, f.request("POST", "/api/v1/rules", r, b, nil), 201)
}
func (f *cloudFixture) syncClient(d model.Device, key ed25519.PrivateKey, session string) model.ClientSnapshot {
	f.t.Helper()
	in := model.ClientSyncRequest{DeviceID: d.ID, SessionID: session, Timestamp: time.Now().Unix(), Nonce: randomToken(24), Capabilities: []string{"tcp", "udp", "http"}}
	in.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, model.ClientSyncPayload(in)))
	return decodeResponse[model.ClientSnapshot](f.t, f.request("POST", "/api/v1/runtime/client/sync", in, nil, nil), 200)
}
func (f *cloudFixture) syncEdge(e model.Edge, boot string, statuses []model.RuleStatus, usage []model.Usage) *httptest.ResponseRecorder {
	return f.request("POST", "/api/v1/runtime/edge/sync", model.EdgeSyncRequest{EdgeID: e.ID, BootID: boot, Statuses: statuses, Usage: usage}, nil, map[string]string{"Authorization": "Bearer " + strings.Repeat(e.Name, 24)})
}

func TestMySQLCookieSecurityBehindExplicitTLSProxy(t *testing.T) {
	f := newCloudFixture(t)
	for _, tc := range []struct {
		name, url        string
		configured, want bool
	}{
		{"direct_tls", "https://cloud.example", false, true},
		{"plain_loopback", "http://cloud.example", false, false},
		{"explicit_tls_proxy", "http://cloud.example", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.s.cfg.SecureCookies = tc.configured
			r := httptest.NewRequest("POST", tc.url+"/auth/login", strings.NewReader(`{"username":"admin","password":"a-strong-test-password"}`))
			// Untrusted forwarding headers must not change cookie policy.
			r.Header.Set("X-Forwarded-Proto", "https")
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Secure != tc.want || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
				t.Fatalf("unexpected session cookie: %+v", cookies)
			}
		})
	}
}

func TestMySQLAuthBindingIsolationAndIdempotency(t *testing.T) {
	f := newCloudFixture(t)
	var n int
	if e := f.s.db.QueryRow("SELECT COUNT(*) FROM quotas").Scan(&n); e != nil || n != 1 {
		t.Fatalf("bootstrap quota: %d %v", n, e)
	}
	if w := f.request("POST", "/auth/login", map[string]string{"username": "admin", "password": "a-strong-test-password"}, nil, map[string]string{"Origin": "https://evil.example"}); w.Code != 403 {
		t.Fatal("cross-origin login accepted", w.Code)
	}
	if w := f.request("POST", "/api/v1/users", map[string]string{}, f.admin, map[string]string{"X-CSRF-Token": "wrong"}); w.Code != 403 {
		t.Fatal("CSRF accepted")
	}
	payload := map[string]string{"username": "parallel", "password": "user-test-password", "role": "user"}
	var responses [2]*httptest.ResponseRecorder
	var wg sync.WaitGroup
	for i := range responses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			responses[i] = f.request("POST", "/api/v1/users", payload, f.admin, map[string]string{"Idempotency-Key": "create-parallel"})
		}(i)
	}
	wg.Wait()
	u0 := decodeResponse[model.User](t, responses[0], 201)
	u1 := decodeResponse[model.User](t, responses[1], 201)
	if u0.ID != u1.ID {
		t.Fatal("retry executed twice")
	}
	if responses[0].Header().Get("Idempotency-Replayed") == "" && responses[1].Header().Get("Idempotency-Replayed") == "" {
		t.Fatal("no replay detected")
	}
	payload["username"] = "changed"
	if w := f.request("POST", "/api/v1/users", payload, f.admin, map[string]string{"Idempotency-Key": "create-parallel"}); w.Code != 409 {
		t.Fatal("key reuse accepted", w.Body.String())
	}
	a := f.login("parallel", "user-test-password")
	b := f.createUser("other")
	d, _ := f.bind(a, "private-device")
	e := f.edge("auth-edge")
	rule := model.Rule{Name: "cross-tenant", DeviceID: d.ID, EdgeID: e.ID, Protocol: "tcp", PublicPort: 20001, Target: "127.0.0.1:80", SourceMode: "socket", Transport: "auto", Enabled: true}
	if w := f.request("POST", "/api/v1/rules", rule, b, nil); w.Code != 409 {
		t.Fatal("cross-tenant device binding accepted", w.Body.String())
	}
	if w := f.request("GET", "/api/v1/devices", nil, b, nil); strings.Contains(w.Body.String(), d.ID) {
		t.Fatal("cross-tenant device disclosed")
	}
	if w := f.request("PATCH", "/api/v1/users/"+a.user.ID, map[string]bool{"disabled": true}, f.admin, nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := f.request("GET", "/api/v1/me", nil, a, nil); w.Code != 401 {
		t.Fatal("disabled session remains active")
	}
	if w := f.request("PATCH", "/api/v1/users/"+f.admin.user.ID, map[string]bool{"disabled": true}, f.admin, nil); w.Code != 409 {
		t.Fatal("last admin disabled")
	}
	if w := f.request("POST", "/auth/logout", map[string]any{}, b, nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := f.request("GET", "/api/v1/me", nil, b, nil); w.Code != 401 {
		t.Fatal("logout not durable")
	}
}

func TestMySQLRuleClaimsVersionsAndRevocation(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("rules")
	d, key := f.bind(b, "device")
	e := f.edge("rules-edge")
	r := f.createRule(b, d, e, 0)
	if r.PublicPort != e.PortMin {
		t.Fatal("automatic allocation failed", r.PublicPort)
	}
	if w := f.request("POST", "/api/v1/rules", r, b, nil); w.Code != 409 {
		t.Fatal("occupied TCP port reused", w.Body.String())
	}
	udp := r
	udp.Protocol = "udp"
	decodeResponse[model.Rule](t, f.request("POST", "/api/v1/rules", udp, b, nil), 201)
	updated := r
	updated.Name = "updated"
	updated = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+r.ID, updated, b, nil), 200)
	if updated.Version != r.Version+1 {
		t.Fatal("version not advanced")
	}
	if w := f.request("PUT", "/api/v1/rules/"+r.ID, r, b, nil); w.Code != 409 {
		t.Fatal("lost update accepted")
	}
	f.syncClient(d, key, "device-process-session")
	snap := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(e, "boot-one", nil, nil), 200)
	if len(snap.Devices) != 1 || len(snap.Grants) != 1 {
		t.Fatal("missing authorization", snap)
	}
	if len(snap.Devices[0].Capabilities) != 3 {
		t.Fatal("edge device grant omitted capabilities", snap.Devices[0])
	}
	telemetry := &model.EdgeRuntime{ReportedAt: now(), ActiveFlows: 2, ActiveCarriers: 1, TLSCarriers: 1, CapacityEnforcement: "payload", Endpoints: []model.EndpointRuntime{{Transport: "tls", Address: "edge.example:8443", Listening: true}}}
	decodeResponse[model.EdgeSnapshot](t, f.request("POST", "/api/v1/runtime/edge/sync", model.EdgeSyncRequest{EdgeID: e.ID, BootID: "boot-one", Runtime: telemetry}, nil, map[string]string{"Authorization": "Bearer " + strings.Repeat(e.Name, 24)}), 200)
	observed := decodeResponse[model.Edge](t, f.request("GET", "/api/v1/edges/"+e.ID, nil, f.admin, nil), 200)
	if observed.Runtime == nil || observed.Runtime.ActiveFlows != 2 || len(observed.Runtime.Endpoints) != 1 || !observed.Runtime.Endpoints[0].Listening {
		t.Fatal("runtime telemetry was not durably read back", observed.Runtime)
	}
	decodeResponse[map[string]any](t, f.request("DELETE", "/api/v1/rules/"+r.ID, nil, b, nil), 200)
	if w := f.request("POST", "/api/v1/rules", r, b, nil); w.Code != 409 {
		t.Fatal("deletion released port before acknowledgement")
	}
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(e, "boot-one", []model.RuleStatus{{ID: r.ID, Version: updated.Version, Status: "deleted"}}, nil), 200)
	if w := f.request("POST", "/api/v1/rules", r, b, nil); w.Code != 409 {
		t.Fatal("stale acknowledgement freed port")
	}
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(e, "boot-one", []model.RuleStatus{{ID: r.ID, Version: updated.Version + 1, Status: "deleted"}}, nil), 200)
	f.createRule(b, d, e, r.PublicPort)
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(e, "boot-two", nil, nil), 200)
	if w := f.syncEdge(e, "boot-one", nil, nil); w.Code != 409 {
		t.Fatal("retired boot reauthorized", w.Body.String())
	}
	if w := f.request("DELETE", "/api/v1/devices/"+d.ID, nil, b, nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	in := model.ClientSyncRequest{DeviceID: d.ID, SessionID: "device-process-session", Timestamp: time.Now().Unix(), Nonce: randomToken(24)}
	in.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, model.ClientSyncPayload(in)))
	if w := f.request("POST", "/api/v1/runtime/client/sync", in, nil, nil); w.Code != 401 {
		t.Fatal("revoked device authorized")
	}
}

func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	der, e := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"app.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"app.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
}
func TestMySQLTemplatesAndEncryptedCertificates(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("policies")
	d, _ := f.bind(b, "device")
	e := f.edge("policy-edge")
	x := decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates", model.ACLTemplate{Name: "empty-draft"}, f.admin, nil), 201)
	if w := f.request("GET", "/api/v1/acl-templates", nil, b, nil); strings.Contains(w.Body.String(), x.ID) {
		t.Fatal("unpublished draft disclosed")
	}
	if w := f.request("POST", "/api/v1/acl-templates/"+x.ID+"/publish", map[string]uint64{"version": x.Version}, f.admin, nil); w.Code != 400 {
		t.Fatal("published missing default action", w.Body.String())
	}
	x.Policy.DefaultAction = "allow"
	x = decodeResponse[model.ACLTemplate](t, f.request("PUT", "/api/v1/acl-templates/"+x.ID, x, f.admin, nil), 200)
	x = decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates/"+x.ID+"/publish", map[string]uint64{"version": x.Version}, f.admin, nil), 200)
	x.Default = true
	x = decodeResponse[model.ACLTemplate](t, f.request("PUT", "/api/v1/acl-templates/"+x.ID, x, f.admin, nil), 200)
	r := f.createRule(b, d, e, 0)
	if r.ACLTemplateID != x.ID {
		t.Fatal("default not persisted")
	}
	x.Policy.DefaultAction = "deny"
	x = decodeResponse[model.ACLTemplate](t, f.request("PUT", "/api/v1/acl-templates/"+x.ID, x, f.admin, nil), 200)
	list := decodeResponse[struct {
		Items []model.ACLTemplate `json:"items"`
	}](t, f.request("GET", "/api/v1/acl-templates", nil, b, nil), 200)
	if len(list.Items) != 1 || list.Items[0].Policy.DefaultAction != "allow" {
		t.Fatal("draft affected user policy")
	}
	actual := decodeResponse[model.Rule](t, f.request("GET", "/api/v1/rules/"+r.ID, nil, b, nil), 200)
	if actual.Version != r.Version {
		t.Fatal("draft changed live rule")
	}
	x = decodeResponse[model.ACLTemplate](t, f.request("POST", "/api/v1/acl-templates/"+x.ID+"/publish", map[string]uint64{"version": x.Version}, f.admin, nil), 200)
	actual = decodeResponse[model.Rule](t, f.request("GET", "/api/v1/rules/"+r.ID, nil, b, nil), 200)
	if actual.Version != r.Version+1 {
		t.Fatal("publish did not invalidate bound rule")
	}
	x.Mandatory = true
	decodeResponse[model.ACLTemplate](t, f.request("PUT", "/api/v1/acl-templates/"+x.ID, x, f.admin, nil), 200)
	cert, key := testCertificate(t)
	c := decodeResponse[model.Certificate](t, f.request("POST", "/api/v1/certificates", model.Certificate{Name: "leaf", CertPEM: cert, KeyPEM: key}, b, nil), 201)
	if c.KeyPEM != "" {
		t.Fatal("certificate response leaked key")
	}
	var encrypted string
	if e := f.s.db.QueryRow("SELECT key_enc FROM certificates WHERE id=?", c.ID).Scan(&encrypted); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(encrypted, "PRIVATE KEY") || encrypted == key {
		t.Fatal("key stored as plaintext")
	}
	plain, e2 := decrypt(f.s.key, encrypted)
	if e2 != nil || plain != key {
		t.Fatal("encrypted key not recoverable")
	}
	site := model.Rule{Name: "site", DeviceID: d.ID, EdgeID: e.ID, Protocol: "https", Domain: "app.example.test", Target: "http://127.0.0.1:8080", SourceMode: "forwarded_headers", Transport: "auto", CertificateID: c.ID, Enabled: true}
	if w := f.request("POST", "/api/v1/rules", site, b, nil); w.Code != 409 {
		t.Fatal("site published without domain proof")
	}
	domain := decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains", map[string]string{"domain": site.Domain}, b, nil), 201)
	f.s.lookupTXT = func(context.Context, string) ([]string, error) { return []string{domain.TXTValue}, nil }
	decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains/"+domain.ID+"/verify", map[string]any{}, b, nil), 200)
	decodeResponse[model.Rule](t, f.request("POST", "/api/v1/rules", site, b, nil), 201)
	if w := f.request("DELETE", "/api/v1/certificates/"+c.ID, nil, b, nil); w.Code != 409 {
		t.Fatal("referenced certificate deleted")
	}
	other := f.createUser("certificate-other")
	if w := f.request("DELETE", "/api/v1/certificates/"+c.ID, nil, other, nil); w.Code != 404 {
		t.Fatal("cross-tenant certificate metadata disclosed")
	}
}

func TestMySQLDurableSharedGrantsAndUsage(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("quotas")
	d, key := f.bind(b, "device")
	a := f.edge("budget-a")
	z := f.edge("budget-z")
	f.createRule(b, d, a, 0)
	f.createRule(b, d, z, 0)
	q := model.Quota{TenantID: b.user.TenantID, BaseBPS: 100, PeakBPS: 200, BurstBytes: 10, MaxConnections: 6, NewFlowsPerSecond: 8, PeriodBytes: 100, Version: 1}
	q = decodeResponse[model.Quota](t, f.request("PUT", "/api/v1/quotas/"+b.user.TenantID, q, f.admin, nil), 200)
	f.syncClient(d, key, "quota-process-session")
	sa := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "a-one", nil, nil), 200)
	sz := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(z, "z-one", nil, nil), 200)
	ga, gz := sa.Grants[0], sz.Grants[0]
	if ga.Bytes+gz.Bytes > 100 || ga.BaseBPS+gz.BaseBPS > 100 || ga.MaxConnections+gz.MaxConnections > 6 {
		t.Fatal("cross-edge over-allocation", ga, gz)
	}
	u := model.Usage{GrantID: ga.ID, Sequence: 1, UploadBytes: 20, DownloadBytes: 10}
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "a-one", nil, []model.Usage{u}), 200)
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "a-one", nil, []model.Usage{u}), 200)
	var used, reserved int64
	if e := f.s.db.QueryRow("SELECT used_bytes,reserved_bytes FROM quotas WHERE tenant_id=?", b.user.TenantID).Scan(&used, &reserved); e != nil {
		t.Fatal(e)
	}
	if used != 30 || used+reserved != 100 {
		t.Fatal("duplicate usage double-charged or credit disappeared", used, reserved)
	}
	bad := u
	bad.Sequence = 2
	bad.UploadBytes = 101
	if w := f.syncEdge(a, "a-one", nil, []model.Usage{bad}); w.Code != 400 {
		t.Fatal("credit overrun accepted", w.Body.String())
	}
	if w := f.syncEdge(z, "z-one", nil, []model.Usage{u}); w.Code != 400 {
		t.Fatal("cross-edge grant report accepted")
	}
	u.Sequence = 2
	u.Closed = true
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(a, "a-one", nil, []model.Usage{u}), 200)
	u.Sequence = 3
	u.UploadBytes = 21
	if w := f.syncEdge(a, "a-one", nil, []model.Usage{u}); w.Code != 400 {
		t.Fatal("closed grant spent after returning reservation")
	}
	// Recreating the control-plane process over the same database cannot reset
	// confirmed charges, active reservations, sessions or resource ownership.
	restarted, e2 := New(context.Background(), f.s.cfg)
	if e2 != nil {
		t.Fatal(e2)
	}
	defer restarted.Close()
	var afterUsed, afterReserved int64
	if e := restarted.db.QueryRow("SELECT used_bytes,reserved_bytes FROM quotas WHERE tenant_id=?", b.user.TenantID).Scan(&afterUsed, &afterReserved); e != nil {
		t.Fatal(e)
	}
	if afterUsed != 30 || afterUsed+afterReserved > 100 {
		t.Fatal("restart reset durable accounting")
	}
}

func TestMySQLQuotaPeriodBoundaryAndLateReports(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("periods")
	d, key := f.bind(b, "period-device")
	edge := f.edge("period-edge")
	f.createRule(b, d, edge, 0)
	q := model.Quota{BaseBPS: -1, PeakBPS: -1, BurstBytes: 0, MaxConnections: -1, NewFlowsPerSecond: -1, PeriodBytes: 100, PeriodSeconds: 60, Version: 1}
	q = decodeResponse[model.Quota](t, f.request("PUT", "/api/v1/quotas/"+b.user.TenantID, q, f.admin, nil), 200)
	f.syncClient(d, key, "period-process-session")
	old := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "period-boot", nil, nil), 200).Grants[0]
	if old.PeriodID != q.PeriodID || old.ExpiresAt.After(q.PeriodEndsAt) {
		t.Fatal("grant outlives assigned period", old, q)
	}
	// Advance the durable period/lease boundary without a timing-sensitive
	// 60-second sleep. The production rollover code sees expired persisted rows.
	start, end := now().Add(-70*time.Second), now().Add(-10*time.Second)
	for _, query := range []struct {
		q    string
		args []any
	}{
		{"UPDATE quotas SET period_started_at=?,period_ends_at=? WHERE tenant_id=?", []any{start, end, b.user.TenantID}},
		{"UPDATE quota_periods SET started_at=?,ends_at=? WHERE tenant_id=? AND period_id=?", []any{start, end, b.user.TenantID, old.PeriodID}},
		{"UPDATE grants_table SET expires_at=? WHERE id=?", []any{end, old.ID}},
	} {
		if _, e := f.s.db.Exec(query.q, query.args...); e != nil {
			t.Fatal(e)
		}
	}
	list := decodeResponse[struct {
		Items []model.Quota `json:"items"`
	}](t, f.request("GET", "/api/v1/quotas", nil, b, nil), 200)
	current := list.Items[0]
	if current.PeriodID == old.PeriodID || current.UsedBytes != 0 || current.ReservedBytes != 0 || !current.PeriodEndsAt.After(now()) {
		t.Fatal("period did not advance", current)
	}
	fresh := decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "period-boot", nil, nil), 200).Grants[0]
	if fresh.ID == old.ID || fresh.PeriodID != current.PeriodID || fresh.Bytes != 100 {
		t.Fatal("new period reused old credit", fresh)
	}
	late := model.Usage{GrantID: old.ID, Sequence: 1, UploadBytes: 25, Closed: true}
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(edge, "period-boot", nil, []model.Usage{late}), 200)
	var oldUsed, oldReserved int64
	if e := f.s.db.QueryRow("SELECT used_bytes,reserved_bytes FROM quota_periods WHERE tenant_id=? AND period_id=?", b.user.TenantID, old.PeriodID).Scan(&oldUsed, &oldReserved); e != nil {
		t.Fatal(e)
	}
	if oldUsed != 100 || oldReserved != 0 {
		t.Fatal("lost credit was refunded by late report", oldUsed, oldReserved)
	}
	var currentUsed, currentReserved int64
	if e := f.s.db.QueryRow("SELECT used_bytes,reserved_bytes FROM quotas WHERE tenant_id=?", b.user.TenantID).Scan(&currentUsed, &currentReserved); e != nil {
		t.Fatal(e)
	}
	if currentUsed != 0 || currentReserved != 100 {
		t.Fatal("old period report changed active ledger", currentUsed, currentReserved)
	}
	// A batch is one durable runtime transaction, even when a later report fails.
	valid := model.Usage{GrantID: fresh.ID, Sequence: 1, UploadBytes: 10}
	invalid := valid
	invalid.Sequence = 2
	invalid.UploadBytes = 101
	if w := f.syncEdge(edge, "period-boot", nil, []model.Usage{valid, invalid}); w.Code != 400 {
		t.Fatal("invalid usage batch accepted", w.Body.String())
	}
	if e := f.s.db.QueryRow("SELECT used_bytes FROM quotas WHERE tenant_id=?", b.user.TenantID).Scan(&currentUsed); e != nil || currentUsed != 0 {
		t.Fatal("failed batch partially committed", currentUsed, e)
	}
	var responses [2]*httptest.ResponseRecorder
	var wg sync.WaitGroup
	for i := range responses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			responses[i] = f.syncEdge(edge, "period-boot", nil, []model.Usage{valid})
		}(i)
	}
	wg.Wait()
	for _, w := range responses {
		decodeResponse[model.EdgeSnapshot](t, w, 200)
	}
	if e := f.s.db.QueryRow("SELECT used_bytes FROM quotas WHERE tenant_id=?", b.user.TenantID).Scan(&currentUsed); e != nil || currentUsed != 10 {
		t.Fatal("concurrent reports double charged", currentUsed, e)
	}
}

func TestMySQLSessionConflictReplayAndMoveClaims(t *testing.T) {
	f := newCloudFixture(t)
	d, key := f.bind(f.admin, "sessions")
	a := f.edge("move-a")
	z := f.edge("move-z")
	in := model.ClientSyncRequest{DeviceID: d.ID, SessionID: "original-process-session", Timestamp: time.Now().Unix(), Nonce: randomToken(24)}
	sign := func() {
		in.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, model.ClientSyncPayload(in)))
	}
	sign()
	first := decodeResponse[model.ClientSnapshot](t, f.request("POST", "/api/v1/runtime/client/sync", in, nil, nil), 200)
	if w := f.request("POST", "/api/v1/runtime/client/sync", in, nil, nil); w.Code != 409 {
		t.Fatal("nonce replay authorized")
	}
	in.SessionID = "conflicting-process-session"
	in.Nonce = randomToken(24)
	sign()
	if w := f.request("POST", "/api/v1/runtime/client/sync", in, nil, nil); w.Code != 409 {
		t.Fatal("active session evicted")
	}
	if _, e := f.s.db.Exec("UPDATE devices SET lease_until=? WHERE id=?", now().Add(-time.Second), d.ID); e != nil {
		t.Fatal(e)
	}
	in.Nonce = randomToken(24)
	sign()
	second := decodeResponse[model.ClientSnapshot](t, f.request("POST", "/api/v1/runtime/client/sync", in, nil, nil), 200)
	if second.Device.Generation != first.Device.Generation+1 {
		t.Fatal("expired session did not advance generation")
	}
	r := f.createRule(f.admin, d, a, 20001)
	r.EdgeID = z.ID
	r = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+r.ID, r, f.admin, nil), 200)
	decodeResponse[map[string]any](t, f.request("DELETE", "/api/v1/rules/"+r.ID, nil, f.admin, nil), 200)
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(z, "move-boot", []model.RuleStatus{{ID: r.ID, Version: r.Version + 1, Status: "deleted"}}, nil), 200)
	// The new edge's deletion ACK cannot acknowledge the previous edge's still
	// valid snapshot. That old port remains held until its lease has expired.
	var claims int
	if e := f.s.db.QueryRow("SELECT COUNT(*) FROM resource_claims WHERE edge_id=? AND rule_id=?", a.ID, r.ID).Scan(&claims); e != nil || claims != 1 {
		t.Fatal("new edge freed old edge claim", claims, e)
	}
	clone := r
	clone.EdgeID = a.ID
	if w := f.request("POST", "/api/v1/rules", clone, f.admin, nil); w.Code != 409 {
		t.Fatal("old snapshot resource reused before expiry")
	}
	if _, e := f.s.db.Exec("UPDATE resource_claims SET release_at=? WHERE edge_id=? AND rule_id=?", now().Add(-time.Second), a.ID, r.ID); e != nil {
		t.Fatal(e)
	}
	f.createRule(f.admin, d, a, 20001)
}

func TestMySQLSharedBudgetZeroUnlimitedAndRemainders(t *testing.T) {
	f := newCloudFixture(t)
	a := f.edge("shares-a")
	z := f.edge("shares-z")
	for _, total := range []int64{0, 1, -1} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			b := f.createUser("shares-" + fmt.Sprint(total))
			d, _ := f.bind(b, "device")
			f.createRule(b, d, a, 0)
			f.createRule(b, d, z, 0)
			q := model.Quota{BaseBPS: total, PeakBPS: total, BurstBytes: max(0, total), MaxConnections: int(total), NewFlowsPerSecond: int(total), PeriodBytes: -1, Version: 1}
			q = decodeResponse[model.Quota](t, f.request("PUT", "/api/v1/quotas/"+b.user.TenantID, q, f.admin, nil), 200)
			ga, e := f.s.allocateGrant(context.Background(), b.user.TenantID, a.ID, "same-boot")
			if e != nil {
				t.Fatal(e)
			}
			gz, e := f.s.allocateGrant(context.Background(), b.user.TenantID, z.ID, "same-boot")
			if e != nil {
				t.Fatal(e)
			}
			if total < 0 {
				if ga.BaseBPS != -1 || gz.BaseBPS != -1 || ga.MaxConnections != -1 || gz.MaxConnections != -1 {
					t.Fatal("unlimited was reinterpreted")
				}
				q.BaseBPS = 1
				q.PeakBPS = 1
				q.MaxConnections = 1
				q.NewFlowsPerSecond = 1
				q = decodeResponse[model.Quota](t, f.request("PUT", "/api/v1/quotas/"+b.user.TenantID, q, f.admin, nil), 200)
				renewedA, e := f.s.allocateGrant(context.Background(), b.user.TenantID, a.ID, "same-boot")
				if e != nil {
					t.Fatal(e)
				}
				if renewedA.ID != ga.ID || renewedA.Bytes < ga.Bytes || renewedA.MaxConnections != 0 || renewedA.BaseBPS != 0 || renewedA.PolicyVersion != q.Version {
					t.Fatal("unlimited peer was not reserved during online tightening", renewedA)
				}
				for range 2 {
					renewedA, e = f.s.allocateGrant(context.Background(), b.user.TenantID, a.ID, "same-boot")
					if e != nil {
						t.Fatal(e)
					}
					gz, e = f.s.allocateGrant(context.Background(), b.user.TenantID, z.ID, "same-boot")
					if e != nil {
						t.Fatal(e)
					}
				}
				if renewedA.MaxConnections+gz.MaxConnections != 1 || renewedA.BaseBPS+gz.BaseBPS != 1 {
					t.Fatal("online policies did not converge without waiting for lease expiry", renewedA, gz)
				}
			} else if ga.BaseBPS+gz.BaseBPS != total || ga.MaxConnections+gz.MaxConnections != int(total) || ga.NewFlowsPerSecond+gz.NewFlowsPerSecond != int(total) {
				t.Fatal("integer share or zero semantics broken", ga, gz)
			}
			if total == 1 {
				newBoot, e := f.s.allocateGrant(context.Background(), b.user.TenantID, a.ID, "new-boot")
				if e != nil {
					t.Fatal(e)
				}
				if newBoot.BaseBPS+ga.BaseBPS+gz.BaseBPS > total || newBoot.MaxConnections+ga.MaxConnections+gz.MaxConnections > int(total) {
					t.Fatal("new boot duplicated live account share")
				}
			}
		})
	}
}
