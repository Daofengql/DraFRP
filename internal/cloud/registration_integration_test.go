package cloud

import (
	"context"
	"drafrp/internal/model"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMySQLRegistrationCaptchaPersistenceAndTenantIsolation(t *testing.T) {
	f := newCloudFixture(t)
	f.s.cfg.CaptchaDisabled = false
	input := func(challenge captchaChallenge, username, answer string) map[string]any {
		return map[string]any{"username": username, "password": "registration-test-password", "captcha_id": challenge.ID, "captcha_answer": answer}
	}
	challenge := issueKnownCaptcha(t, f.s, "ABCD23", 10)
	decodeResponse[map[string]any](t, f.request("POST", "/auth/register", input(challenge, "new-user", "wrong"), nil, nil), 400)
	decodeResponse[map[string]any](t, f.request("POST", "/auth/register", input(challenge, "new-user", "ABCD23"), nil, nil), 400)
	challenge = issueKnownCaptcha(t, f.s, "ABCD23", 11)
	user := decodeResponse[struct {
		User model.User `json:"user"`
	}](t, f.request("POST", "/auth/register", input(challenge, "  new-user  ", "abcd23"), nil, nil), 201).User
	if user.Role != "user" || user.TenantID == "" || user.TenantID == f.admin.user.TenantID || user.Username != "new-user" {
		t.Fatalf("registration granted wrong identity: %+v", user)
	}
	var tenants, users, quotas, audits int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM tenants WHERE id=?", user.TenantID).Scan(&tenants); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM users WHERE id=? AND tenant_id=? AND role='user'", user.ID, user.TenantID).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM quotas WHERE tenant_id=?", user.TenantID).Scan(&quotas); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM audit WHERE actor_id=? AND action='user.register'", user.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if tenants != 1 || users != 1 || quotas != 1 || audits != 1 {
		t.Fatal("registration transaction incomplete", tenants, users, quotas, audits)
	}
	// A fresh control process must retain the account and its privilege scope.
	cfg := f.s.cfg
	f.s.Close()
	restarted, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	f.s, f.h = restarted, restarted.Handler()
	decodeResponse[map[string]any](t, f.request("POST", "/auth/login", map[string]string{"username": "new-user", "password": "registration-test-password"}, nil, nil), 400)
	challenge = issueKnownCaptcha(t, f.s, "EFGH45", 20)
	wrongPassword := input(challenge, "new-user", "EFGH45")
	wrongPassword["password"] = "incorrect-password"
	decodeResponse[map[string]any](t, f.request("POST", "/auth/login", wrongPassword, nil, nil), 401)
	decodeResponse[map[string]any](t, f.request("POST", "/auth/login", input(challenge, "new-user", "EFGH45"), nil, nil), 400)
	challenge = issueKnownCaptcha(t, f.s, "EFGH45", 12)
	w := f.request("POST", "/auth/login", input(challenge, "new-user", "EFGH45"), nil, nil)
	login := decodeResponse[struct {
		User model.User `json:"user"`
		CSRF string     `json:"csrf_token"`
	}](t, w, 200)
	b := &browser{f: f, cookie: w.Result().Cookies()[0], csrf: login.CSRF, user: login.User}
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/users", nil, b, nil), 403)
	decodeResponse[map[string]any](t, f.request("GET", "/api/v1/overview?scope=platform", nil, b, nil), 403)
	decodeResponse[map[string]any](t, f.request("POST", "/auth/login", input(challenge, "new-user", "EFGH45"), nil, nil), 400)
	_, _ = f.bind(f.admin, "private-admin-device")
	response := decodeResponse[struct {
		Items []model.Device `json:"items"`
	}](t, f.request("GET", "/api/v1/devices", nil, b, nil), 200)
	if len(response.Items) != 0 {
		t.Fatal("registered tenant could read administrator devices")
	}
	// The username uniqueness failure must roll back the earlier tenant insert.
	var before, after int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM tenants").Scan(&before); err != nil {
		t.Fatal(err)
	}
	challenge = issueKnownCaptcha(t, f.s, "JKLM67", 13)
	decodeResponse[map[string]any](t, f.request("POST", "/auth/register", input(challenge, "new-user", "JKLM67"), nil, nil), 409)
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM tenants").Scan(&after); err != nil || after != before {
		t.Fatal("duplicate registration leaked an orphan tenant", err, before, after)
	}
	challenge = issueKnownCaptcha(t, f.s, "NPQR89", 14)
	malicious := input(challenge, "privilege-injection", "NPQR89")
	malicious["role"] = "admin"
	malicious["tenant_id"] = f.admin.user.TenantID
	decodeResponse[map[string]any](t, f.request("POST", "/auth/register", malicious, nil, nil), 400)
	challenge = issueKnownCaptcha(t, f.s, "STUV23", 15)
	tooLong := input(challenge, strings.Repeat("用", 65), "STUV23")
	decodeResponse[map[string]any](t, f.request("POST", "/auth/register", tooLong, nil, nil), 400)
	challenge = issueKnownCaptcha(t, f.s, "WXYZ45", 16)
	f.s.captchaMu.Lock()
	entry := f.s.captchas[challenge.ID]
	entry.ExpiresAt = time.Now().Add(-time.Second)
	f.s.captchas[challenge.ID] = entry
	f.s.captchaMu.Unlock()
	decodeResponse[map[string]any](t, f.request("POST", "/auth/register", input(challenge, "expired-challenge", "WXYZ45"), nil, nil), 400)
	f.s.cfg.RegistrationDisabled = true
	decodeResponse[map[string]any](t, f.request("POST", "/auth/register", map[string]string{"username": "disabled", "password": "registration-test-password"}, nil, nil), 403)
}

func TestMySQLConcurrentRegistrationKeepsOneTenant(t *testing.T) {
	f := newCloudFixture(t) // Explicitly disables captcha; this case isolates SQL concurrency.
	var before int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM tenants").Scan(&before); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			responses <- f.request("POST", "/auth/register", map[string]string{"username": "concurrent-user", "password": "registration-test-password"}, nil, nil)
		}()
	}
	close(start)
	wg.Wait()
	close(responses)
	created, conflicted := 0, 0
	for response := range responses {
		switch response.Code {
		case 201:
			created++
		case 409:
			conflicted++
		default:
			t.Fatal("concurrent registration", response.Code, response.Body.String())
		}
	}
	var after, users, quotas int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM tenants").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username='concurrent-user' AND role='user'").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM quotas q JOIN users u ON u.tenant_id=q.tenant_id WHERE u.username='concurrent-user'").Scan(&quotas); err != nil {
		t.Fatal(err)
	}
	if created != 1 || conflicted != 1 || after != before+1 || users != 1 || quotas != 1 {
		t.Fatal("registration created duplicate or orphan account state", created, conflicted, before, after, users, quotas)
	}
}
