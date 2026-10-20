package cloud

import (
	"context"
	"drafrp/internal/model"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMySQLDomainOwnershipWaitsForMovedSiteClaim(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("domain-move-owner")
	d, _ := f.bind(b, "site-device")
	a, z := f.edge("domain-a"), f.edge("domain-z")
	verify := func(name string) verifiedDomain {
		domain := decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains", map[string]string{"domain": name}, b, nil), 201)
		f.s.lookupTXT = func(context.Context, string) ([]string, error) { return []string{domain.TXTValue}, nil }
		return decodeResponse[verifiedDomain](t, f.request("POST", "/api/v1/domains/"+domain.ID+"/verify", map[string]any{}, b, nil), 200)
	}
	old, next := verify("before.example"), verify("after.example")
	rule := model.Rule{Name: "site-before", Protocol: "http", DeviceID: d.ID, EdgeID: a.ID, Domain: old.Domain, Target: "http://127.0.0.1:8080", SourceMode: "forwarded_headers", Transport: "auto", Enabled: true}
	rule = decodeResponse[model.Rule](t, f.request("POST", "/api/v1/rules", rule, b, nil), 201)
	rule.EdgeID = z.ID
	rule.Domain = next.Domain
	rule = decodeResponse[model.Rule](t, f.request("PUT", "/api/v1/rules/"+rule.ID, rule, b, nil), 200)
	if w := f.request("DELETE", "/api/v1/edges/"+a.ID, nil, f.admin, nil); w.Code != 409 {
		t.Fatalf("old edge deleted while old site snapshot survives: %d %s", w.Code, w.Body.String())
	}
	a.Name = "edited-old-edge"
	if w := f.request("PUT", "/api/v1/edges/"+a.ID, a, f.admin, nil); w.Code != 409 {
		t.Fatalf("old edge edited while old site snapshot survives: %d %s", w.Code, w.Body.String())
	}
	if w := f.request("DELETE", "/api/v1/domains/"+old.ID, nil, b, nil); w.Code != 409 {
		t.Fatalf("old domain released while old edge authority survives: %d %s", w.Code, w.Body.String())
	}
	var owner string
	if err := f.s.db.QueryRow("SELECT tenant_id FROM domain_ownership WHERE domain=?", old.Domain).Scan(&owner); err != nil || owner != b.user.TenantID {
		t.Fatal("domain ownership escaped failed release", err)
	}
	// Deletion on the new edge removes the current rule but must retain the old
	// edge's independent claim. Ownership checks must not depend on a live rule.
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/rules/"+rule.ID, nil, b, nil), 200)
	decodeResponse[model.EdgeSnapshot](t, f.syncEdge(z, "domain-delete-boot", []model.RuleStatus{{ID: rule.ID, Version: rule.Version + 1, Status: "deleted"}}, nil), 200)
	if w := f.request("DELETE", "/api/v1/domains/"+old.ID, nil, b, nil); w.Code != 409 {
		t.Fatalf("orphaned old claim lost domain protection: %d %s", w.Code, w.Body.String())
	}
	if w := f.request("DELETE", "/api/v1/edges/"+a.ID, nil, f.admin, nil); w.Code != 409 {
		t.Fatalf("orphaned old claim lost edge protection: %d %s", w.Code, w.Body.String())
	}
	if _, err := f.s.db.Exec("UPDATE resource_claims SET release_at=? WHERE edge_id=? AND resource_key=?", time.Now().Add(-time.Second), a.ID, "site/"+old.Domain); err != nil {
		t.Fatal(err)
	}
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/domains/"+old.ID, nil, b, nil), 200)
	decodeResponse[map[string]bool](t, f.request("DELETE", "/api/v1/edges/"+a.ID, nil, f.admin, nil), 200)
}

func TestMySQLMutationHoldsSessionAuthorityThroughCommit(t *testing.T) {
	f := newCloudFixture(t)
	b := f.createUser("authority-lock")
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "https://cloud.example/api/v1/test-authority", nil)
		r.AddCookie(b.cookie)
		r.Header.Set("X-CSRF-Token", b.csrf)
		w := httptest.NewRecorder()
		f.s.auth(func(w http.ResponseWriter, r *http.Request) {
			close(entered)
			<-release
			writeJSON(w, 200, map[string]bool{"ok": true})
		})(w, r)
		done <- w
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("mutation did not reach authority lock")
	}
	// The direct transaction models a simultaneous administrator revocation;
	// it must wait for this already authorized mutation to finish.
	revoked := make(chan error, 1)
	go func() { _, err := f.s.db.Exec("UPDATE users SET disabled=1 WHERE id=?", b.user.ID); revoked <- err }()
	select {
	case err := <-revoked:
		close(release)
		<-done
		t.Fatalf("revocation crossed an in-flight authorization: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	select {
	case w := <-done:
		if w.Code != 200 {
			t.Fatalf("authorized mutation failed: %d %s", w.Code, w.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authorized mutation did not finish")
	}
	select {
	case err := <-revoked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revocation did not proceed after commit")
	}
	if w := f.request("GET", "/api/v1/me", nil, b, nil); w.Code != 401 {
		t.Fatalf("disabled identity remained authorized: %d", w.Code)
	}
}
