package cloud

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"
)

type verifiedDomain struct {
	ID         string     `json:"id"`
	Domain     string     `json:"domain"`
	Status     string     `json:"status"`
	TXTName    string     `json:"txt_name"`
	TXTValue   string     `json:"txt_value"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (s *Server) loadDomain(ctx context.Context, tid, did string, lock bool) (verifiedDomain, error) {
	var d verifiedDomain
	var verified sql.NullTime
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	e := s.store(ctx).QueryRowContext(ctx, "SELECT id,domain,status,challenge,verified_at,created_at FROM domains WHERE id=? AND tenant_id=?"+suffix, did, tid).Scan(&d.ID, &d.Domain, &d.Status, &d.TXTValue, &verified, &d.CreatedAt)
	d.TXTName = "_drafrp-challenge." + d.Domain
	if verified.Valid {
		d.VerifiedAt = &verified.Time
	}
	return d, e
}
func (s *Server) domains(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, e := s.store(r.Context()).QueryContext(r.Context(), "SELECT id,domain,status,challenge,verified_at,created_at FROM domains WHERE tenant_id=? ORDER BY created_at DESC", tenant(r))
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		defer rows.Close()
		out := []verifiedDomain{}
		for rows.Next() {
			var d verifiedDomain
			var verified sql.NullTime
			if e = rows.Scan(&d.ID, &d.Domain, &d.Status, &d.TXTValue, &verified, &d.CreatedAt); e != nil {
				apiErr(w, 503, "database_unavailable", e.Error())
				return
			}
			d.TXTName = "_drafrp-challenge." + d.Domain
			if verified.Valid {
				d.VerifiedAt = &verified.Time
			}
			out = append(out, d)
		}
		if e = rows.Err(); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
		return
	}
	if !requireMethod(w, r, "POST") {
		return
	}
	var in struct {
		Domain string `json:"domain"`
	}
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	in.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Domain), "."))
	if !validDomain(in.Domain) || len("_drafrp-challenge."+in.Domain) > 253 {
		apiErr(w, 400, "invalid_domain", "supply a DNS hostname without a wildcard")
		return
	}
	d := verifiedDomain{ID: id(), Domain: in.Domain, Status: "pending", TXTName: "_drafrp-challenge." + in.Domain, TXTValue: "drafrp=" + randomToken(32), CreatedAt: now()}
	tx, e := s.beginTx(r.Context(), nil)
	if e != nil {
		apiErr(w, 503, "database_unavailable", "could not start domain registration")
		return
	}
	defer tx.Rollback()
	if e = requireResourceCapacity(r.Context(), tx, tenant(r), resourceDelta{"domains", 1}); e != nil {
		if !writeResourceQuotaError(w, e) {
			apiErr(w, 503, "database_unavailable", "could not check domain resource quota")
		}
		return
	}
	if _, e := tx.ExecContext(r.Context(), "INSERT INTO domains(id,tenant_id,domain,challenge,status,created_at) VALUES(?,?,?,?,?,?)", d.ID, tenant(r), d.Domain, d.TXTValue, d.Status, d.CreatedAt); e != nil {
		apiErr(w, 409, "domain_conflict", "domain verification is already registered in this space")
		return
	}
	if e = tx.Commit(); e != nil {
		apiErr(w, 503, "database_unavailable", "domain registration could not commit")
		return
	}
	s.notify(r.Context())
	writeJSON(w, 201, d)
}
func (s *Server) domain(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/domains/"), "/")
	if len(parts) > 2 {
		apiErr(w, 404, "not_found", "unknown domain action")
		return
	}
	d, e := s.loadDomain(r.Context(), tenant(r), parts[0], r.Method != "GET")
	if e != nil {
		apiErr(w, 404, "not_found", "domain not found")
		return
	}
	if len(parts) == 1 && r.Method == "GET" {
		writeJSON(w, 200, d)
		return
	}
	if len(parts) == 2 && parts[1] == "verify" {
		if !requireMethod(w, r, "POST") {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		records, e := s.lookupTXT(ctx, d.TXTName)
		matched := false
		for _, txt := range records {
			if txt == d.TXTValue {
				matched = true
			}
		}
		if e != nil || !matched {
			apiErr(w, 409, "domain_unverified", "DNS TXT challenge is not visible; publish the exact record and retry")
			return
		}
		if _, e = s.store(r.Context()).ExecContext(r.Context(), "INSERT IGNORE INTO domain_ownership(domain,tenant_id) VALUES(?,?)", d.Domain, tenant(r)); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		var owner string
		if e = s.store(r.Context()).QueryRowContext(r.Context(), "SELECT tenant_id FROM domain_ownership WHERE domain=? FOR UPDATE", d.Domain).Scan(&owner); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if owner != tenant(r) {
			apiErr(w, 409, "domain_owned", "domain is already verified by another space; existing ownership must be released first")
			return
		}
		at := now()
		d.Status = "verified"
		d.VerifiedAt = &at
		if _, e = s.store(r.Context()).ExecContext(r.Context(), "UPDATE domains SET status='verified',verified_at=? WHERE id=?", at, d.ID); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		s.notify(r.Context())
		writeJSON(w, 200, d)
		return
	}
	if len(parts) != 1 {
		apiErr(w, 404, "not_found", "unknown domain action")
		return
	}
	if !requireMethod(w, r, "DELETE") {
		return
	}
	var count int
	if e = s.store(r.Context()).QueryRowContext(r.Context(), "SELECT COUNT(*) FROM rules WHERE tenant_id=? AND domain=?", tenant(r), d.Domain).Scan(&count); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if count > 0 {
		apiErr(w, 409, "domain_in_use", "remove sites and wait for revocation before releasing domain ownership")
		return
	}
	// A moved/renamed site no longer contains its old domain in the current
	// rule, but an offline edge may still hold that domain's earlier snapshot.
	// Keep global ownership until the old resource claim loses authority too.
	// Claims intentionally survive deletion of the current rule when another
	// edge still holds old authority, so this check cannot join current rules.
	// Verified domain ownership is global, as are claims for this site name.
	if e = s.store(r.Context()).QueryRowContext(r.Context(), "SELECT COUNT(*) FROM resource_claims WHERE resource_key=? AND (release_at IS NULL OR release_at>?)", "site/"+d.Domain, now()).Scan(&count); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if count > 0 {
		apiErr(w, 409, "domain_in_use", "old site authorization is awaiting edge revocation or lease expiry")
		return
	}
	if _, e = s.store(r.Context()).ExecContext(r.Context(), "DELETE FROM domains WHERE id=?", d.ID); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	s.notify(r.Context())
	writeJSON(w, 200, map[string]bool{"ok": true})
}
