package cloud

import (
	"drafrp/internal/model"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) user(w http.ResponseWriter, r *http.Request) {
	if uid, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/users/"), "/plan"); ok {
		s.assignUserPlan(w, r, uid)
		return
	}
	if !requireMethod(w, r, "PATCH") {
		return
	}
	var in struct {
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
		Role     *string `json:"role"`
	}
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	uid := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	// Serializing administrator membership prevents two concurrent demotions
	// from each seeing another active administrator and removing both.
	var rev uint64
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT revision FROM config_revision WHERE id=1 FOR UPDATE").Scan(&rev); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	var u model.User
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT id,tenant_id,username,role,disabled FROM users WHERE id=? FOR UPDATE", uid).Scan(&u.ID, &u.TenantID, &u.Username, &u.Role, &u.Disabled); e != nil {
		apiErr(w, 404, "not_found", "user not found")
		return
	}
	if in.Role != nil {
		if !validRole(*in.Role) {
			apiErr(w, 400, "invalid_role", "invalid role")
			return
		}
		u.Role = *in.Role
	}
	if in.Disabled != nil {
		u.Disabled = *in.Disabled
	}
	if u.Disabled || u.Role != "admin" {
		var admins int
		if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT COUNT(*) FROM users WHERE id<>? AND role='admin' AND disabled=0", uid).Scan(&admins); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if admins == 0 {
			apiErr(w, 409, "last_administrator", "at least one active administrator is required")
			return
		}
	}
	if in.Password != nil {
		if len(*in.Password) < 10 || len(*in.Password) > 72 {
			apiErr(w, 400, "invalid_password", "password must be 10..72 bytes")
			return
		}
		pw, e := bcrypt.GenerateFromPassword([]byte(*in.Password), bcrypt.DefaultCost)
		if e != nil {
			apiErr(w, 400, "invalid_password", e.Error())
			return
		}
		if _, e = s.store(r.Context()).ExecContext(r.Context(), "UPDATE users SET password_hash=? WHERE id=?", pw, uid); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
	}
	if _, e := s.store(r.Context()).ExecContext(r.Context(), "UPDATE users SET disabled=?,role=? WHERE id=?", u.Disabled, u.Role, uid); e != nil {
		apiErr(w, 503, "database_unavailable", e.Error())
		return
	}
	if in.Password != nil || u.Disabled {
		if _, e := s.store(r.Context()).ExecContext(r.Context(), "UPDATE sessions SET revoked=1 WHERE user_id=?", uid); e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
	}
	p := r.Context().Value(pkey{}).(*principal)
	s.audit(r.Context(), p.User.ID, u.TenantID, "user.update", "user", uid)
	s.notify(r.Context())
	writeJSON(w, 200, u)
}
