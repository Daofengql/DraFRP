package cloud

import (
	"database/sql"
	"drafrp/internal/model"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) authOptions(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	writeJSON(w, 200, map[string]bool{"registration_enabled": !s.cfg.RegistrationDisabled, "captcha_required": !s.cfg.CaptchaDisabled})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	if !sameOrigin(r) {
		apiErr(w, 403, "origin", "cross-origin registration rejected")
		return
	}
	if s.cfg.RegistrationDisabled {
		apiErr(w, 403, "registration_disabled", "registration is disabled")
		return
	}
	if !s.allowRequest(r, "register", 10) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, 429, "rate_limited", "too many registration attempts")
		return
	}
	var in struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		CaptchaID     string `json:"captcha_id"`
		CaptchaAnswer string `json:"captcha_answer"`
	}
	if err := readJSON(w, r, &in); err != nil {
		apiErr(w, 400, "invalid_json", err.Error())
		return
	}
	if !s.verifyCaptcha(in.CaptchaID, in.CaptchaAnswer) {
		apiErr(w, 400, "captcha_invalid", "验证码错误、过期或已使用，请刷新后重试")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" || utf8.RuneCountInString(in.Username) > 64 || len(in.Username) > 255 || len(in.Password) < 10 || len(in.Password) > 72 {
		apiErr(w, 400, "invalid_registration", "username must be 1..64 characters; password must be 10..72 bytes")
		return
	}
	password, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		apiErr(w, 400, "invalid_password", "password could not be processed")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not start registration")
		return
	}
	defer tx.Rollback()
	u := model.User{ID: id(), TenantID: id(), Username: in.Username, Role: "user"}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)", u.TenantID, u.Username, now()); err != nil {
		apiErr(w, 503, "database_unavailable", "could not create account")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO users(id,tenant_id,username,password_hash,role,created_at) VALUES(?,?,?,?,?,?)", u.ID, u.TenantID, u.Username, string(password), u.Role, now()); err != nil {
		if duplicate, ok := err.(*mysql.MySQLError); ok && duplicate.Number == 1062 {
			apiErr(w, 409, "username_exists", "username is already registered")
		} else {
			apiErr(w, 503, "database_unavailable", "could not create account")
		}
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO quotas(tenant_id,updated_at) VALUES(?,?)", u.TenantID, now()); err != nil {
		apiErr(w, 503, "database_unavailable", "could not initialize account quota")
		return
	}
	if err = initializeAccountPlan(r.Context(), tx, u.TenantID, nil); err != nil {
		apiErr(w, 503, "database_unavailable", "could not initialize account plan")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO audit(id,actor_id,tenant_id,action,resource_type,resource_id,created_at) VALUES(?,?,?,?,?,?,?)", id(), u.ID, u.TenantID, "user.register", "user", u.ID, now()); err != nil {
		apiErr(w, 503, "database_unavailable", "could not record registration")
		return
	}
	if err = tx.Commit(); err != nil {
		apiErr(w, 503, "database_unavailable", "registration could not commit")
		return
	}
	s.broadcast()
	writeJSON(w, 201, map[string]model.User{"user": u})
}
