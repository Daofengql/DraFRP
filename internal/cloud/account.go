package cloud

import (
	"drafrp/internal/model"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) usageSummary(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	rows, err := s.store(r.Context()).QueryContext(r.Context(), "SELECT g.issued_edge_id,COALESCE(e.name,''),SUM(u.upload_bytes),SUM(u.download_bytes),MAX(u.observed_at) FROM usage_table u JOIN grants_table g ON g.id=u.grant_id LEFT JOIN edges e ON e.id=g.issued_edge_id WHERE g.tenant_id=? GROUP BY g.issued_edge_id,e.name ORDER BY MAX(u.observed_at) DESC", tenant(r))
	if err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	defer rows.Close()
	type summary struct {
		EdgeID        string    `json:"edge_id"`
		EdgeName      string    `json:"edge_name"`
		UploadBytes   int64     `json:"upload_bytes"`
		DownloadBytes int64     `json:"download_bytes"`
		ObservedAt    time.Time `json:"observed_at"`
	}
	out := []summary{}
	for rows.Next() {
		var item summary
		if err = rows.Scan(&item.EdgeID, &item.EdgeName, &item.UploadBytes, &item.DownloadBytes, &item.ObservedAt); err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	p := r.Context().Value(pkey{}).(*principal)
	u := p.User
	if err := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT created_at FROM users WHERE id=?", u.ID).Scan(&u.CreatedAt); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	tx, err := s.beginTx(r.Context(), nil)
	if err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	defer tx.Rollback()
	q, err := s.currentQuota(r.Context(), tx, u.TenantID)
	if err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	q.Resources, err = resourceUsage(r.Context(), tx, u.TenantID)
	if err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	var plan *model.Plan
	if q.PlanID != "" {
		v, e := readPlan(r.Context(), tx, q.PlanID)
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		u.PlanID, u.PlanName = v.ID, v.Name
		plan = &v
	}
	if err = tx.Commit(); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"user": u, "plan": plan, "quota": q})
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "PUT") {
		return
	}
	var in struct {
		Current  string `json:"current_password"`
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &in); err != nil {
		apiErr(w, 400, "invalid_json", err.Error())
		return
	}
	if len(in.Password) < 10 || len(in.Password) > 72 || len(in.Current) > 72 {
		apiErr(w, 400, "invalid_password", "密码长度须为 10–72 字节")
		return
	}
	p := r.Context().Value(pkey{}).(*principal)
	var hash string
	if err := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT password_hash FROM users WHERE id=? FOR UPDATE", p.User.ID).Scan(&hash); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Current)) != nil {
		apiErr(w, 400, "current_password_invalid", "当前密码错误")
		return
	}
	password, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		apiErr(w, 400, "invalid_password", "密码无效")
		return
	}
	if _, err = s.store(r.Context()).ExecContext(r.Context(), "UPDATE users SET password_hash=? WHERE id=?", string(password), p.User.ID); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	if _, err = s.store(r.Context()).ExecContext(r.Context(), "UPDATE sessions SET revoked=1 WHERE user_id=? AND id<>?", p.User.ID, p.SessionID); err != nil {
		apiErr(w, 503, "database_unavailable", err.Error())
		return
	}
	s.audit(r.Context(), p.User.ID, p.User.TenantID, "account.password", "user", p.User.ID)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
