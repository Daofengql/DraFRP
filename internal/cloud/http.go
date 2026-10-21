package cloud

import (
	"context"
	"database/sql"
	"drafrp/internal/model"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"

	"drafrp/internal/webui"
	"net/http"
	"strings"
	"time"
)

type principal struct {
	User            model.User
	SessionID, CSRF string
}
type pkey struct{}

var errSession = errors.New("session is unavailable or expired")

func (s *Server) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/auth/options", s.authOptions)
	m.HandleFunc("/auth/captcha", s.captcha)
	m.HandleFunc("/auth/register", s.register)
	m.HandleFunc("/auth/login", s.login)
	m.HandleFunc("/auth/logout", s.auth(s.logout))
	m.HandleFunc("/api/v1/me", s.auth(s.me))
	m.HandleFunc("/api/v1/account", s.auth(s.account))
	m.HandleFunc("/api/v1/account/password", s.auth(s.accountPassword))
	m.HandleFunc("/api/v1/plans", s.authAdmin(s.plans))
	m.HandleFunc("/api/v1/plans/", s.authAdmin(s.plan))
	m.HandleFunc("/api/v1/overview", s.auth(s.overview))
	m.HandleFunc("/api/v1/devices", s.auth(s.devices))
	m.HandleFunc("/api/v1/devices/", s.auth(s.device))
	m.HandleFunc("/api/v1/bind/confirm", s.auth(s.bindConfirm))
	m.HandleFunc("/api/v1/bind/", s.auth(s.bindInspect))
	m.HandleFunc("/api/v1/rules", s.auth(s.rules))
	m.HandleFunc("/api/v1/rules/", s.auth(s.rule))
	m.HandleFunc("/api/v1/edges", s.auth(s.edges))
	m.HandleFunc("/api/v1/edges/", s.authAdmin(s.edge))
	m.HandleFunc("/api/v1/port-resources", s.auth(s.portResources))
	m.HandleFunc("/api/v1/acl/simulate", s.aclSimulation)
	m.HandleFunc("/api/v1/acl/observations", s.auth(s.aclObservations))
	m.HandleFunc("/api/v1/acl/applications", s.authAdmin(s.aclApplications))
	m.HandleFunc("/api/v1/acl-templates", s.auth(s.templates))
	m.HandleFunc("/api/v1/acl-templates/", s.auth(s.template))
	m.HandleFunc("/api/v1/certificates", s.auth(s.certificates))
	m.HandleFunc("/api/v1/certificates/", s.auth(s.certificate))
	m.HandleFunc("/api/v1/domains", s.auth(s.domains))
	m.HandleFunc("/api/v1/domains/", s.auth(s.domain))
	m.HandleFunc("/api/v1/quotas", s.auth(s.quotas))
	m.HandleFunc("/api/v1/quotas/", s.authAdmin(s.quota))
	m.HandleFunc("/api/v1/usage", s.auth(s.usage))
	m.HandleFunc("/api/v1/usage-summary", s.auth(s.usageSummary))
	m.HandleFunc("/api/v1/usage-history", s.auth(s.usageHistory))
	m.HandleFunc("/api/v1/audit", s.authAdmin(s.auditAPI))
	m.HandleFunc("/api/v1/system", s.auth(s.system))
	m.HandleFunc("/api/v1/users", s.authAdmin(s.users))
	m.HandleFunc("/api/v1/users/", s.authAdmin(s.user))
	m.HandleFunc("/api/v1/events", s.auth(s.events))
	m.HandleFunc("/api/v1/runtime/edge/sync", s.edgeSync)
	m.HandleFunc("/api/v1/runtime/client/bind", s.clientBind)
	m.HandleFunc("/api/v1/runtime/client/bind/poll", s.clientBindPoll)
	m.HandleFunc("/api/v1/runtime/client/sync", s.clientSync)
	m.Handle("/console/", webui.Handler())
	m.Handle("/console", webui.Handler())
	m.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			apiErr(w, 405, "method_not_allowed", "method not allowed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	m.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			apiErr(w, 405, "method_not_allowed", "method not allowed")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if e := s.db.PingContext(ctx); e != nil {
			apiErr(w, 503, "database_unavailable", "MySQL unavailable")
			return
		}
		w.WriteHeader(204)
	})
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/console/", http.StatusTemporaryRedirect)
			return
		}
		apiErr(w, 404, "not_found", "resource not found")
	})
	return securityHeaders(m)
}
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" || r.URL.Path == "/auth/login" || strings.HasPrefix(r.URL.Path, "/api/v1/runtime/") {
			next.ServeHTTP(w, r)
			return
		}
		p, _ := r.Context().Value(pkey{}).(*principal)
		if p != nil && p.CSRF != "" && hashToken(r.Header.Get("X-CSRF-Token")) != p.CSRF {
			apiErr(w, 403, "csrf", "missing or invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) auth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, e := s.principal(r)
		if e != nil {
			if !errors.Is(e, errSession) {
				apiErr(w, 503, "database_unavailable", "could not validate session")
				return
			}
			apiErr(w, 401, "unauthorized", "login required")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && hashToken(r.Header.Get("X-CSRF-Token")) != p.CSRF {
			apiErr(w, 403, "csrf", "missing or invalid CSRF token")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && !sameOrigin(r) {
			apiErr(w, 403, "origin", "cross-origin mutation rejected")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), pkey{}, p))
		if r.Method != "GET" && r.Method != "HEAD" {
			s.mutate(w, r, fn)
			return
		}
		fn(w, r)
	}
}
func (s *Server) authAdmin(fn http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(pkey{}).(*principal)
		if p.User.Role != "admin" {
			apiErr(w, 403, "forbidden", "administrator role required")
			return
		}
		fn(w, r)
	})
}
func (s *Server) principal(r *http.Request) (*principal, error) {
	c, e := r.Cookie("drafrp_session")
	if e != nil || c.Value == "" {
		return nil, errSession
	}
	var p principal
	var u model.User
	var disabled bool
	var exp time.Time
	var csrf string
	lock := ""
	if _, inMutation := r.Context().Value(mutationKey{}).(*mutation); inMutation {
		// Hold authorization through commit. User/session revocations must
		// serialize with already authorized browser mutations.
		lock = " FOR SHARE"
	}
	e = s.store(r.Context()).QueryRowContext(r.Context(), "SELECT u.id,u.username,u.role,u.tenant_id,u.disabled,s.id,s.csrf_hash,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked=0"+lock, hashToken(c.Value)).Scan(&u.ID, &u.Username, &u.Role, &u.TenantID, &disabled, &p.SessionID, &csrf, &exp)
	if e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return nil, errSession
		}
		return nil, e
	}
	if disabled || !time.Now().Before(exp) {
		return nil, errSession
	}
	u.Disabled = disabled
	p.User = u
	p.CSRF = csrf
	return &p, nil
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	if !sameOrigin(r) {
		apiErr(w, 403, "origin", "cross-origin login rejected")
		return
	}
	if !s.allowLogin(r) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, 429, "rate_limited", "too many login attempts")
		return
	}
	var in struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		CaptchaID     string `json:"captcha_id"`
		CaptchaAnswer string `json:"captcha_answer"`
	}
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	if !s.verifyCaptcha(in.CaptchaID, in.CaptchaAnswer) {
		apiErr(w, 400, "captcha_invalid", "验证码错误、过期或已使用，请刷新后重试")
		return
	}
	var u model.User
	var hash string
	var disabled bool
	e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT id,tenant_id,username,password_hash,role,disabled FROM users WHERE username=?", in.Username).Scan(&u.ID, &u.TenantID, &u.Username, &hash, &u.Role, &disabled)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		apiErr(w, 503, "database_unavailable", "could not validate credentials")
		return
	}
	if e != nil || disabled || bcryptCompare(hash, in.Password) != nil {
		apiErr(w, 401, "invalid_credentials", "invalid username or password")
		return
	}
	tok := randomToken(32)
	sid := id()
	csrf := s.csrf(sid)
	_, e = s.store(r.Context()).ExecContext(r.Context(), "INSERT INTO sessions(id,user_id,token_hash,csrf_hash,expires_at,created_at) VALUES(?,?,?,?,?,?)", sid, u.ID, hashToken(tok), hashToken(csrf), now().Add(s.cfg.SessionTTL), now())
	if e != nil {
		apiErr(w, 500, "database", "could not create session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "drafrp_session", Value: tok, Path: "/", HttpOnly: true, Secure: r.TLS != nil || s.cfg.SecureCookies, SameSite: http.SameSiteLaxMode, Expires: now().Add(s.cfg.SessionTTL)})
	writeJSON(w, 200, map[string]any{"user": u, "csrf_token": csrf})
}
func bcryptCompare(h, p string) error { return bcrypt.CompareHashAndPassword([]byte(h), []byte(p)) }
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	if c, e := r.Cookie("drafrp_session"); e == nil {
		if _, e = s.store(r.Context()).ExecContext(r.Context(), "UPDATE sessions SET revoked=1 WHERE token_hash=?", hashToken(c.Value)); e != nil {
			apiErr(w, 503, "database_unavailable", "session revocation could not persist")
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "drafrp_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	p, _ := r.Context().Value(pkey{}).(*principal)
	writeJSON(w, 200, map[string]any{"user": p.User, "csrf_token": s.csrf(p.SessionID), "build_id": s.cfg.BuildID})
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		return
	}
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	if len(s.subscribers) >= 1024 {
		s.mu.Unlock()
		apiErr(w, 503, "event_capacity", "event stream capacity reached")
		return
	}
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.subscribers, ch); s.mu.Unlock(); close(ch) }()
	// Idle subscriptions outlive the normal HTTP response timeout; each actual
	// write/flush still has a bound so a non-reading peer cannot retain a slot.
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Time{})
	write := func(data string) bool {
		_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := w.Write([]byte(data))
		if err == nil {
			err = controller.Flush()
		}
		_ = controller.SetWriteDeadline(time.Time{})
		return err == nil
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	timer := time.NewTicker(15 * time.Second)
	defer timer.Stop()
	if !write("event: invalidate\ndata: {}\n\n") {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
			if _, err := s.principal(r); err != nil {
				return
			}
			if !write(": heartbeat\n\n") {
				return
			}
		case <-ch:
			if _, err := s.principal(r); err != nil {
				return
			}
			if !write("event: invalidate\ndata: {}\n\n") {
				return
			}
		}
	}
}
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	platform := r.URL.Query().Get("scope") == "platform"
	if platform && !isAdmin(r) {
		apiErr(w, 403, "forbidden", "administrator role required for platform statistics")
		return
	}
	filter := "tenant_id=?"
	args := []any{tenant(r)}
	if platform {
		filter = "1=1"
		args = nil
	}
	var devices, online, rules, ready, edges int
	queries := []struct {
		sql  string
		dest *int
		args []any
	}{
		{"SELECT COUNT(*) FROM devices WHERE " + filter + " AND revoked=0", &devices, args},
		{"SELECT COUNT(*) FROM devices WHERE " + filter + " AND revoked=0 AND lease_until>UTC_TIMESTAMP(6) AND last_seen>=?", &online, append(append([]any{}, args...), s.started)},
		{"SELECT COUNT(*) FROM rules WHERE " + filter + " AND deleting=0", &rules, args},
		{"SELECT COUNT(*) FROM rules WHERE " + filter + " AND deleting=0 AND enabled=1 AND status='ready'", &ready, args},
		{"SELECT COUNT(*) FROM edges", &edges, nil},
	}
	for _, q := range queries {
		if e := s.store(r.Context()).QueryRowContext(r.Context(), q.sql, q.args...).Scan(q.dest); e != nil {
			apiErr(w, 503, "database_unavailable", "could not read overview")
			return
		}
	}
	if !platform {
		q, err := readQuota(r.Context(), s.store(r.Context()), tenant(r), false)
		if err != nil {
			apiErr(w, 503, "database_unavailable", err.Error())
			return
		}
		if q.AllowedEdgeIDs != nil {
			items, e := s.loadEdges(r.Context(), "")
			if e != nil {
				apiErr(w, 503, "database_unavailable", e.Error())
				return
			}
			edges = 0
			for _, edge := range items {
				if edgeAllowed(q, edge.ID) {
					edges++
				}
			}
		}
	}
	var up, down int64
	if e := s.store(r.Context()).QueryRowContext(r.Context(), "SELECT COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0) FROM usage_table WHERE "+filter, args...).Scan(&up, &down); e != nil {
		apiErr(w, 503, "database_unavailable", "could not read usage totals")
		return
	}
	scope := "tenant"
	if platform {
		scope = "platform"
	}
	writeJSON(w, 200, map[string]any{"scope": scope, "devices": devices, "online_devices": online, "rules": rules, "ready_rules": ready, "edges": edges, "usage_upload_bytes": up, "usage_download_bytes": down, "observed_at": now(), "started_at": s.started})
}
func decodeJSON(s string, v any) {
	if s != "" {
		_ = json.Unmarshal([]byte(s), v)
	}
}
func encodeJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func isAdmin(r *http.Request) bool {
	p, _ := r.Context().Value(pkey{}).(*principal)
	return p != nil && p.User.Role == "admin"
}
func tenant(r *http.Request) string {
	p, _ := r.Context().Value(pkey{}).(*principal)
	if p == nil {
		return ""
	}
	return p.User.TenantID
}

var _ = fmt.Sprintf

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
