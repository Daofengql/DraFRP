package cloud

import (
	"context"
	"crypto/ed25519"
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net"
	"net/http"
	"strings"
	"time"
)

type principal struct {
	User            model.User
	SessionID, CSRF string
}
type pkey struct{}

func (s *Server) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/auth/login", s.login)
	m.HandleFunc("/auth/logout", s.logout)
	m.HandleFunc("/api/v1/me", s.auth(s.me))
	m.HandleFunc("/api/v1/overview", s.auth(s.overview))
	m.HandleFunc("/api/v1/devices", s.auth(s.devices))
	m.HandleFunc("/api/v1/devices/", s.auth(s.device))
	m.HandleFunc("/api/v1/bind/confirm", s.auth(s.bindConfirm))
	m.HandleFunc("/api/v1/rules", s.auth(s.rules))
	m.HandleFunc("/api/v1/rules/", s.auth(s.rule))
	m.HandleFunc("/api/v1/edges", s.authAdmin(s.edges))
	m.HandleFunc("/api/v1/edges/", s.authAdmin(s.edge))
	m.HandleFunc("/api/v1/acl-templates", s.auth(s.templates))
	m.HandleFunc("/api/v1/acl-templates/", s.auth(s.template))
	m.HandleFunc("/api/v1/certificates", s.auth(s.certificates))
	m.HandleFunc("/api/v1/certificates/", s.auth(s.certificate))
	m.HandleFunc("/api/v1/quotas", s.auth(s.quotas))
	m.HandleFunc("/api/v1/quotas/", s.authAdmin(s.quota))
	m.HandleFunc("/api/v1/usage", s.auth(s.usage))
	m.HandleFunc("/api/v1/audit", s.authAdmin(s.auditAPI))
	m.HandleFunc("/api/v1/system", s.auth(s.system))
	m.HandleFunc("/api/v1/users", s.authAdmin(s.users))
	m.HandleFunc("/api/v1/events", s.auth(s.events))
	m.HandleFunc("/api/v1/runtime/edge/sync", s.edgeSync)
	m.HandleFunc("/api/v1/runtime/client/bind", s.clientBind)
	m.HandleFunc("/api/v1/runtime/client/bind/poll", s.clientBindPoll)
	m.HandleFunc("/api/v1/runtime/client/sync", s.clientSync)
	return csrfMiddleware(m)
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
			apiErr(w, 401, "unauthorized", "login required")
			return
		}
		fn(w, r.WithContext(context.WithValue(r.Context(), pkey{}, p)))
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
		return nil, errors.New("no session")
	}
	var p principal
	var u model.User
	var disabled bool
	var exp time.Time
	var csrf string
	e = s.db.QueryRowContext(r.Context(), "SELECT u.id,u.username,u.role,u.tenant_id,u.disabled,s.id,s.csrf_hash,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked=0", hashToken(c.Value)).Scan(&u.ID, &u.Username, &u.Role, &u.TenantID, &disabled, &p.SessionID, &csrf, &exp)
	if e != nil || disabled || time.Now().After(exp) {
		return nil, errors.New("expired")
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
	var in struct{ Username, Password string }
	if e := readJSON(w, r, &in); e != nil {
		apiErr(w, 400, "invalid_json", e.Error())
		return
	}
	var u model.User
	var hash string
	var disabled bool
	e := s.db.QueryRowContext(r.Context(), "SELECT id,tenant_id,username,password_hash,role,disabled FROM users WHERE username=?", in.Username).Scan(&u.ID, &u.TenantID, &u.Username, &hash, &u.Role, &disabled)
	if e != nil || disabled || bcryptCompare(hash, in.Password) != nil {
		apiErr(w, 401, "invalid_credentials", "invalid username or password")
		return
	}
	tok, csrf := randomToken(32), randomToken(32)
	sid := id()
	_, e = s.db.ExecContext(r.Context(), "INSERT INTO sessions(id,user_id,token_hash,csrf_hash,expires_at,created_at) VALUES(?,?,?,?,?,?)", sid, u.ID, hashToken(tok), hashToken(csrf), now().Add(s.cfg.SessionTTL), now())
	if e != nil {
		apiErr(w, 500, "database", "could not create session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "drafrp_session", Value: tok, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, Expires: now().Add(s.cfg.SessionTTL)})
	writeJSON(w, 200, map[string]any{"user": u, "csrf_token": csrf})
}
func bcryptCompare(h, p string) error { return bcrypt.CompareHashAndPassword([]byte(h), []byte(p)) }
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	if c, e := r.Cookie("drafrp_session"); e == nil {
		_, _ = s.db.ExecContext(r.Context(), "UPDATE sessions SET revoked=1 WHERE token_hash=?", hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "drafrp_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(pkey{}).(*principal)
	writeJSON(w, 200, map[string]any{"user": p.User, "csrf_token": randomToken(16), "build_id": s.cfg.BuildID})
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.events[ch] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.events, ch); s.mu.Unlock(); close(ch) }()
	f.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			_, _ = w.Write([]byte("event: invalidate\ndata: {}\n\n"))
			f.Flush()
		}
	}
}
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(pkey{}).(*principal)
	var devices, online, rules, ready, edges int
	_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM devices WHERE tenant_id=? AND revoked=0", p.User.TenantID).Scan(&devices)
	_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM devices WHERE tenant_id=? AND revoked=0 AND last_seen>UTC_TIMESTAMP()-INTERVAL 2 MINUTE", p.User.TenantID).Scan(&online)
	_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM rules WHERE tenant_id=? AND deleting=0", p.User.TenantID).Scan(&rules)
	_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM rules WHERE tenant_id=? AND deleting=0 AND enabled=1 AND status='ready'", p.User.TenantID).Scan(&ready)
	_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM edges").Scan(&edges)
	var up, down int64
	_ = s.db.QueryRowContext(r.Context(), "SELECT COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0) FROM usage_table WHERE tenant_id=?", p.User.TenantID).Scan(&up, &down)
	writeJSON(w, 200, map[string]any{"devices": devices, "online_devices": online, "rules": rules, "ready_rules": ready, "edges": edges, "usage_upload_bytes": up, "usage_download_bytes": down})
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
func validTarget(proto, target string) bool {
	if proto == "tcp" || proto == "udp" {
		h, p, e := net.SplitHostPort(target)
		if e != nil || h == "" {
			return false
		}
		_ = p
		return true
	}
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}
func validateRule(r model.Rule) error {
	if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "http" && r.Protocol != "https" {
		return errors.New("protocol must be tcp, udp, http, or https")
	}
	if !validTarget(r.Protocol, r.Target) {
		return errors.New("invalid target")
	}
	if r.SourceMode != "socket" && r.SourceMode != "native" && r.SourceMode != "forwarded_headers" {
		return errors.New("invalid source_mode")
	}
	if r.SourceMode == "native" {
		return errors.New("native source mode capability is not available")
	}
	if r.Transport != "auto" && r.Transport != "quic_only" && r.Transport != "tls_only" {
		return errors.New("invalid transport")
	}
	if r.PublicPort < 1 || r.PublicPort > 65535 {
		return errors.New("invalid public_port")
	}
	return nil
}

var _ = fmt.Sprintf
var _ = ed25519.PublicKeySize
var _ = base64.StdEncoding
