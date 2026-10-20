package cloud

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, e := url.Parse(origin)
		return e == nil && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && strings.EqualFold(u.Host, r.Host)
	}
	return true
}

type loginAttempt struct {
	until time.Time
	count int
}

// This limiter is intentionally independent from disposable Redis/cache state.
// A bounded source map prevents attacker-selected addresses from growing memory.
func (s *Server) allowLogin(r *http.Request) bool {
	return s.allowRequest(r, "login", 20)
}
func (s *Server) allowRequest(r *http.Request, operation string, limit int) bool {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		host = r.RemoteAddr
	}
	host = operation + ":" + host
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loginAttempts == nil {
		s.loginAttempts = make(map[string]loginAttempt)
	}
	at := now()
	a := s.loginAttempts[host]
	if !at.Before(a.until) {
		a = loginAttempt{until: at.Add(time.Minute)}
	}
	if a.count >= limit {
		return false
	}
	if len(s.loginAttempts) >= 4096 {
		for k, v := range s.loginAttempts {
			if !at.Before(v.until) {
				delete(s.loginAttempts, k)
			}
		}
		if len(s.loginAttempts) >= 4096 {
			return false
		}
	}
	a.count++
	s.loginAttempts[host] = a
	return true
}
