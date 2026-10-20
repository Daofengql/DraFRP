// Package cloud implements the DraFRP single-instance control plane.
package cloud

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"drafrp/internal/cache"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Listen        string        `json:"listen"`
	MySQLDSN      string        `json:"mysql_dsn"`
	Redis         cache.Config  `json:"redis"`
	AdminUsername string        `json:"admin_username"`
	AdminPassword string        `json:"admin_password"`
	StorageKey    string        `json:"storage_key"`
	BuildID       string        `json:"build_id"`
	SessionTTL    time.Duration `json:"session_ttl"`
	BindTTL       time.Duration `json:"bind_ttl"`
	SnapshotTTL   time.Duration `json:"snapshot_ttl"`
}

func (c *Config) defaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = 24 * time.Hour
	}
	if c.BindTTL <= 0 {
		c.BindTTL = 10 * time.Minute
	}
	if c.SnapshotTTL <= 0 {
		c.SnapshotTTL = 3 * time.Minute
	}
	if c.BuildID == "" {
		c.BuildID = "dev"
	}
	if c.MySQLDSN == "" {
		c.MySQLDSN = os.Getenv("DRAFRP_MYSQL_DSN")
	}
	if c.AdminUsername == "" {
		c.AdminUsername = os.Getenv("DRAFRP_ADMIN_USERNAME")
	}
	if c.AdminPassword == "" {
		c.AdminPassword = os.Getenv("DRAFRP_ADMIN_PASSWORD")
	}
	if c.StorageKey == "" {
		c.StorageKey = os.Getenv("DRAFRP_STORAGE_KEY")
	}
}

type Server struct {
	cfg     Config
	db      *sql.DB
	tmp     *cache.Store
	started time.Time
	key     []byte
	mu      sync.Mutex
	events  map[chan struct{}]struct{}
}

func New(ctx context.Context, c Config) (*Server, error) {
	c.defaults()
	if c.MySQLDSN == "" {
		return nil, errors.New("mysql_dsn is required")
	}
	db, e := sql.Open("mysql", c.MySQLDSN)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(10 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if e = db.PingContext(pingCtx); e != nil {
		db.Close()
		return nil, fmt.Errorf("mysql: %w", e)
	}
	if e = migrate(ctx, db); e != nil {
		db.Close()
		return nil, e
	}
	key, e := decodeKey(c.StorageKey)
	if e != nil {
		return nil, e
	}
	s := &Server{cfg: c, db: db, tmp: cache.New(ctx, c.Redis), started: time.Now().UTC(), key: key, events: map[chan struct{}]struct{}{}}
	if c.AdminUsername != "" && c.AdminPassword != "" {
		if e = s.bootstrap(ctx); e != nil {
			return nil, e
		}
	}
	return s, nil
}
func decodeKey(v string) ([]byte, error) {
	if v == "" {
		return nil, errors.New("storage_key is required (base64 AES key)")
	}
	b, e := base64.StdEncoding.DecodeString(v)
	if e != nil {
		return nil, fmt.Errorf("storage_key: %w", e)
	}
	if len(b) != 16 && len(b) != 24 && len(b) != 32 {
		return nil, errors.New("storage_key must decode to 16, 24, or 32 bytes")
	}
	return b, nil
}
func (s *Server) Close() {
	if s.tmp != nil {
		s.tmp.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}
func (s *Server) DB() *sql.DB           { return s.db }
func (s *Server) Handler() http.Handler { return s.routes() }
func (s *Server) notify() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.events {
		select {
		case c <- struct{}{}:
		default:
		}
	}
}
func id() string                { return protocol.ID() }
func now() time.Time            { return time.Now().UTC() }
func hashToken(v string) string { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func apiErr(w http.ResponseWriter, status, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
func (s *Server) bootstrap(ctx context.Context) error {
	var n int
	if e := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return nil
	}
	pw, e := bcrypt.GenerateFromPassword([]byte(s.cfg.AdminPassword), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	uid, tid := id(), id()
	_, e = s.db.ExecContext(ctx, "INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)", tid, s.cfg.AdminUsername, now())
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, "INSERT INTO users(id,tenant_id,username,password_hash,role,disabled,created_at) VALUES(?,?,?,?,?,0,?)", uid, tid, s.cfg.AdminUsername, string(pw), "admin", now())
	if e == nil {
		_ = s.audit(ctx, uid, tid, "bootstrap", "user", uid)
	}
	return e
}
func (s *Server) audit(ctx context.Context, actor, tenant, action, resource string, rid any) {
	_, _ = s.db.ExecContext(ctx, "INSERT INTO audit(id,actor_id,tenant_id,action,resource_id,created_at) VALUES(?,?,?,?,?,?)", id(), actor, tenant, action, fmt.Sprint(rid), now())
}
func encrypt(key []byte, plain string) (string, error) {
	b, _ := aes.NewCipher(key)
	g, e := cipher.NewGCM(b)
	if e != nil {
		return "", e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(g.Seal(n, n, []byte(plain), nil)), nil
}
func decrypt(key []byte, enc string) (string, error) {
	raw, e := base64.StdEncoding.DecodeString(enc)
	if e != nil {
		return "", e
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return "", e
	}
	if len(raw) < g.NonceSize() {
		return "", errors.New("invalid encrypted value")
	}
	v, e := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	return string(v), e
}
func parseBasicBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}
func requireMethod(w http.ResponseWriter, r *http.Request, m string) bool {
	if r.Method != m {
		w.Header().Set("Allow", m)
		apiErr(w, 405, "method_not_allowed", "method not allowed")
		return false
	}
	return true
}
func validRole(role string) bool { return role == "admin" || role == "user" }
func verifyPub(s string) (ed25519.PublicKey, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("public_key must be standard base64 Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}
func parseTime(v string) time.Time { t, _ := time.Parse(time.RFC3339, v); return t }

var _ = log.Printf
var _ = io.EOF
var _ = strconv.Itoa
