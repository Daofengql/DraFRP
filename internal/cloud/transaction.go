package cloud

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type sqlStore interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type mutationKey struct{}
type mutation struct {
	tx      *sql.Tx
	changed bool
	err     error
	audited bool
}

func (s *Server) store(ctx context.Context) sqlStore {
	if m, ok := ctx.Value(mutationKey{}).(*mutation); ok {
		return m.tx
	}
	return s.db
}

type businessTx struct {
	*sql.Tx
	borrowed bool
}

func (t *businessTx) Commit() error {
	if t.borrowed {
		return nil
	}
	return t.Tx.Commit()
}
func (t *businessTx) Rollback() error {
	if t.borrowed {
		return nil
	}
	return t.Tx.Rollback()
}
func (s *Server) beginTx(ctx context.Context, opts *sql.TxOptions) (*businessTx, error) {
	if m, ok := ctx.Value(mutationKey{}).(*mutation); ok {
		return &businessTx{m.tx, true}, nil
	}
	if opts == nil {
		opts = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, e := s.db.BeginTx(ctx, opts)
	if e != nil {
		return nil, e
	}
	return &businessTx{tx, false}, nil
}

type responseBuffer struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *responseBuffer) Header() http.Header { return b.header }
func (b *responseBuffer) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}
func (b *responseBuffer) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = 200
	}
	return b.body.Write(p)
}
func (b *responseBuffer) send(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = v
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}

// A browser mutation, its audit/revision, and its replay response commit together.
// Claiming a key holds the unique row lock, so concurrent retries cannot execute
// the mutation twice, including when the first connection disappears at commit.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc) {
	key := r.Header.Get("Idempotency-Key")
	if len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") {
		apiErr(w, 400, "invalid_idempotency_key", "key must be at most 128 bytes")
		return
	}
	var body []byte
	var e error
	if key != "" {
		body, e = io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if e != nil {
			apiErr(w, 400, "invalid_json", "request body exceeds limit")
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	tx, e := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		apiErr(w, 503, "database_unavailable", "could not start mutation")
		return
	}
	defer tx.Rollback()
	m := &mutation{tx: tx}
	r = r.WithContext(context.WithValue(r.Context(), mutationKey{}, m))
	p := r.Context().Value(pkey{}).(*principal)
	// A session revoked after the middleware check cannot authorize a mutation.
	current, e := s.principal(r)
	if e != nil {
		if !errors.Is(e, errSession) {
			apiErr(w, 503, "database_unavailable", "could not validate session")
			return
		}
		apiErr(w, 401, "unauthorized", "login required")
		return
	}
	p = current
	r = r.WithContext(context.WithValue(r.Context(), pkey{}, p))
	fingerprint := hashToken(r.Method + "\n" + r.URL.RequestURI() + "\n" + string(body))
	if key != "" {
		_, e = tx.ExecContext(r.Context(), "INSERT IGNORE INTO idempotency_keys(actor_id,request_key,fingerprint,created_at) VALUES(?,?,?,?)", p.User.ID, key, fingerprint, now())
		if e != nil {
			apiErr(w, 503, "database_unavailable", "could not claim request")
			return
		}
		var fp string
		var status int
		var raw []byte
		if e = tx.QueryRowContext(r.Context(), "SELECT fingerprint,status_code,response FROM idempotency_keys WHERE actor_id=? AND request_key=? FOR UPDATE", p.User.ID, key).Scan(&fp, &status, &raw); e != nil {
			apiErr(w, 503, "database_unavailable", "could not read request")
			return
		}
		if fp != fingerprint {
			apiErr(w, 409, "idempotency_conflict", "key was used for another request")
			return
		}
		if status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Idempotency-Replayed", "true")
			w.WriteHeader(status)
			_, _ = w.Write(raw)
			return
		}
	}
	b := &responseBuffer{header: make(http.Header)}
	fn(b, r)
	if b.status == 0 {
		b.status = 200
	}
	if b.status >= 400 {
		b.send(w)
		return
	}
	if !m.audited {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
		parts := strings.Split(path, "/")
		resource := parts[0]
		rid := ""
		if len(parts) > 1 {
			rid = parts[1]
		}
		s.audit(r.Context(), p.User.ID, p.User.TenantID, strings.ToLower(r.Method)+"."+resource, resource, rid)
	}
	if m.err != nil {
		apiErr(w, 503, "database_unavailable", "mutation audit or revision could not persist")
		return
	}
	if key != "" {
		if b.body.Len() > 2<<20 || !json.Valid(b.body.Bytes()) {
			apiErr(w, 500, "invalid_replay_response", "mutation produced an invalid response")
			return
		}
		if _, e = tx.ExecContext(r.Context(), "UPDATE idempotency_keys SET status_code=?,response=? WHERE actor_id=? AND request_key=?", b.status, b.body.Bytes(), p.User.ID, key); e != nil {
			apiErr(w, 503, "database_unavailable", "could not save request result")
			return
		}
	}
	if e = tx.Commit(); e != nil {
		apiErr(w, 503, "database_unavailable", "mutation could not commit")
		return
	}
	if m.changed {
		s.broadcast()
	}
	b.send(w)
}

var errVersion = errors.New("resource version changed")

func (s *Server) runtimeMutation(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc) {
	tx, e := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		apiErr(w, 503, "database_unavailable", "could not start runtime update")
		return
	}
	defer tx.Rollback()
	m := &mutation{tx: tx}
	r = r.WithContext(context.WithValue(r.Context(), mutationKey{}, m))
	b := &responseBuffer{header: make(http.Header)}
	fn(b, r)
	if b.status == 0 {
		b.status = 200
	}
	if b.status >= 400 {
		b.send(w)
		return
	}
	if m.err != nil {
		apiErr(w, 503, "database_unavailable", "runtime revision could not persist")
		return
	}
	if e = tx.Commit(); e != nil {
		apiErr(w, 503, "database_unavailable", "runtime update could not commit")
		return
	}
	s.broadcast()
	b.send(w)
}
