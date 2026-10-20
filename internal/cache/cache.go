// Package cache provides bounded, disposable temporary storage. It is never an
// authorization or accounting authority.
package cache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	Address    string `json:"address"`
	Password   string `json:"password"`
	DB         int    `json:"db"`
	MaxEntries int    `json:"max_entries"`
	MaxBytes   int    `json:"max_bytes"`
}
type Stats struct {
	Backend   string `json:"backend"`
	Reason    string `json:"reason,omitempty"`
	Entries   int    `json:"entries"`
	Bytes     int    `json:"bytes"`
	Hits      uint64 `json:"hits"`
	Misses    uint64 `json:"misses"`
	Evictions uint64 `json:"evictions"`
}
type entry struct {
	value  []byte
	expiry time.Time
	serial uint64
}
type Store struct {
	mu         sync.Mutex
	cfg        Config
	redis      *redis.Client
	items      map[string]entry
	stats      Stats
	generation string
	serial     uint64
	cancel     context.CancelFunc
}

func New(ctx context.Context, cfg Config) *Store {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 4096
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 16 << 20
	}
	s := &Store{cfg: cfg, items: make(map[string]entry), generation: nonce(), stats: Stats{Backend: "memory"}}
	if cfg.Address != "" {
		s.redis = redis.NewClient(&redis.Options{Addr: cfg.Address, Password: cfg.Password, DB: cfg.DB, DialTimeout: 300 * time.Millisecond, ReadTimeout: 300 * time.Millisecond, WriteTimeout: 300 * time.Millisecond, MaxRetries: -1})
		c, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
		err := s.redis.Ping(c).Err()
		cancel()
		if err == nil {
			s.stats.Backend = "redis"
		} else {
			s.stats.Reason = "redis unavailable"
		}
	}
	c, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go s.maintain(c)
	return s
}
func nonce() string { var b [12]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func (s *Store) Close() {
	s.cancel()
	if s.redis != nil {
		_ = s.redis.Close()
	}
}
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.stats
	v.Entries = len(s.items)
	return v
}

// Invalidate rotates the logical namespace so a concurrent old fill cannot be read.
func (s *Store) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation = nonce()
	s.items = make(map[string]entry)
	s.stats.Bytes = 0
}
func (s *Store) Generation() string { s.mu.Lock(); defer s.mu.Unlock(); return s.generation }
func (s *Store) fail(g string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation == g && s.stats.Backend == "redis" {
		s.stats.Backend = "memory"
		s.stats.Reason = "redis operation failed"
		s.generation = nonce()
		s.items = make(map[string]entry)
		s.stats.Bytes = 0
	}
}
func (s *Store) Get(ctx context.Context, key string) ([]byte, bool) {
	s.mu.Lock()
	g, backend := s.generation, s.stats.Backend
	if backend == "memory" {
		v, ok := s.items[key]
		if ok && time.Now().Before(v.expiry) {
			s.stats.Hits++
			s.mu.Unlock()
			return append([]byte(nil), v.value...), true
		}
		if ok {
			delete(s.items, key)
			s.stats.Bytes -= len(v.value)
		}
		s.stats.Misses++
		s.mu.Unlock()
		return nil, false
	}
	s.mu.Unlock()
	c, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()
	v, err := s.redis.Get(c, "drafrp:"+g+":"+key).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		s.fail(g)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != g {
		s.stats.Misses++
		return nil, false
	}
	if err == nil {
		s.stats.Hits++
		return v, true
	}
	s.stats.Misses++
	return nil, false
}

// Put writes only if generation still matches the one captured before loading.
func (s *Store) Put(ctx context.Context, g, key string, v []byte, ttl time.Duration) bool {
	if ttl <= 0 || ttl > time.Hour || len(v) > 1<<20 || len(v) > s.cfg.MaxBytes {
		return false
	}
	s.mu.Lock()
	if g != s.generation {
		s.mu.Unlock()
		return false
	}
	backend := s.stats.Backend
	if backend == "memory" {
		if old, ok := s.items[key]; ok {
			s.stats.Bytes -= len(old.value)
			delete(s.items, key)
		}
		s.prune(time.Now())
		for len(s.items) >= s.cfg.MaxEntries || s.stats.Bytes+len(v) > s.cfg.MaxBytes {
			var oldest string
			serial := ^uint64(0)
			for k, e := range s.items {
				if e.serial < serial {
					oldest = k
					serial = e.serial
				}
			}
			e, ok := s.items[oldest]
			if !ok {
				break
			}
			delete(s.items, oldest)
			s.stats.Bytes -= len(e.value)
			s.stats.Evictions++
		}
		s.serial++
		s.items[key] = entry{append([]byte(nil), v...), time.Now().Add(ttl), s.serial}
		s.stats.Bytes += len(v)
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()
	c, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()
	if err := s.redis.Set(c, "drafrp:"+g+":"+key, v, ttl).Err(); err != nil {
		s.fail(g)
		return false
	}
	return true
}
func (s *Store) prune(now time.Time) {
	for k, v := range s.items {
		if !now.Before(v.expiry) {
			delete(s.items, k)
			s.stats.Bytes -= len(v.value)
			s.stats.Evictions++
		}
	}
}
func (s *Store) maintain(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	healthy := 0
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			s.prune(now)
			backend := s.stats.Backend
			s.mu.Unlock()
			if s.redis == nil || backend == "redis" {
				continue
			}
			c, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
			err := s.redis.Ping(c).Err()
			cancel()
			if err != nil {
				healthy = 0
				continue
			}
			healthy++
			if healthy < 3 {
				continue
			}
			s.mu.Lock()
			s.stats.Backend = "redis"
			s.stats.Reason = ""
			s.generation = nonce()
			s.items = make(map[string]entry)
			s.stats.Bytes = 0
			s.mu.Unlock()
			healthy = 0
		}
	}
}
