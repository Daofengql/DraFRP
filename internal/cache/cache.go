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
	"golang.org/x/sync/singleflight"
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
	loads      singleflight.Group
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

// GetOrLoad coalesces rebuilds within the current disposable cache generation.
// Callers must use it only for reconstructible views, never authorization or
// accounting. A failed cache write still returns the authoritative load.
func (s *Store) GetOrLoad(ctx context.Context, key string, ttl time.Duration, load func(context.Context) ([]byte, error)) ([]byte, error) {
	if v, ok := s.Get(ctx, key); ok {
		return v, nil
	}
	g := s.Generation()
	result := s.loads.DoChan(g+"/"+key, func() (any, error) {
		if v, ok := s.Get(ctx, key); ok {
			return v, nil
		}
		v, e := load(ctx)
		if e != nil {
			return nil, e
		}
		_ = s.Put(ctx, g, key, v, ttl)
		return v, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-result:
		if r.Err != nil {
			return nil, r.Err
		}
		return append([]byte(nil), r.Val.([]byte)...), nil
	}
}
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
	if len(key) > 512 || ctx.Err() != nil {
		return nil, false
	}
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
	// Check stored length atomically before returning data. Redis is optional
	// external storage; an oversized value must not become an unbounded reply.
	v, err := s.redis.Eval(c, `local n=redis.call('STRLEN',KEYS[1]); if n>tonumber(ARGV[1]) then return redis.error_reply('cache value exceeds bound') end; return redis.call('GET',KEYS[1])`, []string{"drafrp:" + g + ":" + key}, min(1<<20, s.cfg.MaxBytes)).Text()
	if err != nil && !errors.Is(err, redis.Nil) && ctx.Err() == nil {
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
		return []byte(v), true
	}
	s.stats.Misses++
	return nil, false
}

// Put writes only if generation still matches the one captured before loading.
func (s *Store) Put(ctx context.Context, g, key string, v []byte, ttl time.Duration) bool {
	if ttl <= 0 || ttl > time.Hour || len(v) > 1<<20 || len(v) > s.cfg.MaxBytes || len(key) > 512 || ctx.Err() != nil {
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
		if ctx.Err() == nil {
			s.fail(g)
		}
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation == g && s.stats.Backend == "redis"
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
