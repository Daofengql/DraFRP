package cache

import (
	"context"
	"github.com/redis/go-redis/v9"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryCapacityInvalidationAndCopies(t *testing.T) {
	ctx := context.Background()
	s := New(ctx, Config{MaxEntries: 2, MaxBytes: 6})
	defer s.Close()
	g := s.Generation()
	input := []byte("abc")
	if !s.Put(ctx, g, "a", input, time.Minute) {
		t.Fatal("put failed")
	}
	input[0] = 'x'
	v, ok := s.Get(ctx, "a")
	if !ok || string(v) != "abc" {
		t.Fatal("input was not copied")
	}
	v[0] = 'z'
	v, _ = s.Get(ctx, "a")
	if string(v) != "abc" {
		t.Fatal("output was not copied")
	}
	s.Put(ctx, g, "b", []byte("def"), time.Minute)
	s.Put(ctx, g, "c", []byte("ghi"), time.Minute)
	if _, ok := s.Get(ctx, "a"); ok {
		t.Fatal("old entry not evicted")
	}
	stats := s.Stats()
	if stats.Entries != 2 || stats.Bytes != 6 || stats.Evictions != 1 {
		t.Fatalf("%+v", stats)
	}
	s.Invalidate()
	if s.Put(ctx, g, "stale", []byte("bad"), time.Minute) {
		t.Fatal("old concurrent fill accepted")
	}
	if _, ok := s.Get(ctx, "c"); ok {
		t.Fatal("stale cache survived invalidation")
	}
	if s.Put(ctx, s.Generation(), "large", make([]byte, 7), time.Minute) {
		t.Fatal("capacity exceeded")
	}
	s.Put(ctx, s.Generation(), "ttl", []byte("ok"), time.Millisecond)
	time.Sleep(3 * time.Millisecond)
	if _, ok := s.Get(ctx, "ttl"); ok {
		t.Fatal("expired cache entry read")
	}
}

func TestCoalescedLoadAndGenerationFence(t *testing.T) {
	ctx := context.Background()
	s := New(ctx, Config{})
	defer s.Close()
	var calls atomic.Int32
	start := make(chan struct{})
	release := make(chan struct{})
	load := func(context.Context) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(start)
		}
		<-release
		return []byte("before-invalidation"), nil
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.GetOrLoad(ctx, "view", time.Minute, load)
			if e != nil {
				t.Error(e)
			}
		}()
	}
	<-start
	time.Sleep(20 * time.Millisecond)
	s.Invalidate()
	close(release)
	wg.Wait()
	// A concurrent pre-invalidation fill may finish for its reader, but must
	// not be visible to a new reader after the mutation's generation fence.
	if _, ok := s.Get(ctx, "view"); ok {
		t.Fatal("stale coalesced fill entered current cache")
	}
	if calls.Load() != 1 {
		t.Fatalf("duplicate cache rebuilds: %d", calls.Load())
	}
	v, e := s.GetOrLoad(ctx, "view", time.Minute, func(context.Context) ([]byte, error) { return []byte("current"), nil })
	if e != nil || string(v) != "current" {
		t.Fatal(string(v), e)
	}
	v, e = s.GetOrLoad(ctx, "view", time.Minute, func(context.Context) ([]byte, error) { t.Error("cache hit rebuilt source"); return nil, nil })
	if e != nil || string(v) != "current" {
		t.Fatal(string(v), e)
	}
}

type afterSetHook struct {
	entered, release chan struct{}
	once             sync.Once
}

func (h *afterSetHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}
func (h *afterSetHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *afterSetHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		e := next(ctx, cmd)
		if cmd.Name() == "set" && e == nil {
			h.once.Do(func() { close(h.entered); <-h.release })
		}
		return e
	}
}

func TestRedisGenerationRaceAndBoundedRead(t *testing.T) {
	addr := os.Getenv("DRAFRP_TEST_REDIS_ADDRESS")
	if addr == "" {
		t.Skip("set DRAFRP_TEST_REDIS_ADDRESS for real Redis integration")
	}
	ctx := context.Background()
	s := New(ctx, Config{Address: addr, MaxBytes: 8})
	defer s.Close()
	if s.Stats().Backend != "redis" {
		t.Fatal("test Redis is not reachable")
	}
	g := s.Generation()
	hook := &afterSetHook{entered: make(chan struct{}), release: make(chan struct{})}
	s.redis.AddHook(hook)
	done := make(chan bool, 1)
	go func() { done <- s.Put(ctx, g, "race", []byte("old"), time.Minute) }()
	select {
	case <-hook.entered:
	case <-time.After(time.Second):
		t.Fatal("SET hook was not reached")
	}
	s.Invalidate()
	next := s.Generation()
	close(hook.release)
	if <-done {
		t.Fatal("old fill reported success after invalidation")
	}
	if _, ok := s.Get(ctx, "race"); ok {
		t.Fatal("old namespace was read")
	}
	key := "drafrp:" + next + ":large"
	defer s.redis.Del(ctx, "drafrp:"+g+":race", key)
	if e := s.redis.Set(ctx, key, "oversized-value", time.Minute).Err(); e != nil {
		t.Fatal(e)
	}
	if _, ok := s.Get(ctx, "large"); ok {
		t.Fatal("oversized Redis value was accepted")
	}
	if s.Stats().Backend != "memory" {
		t.Fatal("bad Redis value did not degrade to bounded memory")
	}
}
