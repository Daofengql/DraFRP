package edge

import (
	"context"
	"drafrp/internal/limiter"
	"drafrp/internal/model"
	"testing"
	"time"
)

func TestRootSchedulerDoesNotBlockOtherAccountsBehindLargeChunk(t *testing.T) {
	r := New(Config{})
	defer r.Close()
	r.mu.Lock()
	r.root = limiter.New(model.Grant{BaseBPS: 8000, PeakBPS: 8000, BurstBytes: 0, ExpiresAt: time.Now().Add(time.Minute)})
	r.mu.Unlock()
	largeCtx, largeCancel := context.WithCancel(context.Background())
	defer largeCancel()
	largeDone := make(chan bool, 1)
	go func() { largeDone <- r.waitCapacity(largeCtx, "large-account", 16<<10) }()
	limit := time.Now().Add(time.Second)
	for {
		r.scheduler.mu.Lock()
		pending := r.scheduler.pending
		r.scheduler.mu.Unlock()
		if pending > 0 {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("large request was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	smallCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if !r.waitCapacity(smallCtx, "interactive-account", 1) {
		t.Fatal("small account was blocked behind a large account's full chunk")
	}
	largeCancel()
	select {
	case ok := <-largeDone:
		if ok {
			t.Fatal("canceled large chunk was authorized")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled scheduler waiter leaked")
	}
}
