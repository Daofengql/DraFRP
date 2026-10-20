package cloud

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type eventWriter struct {
	header             http.Header
	status             int
	observed           chan int
	once               sync.Once
	deadline           time.Time
	writesWithDeadline int
	fail               bool
}

func (w *eventWriter) Header() http.Header  { return w.header }
func (w *eventWriter) WriteHeader(code int) { w.status = code }
func (w *eventWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if !w.deadline.IsZero() && time.Now().Before(w.deadline) && w.deadline.Before(time.Now().Add(6*time.Second)) {
		w.writesWithDeadline++
	}
	w.once.Do(func() {
		if w.observed != nil {
			w.observed <- w.status
		}
	})
	if w.fail {
		return 0, io.ErrClosedPipe
	}
	return len(b), nil
}
func (*eventWriter) Flush()                                {}
func (w *eventWriter) SetWriteDeadline(at time.Time) error { w.deadline = at; return nil }

func TestEventCapacityReservationIsAtomic(t *testing.T) {
	s := &Server{subscribers: map[chan struct{}]struct{}{}}
	for i := 0; i < 1023; i++ {
		s.subscribers[make(chan struct{}, 1)] = struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := make(chan int, 32)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.events(&eventWriter{header: make(http.Header), observed: observed}, httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx))
		}()
	}
	close(start)
	accepted := 0
	for i := 0; i < 32; i++ {
		select {
		case code := <-observed:
			if code == 200 {
				accepted++
			} else if code != 503 {
				t.Fatalf("unexpected event status %d", code)
			}
		case <-time.After(time.Second):
			t.Fatal("event capacity check stalled")
		}
	}
	s.mu.Lock()
	active := len(s.subscribers)
	s.mu.Unlock()
	if accepted != 1 || active != 1024 {
		t.Fatalf("capacity exceeded: accepted=%d active=%d", accepted, active)
	}
	cancel()
	wg.Wait()
	s.mu.Lock()
	active = len(s.subscribers)
	s.mu.Unlock()
	if active != 1023 {
		t.Fatal("subscription slot leaked")
	}
}

func TestEventWriteHasDeadlineAndReleasesOnFailure(t *testing.T) {
	s := &Server{subscribers: map[chan struct{}]struct{}{}}
	w := &eventWriter{header: make(http.Header), fail: true}
	s.events(w, httptest.NewRequest("GET", "/api/v1/events", nil))
	if w.writesWithDeadline != 1 || !w.deadline.IsZero() {
		t.Fatal("event write deadline was missing or left active across idle")
	}
	if len(s.subscribers) != 0 {
		t.Fatal("failed event write retained capacity")
	}
}
