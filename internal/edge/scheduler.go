package edge

import (
	"context"
	"sync"
	"time"
)

// The shared root scheduler gives each active account one bounded chunk per
// round. Opening more devices or flows does not increase account weight.
type capacityRequest struct {
	ctx  context.Context
	n    int
	done chan bool
}
type capacityScheduler struct {
	mu       sync.Mutex
	queues   map[string][]capacityRequest
	accounts []string
	pending  int
	wake     chan struct{}
}

func newCapacityScheduler() *capacityScheduler {
	return &capacityScheduler{queues: map[string][]capacityRequest{}, wake: make(chan struct{}, 1)}
}
func (r *Runtime) waitCapacity(ctx context.Context, tenant string, n int) bool {
	for n > 0 {
		size := min(n, 16<<10)
		job := capacityRequest{ctx: ctx, n: size, done: make(chan bool, 1)}
		s := r.scheduler
		s.mu.Lock()
		if s.pending >= 4096 {
			s.mu.Unlock()
			return false
		}
		if len(s.queues[tenant]) == 0 {
			s.accounts = append(s.accounts, tenant)
		}
		s.queues[tenant] = append(s.queues[tenant], job)
		s.pending++
		s.mu.Unlock()
		select {
		case s.wake <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return false
		case <-r.ctx.Done():
			return false
		case ok := <-job.done:
			if !ok {
				return false
			}
		}
		n -= size
	}
	return true
}
func (r *Runtime) schedule() {
	defer r.wg.Done()
	s := r.scheduler
	for {
		s.mu.Lock()
		if len(s.accounts) == 0 {
			s.mu.Unlock()
			select {
			case <-r.ctx.Done():
				return
			case <-s.wake:
				continue
			}
		}
		tenant := s.accounts[0]
		s.accounts = s.accounts[1:]
		job := s.queues[tenant][0]
		s.mu.Unlock()
		finished, allowed := false, false
		var delay time.Duration
		select {
		case <-r.ctx.Done():
			return
		case <-job.ctx.Done():
			finished = true
		default:
			r.mu.RLock()
			root := r.root
			r.mu.RUnlock()
			if root == nil {
				finished = true
			} else {
				taken, wait, ok := root.TakeAvailable(job.n)
				delay = wait
				if !ok {
					finished = true
				} else {
					job.n -= taken
					finished = job.n == 0
					allowed = finished
				}
			}
		}
		s.mu.Lock()
		q := s.queues[tenant]
		if finished {
			q = q[1:]
			s.pending--
		} else {
			q[0] = job
		}
		if len(q) > 0 {
			s.queues[tenant] = q
			s.accounts = append(s.accounts, tenant)
		} else {
			delete(s.queues, tenant)
		}
		s.mu.Unlock()
		if finished {
			job.done <- allowed
		}
		// A pacing delay belongs to this account's next quantum. If another
		// account is already queued, rotate immediately so a large request can
		// never make an interactive request wait behind its token refill.
		if delay > 0 {
			s.mu.Lock()
			otherAccountsPending := len(s.accounts) > 0
			s.mu.Unlock()
			if otherAccountsPending {
				continue
			}
			timer := time.NewTimer(min(delay, 100*time.Millisecond))
			select {
			case <-r.ctx.Done():
				timer.Stop()
				return
			case <-s.wake:
				timer.Stop()
			case <-timer.C:
			}
		}
	}
}
