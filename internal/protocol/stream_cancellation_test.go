package protocol

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// The peer never reads. yamux's actual SYN write therefore remains blocked
// until the pipe/carrier closes, producing a concrete (*yamux.Stream)(nil).
type observedWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *observedWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func blockedOpenCarrier(t *testing.T) (*Carrier, <-chan struct{}) {
	t.Helper()
	a, b := net.Pipe()
	conn := &observedWriteConn{Conn: a, started: make(chan struct{})}
	c, err := WrapTLS(conn, false, "edge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = b.Close() })
	return c, conn.started
}

func TestOpenCancellationThenCarrierCloseDoesNotBoxNilStream(t *testing.T) {
	c, writing := blockedOpenCarrier(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		st, err := c.Open(ctx)
		if st != nil {
			done <- errors.New("cancelled Open returned a stream")
			return
		}
		done <- err
	}()
	select {
	case <-writing:
	case <-time.After(time.Second):
		t.Fatal("real yamux SYN never reached the blocked pipe")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("Open ignored cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled Open did not return before transport shutdown")
	}
	// Cancellation has now started the late-result cleanup goroutine. Closing
	// the transport releases OpenStream with (nil,error), the original panic.
	_ = c.Close()
	deadline := time.Now().Add(time.Second)
	for len(c.openSlots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("cancelled Open retained its concurrency slot")
		}
		runtime.Gosched()
	}
	for range 100 {
		runtime.Gosched()
	}
}

func TestOpenCloseCancellationRaceReturnsNoBoxedNilStreams(t *testing.T) {
	for range 16 {
		c, writing := blockedOpenCarrier(t)
		ctx, cancel := context.WithCancel(context.Background())
		type result struct {
			stream Stream
			err    error
		}
		results := make(chan result, 16)
		for range 16 {
			go func() { st, err := c.Open(ctx); results <- result{st, err} }()
		}
		select {
		case <-writing:
		case <-time.After(time.Second):
			t.Fatal("yamux open did not block")
		}
		var closing sync.WaitGroup
		closing.Add(2)
		go func() { defer closing.Done(); cancel() }()
		go func() { defer closing.Done(); _ = c.Close() }()
		for range 16 {
			select {
			case r := <-results:
				if r.err != nil && r.stream != nil {
					t.Fatalf("failed Open returned a boxed nil: %T %v", r.stream, r.err)
				}
				// An open can win the cancellation/close race. Its successful
				// stream must still be a usable pointer for ordinary cleanup.
				if r.err == nil {
					if r.stream == nil {
						t.Fatal("successful Open returned no stream")
					}
					Abort(r.stream)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancel/close left Open blocked")
			}
		}
		closing.Wait()
	}
}

func TestClosedOpenAndCancelledAcceptReturnNilInterfaces(t *testing.T) {
	for _, transport := range []string{"tls", "quic"} {
		t.Run(transport, func(t *testing.T) {
			c, _ := networkProbePair(t, transport)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if st, err := c.Accept(ctx); err == nil || st != nil {
				t.Fatalf("cancelled Accept boxed a nil stream: %T %v", st, err)
			}
			_ = c.Close()
			if st, err := c.Open(context.Background()); err == nil || st != nil {
				t.Fatalf("closed Open boxed a nil stream: %T %v", st, err)
			}
			if st, err := c.Accept(context.Background()); err == nil || st != nil {
				t.Fatalf("closed Accept boxed a nil stream: %T %v", st, err)
			}
		})
	}
}

func TestCancelledOpenDiscardsLateSuccessfulStreamWithoutClosingCarrier(t *testing.T) {
	a, b := net.Pipe()
	conn := &observedWriteConn{Conn: a, started: make(chan struct{})}
	c, err := WrapTLS(conn, false, "edge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = b.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		st, err := c.Open(ctx)
		if st != nil {
			done <- errors.New("cancelled Open returned a stream")
			return
		}
		done <- err
	}()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("real SYN did not block")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Starting the real peer now releases the pending OpenStream successfully;
	// cancellation cleanup must close that stream, while retaining the carrier.
	peer, err := WrapTLS(b, true, "edge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	acceptCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	st, err := peer.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetDeadline(time.Now().Add(time.Second))
	var one [1]byte
	_, err = st.Read(one[:])
	Abort(st)
	if err == nil {
		t.Fatal("cancelled late stream retained a readable business payload")
	}
	until := time.Now().Add(time.Second)
	for len(c.openSlots) != 0 || c.mux.NumStreams() != 0 {
		if time.Now().After(until) {
			t.Fatal("late successful Open leaked a stream or permit")
		}
		runtime.Gosched()
	}
	written := make(chan error, 1)
	go func() {
		s, err := peer.Open(acceptCtx)
		if err == nil {
			err = WriteFull(s, []byte("after-cancel"))
			Finish(s)
		}
		written <- err
	}()
	st, err = c.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(st)
	Abort(st)
	if err != nil || string(payload) != "after-cancel" || <-written != nil {
		t.Fatal("cancelled Open damaged unrelated business", string(payload), err)
	}
}
