package protocol

import (
	"context"
	"io"
)

// Relay preserves half-close and waits for both copy loops. Cancellation and
// an I/O failure unblock both directions before resources are released.
func Relay(ctx context.Context, a, b io.ReadWriteCloser) error {
	closeBoth := func() { closeIO(a); closeIO(b) }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	errs := make(chan error, 2)
	copyOne := func(dst, src io.ReadWriteCloser) {
		_, e := io.CopyBuffer(dst, src, make([]byte, 32<<10))
		if e == nil {
			HalfClose(dst)
		} else {
			closeBoth()
		}
		errs <- e
	}
	go copyOne(a, b)
	go copyOne(b, a)
	e1, e2 := <-errs, <-errs
	if e1 != nil {
		return e1
	}
	return e2
}
func closeIO(c io.ReadWriteCloser) {
	if s, ok := c.(Stream); ok {
		Abort(s)
	} else {
		_ = c.Close()
	}
}
