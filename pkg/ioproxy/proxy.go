package ioproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

// HalfCloser is a bidirectional stream that supports half-close:
// signalling end-of-write to the remote side while leaving the read
// side open so the peer's remaining data can still drain.
//
// Both golang.org/x/crypto/ssh.Channel and the Kubernetes backend Conn
// satisfy this interface.
type HalfCloser interface {
	io.ReadWriteCloser
	// CloseWrite signals the remote that no more data will be written.
	CloseWrite() error
}

// Proxy bidirectionally copies between a and b until both sides finish
// or ctx is cancelled.
//
//   - When one side finishes reading, the opposite side's write end is
//     half-closed so the peer can drain remaining data.
//   - Context cancellation is treated as an expected lifecycle event:
//     both connections are closed and nil is returned.
//   - Errors caused by the close itself (net.ErrClosed, io.ErrClosedPipe,
//     io.EOF) are suppressed so callers only see real failures.
func Proxy(ctx context.Context, a, b HalfCloser) error {
	errCh := make(chan error, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	defer closeOnce.Do(closeBoth)

	// b -> a: when b has no more bytes, tell a no more bytes will be
	// written to it while still allowing a's remaining output to drain.
	go func() {
		_, err := io.Copy(a, b)
		_ = a.CloseWrite()
		errCh <- normalizeErr(err)
	}()

	// a -> b: symmetric half-close for the other direction.
	go func() {
		_, err := io.Copy(b, a)
		_ = b.CloseWrite()
		errCh <- normalizeErr(err)
	}()

	var result error
	for range 2 {
		select {
		case err := <-errCh:
			if err != nil && result == nil {
				result = err
			}
		case <-ctx.Done():
			closeOnce.Do(closeBoth)
			return nil
		}
	}
	return result
}

// normalizeErr converts expected connection-close errors into nil.
func normalizeErr(err error) error {
	if err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}
