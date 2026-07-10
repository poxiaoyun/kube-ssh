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

type StreamObserver interface {
	StreamOpened(kind string)
	StreamClosed(kind string)
	StreamBytes(kind, direction string, n int64)
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
	return ProxyWithObserver(ctx, a, b, nil, "", "", "")
}

func ProxyWithObserver(ctx context.Context, a, b HalfCloser, observer StreamObserver, kind, aToBDirection, bToADirection string) error {
	if observer != nil {
		observer.StreamOpened(kind)
		defer observer.StreamClosed(kind)
	}
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
		_, err := copyObserved(a, b, observer, kind, bToADirection)
		_ = a.CloseWrite()
		errCh <- normalizeErr(err)
	}()

	// a -> b: symmetric half-close for the other direction.
	go func() {
		_, err := copyObserved(b, a, observer, kind, aToBDirection)
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

func copyObserved(dst io.Writer, src io.Reader, observer StreamObserver, kind, direction string) (int64, error) {
	if observer == nil {
		return io.Copy(dst, src)
	}
	return io.Copy(dst, observedReader{
		reader:    src,
		observer:  observer,
		kind:      kind,
		direction: direction,
	})
}

type observedReader struct {
	reader    io.Reader
	observer  StreamObserver
	kind      string
	direction string
}

func (r observedReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.observer.StreamBytes(r.kind, r.direction, int64(n))
	}
	return n, err
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
