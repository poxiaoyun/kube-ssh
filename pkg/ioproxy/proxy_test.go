package ioproxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestProxyCopiesBothDirectionsAndHalfCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := newTestHalfCloser()
	b := newTestHalfCloser()

	done := make(chan error, 1)
	go func() {
		done <- Proxy(ctx, a, b)
	}()

	aOutput := readAllAsync(a.output)
	bOutput := readAllAsync(b.output)

	writeAndCloseInput(t, a, "from-a")
	writeAndCloseInput(t, b, "from-b")

	if err := waitErr(t, done); err != nil {
		t.Fatalf("Proxy() error = %v", err)
	}
	if got := waitBytes(t, bOutput); string(got) != "from-a" {
		t.Fatalf("b output = %q, want %q", string(got), "from-a")
	}
	if got := waitBytes(t, aOutput); string(got) != "from-b" {
		t.Fatalf("a output = %q, want %q", string(got), "from-b")
	}
	waitClosed(t, a.closeWriteCh, "a CloseWrite")
	waitClosed(t, b.closeWriteCh, "b CloseWrite")
}

func TestProxyWithObserverRecordsLifecycleAndBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := newTestHalfCloser()
	b := newTestHalfCloser()
	observer := &testStreamObserver{bytes: map[string]int64{}}

	done := make(chan error, 1)
	go func() {
		done <- ProxyWithObserver(ctx, a, b, observer, "forward", "a_to_b", "b_to_a")
	}()

	aOutput := readAllAsync(a.output)
	bOutput := readAllAsync(b.output)
	writeAndCloseInput(t, a, "from-a")
	writeAndCloseInput(t, b, "from-b")

	if err := waitErr(t, done); err != nil {
		t.Fatalf("ProxyWithObserver() error = %v", err)
	}
	_ = waitBytes(t, aOutput)
	_ = waitBytes(t, bOutput)
	if observer.opened != 1 || observer.closed != 1 {
		t.Fatalf("opened/closed = %d/%d, want 1/1", observer.opened, observer.closed)
	}
	if got := observer.bytes["a_to_b"]; got != int64(len("from-a")) {
		t.Fatalf("a_to_b bytes = %d, want %d", got, len("from-a"))
	}
	if got := observer.bytes["b_to_a"]; got != int64(len("from-b")) {
		t.Fatalf("b_to_a bytes = %d, want %d", got, len("from-b"))
	}
}

func TestProxyContextCancelClosesBothSides(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a := newTestHalfCloser()
	b := newTestHalfCloser()

	done := make(chan error, 1)
	go func() {
		done <- Proxy(ctx, a, b)
	}()

	cancel()
	if err := waitErr(t, done); err != nil {
		t.Fatalf("Proxy() error = %v", err)
	}
	waitClosed(t, a.closeCh, "a Close")
	waitClosed(t, b.closeCh, "b Close")
}

type testStreamObserver struct {
	mu     sync.Mutex
	opened int
	closed int
	bytes  map[string]int64
}

func (o *testStreamObserver) StreamOpened(string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.opened++
}

func (o *testStreamObserver) StreamClosed(string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed++
}

func (o *testStreamObserver) StreamBytes(_, direction string, n int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.bytes[direction] += n
}

func TestProxyReturnsCopyError(t *testing.T) {
	wantErr := errors.New("write failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := newReadOnlyHalfCloser("payload")
	b := errWriteHalfCloser{err: wantErr}

	err := Proxy(ctx, a, b)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Proxy() error = %v, want %v", err, wantErr)
	}
}

type testHalfCloser struct {
	input        *io.PipeWriter
	read         *io.PipeReader
	output       *io.PipeReader
	write        *io.PipeWriter
	closeWriteCh chan struct{}
	closeCh      chan struct{}
	closeOnce    sync.Once
}

func newTestHalfCloser() *testHalfCloser {
	read, input := io.Pipe()
	output, write := io.Pipe()
	return &testHalfCloser{
		input:        input,
		read:         read,
		output:       output,
		write:        write,
		closeWriteCh: make(chan struct{}),
		closeCh:      make(chan struct{}),
	}
}

func (c *testHalfCloser) Read(p []byte) (int, error) {
	return c.read.Read(p)
}

func (c *testHalfCloser) Write(p []byte) (int, error) {
	return c.write.Write(p)
}

func (c *testHalfCloser) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		_ = c.input.Close()
		_ = c.read.Close()
		_ = c.write.Close()
	})
	return nil
}

func (c *testHalfCloser) CloseWrite() error {
	select {
	case <-c.closeWriteCh:
	default:
		close(c.closeWriteCh)
	}
	return nil
}

type readResult struct {
	data []byte
	err  error
}

func readAllAsync(r io.Reader) <-chan readResult {
	ch := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(r)
		ch <- readResult{data: data, err: err}
	}()
	return ch
}

func writeAndCloseInput(t *testing.T, c *testHalfCloser, data string) {
	t.Helper()
	go func() {
		_, _ = c.input.Write([]byte(data))
		_ = c.input.Close()
	}()
}

func waitBytes(t *testing.T, ch <-chan readResult) []byte {
	t.Helper()
	select {
	case result := <-ch:
		if result.err != nil {
			t.Fatalf("ReadAll() error = %v", result.err)
		}
		return result.data
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bytes")
		return nil
	}
}

func waitErr(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for error")
		return nil
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

type readOnlyHalfCloser struct {
	*io.PipeReader
}

func newReadOnlyHalfCloser(data string) *readOnlyHalfCloser {
	r, w := io.Pipe()
	go func() {
		_, _ = w.Write([]byte(data))
		_ = w.Close()
	}()
	return &readOnlyHalfCloser{PipeReader: r}
}

func (c *readOnlyHalfCloser) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (c *readOnlyHalfCloser) CloseWrite() error {
	return nil
}

type errWriteHalfCloser struct {
	err error
}

func (c errWriteHalfCloser) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c errWriteHalfCloser) Write(_ []byte) (int, error) {
	return 0, c.err
}

func (c errWriteHalfCloser) Close() error {
	return nil
}

func (c errWriteHalfCloser) CloseWrite() error {
	return nil
}
