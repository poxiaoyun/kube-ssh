package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"k8s.io/streaming/pkg/httpstream"
)

func startRuntimeClient(t *testing.T, ctx context.Context) (*RuntimeClient, <-chan error) {
	t.Helper()
	toHelperReader, toHelperWriter := io.Pipe()
	fromHelperReader, fromHelperWriter := io.Pipe()
	t.Cleanup(func() {
		_ = toHelperReader.Close()
		_ = toHelperWriter.Close()
		_ = fromHelperReader.Close()
		_ = fromHelperWriter.Close()
	})

	done := make(chan error, 1)
	go func() {
		done <- RunRuntime(ctx, toHelperReader, fromHelperWriter)
	}()

	client, err := NewRuntimeClient(ctx, toHelperWriter, fromHelperReader)
	if err != nil {
		t.Fatalf("NewRuntimeClient() error = %v", err)
	}
	return client, done
}

func dialForward(t *testing.T, port uint32) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(port), 10)), time.Second)
	if err != nil {
		t.Fatalf("Dial remote-forward listener error = %v", err)
	}
	return conn
}

func readExactly(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	return string(buf)
}

func newPipe() (*io.PipeReader, *io.PipeWriter) {
	return io.Pipe()
}

type fakeRuntimeConn struct {
	mu             sync.Mutex
	removedStreams map[uint32]bool
	closed         chan bool
}

func newFakeRuntimeConn() *fakeRuntimeConn {
	return &fakeRuntimeConn{
		removedStreams: make(map[uint32]bool),
		closed:         make(chan bool),
	}
}

func (c *fakeRuntimeConn) CreateStream(http.Header) (httpstream.Stream, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *fakeRuntimeConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *fakeRuntimeConn) CloseChan() <-chan bool { return c.closed }

func (c *fakeRuntimeConn) SetIdleTimeout(time.Duration) {}

func (c *fakeRuntimeConn) RemoveStreams(streams ...httpstream.Stream) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, stream := range streams {
		c.removedStreams[stream.Identifier()] = true
	}
}

func (c *fakeRuntimeConn) removed(stream httpstream.Stream) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.removedStreams[stream.Identifier()]
}

type fakeStream struct {
	headers http.Header
	closed  bool
	id      uint32
}

func newFakeStream(headers http.Header) *fakeStream {
	return &fakeStream{headers: headers, id: 99}
}

func (s *fakeStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (s *fakeStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *fakeStream) Close() error {
	s.closed = true
	return nil
}

func (s *fakeStream) Reset() error {
	s.closed = true
	return nil
}
func (s *fakeStream) Headers() http.Header { return s.headers }
func (s *fakeStream) Identifier() uint32   { return s.id }

func TestRuntimeRPCErrorResponses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	toHelperReader, toHelperWriter := io.Pipe()
	fromHelperReader, fromHelperWriter := io.Pipe()
	defer toHelperReader.Close()
	defer toHelperWriter.Close()
	defer fromHelperReader.Close()
	defer fromHelperWriter.Close()

	done := make(chan error, 1)
	go func() {
		done <- RunRuntime(ctx, toHelperReader, fromHelperWriter)
	}()

	client, err := NewRuntimeClient(ctx, toHelperWriter, fromHelperReader)
	if err != nil {
		t.Fatalf("NewRuntimeClient() error = %v", err)
	}
	defer client.Close()

	if err := client.call(ctx, "unknown", nil, nil); err == nil {
		t.Fatal("unknown runtime request succeeded")
	}
	if err := client.call(ctx, ControlTypeRemoteForwardListen, json.RawMessage(`{`), nil); err == nil {
		t.Fatal("malformed remote-forward listen payload succeeded")
	}
	if err := client.call(ctx, ControlTypeRemoteForwardListen, RemoteForwardListenRequest{Bind: "not-a-host-port"}, nil); err == nil {
		t.Fatal("invalid remote-forward bind succeeded")
	}

	cancel()
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunRuntime() did not stop")
	}
}
