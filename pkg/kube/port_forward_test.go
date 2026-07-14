package kube

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
)

func TestPortForwardStreamWaitWaitsForRemoteError(t *testing.T) {
	result := newTerminalResult()
	wantErr := errors.New("remote portforward failed")
	reset := make(chan struct{})
	stream := &portForwardStream{
		conn:        &testPortForwardConnection{closed: make(chan bool)},
		dataStream:  &testPortForwardHTTPStream{reset: reset},
		errorStream: &testPortForwardHTTPStream{},
		result:      result,
	}
	waited := make(chan error, 1)
	go func() { waited <- stream.Wait() }()

	select {
	case <-reset:
	case <-time.After(time.Second):
		t.Fatal("Wait() did not reset data stream before waiting")
	}
	select {
	case err := <-waited:
		t.Fatalf("Wait() returned before error stream completed: %v", err)
	default:
	}
	result.complete(wantErr)
	select {
	case err := <-waited:
		if !errors.Is(err, wantErr) {
			t.Fatalf("Wait() error = %v, want %v", err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait() did not return after error stream completed")
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

type testPortForwardConnection struct {
	closeOnce sync.Once
	closed    chan bool
}

func (c *testPortForwardConnection) CreateStream(http.Header) (httpstream.Stream, error) {
	return nil, errors.New("not implemented")
}

func (c *testPortForwardConnection) Close() error {
	c.closeOnce.Do(func() {
		if c.closed != nil {
			close(c.closed)
		}
	})
	return nil
}

func (c *testPortForwardConnection) CloseChan() <-chan bool {
	return c.closed
}

func (*testPortForwardConnection) SetIdleTimeout(time.Duration) {}

func (*testPortForwardConnection) RemoveStreams(...httpstream.Stream) {}

type testPortForwardHTTPStream struct {
	reset chan struct{}
}

func (*testPortForwardHTTPStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (*testPortForwardHTTPStream) Write(p []byte) (int, error) { return len(p), nil }
func (*testPortForwardHTTPStream) Close() error                { return nil }
func (s *testPortForwardHTTPStream) Reset() error {
	if s.reset != nil {
		close(s.reset)
	}
	return nil
}
func (*testPortForwardHTTPStream) Headers() http.Header { return nil }
func (*testPortForwardHTTPStream) Identifier() uint32   { return 0 }

func TestHelperDialStreamCloseReleasesHelper(t *testing.T) {
	helper := &testHelperLease{path: "/helper"}
	done := make(chan struct{})
	b := &Backend{
		helperAcquirer: &testHelperAcquirer{handle: helper},
		execOverride: func(ctx context.Context, req backend.ExecRequest) (int, error) {
			want := []string{"/helper", helperpkg.CapabilityDial, "--host", "echo.default.svc.cluster.local", "--port", "18080"}
			if !reflect.DeepEqual(req.Command, want) {
				t.Fatalf("helper dial command = %#v, want %#v", req.Command, want)
			}
			defer close(done)
			_, err := io.Copy(io.Discard, req.Stdin)
			if err != nil {
				return 1, err
			}
			return 0, ctx.Err()
		},
	}

	stream, err := b.PortForward(context.Background(), backend.PortForwardRequest{
		Target: kubeTargetFixture(),
		Host:   "echo.default.svc.cluster.local",
		Port:   18080,
	})
	if err != nil {
		t.Fatalf("PortForward() error = %v", err)
	}

	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("helper dial exec did not exit after Close()")
	}
	waitHelperRelease(t, helper, 1)
}

func TestHelperDialStreamWaitReturnsTerminalError(t *testing.T) {
	helper := &testHelperLease{path: "/helper"}
	b := &Backend{
		helperAcquirer: &testHelperAcquirer{handle: helper},
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			_, _ = io.Copy(io.Discard, req.Stdin)
			_, _ = req.Stderr.Write([]byte("dial failed"))
			return 2, nil
		},
	}

	stream, err := b.PortForward(context.Background(), backend.PortForwardRequest{
		Target: kubeTargetFixture(),
		Host:   "echo.default.svc.cluster.local",
		Port:   18080,
	})
	if err != nil {
		t.Fatalf("PortForward() error = %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	waiter, ok := stream.(interface{ Wait() error })
	if !ok {
		t.Fatal("helper dial stream does not implement Wait()")
	}
	if err := waiter.Wait(); err == nil || !strings.Contains(err.Error(), "helper dial exited with 2: dial failed") {
		t.Fatalf("Wait() error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	waitHelperRelease(t, helper, 1)
}

func TestHelperDialRejectsInvalidPort(t *testing.T) {
	b := &Backend{helperAcquirer: &testHelperAcquirer{handle: &testHelperLease{path: "/helper"}}}
	for _, port := range []uint32{0, 65536} {
		t.Run(strconv.FormatUint(uint64(port), 10), func(t *testing.T) {
			_, err := b.PortForward(context.Background(), backend.PortForwardRequest{
				Target: kubeTargetFixture(),
				Host:   "echo.default.svc.cluster.local",
				Port:   port,
			})
			if err == nil {
				t.Fatal("PortForward() error = nil")
			}
		})
	}
}
