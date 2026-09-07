package backend

import (
	"context"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
)

func TestHelperDialStreamCloseStopsHelper(t *testing.T) {
	done := make(chan struct{})
	backend := NewExecutor(testTransport{
		execHelper: func(ctx context.Context, req HelperExecRequest) (int, error) {
			want := []string{helperpkg.CapabilityDial, "--host", "echo.default.svc.cluster.local", "--port", "18080"}
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
	})

	stream, err := backend.PortForward(context.Background(), PortForwardRequest{
		Target: podTargetFixture(), Host: "echo.default.svc.cluster.local", Port: 18080,
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
}

func TestHelperDialStreamWaitReturnsTerminalError(t *testing.T) {
	backend := NewExecutor(testTransport{
		execHelper: func(_ context.Context, req HelperExecRequest) (int, error) {
			_, _ = io.Copy(io.Discard, req.Stdin)
			_, _ = req.Stderr.Write([]byte("dial failed"))
			return 2, nil
		},
	})

	stream, err := backend.PortForward(context.Background(), PortForwardRequest{
		Target: podTargetFixture(), Host: "echo.default.svc.cluster.local", Port: 18080,
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
}

func TestPortForwardRejectsInvalidPortBeforeTransport(t *testing.T) {
	backend := NewExecutor(testTransport{})
	for _, port := range []uint32{0, 65536} {
		t.Run(strconv.FormatUint(uint64(port), 10), func(t *testing.T) {
			_, err := backend.PortForward(context.Background(), PortForwardRequest{
				Target: podTargetFixture(), Host: "localhost", Port: port,
			})
			if !apierrors.IsBadRequest(err) {
				t.Fatalf("PortForward() error = %v, want BadRequest", err)
			}
		})
	}
}
