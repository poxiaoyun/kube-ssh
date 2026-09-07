package backend

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
)

func TestRemoteForwardAcquireHelperFailure(t *testing.T) {
	for _, cause := range []error{apierrors.NewNotFound(corev1.Resource("pods"), "app"), context.Canceled} {
		t.Run(cause.Error(), func(t *testing.T) {
			b := NewExecutor(testTransport{execHelper: func(context.Context, HelperExecRequest) (int, error) {
				return 1, cause
			}})
			_, err := b.RemoteForward(context.Background(), RemoteForwardRequest{
				Target: podTargetFixture(), BindHost: "127.0.0.1",
			})
			if !errors.Is(err, cause) {
				t.Fatalf("RemoteForward() error = %v, want cause %v", err, cause)
			}
			if apierrors.IsNotFound(cause) && !apierrors.IsNotFound(err) {
				t.Fatalf("RemoteForward() error = %v, want NotFound", err)
			}
		})
	}
}

func TestRemoteForwardRejectsInvalidPortBeforeTransport(t *testing.T) {
	backend := NewExecutor(testTransport{})
	_, err := backend.RemoteForward(context.Background(), RemoteForwardRequest{
		Target: podTargetFixture(), BindHost: "127.0.0.1", BindPort: 65536,
	})
	if !apierrors.IsBadRequest(err) {
		t.Fatalf("RemoteForward() error = %v, want BadRequest", err)
	}
}

func TestRemoteForwardHelperConnectionExitError(t *testing.T) {
	b := NewExecutor(testTransport{
		execHelper: func(_ context.Context, req HelperExecRequest) (int, error) {
			_, _ = req.Stderr.Write([]byte("boom"))
			return 2, nil
		},
	})

	_, err := b.RemoteForward(context.Background(), RemoteForwardRequest{
		Target:   podTargetFixture(),
		BindHost: "127.0.0.1",
	})
	if !apierrors.IsServiceUnavailable(err) {
		t.Fatalf("RemoteForward() error = %v, want ServiceUnavailable", err)
	}
}

func TestRemoteForwardServesHelperConnection(t *testing.T) {
	b := NewExecutor(testTransport{
		execHelper: func(ctx context.Context, req HelperExecRequest) (int, error) {
			if got := req.Command; len(got) != 1 || got[0] != helperpkg.CommandServe {
				t.Fatalf("helper command = %#v", got)
			}
			return 0, helperpkg.ServeConnection(ctx, req.Stdin.(io.ReadCloser), req.Stdout.(io.WriteCloser))
		},
	})

	forward, err := b.RemoteForward(context.Background(), RemoteForwardRequest{
		Target:   podTargetFixture(),
		BindHost: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("RemoteForward() error = %v", err)
	}

	tcpConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(forward.ActualPort()), 10)), time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer tcpConn.Close()

	stream, info, err := forward.Accept(context.Background())
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer stream.Close()
	if info.OriginHost == "" || info.OriginPort == 0 {
		t.Fatalf("remote info = %+v", info)
	}

	if _, err := tcpConn.Write([]byte("hello")); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	if got := readRemoteForwardExactly(t, stream, len("hello")); got != "hello" {
		t.Fatalf("stream read = %q, want hello", got)
	}

	if err := forward.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func readRemoteForwardExactly(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	return string(buf)
}
