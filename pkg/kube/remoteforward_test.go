package kube

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestRemoteForwardAcquireHelperFailure(t *testing.T) {
	b := &Backend{helperProvider: &testHelperProvider{err: fmt.Errorf("helper unavailable")}}

	_, err := b.RemoteForward(context.Background(), backend.RemoteForwardRequest{
		Target:   kubeTargetFixture(),
		BindHost: "127.0.0.1",
	})
	if err == nil {
		t.Fatal("RemoteForward() error = nil")
	}
}

func TestRemoteForwardHelperRuntimeExitError(t *testing.T) {
	helper := &testHelperHandle{path: "/helper"}
	b := &Backend{
		helperProvider: &testHelperProvider{handle: helper},
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			_, _ = req.Stderr.Write([]byte("boom"))
			return 2, nil
		},
	}

	_, err := b.RemoteForward(context.Background(), backend.RemoteForwardRequest{
		Target:   kubeTargetFixture(),
		BindHost: "127.0.0.1",
	})
	if err == nil {
		t.Fatal("RemoteForward() error = nil")
	}
	waitHelperRelease(t, helper, 1)
}

func TestRemoteForwardRunsHelperRuntimeAndReleasesOnClose(t *testing.T) {
	helper := &testHelperHandle{path: "/helper"}
	b := &Backend{
		helperProvider: &testHelperProvider{handle: helper},
		execOverride: func(ctx context.Context, req backend.ExecRequest) (int, error) {
			if got := req.Command; len(got) != 2 || got[0] != "/helper" || got[1] != helperpkg.CommandRuntime {
				t.Fatalf("helper command = %#v", got)
			}
			return 0, helperpkg.RunRuntime(ctx, req.Stdin, req.Stdout)
		},
	}

	forward, err := b.RemoteForward(context.Background(), backend.RemoteForwardRequest{
		Target:   kubeTargetFixture(),
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
	if got := readKubeRemoteForwardExactly(t, stream, len("hello")); got != "hello" {
		t.Fatalf("stream read = %q, want hello", got)
	}

	if err := forward.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	waitHelperRelease(t, helper, 1)
}

type testHelperProvider struct {
	handle HelperHandle
	err    error
}

func (p *testHelperProvider) Acquire(ctx context.Context, tgt *target.Target, capability string) (HelperHandle, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.handle == nil {
		return nil, fmt.Errorf("missing helper handle")
	}
	return p.handle, nil
}

type testHelperHandle struct {
	path         string
	releaseCount atomic.Int32
}

func (h *testHelperHandle) Command(args ...string) []string {
	command := []string{h.path}
	command = append(command, args...)
	return command
}

func (h *testHelperHandle) Release(ctx context.Context) error {
	h.releaseCount.Add(1)
	return nil
}

func readKubeRemoteForwardExactly(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	return string(buf)
}

func waitHelperRelease(t *testing.T, helper *testHelperHandle, want int32) {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if got := helper.releaseCount.Load(); got == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("Release() count = %d, want %d", helper.releaseCount.Load(), want)
		case <-ticker.C:
		}
	}
}
