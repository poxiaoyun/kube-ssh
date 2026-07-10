package kube

import (
	"context"
	"io"
	"reflect"
	"strconv"
	"testing"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
)

func TestHelperDialStreamCloseReleasesHelper(t *testing.T) {
	helper := &testHelperHandle{path: "/helper"}
	done := make(chan struct{})
	b := &Backend{
		helperProvider: &testHelperProvider{handle: helper},
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

func TestHelperDialRejectsInvalidPort(t *testing.T) {
	b := &Backend{helperProvider: &testHelperProvider{handle: &testHelperHandle{path: "/helper"}}}
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
