package backend

import (
	"context"
	"reflect"
	"testing"

	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestExecutorUsesTransportForExecAndPodPort(t *testing.T) {
	wantCommand := []string{"sh", "-c", "echo ok"}
	execCalled := false
	portCalled := false
	backend := NewExecutor(testTransport{
		exec: func(_ context.Context, req ExecRequest) (int, error) {
			execCalled = true
			if !reflect.DeepEqual(req.Command, wantCommand) {
				t.Fatalf("command = %#v, want %#v", req.Command, wantCommand)
			}
			return 0, nil
		},
		portForward: func(_ context.Context, req PodPortForwardRequest) (ioproxy.HalfCloser, error) {
			portCalled = true
			if req.Port != 8080 {
				t.Fatalf("port-forward request = %+v", req)
			}
			return nil, nil
		},
	})

	if _, err := backend.Exec(context.Background(), ExecRequest{Target: podTargetFixture(), Command: wantCommand}); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if _, err := backend.PortForward(context.Background(), PortForwardRequest{Target: podTargetFixture(), Host: "localhost", Port: 8080}); err != nil {
		t.Fatalf("PortForward() error = %v", err)
	}
	if !execCalled || !portCalled {
		t.Fatalf("transport calls = exec:%t port:%t", execCalled, portCalled)
	}
}

func TestIsPodLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{want: true},
		{host: "localhost", want: true},
		{host: "127.0.0.1", want: true},
		{host: "::1", want: true},
		{host: "kubernetes.default.svc"},
		{host: "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := isPodLoopbackHost(tt.host)
			if got != tt.want {
				t.Fatalf("isPodLoopbackHost(%q) = %t, want %t", tt.host, got, tt.want)
			}
		})
	}
}

type testTransport struct {
	exec        func(context.Context, ExecRequest) (int, error)
	portForward func(context.Context, PodPortForwardRequest) (ioproxy.HalfCloser, error)
	execHelper  func(context.Context, HelperExecRequest) (int, error)
}

func (t testTransport) Exec(ctx context.Context, req ExecRequest) (int, error) {
	return t.exec(ctx, req)
}

func (t testTransport) PortForward(ctx context.Context, req PodPortForwardRequest) (ioproxy.HalfCloser, error) {
	return t.portForward(ctx, req)
}

func (t testTransport) ExecHelper(ctx context.Context, req HelperExecRequest) (int, error) {
	return t.execHelper(ctx, req)
}

func podTargetFixture() *target.Target {
	return podtarget.New("default", "nginx", "app")
}
