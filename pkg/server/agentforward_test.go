package server

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
)

func TestAcceptAgentForwardRequiresSessionPolicy(t *testing.T) {
	ctx, cancel := newRemoteForwardTestContext(&cryptossh.ServerConn{})
	defer cancel()
	WithSessionPolicy(ctx, effectiveSessionPolicy{AgentForwarding: false})

	backend := &agentForwardBackend{forward: newBlockingAgentForward("/tmp/agent.sock")}
	s := newRemoteForwardTestServer(authz.AllowAll{}, backend)

	state, ok := s.acceptAgentForward(ctx, &cryptossh.ServerConn{})
	if ok || state != nil {
		t.Fatal("acceptAgentForward() allowed with disabled policy")
	}
	if backend.agentForwardCalls != 0 {
		t.Fatalf("AgentForward calls = %d, want 0", backend.agentForwardCalls)
	}
}

func TestAcceptAgentForwardAuthorizationDenyDoesNotOpenBackend(t *testing.T) {
	ctx, cancel := newRemoteForwardTestContext(&cryptossh.ServerConn{})
	defer cancel()
	WithSessionPolicy(ctx, effectiveSessionPolicy{AgentForwarding: true})

	backend := &agentForwardBackend{forward: newBlockingAgentForward("/tmp/agent.sock")}
	s := newRemoteForwardTestServer(authz.DenyAll{}, backend)

	state, ok := s.acceptAgentForward(ctx, &cryptossh.ServerConn{})
	if ok || state != nil {
		t.Fatal("acceptAgentForward() allowed after authz deny")
	}
	if backend.agentForwardCalls != 0 {
		t.Fatalf("AgentForward calls = %d, want 0", backend.agentForwardCalls)
	}
}

func TestAcceptAgentForwardStartsAndClosesBackend(t *testing.T) {
	ctx, cancel := newRemoteForwardTestContext(&cryptossh.ServerConn{})
	defer cancel()
	WithSessionPolicy(ctx, effectiveSessionPolicy{AgentForwarding: true})

	forward := newBlockingAgentForward("/tmp/kube-ssh-agent/agent.sock")
	backend := &agentForwardBackend{forward: forward}
	s := newRemoteForwardTestServer(authz.AllowAll{}, backend)

	state, ok := s.acceptAgentForward(ctx, &cryptossh.ServerConn{})
	if !ok || state == nil {
		t.Fatal("acceptAgentForward() denied, want allowed")
	}
	if backend.agentForwardCalls != 1 {
		t.Fatalf("AgentForward calls = %d, want 1", backend.agentForwardCalls)
	}
	if got := state.forward.SocketPath(); got != "/tmp/kube-ssh-agent/agent.sock" {
		t.Fatalf("socket path = %q", got)
	}

	state.Close()
	if got := forward.CloseCount(); got != 1 {
		t.Fatalf("forward close count = %d, want 1", got)
	}
}

type agentForwardBackend struct {
	forward backend.AgentForward
	err     error

	agentForwardCalls int
	agentForwardReq   backend.AgentForwardRequest
}

func (b *agentForwardBackend) Exec(context.Context, backend.ExecRequest) (int, error) {
	return 1, errors.New("unexpected Exec call")
}

func (b *agentForwardBackend) PortForward(context.Context, backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	return nil, errors.New("unexpected PortForward call")
}

func (b *agentForwardBackend) RemoteForward(context.Context, backend.RemoteForwardRequest) (backend.RemoteForward, error) {
	return nil, errors.New("unexpected RemoteForward call")
}

func (b *agentForwardBackend) AgentForward(_ context.Context, req backend.AgentForwardRequest) (backend.AgentForward, error) {
	b.agentForwardCalls++
	b.agentForwardReq = req
	if b.err != nil {
		return nil, b.err
	}
	return b.forward, nil
}

func (b *agentForwardBackend) SFTP(context.Context, backend.StreamRequest) (int, error) {
	return 1, errors.New("unexpected SFTP call")
}

func (b *agentForwardBackend) SCP(context.Context, backend.SCPRequest) (int, error) {
	return 1, errors.New("unexpected SCP call")
}

type blockingAgentForward struct {
	socketPath string

	stopOnce sync.Once
	stopped  chan struct{}

	mu         sync.Mutex
	closeCount int
}

func newBlockingAgentForward(socketPath string) *blockingAgentForward {
	return &blockingAgentForward{
		socketPath: socketPath,
		stopped:    make(chan struct{}),
	}
}

func (f *blockingAgentForward) SocketPath() string { return f.socketPath }

func (f *blockingAgentForward) Accept(ctx context.Context) (ioproxy.HalfCloser, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.stopped:
		return nil, io.EOF
	}
}

func (f *blockingAgentForward) Close() error {
	f.mu.Lock()
	f.closeCount++
	f.mu.Unlock()
	f.stopOnce.Do(func() { close(f.stopped) })
	return nil
}

func (f *blockingAgentForward) CloseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeCount
}
