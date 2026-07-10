package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

func TestHandleTCPIPForwardRegistersActualBind(t *testing.T) {
	conn := &cryptossh.ServerConn{}
	ctx, cancel := newRemoteForwardTestContext(conn)
	defer cancel()

	forward := newBlockingRemoteForward(32001)
	s := newRemoteForwardTestServer(authz.AllowAll{}, &remoteForwardBackend{remoteForward: forward})

	ok, payload := s.handleTCPIPForward(ctx, nil, &cryptossh.Request{
		Payload: cryptossh.Marshal(&remoteForwardRequest{BindAddr: "127.0.0.1", BindPort: 0}),
	})
	if !ok {
		t.Fatal("handleTCPIPForward() ok = false, want true")
	}

	var response remoteForwardSuccess
	if err := cryptossh.Unmarshal(payload, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.BindPort != 32001 {
		t.Fatalf("response port = %d, want 32001", response.BindPort)
	}
	remoteBackend := s.backend.(*remoteForwardBackend)
	if remoteBackend.remoteForwardCalls != 1 {
		t.Fatalf("RemoteForward calls = %d, want 1", remoteBackend.remoteForwardCalls)
	}
	if got := remoteBackend.remoteForwardReq.BindPort; got != 0 {
		t.Fatalf("backend bind port = %d, want original requested port 0", got)
	}

	state := s.findClientState(conn)
	if state == nil {
		t.Fatal("client state missing after tcpip-forward")
	}
	if _, ok := state.RemoveRemoteForward(newRemoteForwardBind("127.0.0.1", 32001)); !ok {
		t.Fatal("remote forward registered under requested port, want actual port")
	}
}

func TestHandleTCPIPForwardAuthorizationDenyDoesNotOpenBackend(t *testing.T) {
	conn := &cryptossh.ServerConn{}
	ctx, cancel := newRemoteForwardTestContext(conn)
	defer cancel()

	backend := &remoteForwardBackend{remoteForward: newBlockingRemoteForward(2222)}
	s := newRemoteForwardTestServer(authz.DenyAll{}, backend)

	ok, payload := s.handleTCPIPForward(ctx, nil, &cryptossh.Request{
		Payload: cryptossh.Marshal(&remoteForwardRequest{BindAddr: "127.0.0.1", BindPort: 2222}),
	})
	if ok {
		t.Fatal("handleTCPIPForward() ok = true, want false")
	}
	if payload != nil {
		t.Fatalf("payload = %v, want nil", payload)
	}
	if backend.remoteForwardCalls != 0 {
		t.Fatalf("RemoteForward calls = %d, want 0", backend.remoteForwardCalls)
	}
	if state := s.findClientState(conn); state != nil {
		t.Fatalf("client state = %#v, want nil", state)
	}
}

func TestHandleCancelTCPIPForwardMissingBindSucceeds(t *testing.T) {
	conn := &cryptossh.ServerConn{}
	ctx, cancel := newRemoteForwardTestContext(conn)
	defer cancel()

	s := newRemoteForwardTestServer(authz.AllowAll{}, &remoteForwardBackend{})
	state := s.getClientState(ctx, conn)
	forward := newBlockingRemoteForward(2222)
	if !state.AddRemoteForward(newRemoteForwardBind("127.0.0.1", 2222), forward) {
		t.Fatal("AddRemoteForward() failed")
	}

	ok, payload := s.handleCancelTCPIPForward(ctx, nil, &cryptossh.Request{
		Payload: cryptossh.Marshal(&remoteForwardRequest{BindAddr: "127.0.0.1", BindPort: 3333}),
	})
	if !ok {
		t.Fatal("handleCancelTCPIPForward() ok = false, want true")
	}
	if payload != nil {
		t.Fatalf("payload = %v, want nil", payload)
	}
	if got := forward.CancelCount(); got != 0 {
		t.Fatalf("Cancel count = %d, want 0", got)
	}
	if _, ok := state.RemoveRemoteForward(newRemoteForwardBind("127.0.0.1", 2222)); !ok {
		t.Fatal("existing remote forward was removed by unrelated cancel")
	}
}

func TestServeRemoteForwardRemovesAndClosesOnContextCancel(t *testing.T) {
	conn := &cryptossh.ServerConn{}
	ctx, cancel := newRemoteForwardTestContext(conn)
	defer cancel()

	s := newRemoteForwardTestServer(authz.AllowAll{}, &remoteForwardBackend{})
	state := s.getClientState(ctx, conn)
	forward := newBlockingRemoteForward(2222)
	bind := newRemoteForwardBind("127.0.0.1", 2222)
	if !state.AddRemoteForward(bind, forward) {
		t.Fatal("AddRemoteForward() failed")
	}

	sc, err := s.newConnectionContext(ctx)
	if err != nil {
		t.Fatalf("newConnectionContext() error = %v", err)
	}
	spec := remoteForwardOperationSpec(sc, "127.0.0.1", 2222)
	done := make(chan struct{})
	results := make(chan string, 1)
	go func() {
		defer close(done)
		s.serveRemoteForward(ctx, conn, state, bind, "127.0.0.1", 2222, forward, sc, spec, func(result string) {
			results <- result
		})
	}()

	select {
	case <-forward.AcceptStarted():
	case <-time.After(time.Second):
		t.Fatal("remote forward accept loop did not start")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("serveRemoteForward did not stop after context cancel")
	}
	if _, ok := state.RemoveRemoteForward(bind); ok {
		t.Fatal("remote forward still registered after serve loop stopped")
	}
	if got := forward.CloseCount(); got != 1 {
		t.Fatalf("Close count = %d, want 1", got)
	}
	if got := <-results; got != metrics.ResultCanceled {
		t.Fatalf("finish result = %q, want canceled", got)
	}
}

func newRemoteForwardTestContext(conn *cryptossh.ServerConn) (*testSSHContext, context.CancelFunc) {
	base, cancel := context.WithCancel(context.Background())
	ctx := newTestSSHContext()
	ctx.Context = base
	ctx.SetValue(gossh.ContextKeyConn, conn)
	WithAuthenticate(ctx, authn.AuthenticateInfo{
		User:   authn.UserInfo{Name: "alice"},
		Method: "password",
	})
	WithTarget(ctx, targetFixturePtr())
	return ctx, cancel
}

func newRemoteForwardTestServer(authorizer authz.Authorizer, backend backend.Backend) *Server {
	return &Server{
		authz:        authorizer,
		backend:      backend,
		audit:        nopAuditRecorder{},
		clientStates: make(map[*cryptossh.ServerConn]*clientState),
	}
}

type nopAuditRecorder struct{}

func (nopAuditRecorder) Record(context.Context, audit.Event) {}

type remoteForwardBackend struct {
	remoteForward backend.RemoteForward
	err           error

	remoteForwardCalls int
	remoteForwardReq   backend.RemoteForwardRequest
}

func (b *remoteForwardBackend) Exec(context.Context, backend.ExecRequest) (int, error) {
	return 1, errors.New("unexpected Exec call")
}

func (b *remoteForwardBackend) PortForward(context.Context, backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	return nil, errors.New("unexpected PortForward call")
}

func (b *remoteForwardBackend) RemoteForward(_ context.Context, req backend.RemoteForwardRequest) (backend.RemoteForward, error) {
	b.remoteForwardCalls++
	b.remoteForwardReq = req
	if b.err != nil {
		return nil, b.err
	}
	return b.remoteForward, nil
}

func (b *remoteForwardBackend) AgentForward(context.Context, backend.AgentForwardRequest) (backend.AgentForward, error) {
	return nil, errors.New("unexpected AgentForward call")
}

func (b *remoteForwardBackend) SFTP(context.Context, backend.StreamRequest) (int, error) {
	return 1, errors.New("unexpected SFTP call")
}

func (b *remoteForwardBackend) SCP(context.Context, backend.SCPRequest) (int, error) {
	return 1, errors.New("unexpected SCP call")
}

type blockingRemoteForward struct {
	actualPort uint32

	acceptOnce sync.Once
	stopOnce   sync.Once
	started    chan struct{}
	stopped    chan struct{}

	mu          sync.Mutex
	cancelCount int
	closeCount  int
}

func newBlockingRemoteForward(actualPort uint32) *blockingRemoteForward {
	return &blockingRemoteForward{
		actualPort: actualPort,
		started:    make(chan struct{}),
		stopped:    make(chan struct{}),
	}
}

func (f *blockingRemoteForward) ActualPort() uint32 { return f.actualPort }

func (f *blockingRemoteForward) Accept(ctx context.Context) (ioproxy.HalfCloser, backend.RemoteForwardConnInfo, error) {
	f.acceptOnce.Do(func() { close(f.started) })
	select {
	case <-ctx.Done():
		return nil, backend.RemoteForwardConnInfo{}, ctx.Err()
	case <-f.stopped:
		return nil, backend.RemoteForwardConnInfo{}, context.Canceled
	}
}

func (f *blockingRemoteForward) Cancel() error {
	f.mu.Lock()
	f.cancelCount++
	f.mu.Unlock()
	f.stopOnce.Do(func() { close(f.stopped) })
	return nil
}

func (f *blockingRemoteForward) Close() error {
	f.mu.Lock()
	f.closeCount++
	f.mu.Unlock()
	f.stopOnce.Do(func() { close(f.stopped) })
	return nil
}

func (f *blockingRemoteForward) AcceptStarted() <-chan struct{} { return f.started }

func (f *blockingRemoteForward) CancelCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cancelCount
}

func (f *blockingRemoteForward) CloseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeCount
}
