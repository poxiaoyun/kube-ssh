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

func TestHandleDirectTCPIPAuthorizationDenyDoesNotOpenBackend(t *testing.T) {
	ctx, cancel := newRemoteForwardTestContext(&cryptossh.ServerConn{})
	defer cancel()

	backend := &directTCPIPBackend{remote: &trackedHalfCloser{}}
	s := newRemoteForwardTestServer(authz.DenyAll{}, backend)
	ch := newDirectTCPIPTestChannel("redis.default.svc", 6379)

	s.handleDirectTCPIP(nil, nil, ch, ctx)

	if backend.portForwardCalls != 0 {
		t.Fatalf("PortForward calls = %d, want 0", backend.portForwardCalls)
	}
	if ch.rejectReason != cryptossh.Prohibited {
		t.Fatalf("reject reason = %v, want Prohibited", ch.rejectReason)
	}
	if ch.acceptCalled {
		t.Fatal("Accept() was called after authorization denied")
	}
}

func TestHandleDirectTCPIPClosesBackendWhenChannelAcceptFails(t *testing.T) {
	ctx, cancel := newRemoteForwardTestContext(&cryptossh.ServerConn{})
	defer cancel()

	remote := &trackedHalfCloser{}
	backend := &directTCPIPBackend{remote: remote}
	s := newRemoteForwardTestServer(authz.AllowAll{}, backend)
	ch := newDirectTCPIPTestChannel("127.0.0.1", 18080)
	ch.acceptErr = errors.New("client closed channel")

	s.handleDirectTCPIP(nil, nil, ch, ctx)

	if backend.portForwardCalls != 1 {
		t.Fatalf("PortForward calls = %d, want 1", backend.portForwardCalls)
	}
	if !ch.acceptCalled {
		t.Fatal("Accept() was not called")
	}
	if got := remote.CloseCount(); got != 1 {
		t.Fatalf("remote close count = %d, want 1", got)
	}
}

func newDirectTCPIPTestChannel(host string, port uint32) *testNewChannel {
	return &testNewChannel{
		extra: cryptossh.Marshal(&directTCPIPData{
			DestAddr:   host,
			DestPort:   port,
			OriginAddr: "127.0.0.1",
			OriginPort: 50000,
		}),
	}
}

type testNewChannel struct {
	extra []byte

	acceptCalled bool
	acceptErr    error

	rejectReason  cryptossh.RejectionReason
	rejectMessage string
}

func (c *testNewChannel) Accept() (cryptossh.Channel, <-chan *cryptossh.Request, error) {
	c.acceptCalled = true
	return nil, nil, c.acceptErr
}

func (c *testNewChannel) Reject(reason cryptossh.RejectionReason, message string) error {
	c.rejectReason = reason
	c.rejectMessage = message
	return nil
}

func (c *testNewChannel) ChannelType() string { return "direct-tcpip" }

func (c *testNewChannel) ExtraData() []byte { return c.extra }

type directTCPIPBackend struct {
	remote ioproxy.HalfCloser
	err    error

	portForwardCalls int
	portForwardReq   backend.PortForwardRequest
}

func (b *directTCPIPBackend) Exec(context.Context, backend.ExecRequest) (int, error) {
	return 1, errors.New("unexpected Exec call")
}

func (b *directTCPIPBackend) PortForward(_ context.Context, req backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	b.portForwardCalls++
	b.portForwardReq = req
	if b.err != nil {
		return nil, b.err
	}
	return b.remote, nil
}

func (b *directTCPIPBackend) RemoteForward(context.Context, backend.RemoteForwardRequest) (backend.RemoteForward, error) {
	return nil, errors.New("unexpected RemoteForward call")
}

func (b *directTCPIPBackend) AgentForward(context.Context, backend.AgentForwardRequest) (backend.AgentForward, error) {
	return nil, errors.New("unexpected AgentForward call")
}

func (b *directTCPIPBackend) SFTP(context.Context, backend.StreamRequest) (int, error) {
	return 1, errors.New("unexpected SFTP call")
}

func (b *directTCPIPBackend) SCP(context.Context, backend.SCPRequest) (int, error) {
	return 1, errors.New("unexpected SCP call")
}

type trackedHalfCloser struct {
	mu         sync.Mutex
	closeCount int
}

func (c *trackedHalfCloser) Read([]byte) (int, error) { return 0, io.EOF }

func (c *trackedHalfCloser) Write(p []byte) (int, error) { return len(p), nil }

func (c *trackedHalfCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCount++
	return nil
}

func (c *trackedHalfCloser) CloseWrite() error { return nil }

func (c *trackedHalfCloser) CloseCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCount
}
