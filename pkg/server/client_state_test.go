package server

import (
	"context"
	"sync"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
)

func TestClientStateRemoteForwardLifecycle(t *testing.T) {
	state := newClientState(nil)
	bindA := newRemoteForwardBind("127.0.0.1", 2222)
	bindB := newRemoteForwardBind("127.0.0.1", 3333)
	forwardA := &testRemoteForward{}
	forwardB := &testRemoteForward{}

	if !state.AddRemoteForward(bindA, forwardA) {
		t.Fatal("AddRemoteForward(bindA) = false")
	}
	if state.AddRemoteForward(bindA, &testRemoteForward{}) {
		t.Fatal("duplicate AddRemoteForward(bindA) = true")
	}
	if !state.AddRemoteForward(bindB, forwardB) {
		t.Fatal("AddRemoteForward(bindB) = false")
	}

	got, ok := state.RemoveRemoteForward(bindA)
	if !ok {
		t.Fatal("RemoveRemoteForward(bindA) = false")
	}
	if got != forwardA {
		t.Fatalf("removed forward = %p, want %p", got, forwardA)
	}

	state.Close()
	state.Close()

	if forwardA.CloseCount() != 0 {
		t.Fatalf("removed forward close count = %d, want 0", forwardA.CloseCount())
	}
	if forwardB.CloseCount() != 1 {
		t.Fatalf("remaining forward close count = %d, want 1", forwardB.CloseCount())
	}
	if state.AddRemoteForward(newRemoteForwardBind("127.0.0.1", 4444), &testRemoteForward{}) {
		t.Fatal("AddRemoteForward() after Close = true")
	}
	if _, ok := state.RemoveRemoteForward(bindB); ok {
		t.Fatal("RemoveRemoteForward(bindB) after Close = true")
	}
}

func TestServerCloseClientStateRemovesAndClosesState(t *testing.T) {
	conn := &cryptossh.ServerConn{}
	state := newClientState(conn)
	forward := &testRemoteForward{}
	if !state.AddRemoteForward(newRemoteForwardBind("127.0.0.1", 2222), forward) {
		t.Fatal("AddRemoteForward() = false")
	}
	server := &Server{
		clientStates: map[*cryptossh.ServerConn]*clientState{conn: state},
	}

	server.closeClientState(conn, state)
	server.closeClientState(conn, state)

	if server.findClientState(conn) != nil {
		t.Fatal("client state was not removed")
	}
	if forward.CloseCount() != 1 {
		t.Fatalf("forward close count = %d, want 1", forward.CloseCount())
	}
}

func TestRemoteForwardBindUsesJoinedAddress(t *testing.T) {
	if got, want := newRemoteForwardBind("127.0.0.1", 2222), remoteForwardBind("127.0.0.1:2222"); got != want {
		t.Fatalf("bind = %q, want %q", got, want)
	}
	if got, want := newRemoteForwardBind("::1", 2222), remoteForwardBind("[::1]:2222"); got != want {
		t.Fatalf("ipv6 bind = %q, want %q", got, want)
	}
}

type testRemoteForward struct {
	mu          sync.Mutex
	cancelCount int
	closeCount  int
}

func (f *testRemoteForward) ActualPort() uint32 { return 0 }

func (f *testRemoteForward) Accept(context.Context) (ioproxy.HalfCloser, backend.RemoteForwardConnInfo, error) {
	return nil, backend.RemoteForwardConnInfo{}, context.Canceled
}

func (f *testRemoteForward) Cancel() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelCount++
	return nil
}

func (f *testRemoteForward) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCount++
	return nil
}

func (f *testRemoteForward) CloseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeCount
}
