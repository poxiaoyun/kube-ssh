package podssh_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	ssh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
)

func sessionTestClient(t *testing.T, executor backend.Backend) *ssh.Client {
	t.Helper()
	address := startPodSSHServer(t, executor, func(sshprotocol.Operation) (sshprotocol.FinishOperation, error) {
		return func(sshprotocol.OperationResult) {}, nil
	})
	raw, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, address, &ssh.ClientConfig{User: "default.notebook", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { client.Close() })
	return client
}

func TestSessionWindowChangesBeforeExec(t *testing.T) {
	executor := &windowSessionBackend{sizes: make(chan backend.TerminalSize, 2)}
	client := sessionTestClient(t, executor)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ok, err := sess.SendRequest(sshprotocol.RequestWindowChange, true, ssh.Marshal(struct{ W, H, PW, PH uint32 }{uint32(100 + i), 30, 0, 0}))
		if err != nil || !ok {
			t.Fatalf("window change %d blocked or rejected: %v, %v", i, ok, err)
		}
	}
	if err := sess.Run("true"); err != nil {
		t.Fatal(err)
	}
	for i, want := range []backend.TerminalSize{{Width: 80, Height: 24}, {Width: 102, Height: 30}} {
		if got := <-executor.sizes; got != want {
			t.Fatalf("terminal size %d = %+v, want %+v", i, got, want)
		}
	}
}

func TestSessionRejectsMalformedExec(t *testing.T) {
	client := sessionTestClient(t, &execBackend{})
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ok, err := sess.SendRequest(sshprotocol.RequestExec, true, []byte{0, 0, 0, 5, 'x'})
	if err != nil || ok {
		t.Fatalf("malformed exec accepted: %v, %v", ok, err)
	}
	if err := sess.Run("true"); err != nil {
		t.Fatalf("valid exec after rejection: %v", err)
	}
}

type cancelSessionBackend struct {
	backend.Backend
	started chan context.Context
}

func (b *cancelSessionBackend) Exec(ctx context.Context, _ backend.ExecRequest) (int, error) {
	b.started <- ctx
	<-ctx.Done()
	return 1, ctx.Err()
}

func TestSessionCloseCancelsOnlyItsExecution(t *testing.T) {
	b := &cancelSessionBackend{started: make(chan context.Context, 2)}
	client := sessionTestClient(t, b)
	first, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start("first"); err != nil {
		t.Fatal(err)
	}
	var firstCtx context.Context
	select {
	case firstCtx = <-b.started:
	case <-time.After(time.Second):
		t.Fatal("first exec did not start")
	}
	second, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.Start("second"); err != nil {
		t.Fatal(err)
	}
	var secondCtx context.Context
	select {
	case secondCtx = <-b.started:
	case <-time.After(time.Second):
		t.Fatal("second exec did not start")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("closing the session did not cancel its backend execution")
	}
	select {
	case <-secondCtx.Done():
		t.Fatal("closing first session canceled second execution")
	default:
	}
}

type windowSessionBackend struct {
	backend.Backend
	sizes chan backend.TerminalSize
}

func (b *windowSessionBackend) Exec(_ context.Context, req backend.ExecRequest) (int, error) {
	for range 2 {
		size := req.TerminalSizeQueue.Next()
		if size == nil {
			return 1, fmt.Errorf("terminal queue closed early")
		}
		b.sizes <- *size
	}
	return 0, nil
}
