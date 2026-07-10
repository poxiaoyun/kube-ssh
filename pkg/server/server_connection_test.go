package server

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
)

func TestAccessSessionMaxDurationClosesSSHConnection(t *testing.T) {
	addr := freeTCPAddress(t)
	authenticator, err := authn.NewStaticPasswordAuthenticator([]authn.PasswordEntry{{
		Subject:  "alice",
		Password: "secret",
	}})
	if err != nil {
		t.Fatalf("NewStaticPasswordAuthenticator() error = %v", err)
	}
	opts := NewDefaultOptions()
	opts.ListenAddress = addr
	opts.SSH.MaxDuration = time.Hour
	access := &sshv1.Access{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "nginx"},
		Spec: sshv1.AccessSpec{
			Session: &sshv1.SessionPolicy{
				MaxDuration: &metav1.Duration{Duration: 100 * time.Millisecond},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunWithDependencies(ctx, opts, Dependencies{
			Authenticator: authenticator,
			Authorizer:    authz.AllowAll{},
			Resolver:      &captureResolver{target: targetFixturePtr()},
			AccessPolicy:  fakeAccessPolicyGetter{access: access},
			Backend:       &directTCPIPBackend{},
			AuditRecorder: nopAuditRecorder{},
		})
	}()
	defer stopTestServer(t, cancel, errCh)

	client := dialTestSSH(t, addr)
	defer client.Close()

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- client.Wait()
	}()
	select {
	case <-waitCh:
	case <-time.After(2 * time.Second):
		t.Fatal("SSH client was not closed by Access maxDuration")
	}
}

func TestSSHAgentForwardingRequestInjectsSocket(t *testing.T) {
	addr := freeTCPAddress(t)
	authenticator, err := authn.NewStaticPasswordAuthenticator([]authn.PasswordEntry{{
		Subject:  "alice",
		Password: "secret",
	}})
	if err != nil {
		t.Fatalf("NewStaticPasswordAuthenticator() error = %v", err)
	}
	opts := NewDefaultOptions()
	opts.ListenAddress = addr
	opts.SSH.AgentForwarding = true
	agentForward := newBlockingAgentForward("/tmp/kube-ssh-agent/agent.sock")
	captureBackend := &agentForwardExecBackend{agentForward: agentForward}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunWithDependencies(ctx, opts, Dependencies{
			Authenticator: authenticator,
			Authorizer:    authz.AllowAll{},
			Resolver:      &captureResolver{target: targetFixturePtr()},
			Backend:       captureBackend,
			AuditRecorder: nopAuditRecorder{},
		})
	}()
	defer stopTestServer(t, cancel, errCh)

	client := dialTestSSH(t, addr)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer sess.Close()

	if err := sshagent.RequestAgentForwarding(sess); err != nil {
		t.Fatalf("RequestAgentForwarding() error = %v", err)
	}
	if err := sess.Run("echo ok"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	wantCommand := []string{"env", "SSH_AUTH_SOCK=/tmp/kube-ssh-agent/agent.sock", "/bin/sh", "-c", "echo ok"}
	if got := captureBackend.Command(); !reflect.DeepEqual(got, wantCommand) {
		t.Fatalf("Exec command = %#v, want %#v", got, wantCommand)
	}
	if got := captureBackend.agentForwardCalls; got != 1 {
		t.Fatalf("AgentForward calls = %d, want 1", got)
	}
	if got := agentForward.CloseCount(); got != 1 {
		t.Fatalf("agent forward close count = %d, want 1", got)
	}
}

func dialTestSSH(t *testing.T, addr string) *cryptossh.Client {
	t.Helper()
	config := &cryptossh.ClientConfig{
		User:            "default.nginx",
		Auth:            []cryptossh.AuthMethod{cryptossh.Password("secret")},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         200 * time.Millisecond,
	}
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := cryptossh.Dial("tcp", addr, config)
		if err == nil {
			return client
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("ssh dial %s: %v", addr, lastErr)
	return nil
}

func freeTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return addr
}

func stopTestServer(t *testing.T, cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("RunWithDependencies() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

type agentForwardExecBackend struct {
	agentForward backend.AgentForward

	mu                sync.Mutex
	command           []string
	agentForwardCalls int
}

func (b *agentForwardExecBackend) Exec(_ context.Context, req backend.ExecRequest) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.command = append([]string(nil), req.Command...)
	return 0, nil
}

func (b *agentForwardExecBackend) Command() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.command...)
}

func (b *agentForwardExecBackend) PortForward(context.Context, backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	return nil, errors.New("unexpected PortForward call")
}

func (b *agentForwardExecBackend) RemoteForward(context.Context, backend.RemoteForwardRequest) (backend.RemoteForward, error) {
	return nil, errors.New("unexpected RemoteForward call")
}

func (b *agentForwardExecBackend) AgentForward(context.Context, backend.AgentForwardRequest) (backend.AgentForward, error) {
	b.mu.Lock()
	b.agentForwardCalls++
	b.mu.Unlock()
	return b.agentForward, nil
}

func (b *agentForwardExecBackend) SFTP(context.Context, backend.StreamRequest) (int, error) {
	return 1, errors.New("unexpected SFTP call")
}

func (b *agentForwardExecBackend) SCP(context.Context, backend.SCPRequest) (int, error) {
	return 1, errors.New("unexpected SCP call")
}
