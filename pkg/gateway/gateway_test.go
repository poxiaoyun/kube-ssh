package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/target"
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
	opts.Policy.Defaults.MaxDuration = time.Hour
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
			PodBackend:    testBackend{},
			AuditRecorder: audit.NopRecorder{},
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
	agentForward := newBlockingAgentForward("/tmp/kube-ssh-agent/agent.sock")
	captureBackend := &agentForwardExecBackend{agentForward: agentForward}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunWithDependencies(ctx, opts, Dependencies{
			Authenticator: authenticator,
			Authorizer:    authz.AllowAll{},
			Resolver:      &captureResolver{target: targetFixturePtr()},
			PodBackend:    captureBackend,
			AuditRecorder: audit.NopRecorder{},
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
	// SSH command completion does not wait for server-side session cleanup.
	select {
	case <-agentForward.closed:
	case <-time.After(time.Second):
		t.Fatal("agent forwarding was not closed after the session ended")
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

func dialTestSSH(t testing.TB, addr string) *cryptossh.Client {
	t.Helper()
	config := &cryptossh.ClientConfig{
		User:            "default.nginx",
		Auth:            []cryptossh.AuthMethod{cryptossh.Password("secret")},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         200 * time.Millisecond,
	}
	deadline := time.Now().
		Add(3 * time.Second)
	var lastErr error
	for time.Now().
		Before(deadline) {
		client, err := cryptossh.Dial("tcp", addr, config)
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		return client
	}
	t.Fatalf("ssh dial %s: %v", addr, lastErr)
	return nil
}

func freeTCPAddress(t testing.TB) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	addr := listener.Addr().
		String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return addr
}

func stopTestServer(t testing.TB, cancel context.CancelFunc, errCh <-chan error) {
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

type blockingAgentForward struct {
	socketPath string
	closed     chan struct{}
	closeOnce  sync.Once

	mu         sync.Mutex
	closeCount int
}

func newBlockingAgentForward(socketPath string) *blockingAgentForward {
	return &blockingAgentForward{socketPath: socketPath, closed: make(chan struct{})}
}

func (f *blockingAgentForward) SocketPath() string {
	return f.socketPath
}

func (f *blockingAgentForward) Accept(ctx context.Context) (ioproxy.HalfCloser, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.closed:
		return nil, context.Canceled
	}
}

func (f *blockingAgentForward) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closeCount++
		f.mu.Unlock()
		close(f.closed)
	})
	return nil
}

func (f *blockingAgentForward) CloseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeCount
}

func TestStartMetricsServerServesMetricsAndHealthChecks(t *testing.T) {
	recorder := metrics.NewPrometheusRecorder(nil, metrics.PrometheusOptions{})
	srv, listener, err := startMetricsServer(context.Background(), MetricsOptions{
		ListenAddress: "127.0.0.1:0",
		Path:          "/custom-metrics",
	}, recorder)
	if err != nil {
		t.Fatalf("startMetricsServer() error = %v", err)
	}
	defer shutdownHTTPServer(srv)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(listener)
	}()

	metricsBody := httpGet(t, "http://"+listener.Addr().
		String()+"/custom-metrics")
	if !strings.Contains(metricsBody, "kube_ssh_build_info") {
		t.Fatalf("metrics body missing build info: %q", metricsBody)
	}
	if body := httpGet(t, "http://"+listener.Addr().
		String()+"/healthz"); body != "ok\n" {
		t.Fatalf("healthz body = %q, want ok", body)
	}
	if body := httpGet(t, "http://"+listener.Addr().
		String()+"/readyz"); body != "ok\n" {
		t.Fatalf("readyz body = %q, want ok", body)
	}

	shutdownHTTPServer(srv)
	if err := <-serveErr; err != nil && err != http.ErrServerClosed {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestStartMetricsServerRejectsInvalidPath(t *testing.T) {
	for _, path := range []string{"metrics", "/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			_, _, err := startMetricsServer(context.Background(), MetricsOptions{
				ListenAddress: "127.0.0.1:0",
				Path:          path,
			}, metrics.NewPrometheusRecorder(nil, metrics.PrometheusOptions{}))
			if err == nil {
				t.Fatal("startMetricsServer() error = nil, want error")
			}
		})
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d body = %q", url, resp.StatusCode, body)
	}
	return string(body)
}

func BenchmarkSSHHandshake(b *testing.B) {
	benchmarks := []struct {
		name        string
		hostKeyFile func(*testing.B) string
	}{
		{name: "ephemeral-rsa", hostKeyFile: func(*testing.B) string { return "" }},
		{name: "ed25519", hostKeyFile: benchmarkEd25519HostKey},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			addr, config := startBenchmarkSSHServer(b, benchmark.hostKeyFile(b))
			b.ReportAllocs()
			for b.Loop() {
				client, err := cryptossh.Dial("tcp", addr, config)
				if err != nil {
					b.Fatalf("SSH dial: %v", err)
				}
				if err := client.Close(); err != nil {
					b.Fatalf("SSH close: %v", err)
				}
			}
		})
	}
}

func BenchmarkSSHExec(b *testing.B) {
	addr, config := startBenchmarkSSHServer(b, "")
	client, err := cryptossh.Dial("tcp", addr, config)
	if err != nil {
		b.Fatalf("SSH dial: %v", err)
	}
	b.Cleanup(func() { _ = client.Close() })

	b.ReportAllocs()
	for b.Loop() {
		session, err := client.NewSession()
		if err != nil {
			b.Fatalf("new SSH session: %v", err)
		}
		if err := session.Run("true"); err != nil {
			b.Fatalf("SSH exec: %v", err)
		}
	}
}

func BenchmarkSSHDirectTCPIPThroughput(b *testing.B) {
	addr, config := startBenchmarkSSHServer(b, "")
	client, err := cryptossh.Dial("tcp", addr, config)
	if err != nil {
		b.Fatalf("SSH dial: %v", err)
	}
	b.Cleanup(func() { _ = client.Close() })
	stream, err := client.Dial("tcp", "benchmark.invalid:8080")
	if err != nil {
		b.Fatalf("open direct-tcpip channel: %v", err)
	}
	b.Cleanup(func() { _ = stream.Close() })
	payload := make([]byte, 32*1024)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := stream.Write(payload); err != nil {
			b.Fatalf("write direct-tcpip stream: %v", err)
		}
	}
}

func BenchmarkSSHHandshakeExecParallel(b *testing.B) {
	addr, config := startBenchmarkSSHServer(b, "")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			client, err := cryptossh.Dial("tcp", addr, config)
			if err != nil {
				b.Errorf("SSH dial: %v", err)
				continue
			}
			session, err := client.NewSession()
			if err != nil {
				_ = client.Close()
				b.Errorf("new SSH session: %v", err)
				continue
			}
			err = session.Run("true")
			_ = client.Close()
			if err != nil {
				b.Errorf("SSH exec: %v", err)
			}
		}
	})
}

func startBenchmarkSSHServer(b *testing.B, hostKeyFile string) (string, *cryptossh.ClientConfig) {
	b.Helper()
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { slog.SetDefault(previousLogger) })

	authenticator, err := authn.NewStaticPasswordAuthenticator([]authn.PasswordEntry{{Subject: "benchmark", Password: "secret"}})
	if err != nil {
		b.Fatalf("build authenticator: %v", err)
	}
	tgt := targetFixturePtr()
	forwardAddr := startBenchmarkDiscardServer(b)
	auditRecorder := audit.NewAsyncRecorder(benchmarkAuditSink{}, 4096, nil)
	dependencies := Dependencies{
		Stop:          auditRecorder.Close,
		Authenticator: authenticator,
		Authorizer:    authz.AllowAll{},
		Resolver:      benchmarkResolver{target: tgt},
		PodBackend:    benchmarkBackend{forwardAddr: forwardAddr},
		AuditRecorder: auditRecorder,
	}
	opts := NewDefaultOptions()
	opts.ListenAddress = freeTCPAddress(b)
	opts.HostKeyFile = hostKeyFile
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		pprof.Do(ctx, pprof.Labels("side", "server"), func(serverCtx context.Context) {
			errCh <- RunWithDependencies(serverCtx, opts, dependencies)
		})
	}()
	b.Cleanup(func() { stopTestServer(b, cancel, errCh) })

	config := &cryptossh.ClientConfig{
		User:            "default.nginx",
		Auth:            []cryptossh.AuthMethod{cryptossh.Password("secret")},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	client := dialTestSSH(b, opts.ListenAddress)
	_ = client.Close()
	return opts.ListenAddress, config
}

func benchmarkEd25519HostKey(b *testing.B) string {
	b.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate Ed25519 host key: %v", err)
	}
	block, err := cryptossh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		b.Fatalf("marshal Ed25519 host key: %v", err)
	}
	path := filepath.Join(b.TempDir(), "ssh_host_ed25519_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		b.Fatalf("write Ed25519 host key: %v", err)
	}
	return path
}

func startBenchmarkDiscardServer(b *testing.B) string {
	b.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("start discard server: %v", err)
	}
	b.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}()
		}
	}()
	return listener.Addr().
		String()
}

type benchmarkResolver struct{ target *target.Target }

func (r benchmarkResolver) Resolve(context.Context, target.ResolveInput) (*target.Target, error) {
	return r.target, nil
}

type benchmarkBackend struct{ forwardAddr string }

func (benchmarkBackend) Exec(context.Context, backend.ExecRequest) (int, error) { return 0, nil }
func (b benchmarkBackend) PortForward(ctx context.Context, _ backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", b.forwardAddr)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}
func (benchmarkBackend) RemoteForward(context.Context, backend.RemoteForwardRequest) (backend.RemoteForward, error) {
	return nil, errors.New("not implemented")
}
func (benchmarkBackend) AgentForward(context.Context, backend.AgentForwardRequest) (backend.AgentForward, error) {
	return nil, errors.New("not implemented")
}
func (benchmarkBackend) SFTP(context.Context, backend.StreamRequest) (int, error) {
	return 1, errors.New("not implemented")
}
func (benchmarkBackend) SCP(context.Context, backend.SCPRequest) (int, error) {
	return 1, errors.New("not implemented")
}

type benchmarkAuditSink struct{}

func (benchmarkAuditSink) Write(context.Context, audit.Event) error { return nil }
func (benchmarkAuditSink) Close(context.Context) error              { return nil }
