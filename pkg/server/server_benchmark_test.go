package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime/pprof"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

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
			b.ResetTimer()
			for range b.N {
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
	b.ResetTimer()
	for range b.N {
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
	b.ResetTimer()
	for range b.N {
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
			if err == nil {
				err = session.Run("true")
			}
			_ = client.Close()
			if err != nil {
				b.Errorf("SSH exec: %v", err)
			}
		}
	})
}

func BenchmarkSessionPolicyConnTouch(b *testing.B) {
	conn := newSessionPolicyConn(benchmarkConn{}, effectiveSessionPolicy{IdleTimeout: time.Minute})
	defer conn.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		conn.touch()
	}
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
		Backend:       benchmarkBackend{forwardAddr: forwardAddr},
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
	return listener.Addr().String()
}

type benchmarkResolver struct{ target *target.Target }

func (r benchmarkResolver) Resolve(context.Context, target.ResolveRequest) (*target.Target, error) {
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

type benchmarkConn struct{}

func (benchmarkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (benchmarkConn) Write(p []byte) (int, error)      { return len(p), nil }
func (benchmarkConn) Close() error                     { return nil }
func (benchmarkConn) LocalAddr() net.Addr              { return benchmarkAddr("local") }
func (benchmarkConn) RemoteAddr() net.Addr             { return benchmarkAddr("remote") }
func (benchmarkConn) SetDeadline(time.Time) error      { return nil }
func (benchmarkConn) SetReadDeadline(time.Time) error  { return nil }
func (benchmarkConn) SetWriteDeadline(time.Time) error { return nil }

type benchmarkAddr string

func (benchmarkAddr) Network() string  { return "benchmark" }
func (a benchmarkAddr) String() string { return string(a) }
