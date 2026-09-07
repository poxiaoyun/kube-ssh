package podssh_test

import (
	"context"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type protocolContextKey string

const podProtocolKey protocolContextKey = "pod-protocol"

func TestProtocolExecutesPodSession(t *testing.T) {
	executor := &execBackend{}
	operations := make(chan sshprotocol.Operation, 1)
	results := make(chan sshprotocol.OperationResult, 1)
	address := startPodSSHServer(t, executor, func(operation sshprotocol.Operation) (sshprotocol.FinishOperation, error) {
		operations <- operation
		return func(result sshprotocol.OperationResult) { results <- result }, nil
	})
	client, err := cryptossh.Dial("tcp", address, &cryptossh.ClientConfig{
		User:            "default.notebook",
		Auth:            []cryptossh.AuthMethod{cryptossh.Password("secret")},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Setenv("LANG", "en_US.UTF-8"); err != nil {
		t.Fatal(err)
	}
	if err := session.Setenv("TOKEN", "secret"); err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("id")
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "pod\n" {
		t.Fatalf("output = %q, want pod", output)
	}
	if got := executor.Command(); !reflect.DeepEqual(got, []string{"env", "LANG=en_US.UTF-8", "/bin/sh", "-c", "id"}) {
		t.Fatalf("backend command = %#v", got)
	}
	operation := <-operations
	if operation.ChannelType != "session" || operation.RequestType != "exec" || operation.Command != "id" {
		t.Fatalf("operation = %+v", operation)
	}
	result := <-results
	if result.Err != nil || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func startPodSSHServer(t *testing.T, executor backend.Backend, begin sshprotocol.BeginOperationFunc) string {
	t.Helper()
	server := &gossh.Server{
		PasswordHandler: func(ctx gossh.Context, password string) bool {
			if password != "secret" {
				return false
			}
			protocol := podssh.NewProtocol(
				ctx,
				&target.Target{
					Kind: target.KindPod,
					Options: []target.Option{
						{Key: "namespaces", Value: "default"},
						{Key: "pods", Value: "notebook"},
					},
				},
				executor,
				begin,
				metrics.NopRecorder{},
				"/bin/sh",
				func(key string) bool { return key == "LANG" },
			)
			ctx.SetValue(podProtocolKey, sshprotocol.ConnectionProtocol(protocol))
			go func() {
				<-ctx.Done()
				protocol.Close()
			}()
			return true
		},
		ChannelHandlers: map[string]gossh.ChannelHandler{
			"default": func(_ *gossh.Server, conn *cryptossh.ServerConn, channel cryptossh.NewChannel, ctx gossh.Context) {
				ctx.Value(podProtocolKey).(sshprotocol.ConnectionProtocol).
					HandleChannel(conn, channel)
			},
		},
		RequestHandlers: map[string]gossh.RequestHandler{
			"default": func(ctx gossh.Context, _ *gossh.Server, request *cryptossh.Request) (bool, []byte) {
				conn := ctx.Value(gossh.ContextKeyConn).(*cryptossh.ServerConn)
				return ctx.Value(podProtocolKey).(sshprotocol.ConnectionProtocol).
					HandleGlobalRequest(conn, request)
			},
		},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	go func() { _ = server.Serve(listener) }()
	return listener.Addr().
		String()
}

type execBackend struct {
	backend.Backend

	mu      sync.Mutex
	command []string
}

func (b *execBackend) Exec(_ context.Context, request backend.ExecRequest) (int, error) {
	b.mu.Lock()
	b.command = append([]string(nil), request.Command...)
	b.mu.Unlock()
	_, _ = request.Stdout.Write([]byte("pod\n"))
	return 0, nil
}

func (b *execBackend) Command() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.command...)
}
