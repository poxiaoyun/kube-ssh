package podssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

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
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &cryptossh.ServerConfig{PasswordCallback: func(_ cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
		if string(password) != "secret" {
			return nil, errors.New("permission denied")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var connections sync.WaitGroup
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); listener.Close(); <-done; connections.Wait() })
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Go(func() {
				ctx, cancel := context.WithCancel(ctx)
				var handlers sync.WaitGroup
				defer func() { cancel(); raw.Close(); handlers.Wait() }()
				stop := context.AfterFunc(ctx, func() { raw.Close() })
				defer stop()
				defer raw.Close()
				conn, channels, requests, err := cryptossh.NewServerConn(raw, config)
				if err != nil {
					return
				}
				defer conn.Close()
				protocol := podssh.NewProtocol(ctx, &target.Target{Kind: target.KindPod, Options: []target.Option{{Key: "namespaces", Value: "default"}, {Key: "pods", Value: "notebook"}}}, executor, begin, metrics.NopRecorder{}, "/bin/sh", func(key string) bool { return key == "LANG" })
				defer protocol.Close()
				handlers.Go(func() {
					for request := range requests {
						ok, payload := protocol.HandleGlobalRequest(conn, request)
						request.Reply(ok, payload)
					}
				})
				for channel := range channels {
					handlers.Go(func() { protocol.HandleChannel(conn, channel) })
				}
			})
		}
	}()

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
