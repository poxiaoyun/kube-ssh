package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestExternalTargetUsesSSHProtocolProxy(t *testing.T) {
	upstreamAddress := startExternalExecServer(t)
	connector := externalConnectionConnectorFunc(func(context.Context, *target.Target) (*sshproxy.Connection, error) {
		conn, err := net.Dial("tcp", upstreamAddress)
		if err != nil {
			return nil, err
		}
		sshConn, channels, requests, err := cryptossh.NewClientConn(conn, upstreamAddress, &cryptossh.ClientConfig{
			User:            "jovyan",
			HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return &sshproxy.Connection{Conn: sshConn, Channels: channels, Requests: requests}, nil
	})
	authenticator, err := authn.NewStaticPasswordAuthenticator([]authn.PasswordEntry{{Subject: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	access := &sshv1.Access{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "nginx", UID: "uid", Generation: 1}}
	tgt := sshproxy.NewTarget(access, "main")
	recorder := &eventRecorder{}
	opts := NewDefaultOptions()
	opts.ListenAddress = freeTCPAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunWithDependencies(ctx, opts, Dependencies{
			Authenticator: authenticator,
			Authorizer:    authz.AllowAll{},
			Resolver:      &captureResolver{target: tgt},
			SSHProxy:      connector,
			AuditRecorder: recorder,
		})
	}()
	defer stopTestServer(t, cancel, errCh)

	client := dialTestSSH(t, opts.ListenAddress)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	output, err := session.Output("whoami")
	if err != nil {
		t.Fatalf("Output() error = %v", err)
	}
	if got, want := string(output), "external-upstream\n"; got != want {
		t.Fatalf("Output() = %q, want %q", got, want)
	}
	auditCtx, auditCancel := context.WithTimeout(context.Background(), time.Second)
	defer auditCancel()
	events, auditRecorded := recorder.Wait(auditCtx, func(events []audit.Event) bool {
		for _, event := range events {
			if event.Type == "operation.end" && event.Target != nil && event.Target.Endpoint == "main" {
				return true
			}
		}
		return false
	})
	if !auditRecorded {
		t.Fatalf("external endpoint was not recorded in operation audit: %+v", events)
	}
	ok, _, err := client.SendRequest("vendor-extension@example.com", true, []byte("opaque"))
	if err != nil {
		t.Fatalf("SendRequest() error = %v", err)
	}
	if ok {
		t.Fatal("default policy allowed an unknown SSH extension")
	}
}

type externalConnectionConnectorFunc func(ctx context.Context, tgt *target.Target) (*sshproxy.Connection, error)

func (f externalConnectionConnectorFunc) Connect(ctx context.Context, tgt *target.Target) (*sshproxy.Connection, error) {
	return f(ctx, tgt)
}

func startExternalExecServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &cryptossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		serverConn, channels, requests, handshakeErr := cryptossh.NewServerConn(conn, config)
		if handshakeErr != nil {
			_ = conn.Close()
			return
		}
		defer serverConn.Close()
		go func() {
			for request := range requests {
				if request.WantReply {
					_ = request.Reply(true, nil)
				}
			}
		}()
		for newChannel := range channels {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(cryptossh.UnknownChannelType, "unsupported")
				continue
			}
			channel, channelRequests, acceptErr := newChannel.Accept()
			if acceptErr != nil {
				continue
			}
			go func() {
				defer channel.Close()
				for request := range channelRequests {
					if request.Type != "exec" {
						if request.WantReply {
							_ = request.Reply(false, nil)
						}
						continue
					}
					if request.WantReply {
						_ = request.Reply(true, nil)
					}
					_, _ = channel.Write([]byte("external-upstream\n"))
					_, _ = channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{Status: 0}))
					return
				}
			}()
		}
	}()
	return listener.Addr().
		String()
}
