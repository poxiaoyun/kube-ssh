package sshproxy_test

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestProxyForwardsExecAndDeniesUnapprovedExtension(t *testing.T) {
	upstreamAddress := startExecSSHServer(t)
	connector := connectionConnectorFunc(func(context.Context, *target.Target) (*sshproxy.Connection, error) {
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

	var operationsMu sync.Mutex
	var operations []sshprotocol.Operation
	noReplyFinished := make(chan sshprotocol.OperationResult, 1)
	deniedFinished := make(chan sshprotocol.OperationResult, 1)
	begin := func(operation sshprotocol.Operation) (sshprotocol.FinishOperation, error) {
		operationsMu.Lock()
		operations = append(operations, operation)
		operationsMu.Unlock()
		if operation.RequestType == "no-reply@example.com" {
			return func(result sshprotocol.OperationResult) { noReplyFinished <- result }, nil
		}
		if operation.RequestType != "exec" {
			return func(result sshprotocol.OperationResult) { deniedFinished <- result }, fmt.Errorf("denied by test policy")
		}
		return func(sshprotocol.OperationResult) {}, nil
	}

	downstreamAddress := startProxySSHServer(t, connector, begin)
	client, err := cryptossh.Dial("tcp", downstreamAddress, &cryptossh.ClientConfig{
		User:            "default.notebook",
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	})
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	output, err := session.Output("whoami")
	if err != nil {
		t.Fatalf("Output() error = %v", err)
	}
	if got, want := string(output), "from-upstream\n"; got != want {
		t.Fatalf("Output() = %q, want %q", got, want)
	}

	ok, _, err := client.SendRequest("vendor-extension@example.com", true, []byte("opaque"))
	if err != nil {
		t.Fatalf("SendRequest() error = %v", err)
	}
	if ok {
		t.Fatal("unapproved extension was forwarded")
	}
	select {
	case result := <-deniedFinished:
		if result.Err != nil || result.ExitCode != nil {
			t.Fatalf("denied extension result = %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("denied extension operation did not finish")
	}
	if _, _, err := client.SendRequest("no-reply@example.com", false, []byte("opaque")); err != nil {
		t.Fatalf("SendRequest() no-reply error = %v", err)
	}
	select {
	case result := <-noReplyFinished:
		if result.Err != nil {
			t.Fatalf("no-reply operation result error = %v", result.Err)
		}
	case <-time.After(time.Second):
		t.Fatal("no-reply operation did not finish")
	}

	operationsMu.Lock()
	got := append([]sshprotocol.Operation(nil), operations...)
	operationsMu.Unlock()
	want := []sshprotocol.Operation{
		{ChannelType: "session", RequestType: "exec", Command: "whoami"},
		{RequestType: "vendor-extension@example.com"},
		{RequestType: "no-reply@example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("authorized operations = %#v, want %#v", got, want)
	}
}

type connectionConnectorFunc func(ctx context.Context, tgt *target.Target) (*sshproxy.Connection, error)

func (f connectionConnectorFunc) Connect(ctx context.Context, tgt *target.Target) (*sshproxy.Connection, error) {
	return f(ctx, tgt)
}

func startProxySSHServer(t *testing.T, connector sshproxy.ConnectionConnector, begin sshprotocol.BeginOperationFunc) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &cryptossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(newSigner(t))
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
		protocol := sshproxy.NewProtocol(context.Background(), &target.Target{}, connector, begin, func(string) bool { return true })
		go func() {
			for request := range requests {
				ok, payload := protocol.HandleGlobalRequest(serverConn, request)
				if request.WantReply {
					_ = request.Reply(ok, payload)
				}
			}
		}()
		for channel := range channels {
			protocol.HandleChannel(serverConn, channel)
		}
		protocol.Close()
	}()
	return listener.Addr().
		String()
}

func startExecSSHServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &cryptossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(newSigner(t))
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
			channel, channelRequests, acceptChannelErr := newChannel.Accept()
			if acceptChannelErr != nil {
				continue
			}
			go serveExecChannel(channel, channelRequests)
		}
	}()
	return listener.Addr().
		String()
}

func serveExecChannel(channel cryptossh.Channel, requests <-chan *cryptossh.Request) {
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			continue
		}
		var payload struct{ Command string }
		if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil || payload.Command != "whoami" {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			return
		}
		if request.WantReply {
			_ = request.Reply(true, nil)
		}
		_, _ = fmt.Fprintln(channel, "from-upstream")
		_, _ = channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{Status: 0}))
		return
	}
}
