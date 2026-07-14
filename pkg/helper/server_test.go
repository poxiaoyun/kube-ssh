package helper

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/spdyrpc"
)

func startServerClient(t *testing.T, ctx context.Context) (*Client, <-chan error) {
	t.Helper()
	toHelperReader, toHelperWriter := io.Pipe()
	fromHelperReader, fromHelperWriter := io.Pipe()
	t.Cleanup(func() {
		_ = toHelperReader.Close()
		_ = toHelperWriter.Close()
		_ = fromHelperReader.Close()
		_ = fromHelperWriter.Close()
	})
	done := make(chan error, 1)
	go func() {
		done <- ServeConnection(ctx, toHelperReader, fromHelperWriter, spdyrpc.ConnectionOptions{})
	}()
	client, err := NewClient(ctx, toHelperWriter, fromHelperReader)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client, done
}

func TestServeConnectionForwardingServices(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, done := startServerClient(t, ctx)
	defer client.Close()

	remote, err := client.ListenRemote(ctx, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("ListenRemote() error = %v", err)
	}
	agent, err := client.ListenAgent(ctx)
	if err != nil {
		t.Fatalf("ListenAgent() error = %v", err)
	}

	tcpConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(remote.ActualPort()), 10)), time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	remoteStream, _, err := remote.Accept(ctx)
	if err != nil {
		t.Fatalf("RemoteListener.Accept() error = %v", err)
	}
	_ = remoteStream.Close()
	_ = tcpConn.Close()

	agentConn, err := net.DialTimeout("unix", agent.SocketPath(), time.Second)
	if err != nil {
		t.Fatalf("agent Dial() error = %v", err)
	}
	agentStream, err := agent.Accept(ctx)
	if err != nil {
		t.Fatalf("AgentListener.Accept() error = %v", err)
	}
	_ = agentStream.Close()
	_ = agentConn.Close()

	if err := remote.Cancel(ctx); err != nil {
		t.Fatalf("RemoteListener.Cancel() error = %v", err)
	}
	if err := agent.Cancel(ctx); err != nil {
		t.Fatalf("AgentListener.Cancel() error = %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("ServeConnection() stopped while connection remained open: %v", err)
	default:
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Client.Close() error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeConnection() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeConnection() did not stop after client close")
	}
}
