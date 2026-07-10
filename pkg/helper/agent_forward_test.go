package helper

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRunRuntimeAgentForward(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, done := startRuntimeClient(t, ctx)
	defer client.Close()

	forward, err := client.AgentForward(ctx)
	if err != nil {
		t.Fatalf("AgentForward() error = %v", err)
	}
	if forward.SocketPath() == "" {
		t.Fatal("SocketPath() is empty")
	}

	podConn, err := net.DialTimeout("unix", forward.SocketPath(), time.Second)
	if err != nil {
		t.Fatalf("dial agent socket: %v", err)
	}
	defer podConn.Close()

	stream, err := forward.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer stream.Close()

	if _, err := podConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write pod conn: %v", err)
	}
	if got := readExactly(t, stream, len("ping")); got != "ping" {
		t.Fatalf("stream read = %q, want ping", got)
	}
	if _, err := stream.Write([]byte("pong")); err != nil {
		t.Fatalf("write stream: %v", err)
	}
	if got := readExactly(t, podConn, len("pong")); got != "pong" {
		t.Fatalf("pod conn read = %q, want pong", got)
	}

	if err := forward.Cancel(ctx); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunRuntime() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunRuntime() did not stop")
	}
}
