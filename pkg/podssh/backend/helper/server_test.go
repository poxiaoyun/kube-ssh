package helper_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
)

func startServerClient(t *testing.T, ctx context.Context) (*helper.Client, <-chan error) {
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
		done <- helper.ServeConnection(ctx, toHelperReader, fromHelperWriter)
	}()
	client, err := helper.NewClient(ctx, toHelperWriter, fromHelperReader)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client, done
}

func TestServeConnectionForwardedStreamLifecycle(t *testing.T) {
	for _, kind := range []string{"remote", "agent"} {
		for _, direction := range []string{"socket to stream", "stream to socket", "full close"} {
			t.Run(kind+"/"+direction, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				client, _ := startServerClient(t, ctx)
				defer client.Close()

				var socket, stream ioproxy.HalfCloser
				switch kind {
				case "remote":
					listener, err := client.ListenRemote(ctx, "127.0.0.1", 0)
					if err != nil {
						t.Fatal(err)
					}
					address := net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(listener.ActualPort()), 10))
					var dialer net.Dialer
					conn, err := dialer.DialContext(ctx, "tcp", address)
					if err != nil {
						t.Fatal(err)
					}
					socket = conn.(*net.TCPConn)
					stream, _, err = listener.Accept(ctx)
					if err != nil {
						t.Fatal(err)
					}
				case "agent":
					listener, err := client.ListenAgent(ctx)
					if err != nil {
						t.Fatal(err)
					}
					var dialer net.Dialer
					conn, err := dialer.DialContext(ctx, "unix", listener.SocketPath())
					if err != nil {
						t.Fatal(err)
					}
					socket = conn.(*net.UnixConn)
					stream, err = listener.Accept(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}
				defer socket.Close()
				defer stream.Close()

				if direction == "full close" {
					readDone := make(chan error, 1)
					go func() {
						_, err := stream.Read(make([]byte, 1))
						readDone <- err
					}()
					if err := stream.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-readDone:
						if err != io.EOF {
							t.Fatalf("closed stream Read() error = %v, want EOF", err)
						}
					case <-ctx.Done():
						t.Fatal("full close did not release stream reader")
					}
					return
				}

				requester, responder := socket, stream
				if direction == "stream to socket" {
					requester, responder = stream, socket
				}
				if _, err := io.WriteString(requester, "request"); err != nil {
					t.Fatal(err)
				}
				if err := requester.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				readForwardedToEOF(t, ctx, responder, "request")
				if _, err := io.WriteString(responder, "response after EOF"); err != nil {
					t.Fatal(err)
				}
				if err := responder.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				readForwardedToEOF(t, ctx, requester, "response after EOF")
			})
		}
	}
}

func readForwardedToEOF(t *testing.T, ctx context.Context, reader io.Reader, want string) {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(reader)
		done <- result{data: data, err: err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if string(got.data) != want {
			t.Fatalf("read through EOF = %q, want %q", got.data, want)
		}
	case <-ctx.Done():
		t.Fatal("forwarded stream did not receive EOF")
	}
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

func TestServeConnectionCancellationClosesStdio(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdin, input := io.Pipe()
	output, stdout := io.Pipe()
	defer input.Close()
	defer output.Close()
	done := make(chan error, 1)
	go func() { done <- helper.ServeConnection(ctx, stdin, stdout) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ServeConnection did not exit after cancellation")
	}
	if _, err := input.Write([]byte("after cancellation")); err != io.ErrClosedPipe {
		t.Fatalf("stdin Write() error = %v, want closed pipe", err)
	}
	if _, err := output.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("stdout Read() error = %v, want EOF", err)
	}
}
