package spdyrpc

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
)

func readExactly(t *testing.T, reader io.Reader, size int) string {
	t.Helper()
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	return string(data)
}

func TestServerCreateStream(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	peer, err := spdy.NewServerConnection(serverSide, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		go func() {
			<-replySent
			if got := readExactly(t, stream, len("ping")); got != "ping" {
				t.Errorf("peer read = %q, want ping", got)
				return
			}
			_, _ = stream.Write([]byte("pong"))
		}()
		return nil
	})
	if err != nil {
		t.Fatalf("NewServerConnection() error = %v", err)
	}
	defer peer.Close()

	connection, err := NewClientConnection(context.Background(), clientSide, ConnectionOptions{})
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	go connection.spdyConn.Serve(connection.newSPDYStream)
	defer connection.Close()

	stream, err := connection.CreateStream(http.Header{})
	if err != nil {
		t.Fatalf("createStream() error = %v", err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("stream.Write() error = %v", err)
	}
	if got := readExactly(t, stream, len("pong")); got != "pong" {
		t.Fatalf("stream read = %q, want pong", got)
	}
}

func TestServerOptions(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	timeout := 5 * time.Second
	connection, err := NewClientConnection(context.Background(), clientSide, ConnectionOptions{
		CreateStreamResponseTimeout: timeout,
	})
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	if connection.createStreamResponseTimeout != timeout {
		t.Fatalf("create stream response timeout = %v, want %v", connection.createStreamResponseTimeout, timeout)
	}
	if _, ok := connection.Codec().(JSONCodec); !ok {
		t.Fatalf("default codec = %T, want JSONCodec", connection.Codec())
	}
	_ = serverSide.Close()
	_ = connection.Close()
}

func TestServerRejectsInvalidTimeout(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	if _, err := NewClientConnection(context.Background(), clientSide, ConnectionOptions{
		CreateStreamResponseTimeout: -time.Second,
	}); err == nil {
		t.Fatal("newServer() error = nil, want invalid timeout error")
	}
}

func TestServerRejectsUnsupportedStream(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	connection, err := NewClientConnection(context.Background(), clientSide, ConnectionOptions{})
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	go connection.spdyConn.Serve(connection.newSPDYStream)
	defer connection.Close()

	peer, err := spdy.NewServerConnection(serverSide, nil)
	if err != nil {
		t.Fatalf("NewServerConnection() error = %v", err)
	}
	defer peer.Close()

	if _, err := peer.CreateStream(http.Header{}); err == nil {
		t.Fatal("CreateStream() succeeded, want rejection error")
	}
}
