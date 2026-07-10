package helper

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
)

func TestClientSPDYConnectionRemoveStreamsDoesNotCloseStream(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	serverConn, err := spdy.NewServerConnection(serverSide, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		go func() {
			<-replySent
			if got := readExactly(t, stream, len("ping")); got != "ping" {
				t.Errorf("server read = %q, want ping", got)
				return
			}
			if _, err := stream.Write([]byte("pong")); err != nil {
				t.Errorf("server write: %v", err)
			}
		}()
		return nil
	})
	if err != nil {
		t.Fatalf("NewServerConnection() error = %v", err)
	}
	defer serverConn.Close()

	clientConn, err := newClientSPDYConnection(clientSide, nil)
	if err != nil {
		t.Fatalf("newClientSPDYConnection() error = %v", err)
	}
	go clientConn.Serve()
	defer clientConn.Close()

	stream, err := clientConn.CreateStream(http.Header{})
	if err != nil {
		t.Fatalf("CreateStream() error = %v", err)
	}
	if got := clientConn.streamCount(); got != 1 {
		t.Fatalf("stream count = %d, want 1", got)
	}
	clientConn.RemoveStreams(stream)
	if got := clientConn.streamCount(); got != 0 {
		t.Fatalf("stream count after RemoveStreams = %d, want 0", got)
	}

	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("client write after RemoveStreams: %v", err)
	}
	if got := readExactly(t, stream, len("pong")); got != "pong" {
		t.Fatalf("client read after RemoveStreams = %q, want pong", got)
	}
	_ = stream.Close()
}

func TestClientSPDYConnectionCloseClearsRegisteredStreams(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	serverConn, err := spdy.NewServerConnection(serverSide, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		go func() {
			<-replySent
			_, _ = io.Copy(io.Discard, stream)
		}()
		return nil
	})
	if err != nil {
		t.Fatalf("NewServerConnection() error = %v", err)
	}
	defer serverConn.Close()

	clientConn, err := newClientSPDYConnection(clientSide, nil)
	if err != nil {
		t.Fatalf("newClientSPDYConnection() error = %v", err)
	}
	go clientConn.Serve()

	if _, err := clientConn.CreateStream(http.Header{}); err != nil {
		t.Fatalf("CreateStream() error = %v", err)
	}
	if got := clientConn.streamCount(); got != 1 {
		t.Fatalf("stream count = %d, want 1", got)
	}
	if err := clientConn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := clientConn.streamCount(); got != 0 {
		t.Fatalf("stream count after Close = %d, want 0", got)
	}
}

func TestClientSPDYConnectionRejectsStreamWhenHandlerFails(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	clientConn, err := newClientSPDYConnection(clientSide, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		return fmt.Errorf("reject")
	})
	if err != nil {
		t.Fatalf("newClientSPDYConnection() error = %v", err)
	}
	go clientConn.Serve()
	defer clientConn.Close()

	serverConn, err := spdy.NewServerConnection(serverSide, nil)
	if err != nil {
		t.Fatalf("NewServerConnection() error = %v", err)
	}
	defer serverConn.Close()

	if _, err := serverConn.CreateStream(http.Header{}); err == nil {
		t.Fatal("CreateStream() succeeded, want rejection error")
	}
	if got := clientConn.streamCount(); got != 0 {
		t.Fatalf("stream count after rejected stream = %d, want 0", got)
	}
}

func TestClientSPDYConnectionReplySentClosesAfterAccept(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	replySentSeen := make(chan struct{}, 1)
	clientConn, err := newClientSPDYConnection(clientSide, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		go func() {
			select {
			case <-replySent:
				replySentSeen <- struct{}{}
			case <-time.After(time.Second):
				t.Errorf("timed out waiting for replySent")
			}
		}()
		return nil
	})
	if err != nil {
		t.Fatalf("newClientSPDYConnection() error = %v", err)
	}
	go clientConn.Serve()
	defer clientConn.Close()

	serverConn, err := spdy.NewServerConnection(serverSide, nil)
	if err != nil {
		t.Fatalf("NewServerConnection() error = %v", err)
	}
	defer serverConn.Close()

	stream, err := serverConn.CreateStream(http.Header{})
	if err != nil {
		t.Fatalf("CreateStream() error = %v", err)
	}
	defer stream.Close()

	select {
	case <-replySentSeen:
	case <-time.After(time.Second):
		t.Fatal("replySent was not closed")
	}
}

func (c *clientSPDYConnection) streamCount() int {
	c.streamLock.Lock()
	defer c.streamLock.Unlock()
	return len(c.streams)
}
