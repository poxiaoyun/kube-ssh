package helper

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
)

func TestSPDYOverStdioConn(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	controlCh := make(chan RuntimeResponse, 1)
	remoteHeadersCh := make(chan http.Header, 1)
	serverConn, err := spdy.NewServerConnection(serverSide, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		switch stream.Headers().Get(StreamTypeHeader) {
		case StreamTypeControl:
			go func() {
				<-replySent
				defer stream.Close()
				control := RuntimeResponse{}
				if err := json.NewDecoder(stream).Decode(&control); err != nil {
					t.Errorf("decode control: %v", err)
					return
				}
				controlCh <- control
			}()
		case StreamTypeRemoteForwardConnection:
			go func() {
				<-replySent
				remoteHeadersCh <- stream.Headers()
			}()
		default:
			t.Errorf("unexpected stream type %q", stream.Headers().Get(StreamTypeHeader))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("NewServerConnection() error = %v", err)
	}
	defer serverConn.Close()

	clientConn, err := spdy.NewClientConnection(clientSide)
	if err != nil {
		t.Fatalf("NewClientConnection() error = %v", err)
	}
	defer clientConn.Close()

	control, err := clientConn.CreateStream(ControlHeaders())
	if err != nil {
		t.Fatalf("CreateStream(control) error = %v", err)
	}
	payload, err := json.Marshal(RemoteForwardListenResponse{ActualPort: 4222})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := json.NewEncoder(control).Encode(RuntimeResponse{OK: true, Payload: payload}); err != nil {
		t.Fatalf("encode control: %v", err)
	}
	_ = control.Close()

	select {
	case control := <-controlCh:
		if !control.OK {
			t.Fatal("control OK = false")
		}
		response := RemoteForwardListenResponse{}
		if err := json.Unmarshal(control.Payload, &response); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if response.ActualPort != 4222 {
			t.Fatalf("ActualPort = %d, want 4222", response.ActualPort)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for control stream")
	}

	remote, err := clientConn.CreateStream(RemoteForwardHeaders("127.0.0.1:4222", "127.0.0.1:0", "127.0.0.1", "5151"))
	if err != nil {
		t.Fatalf("CreateStream(remote-forward) error = %v", err)
	}
	defer remote.Close()

	select {
	case headers := <-remoteHeadersCh:
		if got := headers.Get(StreamTypeHeader); got != StreamTypeRemoteForwardConnection {
			t.Fatalf("stream type = %q, want %q", got, StreamTypeRemoteForwardConnection)
		}
		if got := headers.Get(RemoteForwardBindHeader); got != "127.0.0.1:4222" {
			t.Fatalf("remote-forward bind = %q, want 127.0.0.1:4222", got)
		}
		if got := headers.Get(RemoteForwardRequestedBindHeader); got != "127.0.0.1:0" {
			t.Fatalf("remote-forward requested bind = %q, want 127.0.0.1:0", got)
		}
		if got := headers.Get(OriginHostHeader); got != "127.0.0.1" {
			t.Fatalf("origin host = %q, want 127.0.0.1", got)
		}
		if got := headers.Get(OriginPortHeader); got != "5151" {
			t.Fatalf("origin port = %q, want 5151", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for remote-forward stream")
	}
}

func newStdioConnPair() (net.Conn, net.Conn) {
	clientToServerReader, clientToServerWriter := io.Pipe()
	serverToClientReader, serverToClientWriter := io.Pipe()

	server := NewStdioConn(clientToServerReader, serverToClientWriter, func() error {
		_ = clientToServerReader.Close()
		_ = serverToClientWriter.Close()
		return nil
	})
	client := NewStdioConn(serverToClientReader, clientToServerWriter, func() error {
		_ = serverToClientReader.Close()
		_ = clientToServerWriter.Close()
		return nil
	})
	return server, client
}
