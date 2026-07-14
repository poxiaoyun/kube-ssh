package spdyrpc

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
	"xiaoshiai.cn/kube-ssh/pkg/util"
)

func TestSPDYOverstdioConn(t *testing.T) {
	serverSide, clientSide := newStdioConnPair()
	defer serverSide.Close()
	defer clientSide.Close()

	controlCh := make(chan rpcResponse, 1)
	dataHeadersCh := make(chan http.Header, 1)
	serverConn, err := spdy.NewServerConnection(serverSide, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		switch stream.Headers().Get(StreamTypeHeader) {
		case StreamTypeControl:
			go func() {
				<-replySent
				defer stream.Close()
				control := rpcResponse{}
				if err := json.NewDecoder(stream).Decode(&control); err != nil {
					t.Errorf("decode control: %v", err)
					return
				}
				controlCh <- control
			}()
		case "test.data":
			go func() {
				<-replySent
				dataHeadersCh <- stream.Headers()
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

	controlHeaders := http.Header{}
	controlHeaders.Set(StreamTypeHeader, StreamTypeControl)
	control, err := clientConn.CreateStream(controlHeaders)
	if err != nil {
		t.Fatalf("CreateStream(control) error = %v", err)
	}
	payload, err := json.Marshal("response")
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := json.NewEncoder(control).Encode(rpcResponse{OK: true, Payload: payload}); err != nil {
		t.Fatalf("encode control: %v", err)
	}
	_ = control.Close()

	select {
	case control := <-controlCh:
		if !control.OK {
			t.Fatal("control OK = false")
		}
		response := ""
		if err := json.Unmarshal(control.Payload, &response); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if response != "response" {
			t.Fatalf("response = %q, want response", response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for control stream")
	}

	headers := http.Header{}
	headers.Set(StreamTypeHeader, "test.data")
	headers.Set("testValue", "value")
	data, err := clientConn.CreateStream(headers)
	if err != nil {
		t.Fatalf("CreateStream(data) error = %v", err)
	}
	defer data.Close()

	select {
	case headers := <-dataHeadersCh:
		if got := headers.Get(StreamTypeHeader); got != "test.data" {
			t.Fatalf("stream type = %q, want test.data", got)
		}
		if got := headers.Get("testValue"); got != "value" {
			t.Fatalf("test value = %q, want value", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for data stream")
	}
}

func newStdioConnPair() (net.Conn, net.Conn) {
	clientToServerReader, clientToServerWriter := io.Pipe()
	serverToClientReader, serverToClientWriter := io.Pipe()

	server := util.NewStdioConn(clientToServerReader, serverToClientWriter, func() error {
		_ = clientToServerReader.Close()
		_ = serverToClientWriter.Close()
		return nil
	})
	client := util.NewStdioConn(serverToClientReader, clientToServerWriter, func() error {
		_ = serverToClientReader.Close()
		_ = clientToServerWriter.Close()
		return nil
	})
	return server, client
}
