package spdyrpc_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/moby/spdystream"
	"github.com/moby/spdystream/spdy"
	"xiaoshiai.cn/kube-ssh/pkg/spdyrpc"
)

func TestConnectionGoErrorStopsServe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leftTransport, rightTransport := net.Pipe()
	defer leftTransport.Close()
	defer rightTransport.Close()

	left, err := spdyrpc.NewClientConnection(ctx, leftTransport)
	if err != nil {
		t.Fatalf("spdyrpc.NewClientConnection() error = %v", err)
	}
	right, err := spdyrpc.NewServerConnection(ctx, rightTransport)
	if err != nil {
		t.Fatalf("spdyrpc.NewServerConnection() error = %v", err)
	}
	defer left.Close()
	defer right.Close()

	wantErr := errors.New("background work failed")
	release := make(chan struct{})
	if err := right.Register("work.start", spdyrpc.HandlerFunc(func(context.Context, spdyrpc.RawMessage) (any, error) {
		err := right.Go(func(context.Context) error {
			<-release
			return wantErr
		})
		return nil, err
	})); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	leftDone := make(chan error, 1)
	rightDone := make(chan error, 1)
	go func() { leftDone <- left.Serve() }()
	go func() { rightDone <- right.Serve() }()

	if err := left.Call(ctx, "work.start", nil, nil); err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	close(release)
	select {
	case err := <-rightDone:
		if !errors.Is(err, wantErr) {
			t.Fatalf("Serve() error = %v, want %v", err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop after work error")
	}

	_ = left.Close()
	select {
	case <-leftDone:
	case <-time.After(time.Second):
		t.Fatal("peer Serve() did not stop")
	}
}

func TestConnectionShutdownReleasesIncompleteRPC(t *testing.T) {
	for _, stop := range []string{"close", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			serverTransport, peerTransport := net.Pipe()
			defer serverTransport.Close()
			defer peerTransport.Close()

			server, err := spdyrpc.NewServerConnection(ctx, serverTransport)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			peer, err := spdystream.NewConnection(peerTransport, false)
			if err != nil {
				t.Fatal(err)
			}
			go peer.Serve(func(stream *spdystream.Stream) { _ = stream.Reset() })
			done := make(chan error, 1)
			go func() { done <- server.Serve() }()

			headers := http.Header{}
			headers.Set(spdyrpc.StreamTypeHeader, spdyrpc.StreamTypeControl)
			stream, err := peer.CreateStream(headers, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.WaitTimeout(time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(stream, `{"type":`); err != nil {
				t.Fatal(err)
			}

			switch stop {
			case "close":
				if err := server.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("Serve() waited for an incomplete RPC after shutdown")
			}
		})
	}
}

func TestConnectionCancellationReleasesBlockedResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverTransport, peerTransport := net.Pipe()
	defer serverTransport.Close()
	defer peerTransport.Close()
	server, err := spdyrpc.NewServerConnection(ctx, serverTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	called := make(chan struct{})
	if err := server.Register("reply", spdyrpc.HandlerFunc(func(context.Context, spdyrpc.RawMessage) (any, error) {
		close(called)
		return "response", nil
	})); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()

	peer, err := spdy.NewFramer(peerTransport, peerTransport)
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{}
	headers.Set(spdyrpc.StreamTypeHeader, spdyrpc.StreamTypeControl)
	if err := peer.WriteFrame(&spdy.SynStreamFrame{StreamId: 1, Headers: headers}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	if err := peer.WriteFrame(&spdy.DataFrame{StreamId: 1, Data: []byte(`{"type":"reply"}`)}); err != nil {
		t.Fatal(err)
	}
	// No peer reader remains to consume the response or a shutdown frame.
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("RPC handler was not called")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Serve() waited for the peer to read its response after cancellation")
	}
}

func TestConnectionCallsInBothDirections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leftTransport, rightTransport := net.Pipe()
	defer leftTransport.Close()
	defer rightTransport.Close()

	left, err := spdyrpc.NewClientConnection(ctx, leftTransport)
	if err != nil {
		t.Fatalf("NewConnection(left) error = %v", err)
	}
	right, err := spdyrpc.NewServerConnection(ctx, rightTransport)
	if err != nil {
		t.Fatalf("NewConnection(right) error = %v", err)
	}
	echo := spdyrpc.HandlerFunc(func(_ context.Context, payload spdyrpc.RawMessage) (any, error) {
		var value string
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		return value, nil
	})
	if err := left.Register("left.echo", echo); err != nil {
		t.Fatalf("left.Register() error = %v", err)
	}
	if err := right.Register("right.echo", echo); err != nil {
		t.Fatalf("right.Register() error = %v", err)
	}

	leftDone := make(chan error, 1)
	rightDone := make(chan error, 1)
	go func() { leftDone <- left.Serve() }()
	go func() { rightDone <- right.Serve() }()

	for _, call := range []struct {
		connection *spdyrpc.Connection
		method     string
	}{
		{right, "left.echo"},
		{left, "right.echo"},
	} {
		var response string
		callCtx, callCancel := context.WithTimeout(ctx, time.Second)
		err := call.connection.Call(callCtx, call.method, "hello", &response)
		callCancel()
		if err != nil {
			t.Fatalf("Call(%q) error = %v", call.method, err)
		}
		if response != "hello" {
			t.Fatalf("Call(%q) response = %q, want hello", call.method, response)
		}
	}

	_ = left.Close()
	_ = right.Close()
	select {
	case <-leftDone:
	case <-time.After(time.Second):
		t.Fatal("left Serve() did not stop")
	}
	select {
	case <-rightDone:
	case <-time.After(time.Second):
		t.Fatal("right Serve() did not stop")
	}
}
