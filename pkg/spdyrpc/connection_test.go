package spdyrpc

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"io"
	"testing"
	"time"
)

func TestConnectionGoErrorStopsServe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leftTransport, rightTransport := newStdioConnPair()
	defer leftTransport.Close()
	defer rightTransport.Close()

	left, err := NewClientConnection(ctx, leftTransport, ConnectionOptions{})
	if err != nil {
		t.Fatalf("NewClientConnection() error = %v", err)
	}
	right, err := NewServerConnection(ctx, rightTransport, ConnectionOptions{})
	if err != nil {
		t.Fatalf("NewServerConnection() error = %v", err)
	}
	defer left.Close()
	defer right.Close()

	wantErr := errors.New("background work failed")
	release := make(chan struct{})
	if err := right.Register("work.start", HandlerFunc(func(context.Context, RawMessage) (any, error) {
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

func TestConnectionCallsInBothDirections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leftTransport, rightTransport := newStdioConnPair()
	defer leftTransport.Close()
	defer rightTransport.Close()

	codec := gobCodec{}
	left, err := NewClientConnection(ctx, leftTransport, ConnectionOptions{Codec: codec})
	if err != nil {
		t.Fatalf("NewConnection(left) error = %v", err)
	}
	right, err := NewServerConnection(ctx, rightTransport, ConnectionOptions{Codec: codec})
	if err != nil {
		t.Fatalf("NewConnection(right) error = %v", err)
	}
	echo := HandlerFunc(func(_ context.Context, payload RawMessage) (any, error) {
		var value string
		if err := codec.Decode(bytes.NewReader(payload), &value); err != nil {
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
		connection *Connection
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

type gobCodec struct{}

func (gobCodec) Encode(writer io.Writer, value any) error {
	return gob.NewEncoder(writer).Encode(value)
}

func (gobCodec) Decode(reader io.Reader, value any) error {
	return gob.NewDecoder(reader).Decode(value)
}
