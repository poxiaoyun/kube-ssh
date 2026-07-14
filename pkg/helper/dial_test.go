package helper

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func newPipe() (*io.PipeReader, *io.PipeWriter) {
	return io.Pipe()
}

func TestRunDialUsesProxyAndReturnsWhenRemoteCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("remote closed"))
		serverDone <- err
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	port, err := strconv.ParseUint(portText, 10, 32)
	if err != nil {
		t.Fatalf("ParseUint() error = %v", err)
	}

	stdinReader, stdinWriter := newPipe()
	defer stdinWriter.Close()

	var stdout bytes.Buffer
	err = RunDial(ctx, host, uint(port), stdinReader, &stdout)
	if err != nil {
		t.Fatalf("RunDial() error = %v", err)
	}
	if stdout.String() != "remote closed" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "remote closed")
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server write error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not finish")
	}
}
