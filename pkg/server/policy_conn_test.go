package server

import (
	"net"
	"testing"
	"time"
)

func TestPolicyConnIdleTimeout(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := newPolicyConn(serverSide, effectiveSessionPolicy{IdleTimeout: 20 * time.Millisecond})
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Read() error = nil, want timeout")
		}
		netErr, ok := err.(net.Error)
		if !ok || !netErr.Timeout() {
			t.Fatalf("Read() error = %T %v, want timeout", err, err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read() did not time out")
	}
}

func TestPolicyConnMaxDurationClosesPeer(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := newPolicyConn(serverSide, effectiveSessionPolicy{MaxDuration: 20 * time.Millisecond})
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := clientSide.Read(buf)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("peer Read() error = nil, want close error")
		}
	case <-time.After(time.Second):
		t.Fatal("peer Read() did not observe max duration close")
	}
}

func TestPolicyConnApplyPolicyShortensMaxDuration(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := newPolicyConn(serverSide, effectiveSessionPolicy{MaxDuration: time.Hour})
	defer conn.Close()
	conn.ApplyPolicy(effectiveSessionPolicy{MaxDuration: 20 * time.Millisecond})

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := clientSide.Read(buf)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("peer Read() error = nil, want close error")
		}
	case <-time.After(time.Second):
		t.Fatal("peer Read() did not observe shortened max duration close")
	}
}

func TestPolicyConnWriteRefreshesIdleDeadline(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := newPolicyConn(serverSide, effectiveSessionPolicy{IdleTimeout: time.Second})
	defer conn.Close()

	readCh := make(chan byte, 1)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := clientSide.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		readCh <- buf[0]
	}()

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	select {
	case got := <-readCh:
		if got != 'x' {
			t.Fatalf("peer read %q, want x", got)
		}
	case err := <-errCh:
		t.Fatalf("peer Read() error = %v", err)
	case <-time.After(time.Second):
		t.Fatal("peer did not read written byte")
	}
}
