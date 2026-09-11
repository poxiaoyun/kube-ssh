package gateway

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestSessionPolicyConnIdleTimeout(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := newSessionPolicyConn(serverSide, effectiveSessionPolicy{IdleTimeout: 20 * time.Millisecond})
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
	case <-time.After(time.Second):
		t.Fatal("Read() did not time out")
	}
}

func TestSessionPolicyConnMaxDurationClosesPeer(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := newSessionPolicyConn(serverSide, effectiveSessionPolicy{MaxDuration: 20 * time.Millisecond})
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

func TestSessionPolicyConnApplyPolicyShortensMaxDuration(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := newSessionPolicyConn(serverSide, effectiveSessionPolicy{MaxDuration: time.Hour})
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

func TestSessionPolicyConnWriteRefreshesIdleDeadline(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := newSessionPolicyConn(serverSide, effectiveSessionPolicy{IdleTimeout: time.Second})
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

func BenchmarkSessionPolicyConnTouch(b *testing.B) {
	conn := newSessionPolicyConn(benchmarkConn{}, effectiveSessionPolicy{IdleTimeout: time.Minute})
	defer conn.Close()
	b.ReportAllocs()
	for b.Loop() {
		conn.touch()
	}
}

type benchmarkConn struct{}

func (benchmarkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (benchmarkConn) Write(p []byte) (int, error)      { return len(p), nil }
func (benchmarkConn) Close() error                     { return nil }
func (benchmarkConn) LocalAddr() net.Addr              { return benchmarkAddr("local") }
func (benchmarkConn) RemoteAddr() net.Addr             { return benchmarkAddr("remote") }
func (benchmarkConn) SetDeadline(time.Time) error      { return nil }
func (benchmarkConn) SetReadDeadline(time.Time) error  { return nil }
func (benchmarkConn) SetWriteDeadline(time.Time) error { return nil }

type benchmarkAddr string

func (benchmarkAddr) Network() string  { return "benchmark" }
func (a benchmarkAddr) String() string { return string(a) }
