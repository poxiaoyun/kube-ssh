package util

import (
	"bytes"
	"errors"
	"testing"
)

func TestStdioConn(t *testing.T) {
	input := bytes.NewBufferString("input")
	output := &bytes.Buffer{}
	closeErr := errors.New("close error")
	closeCalls := 0
	conn := NewStdioConn(input, output, func() error {
		closeCalls++
		return closeErr
	})

	buf := make([]byte, len("input"))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := string(buf); got != "input" {
		t.Fatalf("Read() = %q, want input", got)
	}
	if _, err := conn.Write([]byte("output")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := output.String(); got != "output" {
		t.Fatalf("Write() output = %q, want output", got)
	}

	if err := conn.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("first Close() error = %v, want %v", err, closeErr)
	}
	if err := conn.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("second Close() error = %v, want %v", err, closeErr)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
	if got := conn.LocalAddr().Network(); got != "stdio" {
		t.Fatalf("LocalAddr().Network() = %q, want stdio", got)
	}
}
