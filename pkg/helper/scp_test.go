package helper

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSCPOptions(t *testing.T) {
	opts, err := parseSCPOptions([]string{"-trp", "/tmp"})
	if err != nil {
		t.Fatalf("parseSCPOptions() error = %v", err)
	}
	if !opts.sink || opts.source || !opts.recursive || !opts.preserve || opts.target != "/tmp" {
		t.Fatalf("opts = %+v", opts)
	}
}

func TestSCPSinkReceivesFile(t *testing.T) {
	dir := t.TempDir()
	input := strings.NewReader("C0644 5 hello.txt\nhello\x00")
	var output bytes.Buffer

	err := RunSCP(context.Background(), []string{"-t", dir}, input, &output)
	if err != nil {
		t.Fatalf("RunSCP() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("file data = %q, want hello", string(data))
	}
	if got, want := output.String(), "\x00\x00\x00"; got != want {
		t.Fatalf("scp acks = %q, want %q", got, want)
	}
}

func TestSCPSourceSendsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	input := strings.NewReader("\x00\x00\x00")
	var output bytes.Buffer
	err := RunSCP(context.Background(), []string{"-f", path}, input, &output)
	if err != nil {
		t.Fatalf("RunSCP() error = %v", err)
	}
	got := output.String()
	if !strings.HasPrefix(got, "C0644 5 hello.txt\nhello\x00") {
		t.Fatalf("scp output = %q", got)
	}
}

func TestSCPCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var output bytes.Buffer
	err := RunSCP(ctx, []string{"-t", t.TempDir()}, strings.NewReader("C0644 5 hello.txt\nhello\x00"), &output)
	if err == nil {
		t.Fatal("RunSCP() error = nil, want context cancellation")
	}
}

func TestParseSCPFileRejectsNegativeSize(t *testing.T) {
	if _, _, _, err := parseSCPFile("C0644 -1 hello.txt"); err == nil {
		t.Fatal("parseSCPFile() error = nil, want negative size error")
	}
}
