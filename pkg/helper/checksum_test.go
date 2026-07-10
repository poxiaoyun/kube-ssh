package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

func TestSelfChecksum(t *testing.T) {
	got, err := SelfChecksum()
	if err != nil {
		t.Fatalf("SelfChecksum() error = %v", err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable() error = %v", err)
	}
	f, err := os.Open(executable)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		t.Fatalf("Copy() error = %v", err)
	}
	want := hex.EncodeToString(hash.Sum(nil))
	if got != want {
		t.Fatalf("SelfChecksum() = %q, want %q", got, want)
	}
}
