package kube

import (
	"errors"
	"testing"
	"time"
)

func TestTerminalResultWaitAndPollAreRepeatable(t *testing.T) {
	result := newTerminalResult()
	wantErr := errors.New("terminal failure")
	waited := make(chan error, 1)
	go func() { waited <- result.wait() }()

	if err, done := result.poll(); done || err != nil {
		t.Fatalf("Poll() before completion = (%v, %v), want (nil, false)", err, done)
	}
	result.complete(wantErr)

	select {
	case err := <-waited:
		if !errors.Is(err, wantErr) {
			t.Fatalf("Wait() error = %v, want %v", err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait() did not return after completion")
	}
	for range 2 {
		if err := result.wait(); !errors.Is(err, wantErr) {
			t.Fatalf("repeated Wait() error = %v, want %v", err, wantErr)
		}
		if err, done := result.poll(); !done || !errors.Is(err, wantErr) {
			t.Fatalf("repeated Poll() = (%v, %v), want (%v, true)", err, done, wantErr)
		}
	}
}

func TestTerminalResultCompletesOnlyOnce(t *testing.T) {
	result := newTerminalResult()
	wantErr := errors.New("first")
	result.complete(wantErr)
	result.complete(errors.New("second"))
	if err := result.wait(); !errors.Is(err, wantErr) {
		t.Fatalf("Wait() error = %v, want %v", err, wantErr)
	}
}
