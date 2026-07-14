package kube

import (
	"context"
	"errors"
	"testing"
	"time"

	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
)

func TestHelperRuntimeErrorPreservesAcceptError(t *testing.T) {
	session := &helperSession{result: newTerminalResult()}
	if err := session.resolveClientError(context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("resolveClientError() = %v, want context.Canceled", err)
	}
}

func TestHelperRuntimeErrorWaitsForTerminalFailure(t *testing.T) {
	result := newTerminalResult()
	session := &helperSession{result: result}
	wantErr := errors.New("helper exited with status 2")
	started := make(chan struct{})
	returned := make(chan error, 1)
	go func() {
		close(started)
		returned <- session.resolveClientError(helperpkg.ErrClientClosed)
	}()
	<-started

	select {
	case err := <-returned:
		t.Fatalf("resolveClientError() returned before terminal result: %v", err)
	default:
	}
	result.complete(wantErr)
	select {
	case err := <-returned:
		if !errors.Is(err, wantErr) {
			t.Fatalf("resolveClientError() = %v, want %v", err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("resolveClientError() did not return after terminal result")
	}
}

func TestHelperRuntimeErrorKeepsClosedErrorAfterCleanExit(t *testing.T) {
	result := newTerminalResult()
	result.complete(nil)
	session := &helperSession{result: result}
	if err := session.resolveClientError(helperpkg.ErrClientClosed); !errors.Is(err, helperpkg.ErrClientClosed) {
		t.Fatalf("resolveClientError() = %v, want ErrClientClosed", err)
	}
}
