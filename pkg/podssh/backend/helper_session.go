package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// helperSession owns one long-running helper process and its connection client.
// Agent and remote forwarding only differ in the listener they open.
type helperSession struct {
	client *helperpkg.Client
	result *terminalResult
	cancel context.CancelFunc
}

func (b *Executor) startHelperSession(ctx context.Context, tgt *target.Target, capability string) (*helperSession, error) {
	ctx, cancel := context.WithCancel(ctx)
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderr := &lockedBuffer{}
	result := newTerminalResult()

	go func() {
		defer stdoutWriter.Close()
		exitCode, err := b.execHelper(ctx, capability, []string{helperpkg.CommandServe}, StreamRequest{
			Target: tgt, Stdin: stdinReader, Stdout: stdoutWriter, Stderr: stderr,
		})
		_ = stdinReader.Close()
		switch {
		case err != nil:
			result.complete(err)
		case exitCode != 0:
			result.complete(apierrors.NewServiceUnavailable(fmt.Sprintf("helper %s exited with %d: %s", capability, exitCode, strings.TrimSpace(stderr.String()))))
		default:
			result.complete(nil)
		}
	}()

	client, err := helperpkg.NewClient(ctx, stdinWriter, stdoutReader)
	if err != nil {
		cancel()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		return nil, fmt.Errorf("create helper connection client: %w", err)
	}
	return &helperSession{client: client, result: result, cancel: cancel}, nil
}

func (s *helperSession) resolveClientError(err error) error {
	if !errors.Is(err, helperpkg.ErrClientClosed) {
		return err
	}
	if terminalErr := s.result.wait(); terminalErr != nil {
		return terminalErr
	}
	return err
}

func (s *helperSession) Close() error {
	s.cancel()
	return s.client.Close()
}
