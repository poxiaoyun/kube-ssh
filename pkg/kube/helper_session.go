package kube

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// helperSession owns one long-running helper process and its connection client.
// Agent and remote forwarding only differ in the listener they open.
type helperSession struct {
	client *helperpkg.Client
	result *terminalResult
	cancel context.CancelFunc
}

func (b *Backend) startHelperSession(ctx context.Context, tgt *target.Target, capability string) (*helperSession, error) {
	ctx, cancel := context.WithCancel(ctx)
	helper, err := b.acquireHelper(ctx, tgt, capability)
	if err != nil {
		cancel()
		return nil, err
	}

	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderr := &lockedBuffer{}
	result := newTerminalResult()

	go func() {
		defer stdoutWriter.Close()
		defer func() { _ = helper.Release(context.WithoutCancel(ctx)) }()
		exitCode, err := b.exec(ctx, backend.ExecRequest{
			Target:  tgt,
			Command: helper.Command(helperpkg.CommandServe),
			Stdin:   stdinReader,
			Stdout:  stdoutWriter,
			Stderr:  stderr,
			TTY:     false,
		})
		_ = stdinReader.Close()
		switch {
		case err != nil:
			result.complete(err)
		case exitCode != 0:
			result.complete(status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper %s exited with %d: %s", capability, exitCode, strings.TrimSpace(stderr.String())))
		default:
			result.complete(nil)
		}
	}()

	client, err := helperpkg.NewClient(ctx, stdinWriter, stdoutReader)
	if err != nil {
		cancel()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		return nil, status.HelperUnavailable(err, "create helper connection client")
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
	if s.cancel != nil {
		s.cancel()
	}
	return s.client.Close()
}
