package kube

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/status"
)

func (b *Backend) AgentForward(ctx context.Context, req backend.AgentForwardRequest) (backend.AgentForward, error) {
	ctx, cancel := context.WithCancel(ctx)
	helper, err := b.acquireHelper(ctx, req.Target, helperpkg.CapabilityAgentForward)
	if err != nil {
		cancel()
		return nil, err
	}

	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderr := &safeBuffer{}
	done := make(chan error, 1)

	go func() {
		defer stdoutWriter.Close()
		defer func() { _ = helper.Release(context.WithoutCancel(ctx)) }()
		exitCode, err := b.runExec(ctx, backend.ExecRequest{
			Target:  req.Target,
			Command: helper.Command(helperpkg.CommandRuntime),
			Stdin:   stdinReader,
			Stdout:  stdoutWriter,
			Stderr:  stderr,
			TTY:     false,
		})
		_ = stdinReader.Close()
		if err != nil {
			done <- err
			return
		}
		if exitCode != 0 {
			done <- status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper agent-forward exited with %d: %s", exitCode, strings.TrimSpace(stderr.String()))
			return
		}
		done <- nil
	}()

	runtimeClient, err := helperpkg.NewRuntimeClient(ctx, stdinWriter, stdoutReader)
	if err != nil {
		cancel()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		return nil, status.HelperUnavailable(err, "create helper runtime client")
	}
	forward, err := runtimeClient.AgentForward(ctx)
	if err != nil {
		cancel()
		_ = runtimeClient.Close()
		return nil, status.HelperUnavailable(err, "create helper agent-forward")
	}
	return &agentForward{client: runtimeClient, forward: forward, done: done, cancel: cancel}, nil
}

type agentForward struct {
	client    *helperpkg.RuntimeClient
	forward   *helperpkg.AgentForward
	done      chan error
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func (f *agentForward) SocketPath() string {
	return f.forward.SocketPath()
}

func (f *agentForward) Accept(ctx context.Context) (ioproxy.HalfCloser, error) {
	stream, err := f.forward.Accept(ctx)
	if err != nil {
		select {
		case doneErr := <-f.done:
			if doneErr != nil {
				return nil, doneErr
			}
		default:
		}
		return nil, err
	}
	return stream, nil
}

func (f *agentForward) Close() error {
	f.closeOnce.Do(func() {
		if f.cancel != nil {
			f.cancel()
		}
		f.closeErr = f.client.Close()
	})
	return f.closeErr
}
