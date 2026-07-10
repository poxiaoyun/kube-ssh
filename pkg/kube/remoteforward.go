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

func (b *Backend) RemoteForward(ctx context.Context, req backend.RemoteForwardRequest) (backend.RemoteForward, error) {
	if req.BindPort > 65535 {
		return nil, status.InvalidTarget("invalid bind port %d", req.BindPort)
	}
	ctx, cancel := context.WithCancel(ctx)
	helper, err := b.acquireHelper(ctx, req.Target, helperpkg.CapabilityRemoteForward)
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
			done <- status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper remote-forward exited with %d: %s", exitCode, strings.TrimSpace(stderr.String()))
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
	forward, err := runtimeClient.RemoteForward(ctx, req.BindHost, req.BindPort)
	if err != nil {
		cancel()
		_ = runtimeClient.Close()
		return nil, status.HelperUnavailable(err, "create helper remote-forward")
	}
	return &remoteForward{client: runtimeClient, forward: forward, done: done, cancel: cancel}, nil
}

type remoteForward struct {
	client    *helperpkg.RuntimeClient
	forward   *helperpkg.RemoteForward
	done      chan error
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func (f *remoteForward) ActualPort() uint32 {
	return f.forward.ActualPort()
}

func (f *remoteForward) Accept(ctx context.Context) (ioproxy.HalfCloser, backend.RemoteForwardConnInfo, error) {
	stream, info, err := f.forward.Accept(ctx)
	if err != nil {
		select {
		case doneErr := <-f.done:
			if doneErr != nil {
				return nil, backend.RemoteForwardConnInfo{}, doneErr
			}
		default:
		}
		return nil, backend.RemoteForwardConnInfo{}, err
	}
	return stream, backend.RemoteForwardConnInfo{
		OriginHost: info.OriginHost,
		OriginPort: info.OriginPort,
	}, nil
}

func (f *remoteForward) Cancel() error {
	return f.forward.Cancel(context.Background())
}

func (f *remoteForward) Close() error {
	f.closeOnce.Do(func() {
		if f.cancel != nil {
			f.cancel()
		}
		f.closeErr = f.client.Close()
	})
	return f.closeErr
}
