package backend

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
)

// PortForward uses Pod port-forwarding for loopback hosts and helper dialing otherwise.
// The caller owns the returned stream.
func (b *Executor) PortForward(ctx context.Context, req PortForwardRequest) (ioproxy.HalfCloser, error) {
	if req.Port == 0 || req.Port > 65535 {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("invalid port %d", req.Port))
	}
	if isPodLoopbackHost(req.Host) {
		return b.transport.PortForward(ctx, PodPortForwardRequest{Target: req.Target, Port: req.Port})
	}
	return b.dialThroughHelper(ctx, req)
}

func (b *Executor) dialThroughHelper(ctx context.Context, req PortForwardRequest) (ioproxy.HalfCloser, error) {
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderr := &lockedBuffer{}

	result := newTerminalResult()
	stream := &helperDialStream{
		stdin:  stdinWriter,
		stdout: stdoutReader,
		result: result,
	}

	go func() {
		defer stdoutWriter.Close()
		exitCode, err := b.execHelper(ctx, helperpkg.CapabilityDial,
			[]string{
				helperpkg.CapabilityDial,
				"--host", req.Host,
				"--port", strconv.FormatUint(uint64(req.Port), 10),
			}, StreamRequest{Target: req.Target, Stdin: stdinReader, Stdout: stdoutWriter, Stderr: stderr})
		_ = stdinReader.Close()
		if err != nil {
			result.complete(err)
			return
		}
		if exitCode != 0 {
			result.complete(fmt.Errorf("helper dial exited with %d: %s", exitCode, strings.TrimSpace(stderr.String())))
			return
		}
		result.complete(nil)
	}()

	return stream, nil
}

type helperDialStream struct {
	stdin  *io.PipeWriter
	stdout *io.PipeReader
	result *terminalResult
}

func (s *helperDialStream) Read(p []byte) (int, error) {
	return s.stdout.Read(p)
}

func (s *helperDialStream) Write(p []byte) (int, error) {
	return s.stdin.Write(p)
}

func (s *helperDialStream) Close() error {
	_ = s.stdin.Close()
	_ = s.stdout.Close()
	return nil
}

func (s *helperDialStream) Wait() error { return s.result.wait() }

// CloseWrite closes the stdin pipe so the helper binary receives EOF on its
// stdin and knows the client has finished sending.
func (s *helperDialStream) CloseWrite() error {
	return s.stdin.Close()
}

func isPodLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}
