package kube

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/status"
)

func (b *Backend) PortForward(ctx context.Context, req backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	// if the host is localhost or empty, we can use the Kubernetes API to port forward directly to the pod.
	if isPodLoopbackHost(req.Host) {
		return b.forwardPodPort(ctx, req)
	}
	return b.dialThroughHelper(ctx, req)
}

func (b *Backend) forwardPodPort(ctx context.Context, req backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	if req.Port == 0 || req.Port > 65535 {
		return nil, status.InvalidTarget("invalid port %d", req.Port)
	}
	podTarget, err := ParseTarget(req.Target)
	if err != nil {
		return nil, err
	}
	restReq := b.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podTarget.Pod).
		Namespace(podTarget.Namespace).
		SubResource("portforward")

	transport, upgrader, err := spdy.RoundTripperFor(b.restConfig)
	if err != nil {
		return nil, status.BackendFailure(err, "create portforward transport")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, restReq.URL().String(), nil)
	if err != nil {
		return nil, status.BackendFailure(err, "create portforward request")
	}
	conn, protocol, err := spdy.NegotiateStreaming(upgrader, &http.Client{Transport: transport}, httpReq, portforward.PortForwardProtocolV1Name)
	if err != nil {
		return nil, status.BackendFailure(err, "dial portforward")
	}
	if protocol != portforward.PortForwardProtocolV1Name {
		_ = conn.Close()
		return nil, status.BackendFailure(fmt.Errorf("unexpected protocol %q", protocol), "dial portforward")
	}

	headers := http.Header{}
	headers.Set(corev1.StreamType, corev1.StreamTypeError)
	headers.Set(corev1.PortHeader, strconv.FormatUint(uint64(req.Port), 10))
	headers.Set(corev1.PortForwardRequestIDHeader, "0")
	errorStream, err := conn.CreateStream(headers)
	if err != nil {
		_ = conn.Close()
		return nil, status.BackendFailure(err, "create portforward error stream")
	}
	_ = errorStream.Close()

	result := newTerminalResult()
	go func() {
		message, err := io.ReadAll(errorStream)
		switch {
		case err != nil:
			result.complete(fmt.Errorf("read portforward error stream: %w", err))
		case len(message) > 0:
			result.complete(fmt.Errorf("portforward remote error: %s", strings.TrimSpace(string(message))))
		default:
			result.complete(nil)
		}
	}()

	headers.Set(corev1.StreamType, corev1.StreamTypeData)
	dataStream, err := conn.CreateStream(headers)
	if err != nil {
		conn.RemoveStreams(errorStream)
		_ = conn.Close()
		return nil, status.BackendFailure(err, "create portforward data stream")
	}

	return &portForwardStream{
		conn:        conn,
		dataStream:  dataStream,
		errorStream: errorStream,
		result:      result,
	}, nil
}

func (b *Backend) dialThroughHelper(ctx context.Context, req backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	if req.Port == 0 || req.Port > 65535 {
		return nil, status.InvalidTarget("invalid port %d", req.Port)
	}
	helper, err := b.acquireHelper(ctx, req.Target, helperpkg.CapabilityDial)
	if err != nil {
		return nil, err
	}

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
		defer func() { _ = helper.Release(context.WithoutCancel(ctx)) }()
		exitCode, err := b.exec(ctx, backend.ExecRequest{
			Target: req.Target,
			Command: helper.Command(
				helperpkg.CapabilityDial,
				"--host", req.Host,
				"--port", strconv.FormatUint(uint64(req.Port), 10),
			),
			Stdin:  stdinReader,
			Stdout: stdoutWriter,
			Stderr: stderr,
			TTY:    false,
		})
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

type portForwardStream struct {
	conn       httpstream.Connection
	dataStream httpstream.Stream

	// errorStream must remain owned by the forwarding request until its reader
	// reports the server terminal result.
	errorStream httpstream.Stream
	result      *terminalResult
	resetOnce   sync.Once
}

func (s *portForwardStream) Read(p []byte) (int, error) {
	return s.dataStream.Read(p)
}

func (s *portForwardStream) Write(p []byte) (int, error) {
	return s.dataStream.Write(p)
}

func (s *portForwardStream) Wait() error {
	// Reset the data stream before waiting for the error stream. The two
	// streams share one SPDY connection, so unread or blocked data can
	// otherwise prevent the server from completing the error stream.
	s.resetOnce.Do(func() { _ = s.dataStream.Reset() })
	return s.result.wait()
}

func (s *portForwardStream) Close() error {
	_ = s.dataStream.Close()
	_ = s.errorStream.Close()
	s.conn.RemoveStreams(s.dataStream, s.errorStream)
	return s.conn.Close()
}

// CloseWrite is a no-op for SPDY portforward streams: the protocol does not
// support independent half-close of the write side. The full close of the
// connection will be handled by Close.
func (s *portForwardStream) CloseWrite() error { return nil }
