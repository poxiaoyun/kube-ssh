package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// Backend executes commands through Kubernetes APIs.
type Backend struct {
	client         kubernetes.Interface
	restConfig     *rest.Config
	helperProvider HelperProvider
	metrics        metrics.Recorder
	execOverride   func(context.Context, backend.ExecRequest) (int, error)
}

type Options struct {
	HelperPath      string
	HelperRemoteDir string
	Metrics         metrics.Recorder
}

func NewBackend(client kubernetes.Interface, restConfig *rest.Config, opts ...Options) *Backend {
	options := Options{HelperRemoteDir: "/tmp"}
	if len(opts) > 0 {
		options = opts[0]
		if options.HelperRemoteDir == "" {
			options.HelperRemoteDir = "/tmp"
		}
	}
	b := &Backend{
		client:     client,
		restConfig: restConfig,
		metrics:    options.Metrics,
	}
	if b.metrics == nil {
		b.metrics = metrics.NopRecorder{}
	}
	b.helperProvider = NewCopyHelperProvider(b, CopyHelperProviderOptions{
		LocalPath: options.HelperPath,
		RemoteDir: options.HelperRemoteDir,
	})
	return b
}

// Exec runs a command in a pod container and returns the process exit code.
// A nil error with a non-zero exit code means the command ran but exited non-zero;
// a non-nil error means the exec itself failed.
func (b *Backend) Exec(ctx context.Context, req backend.ExecRequest) (int, error) {
	namespace, pod, container, err := kubeTarget(req.Target)
	if err != nil {
		return 1, err
	}

	opts := &corev1.PodExecOptions{
		Container: container,
		Command:   req.Command,
		Stdin:     req.Stdin != nil,
		Stdout:    req.Stdout != nil,
		Stderr:    !req.TTY && req.Stderr != nil,
		TTY:       req.TTY,
	}

	restReq := b.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(opts, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(b.restConfig, "POST", restReq.URL())
	if err != nil {
		return 1, status.BackendFailure(err, "create executor")
	}

	streamOpts := remotecommand.StreamOptions{
		Stdin:  req.Stdin,
		Stdout: req.Stdout,
		Tty:    req.TTY,
	}
	if req.TerminalSizeQueue != nil {
		streamOpts.TerminalSizeQueue = terminalSizeQueue{queue: req.TerminalSizeQueue}
	}
	if !req.TTY {
		streamOpts.Stderr = req.Stderr
	}

	err = executor.StreamWithContext(ctx, streamOpts)
	if err != nil {
		var exitError interface{ ExitStatus() int }
		if errors.As(err, &exitError) {
			return exitError.ExitStatus(), nil
		}
		return 1, status.BackendFailure(err, "exec stream")
	}
	return 0, nil
}

func (b *Backend) runExec(ctx context.Context, req backend.ExecRequest) (int, error) {
	if b.execOverride != nil {
		return b.execOverride(ctx, req)
	}
	return b.Exec(ctx, req)
}

func (b *Backend) PortForward(ctx context.Context, req backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	if !IsPodLocalForwardHost(req.Host) {
		return b.helperDial(ctx, req)
	}
	return b.podPortForward(ctx, req)
}

func (b *Backend) podPortForward(ctx context.Context, req backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	namespace, pod, _, err := kubeTarget(req.Target)
	if err != nil {
		return nil, err
	}
	if req.Port == 0 || req.Port > 65535 {
		return nil, status.InvalidTarget("invalid port %d", req.Port)
	}

	restReq := b.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("portforward")

	transport, upgrader, err := spdy.RoundTripperFor(b.restConfig)
	if err != nil {
		return nil, status.BackendFailure(err, "create portforward transport")
	}
	dialer := spdy.NewDialerForStreaming(upgrader, &http.Client{Transport: transport}, "POST", restReq.URL())
	conn, protocol, err := dialer.Dial(portforward.PortForwardProtocolV1Name)
	if err != nil {
		return nil, status.BackendFailure(err, "dial portforward")
	}
	if protocol != portforward.PortForwardProtocolV1Name {
		_ = conn.Close()
		return nil, status.BackendFailure(fmt.Errorf("unexpected protocol %q", protocol), "dial portforward")
	}

	port := strconv.FormatUint(uint64(req.Port), 10)
	headers := http.Header{}
	headers.Set(corev1.StreamType, corev1.StreamTypeError)
	headers.Set(corev1.PortHeader, port)
	headers.Set(corev1.PortForwardRequestIDHeader, "0")
	errorStream, err := conn.CreateStream(headers)
	if err != nil {
		_ = conn.Close()
		return nil, status.BackendFailure(err, "create portforward error stream")
	}
	_ = errorStream.Close()

	errorCh := make(chan error, 1)
	go func() {
		message, err := io.ReadAll(errorStream)
		switch {
		case err != nil:
			errorCh <- fmt.Errorf("read portforward error stream: %w", err)
		case len(message) > 0:
			errorCh <- fmt.Errorf("portforward remote error: %s", strings.TrimSpace(string(message)))
		default:
			errorCh <- nil
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
		errorCh:     errorCh,
	}, nil
}

func (b *Backend) helperDial(ctx context.Context, req backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	if req.Port == 0 || req.Port > 65535 {
		return nil, status.InvalidTarget("invalid port %d", req.Port)
	}
	helper, err := b.acquireHelper(ctx, req.Target, helperpkg.CapabilityDial)
	if err != nil {
		return nil, err
	}

	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderr := &safeBuffer{}

	stream := &helperDialStream{
		stdin:  stdinWriter,
		stdout: stdoutReader,
		done:   make(chan error, 1),
	}

	go func() {
		defer stdoutWriter.Close()
		defer func() { _ = helper.Release(context.WithoutCancel(ctx)) }()
		exitCode, err := b.runExec(ctx, backend.ExecRequest{
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
			stream.done <- err
			return
		}
		if exitCode != 0 {
			stream.done <- fmt.Errorf("helper dial exited with %d: %s", exitCode, strings.TrimSpace(stderr.String()))
			return
		}
		stream.done <- nil
	}()

	return stream, nil
}

type helperDialStream struct {
	stdin     *io.PipeWriter
	stdout    *io.PipeReader
	done      chan error
	closeOnce sync.Once
	closeErr  error
}

func (s *helperDialStream) Read(p []byte) (int, error) {
	return s.stdout.Read(p)
}

func (s *helperDialStream) Write(p []byte) (int, error) {
	return s.stdin.Write(p)
}

func (s *helperDialStream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.stdin.Close()
		_ = s.stdout.Close()
		select {
		case err := <-s.done:
			s.closeErr = err
		default:
		}
	})
	return s.closeErr
}

// CloseWrite closes the stdin pipe so the helper binary receives EOF on its
// stdin and knows the client has finished sending.
func (s *helperDialStream) CloseWrite() error {
	return s.stdin.Close()
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func kubeTarget(tgt *target.Target) (string, string, string, error) {
	if tgt == nil {
		return "", "", "", status.InvalidTarget("target is not specified")
	}
	if tgt.Kind != KindTarget {
		return "", "", "", status.InvalidTarget("unsupported target kind %q", tgt.Kind)
	}

	namespace := tgt.Option(OptionNamespaces)
	pod := tgt.Option(OptionPods)
	container := tgt.Option(OptionContainers)
	if namespace == "" || pod == "" {
		return "", "", "", status.InvalidTarget("kube target requires %q and %q options", OptionNamespaces, OptionPods)
	}
	return namespace, pod, container, nil
}

func IsPodLocalForwardHost(host string) bool {
	switch strings.ToLower(host) {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

type portForwardStream struct {
	conn        httpstream.Connection
	dataStream  httpstream.Stream
	errorStream httpstream.Stream
	errorCh     <-chan error
	closeOnce   sync.Once
	closeErr    error
}

func (s *portForwardStream) Read(p []byte) (int, error) {
	return s.dataStream.Read(p)
}

func (s *portForwardStream) Write(p []byte) (int, error) {
	return s.dataStream.Write(p)
}

func (s *portForwardStream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.dataStream.Reset()
		_ = s.dataStream.Close()
		_ = s.errorStream.Close()
		s.conn.RemoveStreams(s.dataStream, s.errorStream)
		s.closeErr = s.conn.Close()
		select {
		case err := <-s.errorCh:
			if err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		default:
		}
	})
	return s.closeErr
}

// CloseWrite is a no-op for SPDY portforward streams: the protocol does not
// support independent half-close of the write side. The full close of the
// connection will be handled by Close.
func (s *portForwardStream) CloseWrite() error { return nil }

type terminalSizeQueue struct {
	queue backend.TerminalSizeQueue
}

func (q terminalSizeQueue) Next() *remotecommand.TerminalSize {
	size := q.queue.Next()
	if size == nil {
		return nil
	}
	return &remotecommand.TerminalSize{Width: size.Width, Height: size.Height}
}
