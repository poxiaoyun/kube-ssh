// Package cri implements Pod backend transport through the node-local CRI data plane.
package cri

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type Options struct {
	Port       int
	ServerName string
	CAFile     string
	CertFile   string
	KeyFile    string
}

// Transport executes Pod backend primitives through the node-local CRI data plane.
type Transport struct {
	client  kubernetes.Interface
	options Options
}

type podLocation struct {
	Namespace string
	Pod       string
	UID       string
	Container string
	HostIP    string
	NodeName  string
}

// New creates a gateway-to-node CRI transport.
func New(client kubernetes.Interface, options Options) (*Transport, error) {
	if options.Port == 0 {
		options.Port = DefaultStreamPort
	}
	if options.Port < 1 || options.Port > 65535 {
		return nil, fmt.Errorf("node port %d is invalid", options.Port)
	}
	if options.ServerName == "" || options.CAFile == "" || options.CertFile == "" || options.KeyFile == "" {
		return nil, fmt.Errorf("node server name, CA, client certificate, and client key are required")
	}
	return &Transport{client: client, options: options}, nil
}

func (t *Transport) locate(ctx context.Context, target *target.Target) (podLocation, error) {
	podTarget, err := podtarget.Parse(target)
	if err != nil {
		return podLocation{}, err
	}
	pod, err := t.client.
		CoreV1().
		Pods(podTarget.Namespace).
		Get(ctx, podTarget.Pod, metav1.GetOptions{})
	if err != nil {
		return podLocation{}, fmt.Errorf("resolve target Pod for CRI transport: %w", err)
	}
	if pod.UID == "" || pod.Spec.NodeName == "" || pod.Status.HostIP == "" {
		return podLocation{}, apierrors.NewServiceUnavailable(fmt.Sprintf("pod %s/%s is not assigned to a reachable node", pod.Namespace, pod.Name))
	}
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return podLocation{}, apierrors.NewServiceUnavailable(fmt.Sprintf("pod %s/%s is not running", pod.Namespace, pod.Name))
	}
	binding := podtarget.BoundIdentity(target)
	if binding.UID == "" || binding.NodeName == "" || binding.HostIP == "" {
		return podLocation{}, apierrors.NewBadRequest(fmt.Sprintf("pod %s/%s target is not bound to a node instance", pod.Namespace, pod.Name))
	}
	if binding.UID != string(pod.UID) {
		return podLocation{}, apierrors.NewConflict(corev1.Resource("pods"), pod.Name, fmt.Errorf("pod %s/%s was replaced after target resolution", pod.Namespace, pod.Name))
	}
	if binding.NodeName != pod.Spec.NodeName || binding.HostIP != pod.Status.HostIP {
		return podLocation{}, apierrors.NewConflict(corev1.Resource("pods"), pod.Name, fmt.Errorf("pod %s/%s moved after target resolution", pod.Namespace, pod.Name))
	}
	return podLocation{
		Namespace: pod.Namespace, Pod: pod.Name, UID: string(pod.UID), Container: podTarget.Container,
		HostIP: pod.Status.HostIP, NodeName: pod.Spec.NodeName,
	}, nil
}

// Exec runs a command through the target node's CRI streaming server.
func (t *Transport) Exec(ctx context.Context, req backend.ExecRequest) (int, error) {
	location, err := t.locate(ctx, req.Target)
	if err != nil {
		return 1, err
	}
	u := t.endpoint(location, "exec", location.Container)
	query := u.Query()
	for _, value := range req.Command {
		query.Add(QueryCommand, value)
	}
	query.Set(QueryStdin, strconv.FormatBool(req.Stdin != nil))
	query.Set(QueryStdout, strconv.FormatBool(req.Stdout != nil))
	query.Set(QueryStderr, strconv.FormatBool(!req.TTY && req.Stderr != nil))
	query.Set(QueryTTY, strconv.FormatBool(req.TTY))
	u.RawQuery = query.Encode()
	executor, err := remotecommand.NewSPDYExecutor(t.restConfig(u), http.MethodPost, u)
	if err != nil {
		return 1, fmt.Errorf("create node executor: %w", err)
	}
	streamOptions := remotecommand.StreamOptions{Stdin: req.Stdin, Stdout: req.Stdout, Tty: req.TTY}
	if !req.TTY {
		streamOptions.Stderr = req.Stderr
	}
	if req.TerminalSizeQueue != nil {
		streamOptions.TerminalSizeQueue = terminalSizeQueue{req.TerminalSizeQueue}
	}
	if err := executor.StreamWithContext(ctx, streamOptions); err != nil {
		var exitError interface{ ExitStatus() int }
		if errors.As(err, &exitError) {
			return exitError.ExitStatus(), nil
		}
		return 1, fmt.Errorf("node exec stream: %w", err)
	}
	return 0, nil
}

// ExecHelper asks the target node to prepare and run one helper command.
func (t *Transport) ExecHelper(ctx context.Context, req backend.HelperExecRequest) (int, error) {
	location, err := t.locate(ctx, req.Target)
	if err != nil {
		return 1, err
	}
	u := t.endpoint(location, "helper", location.Container, req.Capability)
	query := u.Query()
	for _, value := range req.Command {
		query.Add(QueryArgument, value)
	}
	query.Set(QueryStdin, strconv.FormatBool(req.Stdin != nil))
	query.Set(QueryStdout, strconv.FormatBool(req.Stdout != nil))
	query.Set(QueryStderr, strconv.FormatBool(req.Stderr != nil))
	u.RawQuery = query.Encode()
	executor, err := remotecommand.NewSPDYExecutor(t.restConfig(u), http.MethodPost, u)
	if err != nil {
		return 1, fmt.Errorf("create node helper executor: %w", err)
	}
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: req.Stdin, Stdout: req.Stdout, Stderr: req.Stderr})
	if err != nil {
		var exitError interface{ ExitStatus() int }
		if errors.As(err, &exitError) {
			return exitError.ExitStatus(), nil
		}
		return 1, fmt.Errorf("node helper stream: %w", err)
	}
	return 0, nil
}

// PortForward opens a Pod-local port-forward through the target node.
func (t *Transport) PortForward(ctx context.Context, req backend.PodPortForwardRequest) (ioproxy.HalfCloser, error) {
	location, err := t.locate(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	u := t.endpoint(location, "portforward")
	query := u.Query()
	query.Set(QueryPort, strconv.FormatUint(uint64(req.Port), 10))
	u.RawQuery = query.Encode()
	config := t.restConfig(u)
	roundTripper, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, fmt.Errorf("create node port-forward transport: %w", err)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create node port-forward request: %w", err)
	}
	conn, protocol, err := spdy.NegotiateStreaming(upgrader, &http.Client{Transport: roundTripper}, httpRequest, portforward.PortForwardProtocolV1Name)
	if err != nil {
		return nil, fmt.Errorf("dial node port-forward: %w", err)
	}
	if protocol != portforward.PortForwardProtocolV1Name {
		_ = conn.Close()
		return nil, fmt.Errorf("dial node port-forward: unexpected protocol %q", protocol)
	}
	headers := http.Header{}
	headers.Set(corev1.StreamType, corev1.StreamTypeError)
	headers.Set(corev1.PortHeader, strconv.FormatUint(uint64(req.Port), 10))
	headers.Set(corev1.PortForwardRequestIDHeader, "0")
	errorStream, err := conn.CreateStream(headers)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create node port-forward error stream: %w", err)
	}
	_ = errorStream.Close()
	result := make(chan error, 1)
	go func() {
		message, readErr := io.ReadAll(errorStream)
		if readErr != nil {
			result <- fmt.Errorf("read node port-forward error: %w", readErr)
		} else if len(message) != 0 {
			result <- fmt.Errorf("node port-forward: %s", strings.TrimSpace(string(message)))
		} else {
			result <- nil
		}
	}()
	headers.Set(corev1.StreamType, corev1.StreamTypeData)
	dataStream, err := conn.CreateStream(headers)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create node port-forward data stream: %w", err)
	}
	return &forwardStream{conn: conn, data: dataStream, result: result}, nil
}

func (t *Transport) endpoint(location podLocation, operation string, suffix ...string) *url.URL {
	parts := []string{"", APIVersion, operation, location.Namespace, location.Pod, location.UID}
	parts = append(parts, suffix...)
	return &url.URL{Scheme: "https", Host: net.JoinHostPort(location.HostIP, strconv.Itoa(t.options.Port)), Path: strings.Join(parts, "/")}
}

func (t *Transport) restConfig(endpoint *url.URL) *rest.Config {
	return &rest.Config{
		Host: endpoint.Scheme + "://" + endpoint.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile: t.options.CAFile, CertFile: t.options.CertFile, KeyFile: t.options.KeyFile, ServerName: t.options.ServerName,
		},
	}
}

type terminalSizeQueue struct {
	backend.TerminalSizeQueue
}

func (q terminalSizeQueue) Next() *remotecommand.TerminalSize {
	size := q.TerminalSizeQueue.Next()
	if size == nil {
		return nil
	}
	return &remotecommand.TerminalSize{Width: size.Width, Height: size.Height}
}

type forwardStream struct {
	conn   httpstream.Connection
	data   httpstream.Stream
	result <-chan error
	wait   sync.Once
	err    error
}

func (s *forwardStream) Read(p []byte) (int, error)  { return s.data.Read(p) }
func (s *forwardStream) Write(p []byte) (int, error) { return s.data.Write(p) }
func (s *forwardStream) CloseWrite() error           { return s.data.Close() }
func (s *forwardStream) Wait() error {
	s.wait.Do(func() {
		_ = s.data.Reset()
		s.err = <-s.result
	})
	return s.err
}
func (s *forwardStream) Close() error {
	return s.conn.Close()
}
