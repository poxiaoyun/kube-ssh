package nodebackend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/kube"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	nodeprotocol "xiaoshiai.cn/kube-ssh/pkg/node"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type Options struct {
	Port       int
	ServerName string
	CAFile     string
	CertFile   string
	KeyFile    string
	Metrics    metrics.Recorder
}

type transport struct {
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

func New(client kubernetes.Interface, options Options) (backend.Backend, error) {
	if client == nil {
		return nil, fmt.Errorf("node backend requires a Kubernetes client")
	}
	if options.Port == 0 {
		options.Port = nodeprotocol.DefaultStreamPort
	}
	if options.Port < 1 || options.Port > 65535 {
		return nil, fmt.Errorf("node port %d is invalid", options.Port)
	}
	if options.ServerName == "" || options.CAFile == "" || options.CertFile == "" || options.KeyFile == "" {
		return nil, fmt.Errorf("node server name, CA, client certificate, and client key are required")
	}
	if err := validateClientTLS(options); err != nil {
		return nil, err
	}
	t := &transport{client: client, options: options}
	inner := kube.NewBackend(nil, nil, kube.BackendOptions{
		Metrics:              options.Metrics,
		ExecTransport:        t.exec,
		PortForwardTransport: t.portForward,
		HelperExecTransport:  t.execHelper,
	})
	return inner, nil
}

func validateClientTLS(options Options) error {
	caData, err := os.ReadFile(options.CAFile)
	if err != nil {
		return fmt.Errorf("read node CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return fmt.Errorf("node CA contains no certificates")
	}
	if _, err := tls.LoadX509KeyPair(options.CertFile, options.KeyFile); err != nil {
		return fmt.Errorf("load node client certificate: %w", err)
	}
	return nil
}

func (t *transport) locate(ctx context.Context, target *target.Target) (podLocation, error) {
	podTarget, err := kube.ParseTarget(target)
	if err != nil {
		return podLocation{}, err
	}
	pod, err := t.client.CoreV1().Pods(podTarget.Namespace).Get(ctx, podTarget.Pod, metav1.GetOptions{})
	if err != nil {
		return podLocation{}, status.BackendFailure(err, "resolve target pod for node backend")
	}
	if pod.UID == "" || pod.Spec.NodeName == "" || pod.Status.HostIP == "" {
		return podLocation{}, status.InvalidTarget("pod %s/%s is not assigned to a reachable node", pod.Namespace, pod.Name)
	}
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return podLocation{}, status.InvalidTarget("pod %s/%s is not running", pod.Namespace, pod.Name)
	}
	resolvedUID := target.RuntimeValue(kube.RuntimePodUID)
	resolvedNode := target.RuntimeValue(kube.RuntimeNodeName)
	resolvedHostIP := target.RuntimeValue(kube.RuntimeHostIP)
	if resolvedUID == "" || resolvedNode == "" || resolvedHostIP == "" {
		return podLocation{}, status.InvalidTarget("pod %s/%s target is not bound to a node instance", pod.Namespace, pod.Name)
	}
	if resolvedUID != string(pod.UID) {
		return podLocation{}, status.InvalidTarget("pod %s/%s was replaced after target resolution", pod.Namespace, pod.Name)
	}
	if resolvedNode != pod.Spec.NodeName || resolvedHostIP != pod.Status.HostIP {
		return podLocation{}, status.InvalidTarget("pod %s/%s moved after target resolution", pod.Namespace, pod.Name)
	}
	return podLocation{
		Namespace: pod.Namespace, Pod: pod.Name, UID: string(pod.UID), Container: podTarget.Container,
		HostIP: pod.Status.HostIP, NodeName: pod.Spec.NodeName,
	}, nil
}

func (t *transport) exec(ctx context.Context, req backend.ExecRequest) (int, error) {
	location, err := t.locate(ctx, req.Target)
	if err != nil {
		return 1, err
	}
	u := t.endpoint(location, "exec", location.Container)
	query := u.Query()
	for _, value := range req.Command {
		query.Add(nodeprotocol.QueryCommand, value)
	}
	query.Set(nodeprotocol.QueryStdin, strconv.FormatBool(req.Stdin != nil))
	query.Set(nodeprotocol.QueryStdout, strconv.FormatBool(req.Stdout != nil))
	query.Set(nodeprotocol.QueryStderr, strconv.FormatBool(!req.TTY && req.Stderr != nil))
	query.Set(nodeprotocol.QueryTTY, strconv.FormatBool(req.TTY))
	u.RawQuery = query.Encode()
	executor, err := remotecommand.NewSPDYExecutor(t.restConfig(u), http.MethodPost, u)
	if err != nil {
		return 1, status.BackendFailure(err, "create node executor")
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
		return 1, status.BackendFailure(err, "node exec stream")
	}
	return 0, nil
}

func (t *transport) execHelper(ctx context.Context, target *target.Target, capability string, command []string, stream backend.StreamRequest) (int, error) {
	location, err := t.locate(ctx, target)
	if err != nil {
		return 1, err
	}
	u := t.endpoint(location, "helper", location.Container, capability)
	query := u.Query()
	for _, value := range command {
		query.Add(nodeprotocol.QueryArgument, value)
	}
	query.Set(nodeprotocol.QueryStdin, strconv.FormatBool(stream.Stdin != nil))
	query.Set(nodeprotocol.QueryStdout, strconv.FormatBool(stream.Stdout != nil))
	query.Set(nodeprotocol.QueryStderr, strconv.FormatBool(stream.Stderr != nil))
	u.RawQuery = query.Encode()
	executor, err := remotecommand.NewSPDYExecutor(t.restConfig(u), http.MethodPost, u)
	if err != nil {
		return 1, status.BackendFailure(err, "create node helper executor")
	}
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: stream.Stdin, Stdout: stream.Stdout, Stderr: stream.Stderr})
	if err != nil {
		var exitError interface{ ExitStatus() int }
		if errors.As(err, &exitError) {
			return exitError.ExitStatus(), nil
		}
		return 1, status.BackendFailure(err, "node helper stream")
	}
	return 0, nil
}

func (t *transport) portForward(ctx context.Context, req backend.PortForwardRequest) (ioproxy.HalfCloser, error) {
	if req.Port == 0 || req.Port > 65535 {
		return nil, status.InvalidTarget("invalid port %d", req.Port)
	}
	location, err := t.locate(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	u := t.endpoint(location, "portforward")
	query := u.Query()
	query.Set(nodeprotocol.QueryPort, strconv.FormatUint(uint64(req.Port), 10))
	u.RawQuery = query.Encode()
	config := t.restConfig(u)
	roundTripper, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, status.BackendFailure(err, "create node port-forward transport")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, status.BackendFailure(err, "create node port-forward request")
	}
	conn, protocol, err := spdy.NegotiateStreaming(upgrader, &http.Client{Transport: roundTripper}, httpRequest, portforward.PortForwardProtocolV1Name)
	if err != nil {
		return nil, status.BackendFailure(err, "dial node port-forward")
	}
	if protocol != portforward.PortForwardProtocolV1Name {
		_ = conn.Close()
		return nil, status.BackendFailure(fmt.Errorf("unexpected protocol %q", protocol), "dial node port-forward")
	}
	headers := http.Header{}
	headers.Set(corev1.StreamType, corev1.StreamTypeError)
	headers.Set(corev1.PortHeader, strconv.FormatUint(uint64(req.Port), 10))
	headers.Set(corev1.PortForwardRequestIDHeader, "0")
	errorStream, err := conn.CreateStream(headers)
	if err != nil {
		_ = conn.Close()
		return nil, status.BackendFailure(err, "create node port-forward error stream")
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
		return nil, status.BackendFailure(err, "create node port-forward data stream")
	}
	return &forwardStream{conn: conn, data: dataStream, errs: errorStream, result: result}, nil
}

func (t *transport) endpoint(location podLocation, operation string, suffix ...string) *url.URL {
	parts := []string{"", nodeprotocol.APIVersion, operation, location.Namespace, location.Pod, location.UID}
	for _, value := range suffix {
		parts = append(parts, value)
	}
	return &url.URL{Scheme: "https", Host: net.JoinHostPort(location.HostIP, strconv.Itoa(t.options.Port)), Path: strings.Join(parts, "/")}
}

func (t *transport) restConfig(endpoint *url.URL) *rest.Config {
	return &rest.Config{
		Host: endpoint.Scheme + "://" + endpoint.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile: t.options.CAFile, CertFile: t.options.CertFile, KeyFile: t.options.KeyFile, ServerName: t.options.ServerName,
		},
	}
}

type terminalSizeQueue struct{ backend.TerminalSizeQueue }

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
	errs   httpstream.Stream
	result <-chan error
	reset  sync.Once
	wait   sync.Once
	err    error
}

func (s *forwardStream) Read(p []byte) (int, error)  { return s.data.Read(p) }
func (s *forwardStream) Write(p []byte) (int, error) { return s.data.Write(p) }
func (s *forwardStream) CloseWrite() error           { return nil }
func (s *forwardStream) Wait() error {
	s.reset.Do(func() { _ = s.data.Reset() })
	s.wait.Do(func() { s.err = <-s.result })
	return s.err
}
func (s *forwardStream) Close() error {
	_ = s.data.Close()
	_ = s.errs.Close()
	s.conn.RemoveStreams(s.data, s.errs)
	return s.conn.Close()
}
