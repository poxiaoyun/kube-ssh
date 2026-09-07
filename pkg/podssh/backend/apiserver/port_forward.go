package apiserver

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
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
)

// PortForward opens one Kubernetes pods/portforward stream.
func (t *Transport) PortForward(ctx context.Context, req backend.PodPortForwardRequest) (ioproxy.HalfCloser, error) {
	target, err := podtarget.Parse(req.Target)
	if err != nil {
		return nil, err
	}
	restRequest := t.client.
		CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Name(target.Pod).
		Namespace(target.Namespace).
		SubResource("portforward")

	roundTripper, upgrader, err := spdy.RoundTripperFor(t.restConfig)
	if err != nil {
		return nil, fmt.Errorf("create API Server port-forward transport: %w", err)
	}
	endpoint := restRequest.URL()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create API Server port-forward request: %w", err)
	}
	connection, protocol, err := spdy.NegotiateStreaming(upgrader, &http.Client{Transport: roundTripper}, httpRequest, portforward.PortForwardProtocolV1Name)
	if err != nil {
		return nil, fmt.Errorf("dial API Server port-forward: %w", err)
	}
	if protocol != portforward.PortForwardProtocolV1Name {
		_ = connection.Close()
		return nil, fmt.Errorf("dial API Server port-forward: unexpected protocol %q", protocol)
	}

	headers := http.Header{}
	headers.Set(corev1.StreamType, corev1.StreamTypeError)
	headers.Set(corev1.PortHeader, strconv.FormatUint(uint64(req.Port), 10))
	headers.Set(corev1.PortForwardRequestIDHeader, "0")
	errorStream, err := connection.CreateStream(headers)
	if err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("create API Server port-forward error stream: %w", err)
	}
	_ = errorStream.Close()

	result := make(chan error, 1)
	go func() {
		message, readErr := io.ReadAll(errorStream)
		if readErr != nil {
			result <- fmt.Errorf("read API Server port-forward error: %w", readErr)
			return
		}
		if len(message) != 0 {
			result <- fmt.Errorf("API Server port-forward: %s", strings.TrimSpace(string(message)))
			return
		}
		result <- nil
	}()

	headers.Set(corev1.StreamType, corev1.StreamTypeData)
	dataStream, err := connection.CreateStream(headers)
	if err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("create API Server port-forward data stream: %w", err)
	}
	return &portForwardStream{connection: connection, data: dataStream, result: result}, nil
}

type portForwardStream struct {
	connection httpstream.Connection
	data       httpstream.Stream
	result     <-chan error
	wait       sync.Once
	err        error
}

func (s *portForwardStream) Read(p []byte) (int, error)  { return s.data.Read(p) }
func (s *portForwardStream) Write(p []byte) (int, error) { return s.data.Write(p) }
func (s *portForwardStream) CloseWrite() error           { return s.data.Close() }

func (s *portForwardStream) Wait() error {
	s.wait.Do(func() {
		_ = s.data.Reset()
		s.err = <-s.result
	})
	return s.err
}

func (s *portForwardStream) Close() error {
	return s.connection.Close()
}
