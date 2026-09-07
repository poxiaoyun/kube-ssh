package apiserver_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend/apiserver"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
)

func TestPortForwardWaitsForRemoteError(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	dataStopped := make(chan struct{})
	releaseError := make(chan struct{})
	stream := openAPIServerPortForward(t, ctx, func(data, errs httpstream.Stream) {
		_, _ = data.Read(make([]byte, 1))
		close(dataStopped)
		select {
		case <-releaseError:
		case <-ctx.Done():
			return
		}
		_, _ = io.WriteString(errs, "remote port-forward failed")
		_ = errs.Close()
	})

	waited := make(chan error, 1)
	go func() {
		waited <- stream.(ioproxy.Waiter).
			Wait()
	}()
	select {
	case <-dataStopped:
	case <-ctx.Done():
		t.Fatal("Wait() did not reset the data stream")
	}
	select {
	case err := <-waited:
		t.Fatalf("Wait() returned before the error stream completed: %v", err)
	default:
	}
	close(releaseError)
	select {
	case err := <-waited:
		if err == nil || !strings.Contains(err.Error(), "remote port-forward failed") {
			t.Fatalf("Wait() error = %v, want remote port-forward failure", err)
		}
	case <-ctx.Done():
		t.Fatal("Wait() did not return after the error stream completed")
	}
}

func TestPortForwardCloseWriteDrainsResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream := openAPIServerPortForward(t, ctx, func(data, errs httpstream.Stream) {
		defer data.Close()
		defer errs.Close()
		request, err := io.ReadAll(data)
		if err != nil {
			t.Errorf("read forwarded request: %v", err)
			return
		}
		if string(request) != "request" {
			t.Errorf("forwarded request = %q, want request", request)
			return
		}
		if _, err := io.WriteString(data, "response after EOF"); err != nil {
			t.Errorf("write forwarded response: %v", err)
		}
	})

	if _, err := io.WriteString(stream, "request"); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite(): %v", err)
	}
	type result struct {
		response []byte
		err      error
	}
	finished := make(chan result, 1)
	go func() {
		response, err := io.ReadAll(stream)
		if err != nil {
			finished <- result{err: err}
			return
		}
		finished <- result{response: response, err: stream.(ioproxy.Waiter).
			Wait()}
	}()
	select {
	case got := <-finished:
		if got.err != nil {
			t.Fatalf("drain response after CloseWrite(): %v", got.err)
		}
		if string(got.response) != "response after EOF" {
			t.Fatalf("response = %q, want response after peer observed EOF", got.response)
		}
	case <-ctx.Done():
		t.Fatal("CloseWrite() did not let the peer receive EOF and return its response")
	}
}

func TestPortForwardCloseUnblocksReadAndWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// The peer intentionally sends neither data nor FIN on either stream.
	stream := openAPIServerPortForward(t, ctx, func(httpstream.Stream, httpstream.Stream) {})
	finished := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 1))
		_ = stream.(ioproxy.Waiter).
			Wait()
		finished <- err
	}()

	if err := stream.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	select {
	case err := <-finished:
		if err != nil {
			return
		}
		t.Fatal("Read() succeeded although the peer sent no data")
	case <-ctx.Done():
		t.Fatal("Close() did not release the data read and terminal wait")
	}
}

func openAPIServerPortForward(t *testing.T, ctx context.Context, serve func(data, errs httpstream.Stream)) ioproxy.HalfCloser {
	t.Helper()
	finished := make(chan struct{})
	peerConnection := make(chan httpstream.Connection, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		if _, err := httpstream.Handshake(r, w, []string{portforward.PortForwardProtocolV1Name}); err != nil {
			t.Errorf("negotiate port-forward: %v", err)
			return
		}
		type incomingStream struct {
			httpstream.Stream
			acknowledged <-chan struct{}
		}
		incoming := make(chan incomingStream, 2)
		upgrader := spdy.NewResponseUpgrader()
		connection := upgrader.UpgradeResponse(w, r, func(stream httpstream.Stream, acknowledged <-chan struct{}) error {
			incoming <- incomingStream{Stream: stream, acknowledged: acknowledged}
			return nil
		})
		if connection == nil {
			t.Error("port-forward upgrade failed")
			return
		}
		peerConnection <- connection
		defer connection.Close()
		streams := make(map[string]httpstream.Stream, 2)
		for range 2 {
			stream := <-incoming
			<-stream.acknowledged
			streamType := stream.
				Headers().
				Get(corev1.StreamType)
			streams[streamType] = stream.Stream
		}
		serve(streams[corev1.StreamTypeData], streams[corev1.StreamTypeError])
		<-connection.CloseChan()
	}))
	t.Cleanup(server.Close)

	config := &rest.Config{Host: server.URL}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	transport := apiserver.New(client, config, apiserver.Options{})
	stream, err := transport.PortForward(ctx, backend.PodPortForwardRequest{
		Target: podtarget.New("default", "app", "app"),
		Port:   8080,
	})
	if err != nil {
		t.Fatalf("PortForward(): %v", err)
	}
	peer := <-peerConnection
	t.Cleanup(func() {
		_ = stream.Close()
		_ = peer.Close()
		<-finished
	})
	return stream
}
