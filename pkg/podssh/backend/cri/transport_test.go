package cri_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/portforward"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend/cri"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
)

func TestExecRejectsReplacedPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", UID: types.UID("new-uid")},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, HostIP: "10.0.0.2"},
	}
	tgt := podtarget.New("default", "app", "app")
	// Model a target resolved before the Pod was recreated.
	old := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", UID: types.UID("old-uid")},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{HostIP: "10.0.0.2"},
	}
	bound := podtarget.Bind(old, "app")
	if tgt.String() != bound.String() {
		t.Fatalf("test targets differ: %s != %s", tgt.String(), bound.String())
	}
	transport := newTransport(t, fake.NewSimpleClientset(pod))
	_, err := transport.Exec(context.Background(), backend.ExecRequest{Target: bound})
	if !apierrors.IsConflict(err) || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("Exec() error = %v, want replacement Conflict", err)
	}
}

func TestExecRejectsUnboundTarget(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", UID: types.UID("uid-1")},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, HostIP: "10.0.0.2"},
	}
	transport := newTransport(t, fake.NewSimpleClientset(pod))
	_, err := transport.Exec(context.Background(), backend.ExecRequest{Target: podtarget.New("default", "app", "app")})
	if !apierrors.IsBadRequest(err) || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("Exec() error = %v, want unbound target BadRequest", err)
	}
}

func TestExecRejectsUnavailablePod(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodPending, corev1.PodSucceeded} {
		t.Run(string(phase), func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", UID: "uid-1"},
				Spec:       corev1.PodSpec{NodeName: "node-a"},
				Status:     corev1.PodStatus{Phase: phase, HostIP: "10.0.0.2"},
			}
			transport := newTransport(t, fake.NewSimpleClientset(pod))
			_, err := transport.Exec(context.Background(), backend.ExecRequest{Target: podtarget.Bind(pod, "app")})
			if !apierrors.IsServiceUnavailable(err) {
				t.Fatalf("Exec() error = %v, want ServiceUnavailable", err)
			}
		})
	}
}

func TestExecPreservesPodLookupCause(t *testing.T) {
	for _, cause := range []error{apierrors.NewNotFound(corev1.Resource("pods"), "app"), context.Canceled} {
		t.Run(cause.Error(), func(t *testing.T) {
			client := fake.NewSimpleClientset()
			client.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, cause
			})
			transport := newTransport(t, client)
			_, err := transport.Exec(context.Background(), backend.ExecRequest{Target: podtarget.New("default", "app", "app")})
			if !errors.Is(err, cause) {
				t.Fatalf("Exec() error = %v, want cause %v", err, cause)
			}
			if apierrors.IsNotFound(cause) && !apierrors.IsNotFound(err) {
				t.Fatalf("Exec() error = %v, want NotFound", err)
			}
		})
	}
}

func newTransport(t *testing.T, client kubernetes.Interface) *cri.Transport {
	t.Helper()
	transport, err := cri.New(client, cri.Options{
		ServerName: "kube-ssh-node", CAFile: "ca.crt", CertFile: "client.crt", KeyFile: "client.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func TestTransportAuthenticatesNodeStreams(t *testing.T) {
	certificate, key := nodeCertificate(t)
	otherCertificate, _ := nodeCertificate(t)
	identity, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certificate)
	dir := t.TempDir()
	for name, data := range map[string][]byte{"tls.crt": certificate, "tls.key": key, "other.crt": otherCertificate} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				if host == "::1" {
					t.Skipf("IPv6 loopback is unavailable: %v", err)
				}
				t.Fatal(err)
			}
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if len(r.TLS.VerifiedChains) == 0 || r.TLS.ServerName != "kube-ssh-node" {
					t.Errorf("node request has no verified client identity or unexpected server name")
				}
				http.Error(w, "authenticated node request", http.StatusForbidden)
			}))
			server.Listener.Close()
			server.Listener = listener
			server.TLS = &tls.Config{Certificates: []tls.Certificate{identity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			address := listener.Addr().
				String()
			_, portText, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", UID: "uid-1"},
				Spec:       corev1.PodSpec{NodeName: "node-a"},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning, HostIP: host},
			}
			tgt := podtarget.Bind(pod, "app")
			for _, operation := range []string{"exec", "helper", "portforward"} {
				for _, scenario := range []string{"mTLS", "wrong server name", "untrusted CA", "missing CA", "missing client key"} {
					t.Run(operation+"/"+scenario, func(t *testing.T) {
						options := cri.Options{
							Port: port, ServerName: "kube-ssh-node",
							CAFile: filepath.Join(dir, "tls.crt"), CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"),
						}
						switch scenario {
						case "wrong server name":
							options.ServerName = "other-node"
						case "untrusted CA":
							options.CAFile = filepath.Join(dir, "other.crt")
						case "missing CA":
							options.CAFile = filepath.Join(dir, "missing.crt")
						case "missing client key":
							options.KeyFile = filepath.Join(dir, "missing.key")
						}
						transport, err := cri.New(fake.NewSimpleClientset(pod), options)
						if err != nil {
							t.Fatal(err)
						}
						ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
						defer cancel()
						before := requests.Load()
						switch operation {
						case "exec":
							_, err = transport.Exec(ctx, backend.ExecRequest{Target: tgt, Command: []string{"true"}})
						case "helper":
							_, err = transport.ExecHelper(ctx, backend.HelperExecRequest{StreamRequest: backend.StreamRequest{Target: tgt}, Capability: "conn"})
						case "portforward":
							_, err = transport.PortForward(ctx, backend.PodPortForwardRequest{Target: tgt, Port: 8080})
						}
						if err == nil {
							t.Fatal("expected node rejection or TLS failure")
						}
						if scenario == "mTLS" {
							if requests.Load()-before != 1 || !strings.Contains(err.Error(), "authenticated node request") {
								t.Fatalf("request did not reach authenticated node handler: %v", err)
							}
							return
						}
						if requests.Load() != before {
							t.Fatal("invalid TLS configuration reached the node handler")
						}
						if scenario == "missing CA" || scenario == "missing client key" {
							if !errors.Is(err, os.ErrNotExist) {
								t.Fatalf("error = %v, want missing TLS file", err)
							}
						}
					})
				}
			}
		})
	}
}

func TestPortForwardCloseWriteDrainsResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream := openNodePortForward(t, ctx, func(data, errs httpstream.Stream) {
		defer data.Close()
		defer errs.Close()
		request, err := io.ReadAll(data)
		if err != nil {
			t.Errorf("read forwarded request: %v", err)
			return
		}
		if string(request) != "request" {
			t.Errorf("forwarded request = %q", request)
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
	type responseResult struct {
		data []byte
		err  error
	}
	finished := make(chan responseResult, 1)
	go func() {
		response, err := io.ReadAll(stream)
		if err != nil {
			finished <- responseResult{err: err}
			return
		}
		waiter := stream.(ioproxy.Waiter)
		finished <- responseResult{data: response, err: waiter.Wait()}
	}()
	select {
	case response := <-finished:
		if response.err != nil {
			t.Fatalf("read and wait after CloseWrite(): %v", response.err)
		}
		if string(response.data) != "response after EOF" {
			t.Fatalf("response = %q, want response after peer observed EOF", response.data)
		}
	case <-ctx.Done():
		t.Fatal("CloseWrite() did not allow the response to drain and finish")
	}
}

func TestPortForwardCloseUnblocksRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// The peer never sends data or FIN on either stream.
	stream := openNodePortForward(t, ctx, func(httpstream.Stream, httpstream.Stream) {})
	finished := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 1))
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
		t.Fatal("Close() did not release the data read")
	}
}

func TestPortForwardCloseUnblocksTerminalWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	dataReset := make(chan struct{})
	stream := openNodePortForward(t, ctx, func(data, errs httpstream.Stream) {
		_, _ = io.Copy(io.Discard, data)
		close(dataReset)
		// Keep the error stream open after observing Wait reset the data stream.
	})
	finished := make(chan error, 1)
	go func() {
		waiter := stream.(ioproxy.Waiter)
		finished <- waiter.Wait()
	}()
	select {
	case <-dataReset:
	case <-ctx.Done():
		t.Fatal("Wait() did not finish the data path")
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("Close() did not release the terminal wait")
	}
}

func openNodePortForward(t *testing.T, ctx context.Context, serve func(data, errs httpstream.Stream)) ioproxy.HalfCloser {
	t.Helper()
	certificate, key := nodeCertificate(t)
	identity, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certificate)
	dir := t.TempDir()
	for name, contents := range map[string][]byte{"tls.crt": certificate, "tls.key": key} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	finished := make(chan struct{})
	peerConnection := make(chan httpstream.Connection, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			headers := stream.Headers()
			streams[headers.Get(corev1.StreamType)] = stream.Stream
		}
		serve(streams[corev1.StreamTypeData], streams[corev1.StreamTypeError])
		<-connection.CloseChan()
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{identity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	address := server.Listener.Addr().
		String()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", UID: "uid-1"},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, HostIP: host},
	}
	transport, err := cri.New(fake.NewSimpleClientset(pod), cri.Options{
		Port: port, ServerName: "kube-ssh-node",
		CAFile: filepath.Join(dir, "tls.crt"), CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := transport.PortForward(ctx, backend.PodPortForwardRequest{Target: podtarget.Bind(pod, "app"), Port: 8080})
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

func nodeCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "kube-ssh-node"}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keyutil.MarshalPrivateKeyToPEM(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), key
}
