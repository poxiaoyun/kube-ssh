package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

type fakeRuntime struct {
	sandboxes  []*runtimeapi.PodSandbox
	containers []*runtimeapi.Container
	execURL    string
	lastExec   *runtimeapi.ExecRequest
	versionErr error
	status     *runtimeapi.StatusResponse
	statusErr  error
}

func (f *fakeRuntime) Version(context.Context, *runtimeapi.VersionRequest, ...grpc.CallOption) (*runtimeapi.VersionResponse, error) {
	if f.versionErr != nil {
		return nil, f.versionErr
	}
	return &runtimeapi.VersionResponse{}, nil
}
func (f *fakeRuntime) Status(context.Context, *runtimeapi.StatusRequest, ...grpc.CallOption) (*runtimeapi.StatusResponse, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	if f.status != nil {
		return f.status, nil
	}
	return &runtimeapi.StatusResponse{}, nil
}
func (f *fakeRuntime) ListPodSandbox(context.Context, *runtimeapi.ListPodSandboxRequest, ...grpc.CallOption) (*runtimeapi.ListPodSandboxResponse, error) {
	return &runtimeapi.ListPodSandboxResponse{Items: f.sandboxes}, nil
}
func (f *fakeRuntime) ListContainers(context.Context, *runtimeapi.ListContainersRequest, ...grpc.CallOption) (*runtimeapi.ListContainersResponse, error) {
	return &runtimeapi.ListContainersResponse{Containers: f.containers}, nil
}
func (f *fakeRuntime) Exec(_ context.Context, request *runtimeapi.ExecRequest, _ ...grpc.CallOption) (*runtimeapi.ExecResponse, error) {
	f.lastExec = request
	return &runtimeapi.ExecResponse{Url: f.execURL}, nil
}
func (f *fakeRuntime) ExecSync(context.Context, *runtimeapi.ExecSyncRequest, ...grpc.CallOption) (*runtimeapi.ExecSyncResponse, error) {
	return &runtimeapi.ExecSyncResponse{}, nil
}
func (f *fakeRuntime) PortForward(context.Context, *runtimeapi.PortForwardRequest, ...grpc.CallOption) (*runtimeapi.PortForwardResponse, error) {
	return &runtimeapi.PortForwardResponse{}, nil
}

func TestResolveRuntimeTargetUsesExactPodUIDAndContainer(t *testing.T) {
	runtime := &fakeRuntime{
		sandboxes: []*runtimeapi.PodSandbox{
			{Id: "old", State: runtimeapi.PodSandboxState_SANDBOX_READY, Metadata: &runtimeapi.PodSandboxMetadata{Name: "app", Namespace: "default", Uid: "old-uid"}},
			{Id: "wanted", State: runtimeapi.PodSandboxState_SANDBOX_READY, Metadata: &runtimeapi.PodSandboxMetadata{Name: "app", Namespace: "default", Uid: "uid-1"}},
		},
		containers: []*runtimeapi.Container{
			{Id: "sidecar-id", PodSandboxId: "wanted", Metadata: &runtimeapi.ContainerMetadata{Name: "sidecar"}, State: runtimeapi.ContainerState_CONTAINER_RUNNING},
			{Id: "app-id", PodSandboxId: "wanted", Metadata: &runtimeapi.ContainerMetadata{Name: "app"}, State: runtimeapi.ContainerState_CONTAINER_RUNNING},
		},
	}
	got, err := resolveRuntimeTarget(context.Background(), runtime, podIdentity{Namespace: "default", Name: "app", UID: "uid-1", Container: "app"}, true)
	if err != nil {
		t.Fatalf("resolveRuntimeTarget() error = %v", err)
	}
	if got.SandboxID != "wanted" || got.ContainerID != "app-id" {
		t.Fatalf("target = %#v", got)
	}
}

func TestResolveRuntimeTargetRejectsAmbiguousSandbox(t *testing.T) {
	metadata := &runtimeapi.PodSandboxMetadata{Name: "app", Namespace: "default", Uid: "uid-1"}
	runtime := &fakeRuntime{sandboxes: []*runtimeapi.PodSandbox{{Id: "one", State: runtimeapi.PodSandboxState_SANDBOX_READY, Metadata: metadata}, {Id: "two", State: runtimeapi.PodSandboxState_SANDBOX_READY, Metadata: metadata}}}
	_, err := resolveRuntimeTarget(context.Background(), runtime, podIdentity{Namespace: "default", Name: "app", UID: "uid-1"}, false)
	if err == nil || !strings.Contains(err.Error(), "multiple ready pod sandboxes") {
		t.Fatalf("resolveRuntimeTarget() error = %v", err)
	}
}

func TestParseStreamingURL(t *testing.T) {
	if _, err := parseStreamingURL("http://127.0.0.1:1234/exec/token"); err != nil {
		t.Fatalf("parseStreamingURL() error = %v", err)
	}
	for _, raw := range []string{"file:///tmp/socket", "http:///missing-host"} {
		if _, err := parseStreamingURL(raw); err == nil {
			t.Fatalf("parseStreamingURL(%q) error = nil", raw)
		}
	}
}

func TestExecHandlerResolvesCRIAndProxies(t *testing.T) {
	streaming := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "proxied")
	}))
	defer streaming.Close()
	runtime := &fakeRuntime{
		sandboxes:  []*runtimeapi.PodSandbox{{Id: "sandbox", State: runtimeapi.PodSandboxState_SANDBOX_READY, Metadata: &runtimeapi.PodSandboxMetadata{Name: "app", Namespace: "default", Uid: "uid-1"}}},
		containers: []*runtimeapi.Container{{Id: "container", State: runtimeapi.ContainerState_CONTAINER_RUNNING, Metadata: &runtimeapi.ContainerMetadata{Name: "main"}}},
		execURL:    streaming.URL,
	}
	server := &Server{
		options: ServerOptions{ExpectedClientName: DefaultClientName},
		runtime: runtime,
		metrics: metrics.NewPrometheusRecorder(nil, metrics.PrometheusOptions{Namespace: "test_node"}),
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/exec/default/app/uid-1/main?command=echo&command=ok&stdout=true", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: DefaultClientName}}}}
	response := httptest.NewRecorder()
	server.streamHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "proxied" {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	if runtime.lastExec == nil || runtime.lastExec.ContainerId != "container" || strings.Join(runtime.lastExec.Cmd, " ") != "echo ok" || !runtime.lastExec.Stdout {
		t.Fatalf("CRI Exec request = %#v", runtime.lastExec)
	}
}

func TestStreamHandlerRejectsWrongClientIdentity(t *testing.T) {
	server := &Server{options: ServerOptions{ExpectedClientName: DefaultClientName}}
	request := httptest.NewRequest(http.MethodPost, "/v1/exec/default/app/uid-1/main", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "other"}}}}
	response := httptest.NewRecorder()
	server.streamHandler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestManagementHandler(t *testing.T) {
	runtime := &fakeRuntime{status: readyRuntimeStatus()}
	server := &Server{
		runtime: runtime,
		metrics: metrics.NewPrometheusRecorder(nil, metrics.PrometheusOptions{Namespace: "test_node_management"}),
	}
	handler := server.managementHandler()
	for _, test := range []struct {
		name   string
		method string
		path   string
		status int
	}{
		{name: "health", method: http.MethodGet, path: "/healthz", status: http.StatusOK},
		{name: "ready", method: http.MethodGet, path: "/readyz", status: http.StatusOK},
		{name: "metrics", method: http.MethodGet, path: "/metrics", status: http.StatusOK},
		{name: "method not allowed", method: http.MethodPost, path: "/healthz", status: http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestManagementReadyHandlerReportsRuntimeFailure(t *testing.T) {
	server := &Server{
		runtime: &fakeRuntime{statusErr: errors.New("runtime unavailable")},
		metrics: metrics.NewPrometheusRecorder(nil, metrics.PrometheusOptions{Namespace: "test_node_unready"}),
	}
	response := httptest.NewRecorder()
	server.managementHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func readyRuntimeStatus() *runtimeapi.StatusResponse {
	return &runtimeapi.StatusResponse{Status: &runtimeapi.RuntimeStatus{Conditions: []*runtimeapi.RuntimeCondition{{
		Type: runtimeapi.RuntimeReady, Status: true,
	}}}}
}

type readyRuntimeServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
}

func (readyRuntimeServer) Version(context.Context, *runtimeapi.VersionRequest) (*runtimeapi.VersionResponse, error) {
	return &runtimeapi.VersionResponse{RuntimeName: "test"}, nil
}

func (readyRuntimeServer) Status(context.Context, *runtimeapi.StatusRequest) (*runtimeapi.StatusResponse, error) {
	return readyRuntimeStatus(), nil
}

func TestSelectRuntimeChecksEndpointsInOrder(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "runtime.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(grpcServer, readyRuntimeServer{})
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	endpoints := []string{
		"unix://" + filepath.Join(t.TempDir(), "missing.sock"),
		"unix://" + socket,
	}
	conn, _, selected, err := selectRuntime(context.Background(), endpoints, time.Second)
	if err != nil {
		t.Fatalf("selectRuntime() error = %v", err)
	}
	defer conn.Close()
	if selected != endpoints[1] {
		t.Fatalf("selected endpoint = %q, want %q", selected, endpoints[1])
	}
}

func TestDefaultServerOptionsIncludesCommonRuntimeEndpoints(t *testing.T) {
	options := defaultServerOptions(ServerOptions{})
	if len(options.RuntimeEndpoints) < 5 {
		t.Fatalf("runtime endpoints = %v", options.RuntimeEndpoints)
	}
	for _, expected := range []string{"containerd", "crio", "k3s", "k0s", "cri-dockerd"} {
		if !strings.Contains(strings.Join(options.RuntimeEndpoints, "\n"), expected) {
			t.Errorf("runtime endpoints do not include %q: %v", expected, options.RuntimeEndpoints)
		}
	}
}
