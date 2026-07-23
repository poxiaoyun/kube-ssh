package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	utilproxy "k8s.io/apimachinery/pkg/util/proxy"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/version"
)

type ServerOptions struct {
	ListenAddress      string
	ManagementAddress  string
	RuntimeEndpoints   []string
	HelperPath         string
	HelperRemoteDir    string
	TLSCAFile          string
	TLSCertFile        string
	TLSKeyFile         string
	ExpectedClientName string
	ShutdownTimeout    time.Duration
	RuntimeTimeout     time.Duration
}

type Server struct {
	options         ServerOptions
	runtime         runtimeClient
	helper          *helperManager
	metrics         *metrics.PrometheusRecorder
	streamMu        sync.Mutex
	activeStreams   int
	streamsDraining bool
	streamsDrained  chan struct{}
	runtimeEndpoint string
}

var defaultRuntimeEndpoints = []string{
	"unix:///run/containerd/containerd.sock",
	"unix:///run/crio/crio.sock",
	"unix:///run/k3s/containerd/containerd.sock",
	"unix:///run/k0s/containerd.sock",
	"unix:///run/cri-dockerd.sock",
}

func Run(ctx context.Context, options ServerOptions) error {
	options = defaultServerOptions(options)
	if err := validateServerOptions(options); err != nil {
		return err
	}
	tlsConfig, tlsRuntime, err := loadServerTLS(options)
	if err != nil {
		return err
	}
	conn, runtime, endpoint, err := selectRuntime(ctx, options.RuntimeEndpoints, options.RuntimeTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	server := newServer(ctx, options, runtime, endpoint)
	return server.serve(ctx, tlsConfig, tlsRuntime)
}

func defaultServerOptions(options ServerOptions) ServerOptions {
	if options.ListenAddress == "" {
		options.ListenAddress = ":10443"
	}
	if options.ManagementAddress == "" {
		options.ManagementAddress = ":18080"
	}
	if len(options.RuntimeEndpoints) == 0 {
		options.RuntimeEndpoints = append([]string(nil), defaultRuntimeEndpoints...)
	}
	if options.ExpectedClientName == "" {
		options.ExpectedClientName = DefaultClientName
	}
	if options.ShutdownTimeout <= 0 {
		options.ShutdownTimeout = 30 * time.Second
	}
	if options.RuntimeTimeout <= 0 {
		options.RuntimeTimeout = 10 * time.Second
	}
	return options
}

func validateServerOptions(options ServerOptions) error {
	for _, endpoint := range options.RuntimeEndpoints {
		if !strings.HasPrefix(endpoint, "unix://") {
			return fmt.Errorf("CRI runtime endpoint %q must use unix://", endpoint)
		}
	}
	if info, err := os.Stat(options.HelperPath); err != nil {
		return fmt.Errorf("stat helper binary: %w", err)
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("helper path %q is not a regular file", options.HelperPath)
	}
	return nil
}

func newServer(ctx context.Context, options ServerOptions, runtime runtimeClient, runtimeEndpoint string) *Server {
	info := version.Get()
	recorder := metrics.NewPrometheusRecorder(nil, metrics.PrometheusOptions{
		Namespace: "kube_ssh_node",
		BuildInfo: metrics.BuildInfo{Version: info.GitVersion, Commit: info.GitCommit, BuildDate: info.BuildDate},
	})
	return &Server{
		options:         options,
		runtime:         runtime,
		helper:          newHelperManager(ctx, runtime, options.HelperPath, options.HelperRemoteDir),
		metrics:         recorder,
		runtimeEndpoint: runtimeEndpoint,
	}
}

func (s *Server) serve(ctx context.Context, tlsConfig *tls.Config, tlsRuntime *dynamicTLSRuntime) error {
	streamServer := &http.Server{
		Addr: s.options.ListenAddress, Handler: s.streamHandler(), TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
	}
	managementServer := &http.Server{
		Addr: s.options.ManagementAddress, Handler: s.managementHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	streamListener, err := net.Listen("tcp", s.options.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for node streams: %w", err)
	}
	defer streamListener.Close()
	managementListener, err := net.Listen("tcp", s.options.ManagementAddress)
	if err != nil {
		return fmt.Errorf("listen for node management: %w", err)
	}
	defer managementListener.Close()

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		tlsRuntime.Run(groupCtx)
		return nil
	})
	group.Go(func() error {
		err := streamServer.ServeTLS(streamListener, "", "")
		if groupCtx.Err() != nil && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
			return nil
		}
		return fmt.Errorf("serve node streams: %w", err)
	})
	group.Go(func() error {
		err := managementServer.Serve(managementListener)
		if groupCtx.Err() != nil && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
			return nil
		}
		return fmt.Errorf("serve node management: %w", err)
	})
	group.Go(func() error {
		<-groupCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.options.ShutdownTimeout)
		defer cancel()
		drained := s.startStreamDrain()
		_ = streamListener.Close()
		_ = managementListener.Close()
		managementErr := managementServer.Shutdown(shutdownCtx)
		streamErr := streamServer.Shutdown(shutdownCtx)
		select {
		case <-drained:
		case <-shutdownCtx.Done():
		}
		return errors.Join(managementErr, streamErr)
	})

	slog.Info("kube-ssh node started", "listen", s.options.ListenAddress, "management_listen", s.options.ManagementAddress, "runtime_endpoint", s.runtimeEndpoint)
	if err := group.Wait(); err != nil {
		return err
	}
	return ctx.Err()
}

func (s *Server) managementHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.Handle("GET /metrics", s.metrics.Handler())
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.checkRuntime(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) streamHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/exec/{namespace}/{pod}/{uid}/{container}", s.observe("exec", s.handleExec))
	mux.HandleFunc("POST /v1/helper/{namespace}/{pod}/{uid}/{container}/{capability}", s.observe("helper", s.handleHelper))
	mux.HandleFunc("POST /v1/portforward/{namespace}/{pod}/{uid}", s.observe("portforward", s.handlePortForward))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorizedPeer(r, s.options.ExpectedClientName) {
			http.Error(w, "unauthorized gateway certificate", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) observe(operation string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.beginStream() {
			http.Error(w, "node data plane is draining", http.StatusServiceUnavailable)
			return
		}
		defer s.endStream()
		s.metrics.StreamOpened(operation)
		defer s.metrics.StreamClosed(operation)
		handler(w, r)
	}
}

func (s *Server) beginStream() bool {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.streamsDraining {
		return false
	}
	s.activeStreams++
	return true
}

func (s *Server) endStream() {
	s.streamMu.Lock()
	s.activeStreams--
	if s.streamsDraining && s.activeStreams == 0 && s.streamsDrained != nil {
		close(s.streamsDrained)
		s.streamsDrained = nil
	}
	s.streamMu.Unlock()
}

func (s *Server) startStreamDrain() <-chan struct{} {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	s.streamsDraining = true
	drained := make(chan struct{})
	if s.activeStreams == 0 {
		close(drained)
	} else {
		s.streamsDrained = drained
	}
	return drained
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	identity := requestIdentity(r)
	if err := validateIdentity(identity, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target, err := resolveRuntimeTarget(r.Context(), s.runtime, identity, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	query := r.URL.Query()
	response, err := s.runtime.Exec(r.Context(), &runtimeapi.ExecRequest{
		ContainerId: target.ContainerID,
		Cmd:         query[QueryCommand],
		Stdin:       queryBool(query, QueryStdin),
		Stdout:      queryBool(query, QueryStdout),
		Stderr:      queryBool(query, QueryStderr),
		Tty:         queryBool(query, QueryTTY),
	})
	if err != nil {
		http.Error(w, "prepare CRI exec: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.proxyStream(w, r, response.Url)
}

func (s *Server) handleHelper(w http.ResponseWriter, r *http.Request) {
	identity := requestIdentity(r)
	if err := validateIdentity(identity, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target, err := resolveRuntimeTarget(r.Context(), s.runtime, identity, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	capability := r.PathValue("capability")
	helperPath, err := s.helper.prepare(r.Context(), target.ContainerID, capability)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	query := r.URL.Query()
	command := append([]string{helperPath}, query[QueryArgument]...)
	response, err := s.runtime.Exec(r.Context(), &runtimeapi.ExecRequest{
		ContainerId: target.ContainerID, Cmd: command,
		Stdin: queryBool(query, QueryStdin), Stdout: queryBool(query, QueryStdout), Stderr: queryBool(query, QueryStderr),
	})
	if err != nil {
		http.Error(w, "prepare helper exec: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.proxyStream(w, r, response.Url)
}

func (s *Server) handlePortForward(w http.ResponseWriter, r *http.Request) {
	identity := requestIdentity(r)
	if err := validateIdentity(identity, false); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target, err := resolveRuntimeTarget(r.Context(), s.runtime, identity, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	port, err := strconv.ParseInt(r.URL.Query().Get(QueryPort), 10, 32)
	if err != nil || port < 1 || port > 65535 {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}
	response, err := s.runtime.PortForward(r.Context(), &runtimeapi.PortForwardRequest{PodSandboxId: target.SandboxID, Port: []int32{int32(port)}})
	if err != nil {
		http.Error(w, "prepare CRI port-forward: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.proxyStream(w, r, response.Url)
}

func (s *Server) proxyStream(w http.ResponseWriter, r *http.Request, rawURL string) {
	target, err := parseStreamingURL(rawURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	var transport http.RoundTripper
	if target.Scheme == "https" {
		// CRI returns a short-lived capability URL but no CA material for its
		// streaming server. The URL comes from the privileged local Unix socket.
		transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} // #nosec G402
	}
	handler := utilproxy.NewUpgradeAwareHandler(target, transport, false, false, proxyResponder{})
	handler.ServeHTTP(w, r)
}

func (s *Server) checkRuntime(ctx context.Context) error {
	return checkRuntime(ctx, s.runtime)
}

func checkRuntime(ctx context.Context, runtime runtimeClient) error {
	if _, err := runtime.Version(ctx, &runtimeapi.VersionRequest{Version: "0.1.0"}); err != nil {
		return fmt.Errorf("CRI v1 version check: %w", err)
	}
	status, err := runtime.Status(ctx, &runtimeapi.StatusRequest{})
	if err != nil {
		return fmt.Errorf("CRI status: %w", err)
	}
	if status.Status == nil {
		return fmt.Errorf("CRI runtime returned no status")
	}
	for _, condition := range status.Status.GetConditions() {
		if condition.Type == runtimeapi.RuntimeReady && condition.Status {
			return nil
		}
	}
	return fmt.Errorf("CRI runtime is not ready")
}

func selectRuntime(ctx context.Context, endpoints []string, timeout time.Duration) (*grpc.ClientConn, runtimeClient, string, error) {
	var failures []error
	for _, endpoint := range endpoints {
		socketPath := strings.TrimPrefix(endpoint, "unix://")
		info, err := os.Stat(socketPath)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: stat socket: %w", endpoint, err))
			continue
		}
		if info.Mode()&os.ModeSocket == 0 {
			failures = append(failures, fmt.Errorf("%s: %s is not a Unix socket", endpoint, socketPath))
			continue
		}
		conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", endpoint, err))
			continue
		}
		runtime := runtimeapi.NewRuntimeServiceClient(conn)
		checkCtx, cancel := context.WithTimeout(ctx, timeout)
		err = checkRuntime(checkCtx, runtime)
		cancel()
		if err == nil {
			return conn, runtime, endpoint, nil
		}
		_ = conn.Close()
		failures = append(failures, fmt.Errorf("%s: %w", endpoint, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, nil, "", fmt.Errorf("no ready CRI v1 endpoint: %w", errors.Join(failures...))
}

type proxyResponder struct{}

func (proxyResponder) Error(w http.ResponseWriter, _ *http.Request, err error) {
	http.Error(w, "stream proxy: "+err.Error(), http.StatusBadGateway)
}

func requestIdentity(r *http.Request) podIdentity {
	return podIdentity{Namespace: r.PathValue("namespace"), Name: r.PathValue("pod"), UID: r.PathValue("uid"), Container: r.PathValue("container")}
}

func validateIdentity(identity podIdentity, needContainer bool) error {
	if identity.Namespace == "" || identity.Name == "" || identity.UID == "" {
		return fmt.Errorf("namespace, pod, and uid are required")
	}
	if needContainer && identity.Container == "" {
		return fmt.Errorf("container is required")
	}
	return nil
}

func queryBool(values url.Values, key string) bool {
	value, _ := strconv.ParseBool(values.Get(key))
	return value
}

func authorizedPeer(r *http.Request, expected string) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName == expected
}

type dynamicTLSRuntime struct {
	clientCA    *dynamiccertificates.DynamicFileCAContent
	servingCert *dynamiccertificates.DynamicCertKeyPairContent
	controller  *dynamiccertificates.DynamicServingCertificateController
}

func (r *dynamicTLSRuntime) Run(ctx context.Context) {
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		r.clientCA.Run(groupCtx, 1)
		return nil
	})
	group.Go(func() error {
		r.servingCert.Run(groupCtx, 1)
		return nil
	})
	group.Go(func() error {
		r.controller.Run(1, groupCtx.Done())
		return nil
	})
	_ = group.Wait()
}

func loadServerTLS(options ServerOptions) (*tls.Config, *dynamicTLSRuntime, error) {
	if options.TLSCAFile == "" || options.TLSCertFile == "" || options.TLSKeyFile == "" {
		return nil, nil, fmt.Errorf("node TLS CA, certificate, and key files are required")
	}
	clientCA, err := dynamiccertificates.NewDynamicCAContentFromFile("kube-ssh-node-client-ca", options.TLSCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load node client CA: %w", err)
	}
	servingCert, err := dynamiccertificates.NewDynamicServingContentFromFiles("kube-ssh-node-serving-cert", options.TLSCertFile, options.TLSKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load node server certificate: %w", err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert}
	controller := dynamiccertificates.NewDynamicServingCertificateController(tlsConfig, clientCA, servingCert, nil, nil)
	clientCA.AddListener(controller)
	servingCert.AddListener(controller)
	if err := controller.RunOnce(); err != nil {
		return nil, nil, fmt.Errorf("initialize node TLS configuration: %w", err)
	}
	tlsConfig.GetConfigForClient = controller.GetConfigForClient
	return tlsConfig, &dynamicTLSRuntime{clientCA: clientCA, servingCert: servingCert, controller: controller}, nil
}
