// Package gateway runs the kube-ssh ingress and coordinates connection policy.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// RunWithDependencies supplies the required collaborators and defaults once.
// AccessPolicy and target-specific adapters remain optional.
type gateway struct {
	opts         *Options
	authn        authn.SSHAuthenticator
	authz        authz.Authorizer
	resolver     target.Resolver
	accessPolicy accesspolicy.AccessGetter
	podBackend   backend.Backend
	sshProxy     sshproxy.ConnectionConnector
	audit        audit.Recorder
	metrics      metrics.Recorder
}

// Run builds the gateway from opts and runs it until ctx is cancelled.
func Run(ctx context.Context, opts *Options) error {
	if opts == nil {
		opts = NewDefaultOptions()
	}

	deps, err := buildDependencies(ctx, opts)
	if err != nil {
		return err
	}
	return RunWithDependencies(ctx, opts, deps)
}

// RunWithDependencies runs the gateway with caller-provided runtime dependencies.
func RunWithDependencies(ctx context.Context, opts *Options, deps Dependencies) error {
	if opts == nil {
		opts = NewDefaultOptions()
	}
	if deps.Stop != nil {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := deps.Stop(shutdownCtx); err != nil {
				slog.Error("stop dependencies", "err", err)
			}
		}()
	}
	methods, err := enabledAuthenticationMethods(opts.Authentication.Methods)
	if err != nil {
		return err
	}
	if err := deps.Validate(); err != nil {
		return fmt.Errorf("invalid dependencies: %w", err)
	}
	if err := validatePolicyOptions(opts); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}
	if _, ok := deps.Authorizer.(*policyGuardedAuthorizer); !ok {
		guarded, err := withPolicyGuards(opts, deps.Authorizer)
		if err != nil {
			return fmt.Errorf("invalid policy: %w", err)
		}
		deps.Authorizer = guarded
	}
	if deps.Metrics == nil {
		deps.Metrics = metrics.NopRecorder{}
	}

	if deps.Start != nil {
		if err := deps.Start(ctx); err != nil {
			return fmt.Errorf("start dependencies: %w", err)
		}
	}
	s := &gateway{
		opts:         opts,
		authn:        deps.Authenticator,
		authz:        deps.Authorizer,
		audit:        deps.AuditRecorder,
		metrics:      deps.Metrics,
		resolver:     deps.Resolver,
		accessPolicy: deps.AccessPolicy,
		podBackend:   deps.PodBackend,
		sshProxy:     deps.SSHProxy,
	}
	signer, err := loadHostKey(opts.HostKeyFile)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", opts.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen SSH: %w", err)
	}
	defer listener.Close()

	slog.InfoContext(ctx, "kube-ssh listening", "addr", s.opts.ListenAddress)

	metricsSrv, metricsListener, err := startMetricsServer(ctx, s.opts.Metrics, s.metrics)
	if err != nil {
		return err
	}

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		err := s.serveSSH(groupCtx, listener, signer, methods)
		if groupCtx.Err() != nil {
			return nil
		}
		return err
	})
	if metricsSrv != nil {
		group.Go(func() error {
			err := metricsSrv.Serve(metricsListener)
			if errors.Is(err, http.ErrServerClosed) || groupCtx.Err() != nil {
				return nil
			}
			return err
		})
	}
	// SSH and metrics listeners share one shutdown path so either server error
	// tears down the other listener instead of leaving a background goroutine.
	group.Go(func() error {
		<-groupCtx.Done()
		_ = listener.Close()
		shutdownHTTPServer(metricsSrv)
		return nil
	})

	err = group.Wait()
	if err != nil {
		return err
	}
	return ctx.Err()
}

func startMetricsServer(ctx context.Context, opts MetricsOptions, recorder metrics.Recorder) (*http.Server, net.Listener, error) {
	if opts.ListenAddress == "" {
		return nil, nil, nil
	}
	path := opts.Path
	if path == "" {
		path = "/metrics"
	}
	if !strings.HasPrefix(path, "/") {
		return nil, nil, fmt.Errorf("metrics path must start with /")
	}
	if path == "/healthz" || path == "/readyz" {
		return nil, nil, fmt.Errorf("metrics path %q conflicts with a health endpoint", path)
	}
	provider, ok := recorder.(metrics.HandlerProvider)
	if !ok {
		return nil, nil, fmt.Errorf("metrics recorder does not provide an HTTP handler")
	}

	mux := http.NewServeMux()
	mux.Handle(path, provider.Handler())
	healthHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().
			Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/readyz", healthHandler)

	listener, err := net.Listen("tcp", opts.ListenAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("listen metrics: %w", err)
	}
	srv := &http.Server{Handler: mux}
	slog.InfoContext(ctx, "kube-ssh metrics listening", "addr", listener.Addr().
		String(), "path", path)
	return srv, listener, nil
}

func shutdownHTTPServer(srv *http.Server) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func (s *gateway) acceptAuthenticated(ctx *connectionState, info *authn.AuthenticateInfo, publicKeyFingerprint, credential string) bool {
	tgt, err := s.resolver.Resolve(ctx, target.ResolveInput{
		SSHUser:   ctx.User(),
		UserName:  info.User.Name,
		AuthExtra: info.Extra,
		SourceIP:  remoteHost(ctx.RemoteAddr()),
		Hints:     info.TargetHints,
	})
	if err != nil {
		event := s.connectionEvent(ctx, "target_resolution.result")
		event.Actor = auditActor(*info, publicKeyFingerprint)
		event.Access = auditAccess(*info)
		event.Outcome = &audit.Outcome{Result: metrics.ResultRejected, Error: err.Error()}
		s.audit.Record(ctx, event)
		s.metrics.
			AuthAttempt(credential, "target_rejected")
		slog.WarnContext(ctx, "target resolution failed",
			"user", ctx.User(),
			"err", err,
		)
		return false
	}
	targetEvent := s.connectionEvent(ctx, "target_resolution.result")
	targetEvent.Actor = auditActor(*info, publicKeyFingerprint)
	targetEvent.Target = auditTarget(tgt)
	targetEvent.Access = auditAccess(*info)
	targetEvent.Outcome = &audit.Outcome{Result: metrics.ResultSuccess}
	s.audit.Record(ctx, targetEvent)

	policy, err := s.resolveSessionPolicy(ctx, ctx.User(), info.Extra)
	if err != nil {
		s.metrics.
			AuthAttempt(credential, "session_policy_rejected")
		slog.WarnContext(ctx, "session policy resolution failed",
			"user", ctx.User(),
			"err", err,
		)
		return false
	}
	ctx.policyConn.ApplyPolicy(policy)
	protocol, err := s.selectConnectionProtocol(ctx, tgt, policy)
	if err != nil {
		s.metrics.
			AuthAttempt(credential, "protocol_rejected")
		slog.WarnContext(ctx, "SSH protocol selection failed",
			"user", ctx.User(),
			"target", tgt.String(),
			"err", err,
		)
		return false
	}

	ctx.publishAuthenticated(authenticatedConnection{info: *info, target: tgt, protocol: protocol, fingerprint: publicKeyFingerprint})
	return true
}

// connectionEstablished publishes success only after the SSH handshake completes.
func (s *gateway) connectionEstablished(ctx *connectionState, credential string) {
	ctx.markEstablished()
	result := ctx.snapshot().authenticated
	info, tgt := result.info, result.target
	ready := s.connectionEvent(ctx, "connection.ready")
	ready.Outcome = &audit.Outcome{Result: metrics.ResultSuccess}
	s.audit.Record(ctx, ready)
	s.metrics.AuthAttempt(credential, metrics.ResultSuccess)
	s.metrics.ConnectionOpened(info.Method)
	slog.InfoContext(ctx, "authenticated", "user", info.User.Name, "method", info.Method, "kind", tgt.Kind, "target", tgt.String(), "remote", ctx.RemoteAddr().String())
}

func remoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
