package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// Server is the kube-ssh gateway.
type Server struct {
	opts         *Options
	authn        authn.SSHAuthenticator
	authz        authz.Authorizer
	resolver     target.Resolver
	accessPolicy accessSessionPolicyGetter
	backend      backend.Backend
	audit        audit.Recorder
	metrics      metrics.Recorder

	clientStateMu sync.Mutex
	clientStates  map[*cryptossh.ServerConn]*clientState
}

// Run builds a Server from opts and runs it until ctx is cancelled.
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

// RunWithDependencies runs a Server with caller-provided runtime dependencies.
func RunWithDependencies(ctx context.Context, opts *Options, deps Dependencies) error {
	if opts == nil {
		opts = NewDefaultOptions()
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
	if deps.Stop != nil {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := deps.Stop(shutdownCtx); err != nil {
				slog.Error("stop dependencies", "err", err)
			}
		}()
	}
	if deps.Start != nil {
		if err := deps.Start(ctx); err != nil {
			return fmt.Errorf("start dependencies: %w", err)
		}
	}
	s := &Server{
		opts:         opts,
		authn:        deps.Authenticator,
		authz:        deps.Authorizer,
		audit:        deps.AuditRecorder,
		metrics:      deps.Metrics,
		resolver:     deps.Resolver,
		accessPolicy: deps.AccessPolicy,
		backend:      deps.Backend,
		clientStates: make(map[*cryptossh.ServerConn]*clientState),
	}
	connectionFeatures := s.connectionFeatures()

	srv := &gossh.Server{
		Addr: s.opts.ListenAddress,
		ConnCallback: func(ctx gossh.Context, conn net.Conn) net.Conn {
			return applyConnectionFeatures(ctx, conn, connectionFeatures...)
		},
		Handler:          s.handleSession,
		PublicKeyHandler: s.handlePublicKey,
		PasswordHandler:  s.handlePassword,
		ChannelHandlers: map[string]gossh.ChannelHandler{
			"session":      s.handleSessionChannel,
			"direct-tcpip": s.handleDirectTCPIP,
		},
		RequestHandlers: map[string]gossh.RequestHandler{
			"tcpip-forward":        s.handleTCPIPForward,
			"cancel-tcpip-forward": s.handleCancelTCPIPForward,
		},
		SessionRequestCallback: func(sess gossh.Session, requestType string) bool {
			WithSessionRequestType(sess.Context(), requestType)
			return true
		},
		SubsystemHandlers: map[string]gossh.SubsystemHandler{
			"sftp": s.handleSFTP,
		},
	}

	if s.opts.HostKeyFile != "" {
		if err := srv.SetOption(gossh.HostKeyFile(s.opts.HostKeyFile)); err != nil {
			return err
		}
	} else {
		slog.Warn("no host-key-file configured; ssh server will generate an ephemeral host key")
	}

	slog.InfoContext(ctx, "kube-ssh listening", "addr", s.opts.ListenAddress)

	metricsSrv, metricsListener, err := startMetricsServer(ctx, s.opts.Metrics, s.metrics)
	if err != nil {
		return err
	}

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		err := srv.ListenAndServe()
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
		_ = srv.Close()
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
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
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
	slog.InfoContext(ctx, "kube-ssh metrics listening", "addr", listener.Addr().String(), "path", path)
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

func (s *Server) metricsRecorder() metrics.Recorder {
	if s == nil || s.metrics == nil {
		return metrics.NopRecorder{}
	}
	return s.metrics
}

func (s *Server) handlePublicKey(ctx gossh.Context, key gossh.PublicKey) bool {
	fingerprint := cryptossh.FingerprintSHA256(key)
	info, err := s.authn.AuthenticatePublicKey(ctx, ctx.User(), key)
	if err != nil {
		s.recordAuthentication(ctx, metrics.CredentialPublicKey, fingerprint, metrics.ResultRejected, nil, err)
		s.metricsRecorder().AuthAttempt(metrics.CredentialPublicKey, metrics.ResultRejected)
		slog.WarnContext(ctx, "public key rejected",
			"fingerprint", fingerprint,
			"user", ctx.User(),
			"remote", ctx.RemoteAddr().String(),
			"err", err,
		)
		return false
	}
	s.recordAuthentication(ctx, metrics.CredentialPublicKey, fingerprint, metrics.ResultSuccess, info, nil)
	return s.acceptAuthenticated(ctx, info, fingerprint, metrics.CredentialPublicKey)
}

func (s *Server) handlePassword(ctx gossh.Context, password string) bool {
	info, err := s.authn.AuthenticateBasic(ctx, ctx.User(), password)
	if err != nil {
		s.recordAuthentication(ctx, metrics.CredentialPassword, "", metrics.ResultRejected, nil, err)
		s.metricsRecorder().AuthAttempt(metrics.CredentialPassword, metrics.ResultRejected)
		slog.WarnContext(ctx, "password rejected",
			"user", ctx.User(),
			"remote", ctx.RemoteAddr().String(),
			"err", err,
		)
		return false
	}
	s.recordAuthentication(ctx, metrics.CredentialPassword, "", metrics.ResultSuccess, info, nil)
	return s.acceptAuthenticated(ctx, info, "", metrics.CredentialPassword)
}

func (s *Server) acceptAuthenticated(ctx gossh.Context, info *authn.AuthenticateInfo, publicKeyFingerprint, credential string) bool {
	tgt, err := s.resolver.Resolve(ctx, target.ResolveRequest{
		SSHUser:              ctx.User(),
		User:                 info.User,
		AuthMethod:           info.Method,
		AuthExtra:            info.Extra,
		PublicKeyFingerprint: publicKeyFingerprint,
		SourceIP:             remoteHost(ctx.RemoteAddr()),
		TargetHints:          info.TargetHints,
	})
	if err != nil {
		event := s.connectionEvent(ctx, connectionAuditFromContext(ctx), "target_resolution.result")
		event.Actor = auditActor(*info, publicKeyFingerprint)
		event.Access = auditAccess(*info)
		event.Outcome = &audit.Outcome{Result: metrics.ResultRejected, Error: err.Error()}
		s.audit.Record(ctx, event)
		s.metricsRecorder().AuthAttempt(credential, "target_rejected")
		slog.WarnContext(ctx, "target resolution failed",
			"user", ctx.User(),
			"err", err,
		)
		return false
	}
	targetEvent := s.connectionEvent(ctx, connectionAuditFromContext(ctx), "target_resolution.result")
	targetEvent.Actor = auditActor(*info, publicKeyFingerprint)
	targetEvent.Target = auditTarget(tgt)
	targetEvent.Access = auditAccess(*info)
	targetEvent.Outcome = &audit.Outcome{Result: metrics.ResultSuccess}
	s.audit.Record(ctx, targetEvent)

	policy, err := s.resolveSessionPolicy(ctx, ctx.User(), info.Extra)
	if err != nil {
		tgt.Release()
		s.metricsRecorder().AuthAttempt(credential, "session_policy_rejected")
		slog.WarnContext(ctx, "session policy resolution failed",
			"user", ctx.User(),
			"err", err,
		)
		return false
	}
	if sessionPolicyConn, ok := sessionPolicyConnFromContext(ctx); ok {
		sessionPolicyConn.ApplyPolicy(policy)
	}

	WithAuthenticate(ctx, *info)
	WithTarget(ctx, tgt)
	WithSessionPolicy(ctx, policy)
	WithAuditFingerprint(ctx, publicKeyFingerprint)
	if state := connectionAuditFromContext(ctx); state != nil {
		ready := s.connectionEvent(ctx, state, "connection.ready")
		ready.Outcome = &audit.Outcome{Result: metrics.ResultSuccess}
		s.audit.Record(ctx, ready)
	}
	recorder := s.metricsRecorder()
	recorder.AuthAttempt(credential, metrics.ResultSuccess)
	recorder.ConnectionOpened(info.Method)
	go func() {
		<-ctx.Done()
		tgt.Release()
		recorder.ConnectionClosed(info.Method)
	}()

	slog.InfoContext(ctx, "authenticated",
		"user", info.User.Name,
		"method", info.Method,
		"kind", tgt.Kind,
		"target", tgt.ToPath(),
		"remote", ctx.RemoteAddr().String(),
	)
	return true
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
