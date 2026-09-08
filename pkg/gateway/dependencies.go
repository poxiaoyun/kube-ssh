package gateway

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend/apiserver"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend/cri"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
	"xiaoshiai.cn/kube-ssh/pkg/version"
)

const nodeIPPlaceholder = "{NodeIP}"

// Dependencies are the runtime collaborators built from raw Options.
//
// The SSH login path is intentionally staged:
//   - Authenticator validates credentials and returns caller identity.
//   - Resolver maps the authenticated connection to one connection target.
//   - Authorizer checks each shell/exec/SFTP/forward operation.
//   - A resolved target selects either the Pod backend or
//     SSHProxy for complete upstream SSH proxying.
//
// Tests and embedders may provide custom implementations directly instead of
// using Options-based construction.
type Dependencies struct {
	Start         func(context.Context) error
	Stop          func(context.Context) error
	Authenticator authn.SSHAuthenticator
	Authorizer    authz.Authorizer
	Resolver      target.Resolver
	AccessPolicy  accesspolicy.AccessGetter
	PodBackend    backend.Backend
	SSHProxy      sshproxy.ConnectionConnector
	AuditRecorder audit.Recorder
	Metrics       metrics.Recorder
}

// Validate checks the collaborators required to authenticate, resolve, authorize,
// and audit connections. Start, Stop, Metrics, and target-specific adapters are
// optional; an adapter is needed only when its target kind is selected.
func (d Dependencies) Validate() error {
	if d.Authenticator == nil {
		return fmt.Errorf("authenticator is required")
	}
	if d.Authorizer == nil {
		return fmt.Errorf("authorizer is required")
	}
	if d.Resolver == nil {
		return fmt.Errorf("resolver is required")
	}
	if d.AuditRecorder == nil {
		return fmt.Errorf("audit recorder is required")
	}
	return nil
}

func buildDependencies(ctx context.Context, opts *Options) (Dependencies, error) {
	if err := ctx.Err(); err != nil {
		return Dependencies{}, err
	}
	if err := validatePolicyOptions(opts); err != nil {
		return Dependencies{}, err
	}
	restConfig, err := loadKubernetesConfig(opts.Kubeconfig)
	if err != nil {
		return Dependencies{}, fmt.Errorf("load kubernetes config: %w", err)
	}
	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return Dependencies{}, fmt.Errorf("create kubernetes client: %w", err)
	}
	metricsRecorder := buildMetrics(opts)
	accessRuntime, err := buildAccessPolicyRuntime(opts, kubeClient, restConfig, metricsRecorder)
	if err != nil {
		return Dependencies{}, fmt.Errorf("build access policy runtime: %w", err)
	}
	authenticator, err := buildAuthenticator(opts, accessRuntime.authenticator)
	if err != nil {
		return Dependencies{}, fmt.Errorf("build authenticator: %w", err)
	}
	authorizer, err := buildAuthorizer(opts, kubeClient, accessRuntime.authorizer)
	if err != nil {
		return Dependencies{}, err
	}
	podBackend, err := buildPodBackend(opts, kubeClient, restConfig, metricsRecorder)
	if err != nil {
		return Dependencies{}, err
	}
	directResolver := accessRuntime.directResolver
	if directResolver == nil {
		directResolver = podtarget.NewUsernameResolver()
	}
	auditRecorder := audit.NewAsyncRecorder(audit.NewStdoutSink(nil), opts.Audit.QueueSize, metricsRecorder.AuditDelivery)
	return Dependencies{
		Start: accessRuntime.start,
		Stop: func(ctx context.Context) error {
			flushTimeout := opts.Audit.FlushTimeout
			if flushTimeout <= 0 {
				flushTimeout = 5 * time.Second
			}
			flushCtx, cancel := context.WithTimeout(ctx, flushTimeout)
			defer cancel()
			return auditRecorder.Close(flushCtx)
		},
		Authenticator: authenticator,
		Authorizer:    authorizer,
		Resolver: podtarget.NewBindingResolver(buildResolver(accessRuntime.resolver, directResolver), podtarget.ResolverOptions{
			Pods:                 accesspolicy.NewKubernetesPodLister(kubeClient),
			DefaultContainerMode: opts.Policy.Defaults.ContainerMode,
			LimitContainerMode:   opts.Policy.Limits.ContainerMode,
		}),
		AccessPolicy:  accessRuntime.accessPolicy,
		PodBackend:    podBackend,
		SSHProxy:      accessRuntime.sshProxy,
		AuditRecorder: auditRecorder,
		Metrics:       metricsRecorder,
	}, nil
}

func validatePolicyOptions(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("options are required")
	}
	if opts.GatewayClassName != "" {
		if problems := validation.IsDNS1123Subdomain(opts.GatewayClassName); len(problems) > 0 {
			return fmt.Errorf("gateway class name %q is invalid: %s", opts.GatewayClassName, strings.Join(problems, ", "))
		}
	}
	if _, err := advertisedAccessEndpoints(opts.AdvertiseAddresses); err != nil {
		return err
	}
	for name, mode := range map[string]string{"defaults": opts.Policy.Defaults.ContainerMode, "limits": opts.Policy.Limits.ContainerMode} {
		if !slices.Contains([]string{"KubernetesDefault", "All", "None"}, mode) {
			return fmt.Errorf("policy %s container mode %q is invalid", name, mode)
		}
	}
	for name, patterns := range map[string][]string{
		"default local forward":  opts.Policy.Defaults.LocalForwardDestinations,
		"default remote forward": opts.Policy.Defaults.RemoteForwardBinds,
		"limit local forward":    opts.Policy.Limits.LocalForwardDestinations,
		"limit remote forward":   opts.Policy.Limits.RemoteForwardBinds,
	} {
		for _, pattern := range patterns {
			if pattern == "*" || pattern == "*:*" {
				continue
			}
			if _, _, err := net.SplitHostPort(pattern); err != nil {
				return fmt.Errorf("policy %s expression %q is invalid: %w", name, pattern, err)
			}
		}
	}
	return nil
}

func advertisedAccessEndpoints(addresses []string) ([]sshv1.AccessStatusEndpoint, error) {
	seen := map[string]struct{}{}
	result := make([]sshv1.AccessStatusEndpoint, 0, len(addresses))
	for _, value := range addresses {
		address := strings.TrimSpace(value)
		host, rawPort, err := net.SplitHostPort(address)
		if err != nil || host == "" {
			return nil, fmt.Errorf("advertise address %q must use host:port form", value)
		}
		if host != nodeIPPlaceholder && net.ParseIP(host) == nil {
			if problems := validation.IsDNS1123Subdomain(host); len(problems) > 0 {
				return nil, fmt.Errorf("advertise address %q has invalid host: %s", value, strings.Join(problems, ", "))
			}
		}
		port, err := strconv.Atoi(rawPort)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("advertise address %q has invalid port", value)
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, sshv1.AccessStatusEndpoint{Address: address})
	}
	return result, nil
}

func buildAuthenticator(opts *Options, accessAuthenticator authn.SSHAuthenticator) (authn.SSHAuthenticator, error) {
	authenticators := []authn.SSHAuthenticator{}
	staticPublicKey, err := authn.NewStaticPublicKeyAuthenticator(opts.Authentication.AuthorizedKeys)
	if err != nil {
		return nil, err
	}
	authenticators = append(authenticators, staticPublicKey)
	staticPassword, err := authn.NewStaticPasswordAuthenticator(opts.Authentication.Passwords)
	if err != nil {
		return nil, err
	}
	authenticators = append(authenticators, staticPassword)
	if accessAuthenticator != nil {
		authenticators = append(authenticators, accessAuthenticator)
	}
	if opts.Authentication.Webhook.Enabled() {
		webhookAuthenticator, err := authn.NewWebhookAuthenticator(opts.Authentication.Webhook)
		if err != nil {
			return nil, err
		}
		authenticators = append(authenticators, webhookAuthenticator)
	}
	if opts.Authentication.Anonymous {
		authenticators = append(authenticators, authn.Anonymous{})
	}
	return authn.NewChain(authenticators...), nil
}

func buildResolver(accessResolver, directResolver target.Resolver) target.Resolver {
	resolvers := target.Chain{}
	if accessResolver != nil {
		resolvers = append(resolvers, accessResolver)
	}
	resolvers = append(resolvers, directResolver, target.HintResolver{})
	return resolvers
}

func buildAuthorizer(opts *Options, kubeClient kubernetes.Interface, accessAuthorizer authz.Authorizer) (authz.Authorizer, error) {
	chain := authz.Chain{}
	if accessAuthorizer != nil {
		chain = append(chain, accessAuthorizer)
	}
	if opts.Authorization.KubernetesSAR {
		if opts.Authorization.Webhook.Enabled() {
			webhookAuthorizer, err := authz.NewWebhookAuthorizer(opts.Authorization.Webhook)
			if err != nil {
				return nil, err
			}
			chain = append(chain, webhookAuthorizer)
		}
		chain = append(chain, authz.NewKubernetesSARAuthorizer(kubeClient))
		return withPolicyGuards(opts, chain)
	}
	if opts.Authorization.Webhook.Enabled() {
		webhookAuthorizer, err := authz.NewWebhookAuthorizer(opts.Authorization.Webhook)
		if err != nil {
			return nil, err
		}
		chain = append(chain, webhookAuthorizer)
		return withPolicyGuards(opts, chain)
	}
	if opts.Authorization.AllowAll {
		chain = append(chain, authz.AllowAll{})
		return withPolicyGuards(opts, chain)
	}
	if len(chain) > 0 {
		return withPolicyGuards(opts, chain)
	}
	return nil, fmt.Errorf("authorization is not configured")
}

type policyGuardedAuthorizer struct {
	chain authz.Chain
}

func (a *policyGuardedAuthorizer) Authorize(ctx context.Context, req authz.Request) (authz.Decision, string, error) {
	return a.chain.Authorize(ctx, req)
}

func withPolicyGuards(opts *Options, next authz.Authorizer) (authz.Authorizer, error) {
	limits, err := parseCapabilities(opts.Policy.Limits.Capabilities)
	if err != nil {
		return nil, err
	}
	defaults, err := parseCapabilities(opts.Policy.Defaults.Capabilities)
	if err != nil {
		return nil, err
	}
	return &policyGuardedAuthorizer{chain: authz.Chain{
		authz.PolicyLimits{
			Capabilities:             limits,
			LocalForwardDestinations: opts.Policy.Limits.LocalForwardDestinations,
			RemoteForwardBinds:       opts.Policy.Limits.RemoteForwardBinds,
		},
		authz.PolicyLimits{
			Capabilities:             defaults,
			LocalForwardDestinations: opts.Policy.Defaults.LocalForwardDestinations,
			RemoteForwardBinds:       opts.Policy.Defaults.RemoteForwardBinds,
			SkipAccess:               true,
		},
		next,
	}}, nil
}

func buildMetrics(opts *Options) metrics.Recorder {
	if opts == nil || opts.Metrics.ListenAddress == "" {
		return metrics.NopRecorder{}
	}
	info := version.Get()
	return metrics.NewPrometheusRecorder(nil, metrics.PrometheusOptions{
		BuildInfo: metrics.BuildInfo{
			Version:   info.GitVersion,
			Commit:    info.GitCommit,
			BuildDate: info.BuildDate,
		},
	})
}

func buildPodBackend(opts *Options, kubeClient kubernetes.Interface, restConfig *rest.Config, recorder metrics.Recorder) (backend.Backend, error) {
	var transport backend.Transport
	switch opts.PodSSH.Transport {
	case PodSSHTransportCRI:
		criTransport, err := cri.New(kubeClient, cri.Options{
			Port: opts.PodSSH.CRI.Port, ServerName: opts.PodSSH.CRI.ServerName,
			CAFile: opts.PodSSH.CRI.CAFile, CertFile: opts.PodSSH.CRI.CertFile,
			KeyFile: opts.PodSSH.CRI.KeyFile,
		})
		if err != nil {
			return nil, fmt.Errorf("build CRI transport: %w", err)
		}
		transport = criTransport
	case PodSSHTransportAPIServer:
		transport = apiserver.New(kubeClient, restConfig, apiserver.Options{
			HelperPath: opts.Helper.Path, HelperRemoteDir: opts.Helper.RemoteDir, Metrics: recorder,
		})
	default:
		return nil, fmt.Errorf("pod SSH transport %q is invalid; use apiserver or cri", opts.PodSSH.Transport)
	}
	return backend.WithMetrics(backend.NewExecutor(transport), recorder), nil
}

func parseCapabilities(values []string) ([]authz.Capability, error) {
	capabilities := make([]authz.Capability, 0, len(values))
	for _, value := range values {
		if value == "*" {
			capabilities = append(capabilities, authz.Capability(value))
			continue
		}
		capability, err := authz.ParseCapability(value)
		if err != nil {
			return nil, err
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities, nil
}
