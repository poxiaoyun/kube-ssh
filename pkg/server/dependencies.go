package server

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	generatedclient "xiaoshiai.cn/kube-ssh/pkg/generated/clientset/versioned"
	generatedinformers "xiaoshiai.cn/kube-ssh/pkg/generated/informers/externalversions"
	"xiaoshiai.cn/kube-ssh/pkg/kube"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/target"
	"xiaoshiai.cn/kube-ssh/pkg/version"
)

// Dependencies are the runtime collaborators built from raw Options.
//
// The SSH login path is intentionally staged:
//   - Authenticator validates credentials and returns caller identity.
//   - Resolver maps the authenticated connection to one backend target.
//   - Authorizer checks each shell/exec/SFTP/forward operation.
//
// Tests and embedders may provide custom implementations directly instead of
// using Options-based construction.
type Dependencies struct {
	Start         func(context.Context) error
	Authenticator authn.SSHAuthenticator
	Authorizer    authz.Authorizer
	Resolver      target.Resolver
	Backend       backend.Backend
	AuditRecorder audit.Recorder
	Metrics       metrics.Recorder
}

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
	if d.Backend == nil {
		return fmt.Errorf("backend is required")
	}
	if d.AuditRecorder == nil {
		return fmt.Errorf("audit recorder is required")
	}
	return nil
}

func buildDependencies(opts *Options) (Dependencies, error) {
	kubeClient, restConfig, err := kube.Build(opts.Kubeconfig)
	if err != nil {
		return Dependencies{}, fmt.Errorf("build kubernetes client: %w", err)
	}
	accessRuntime, err := buildAccessPolicyRuntime(opts, kubeClient, restConfig)
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
	metricsRecorder := buildMetrics(opts)
	backend, err := buildBackend(opts, kubeClient, restConfig, metricsRecorder)
	if err != nil {
		return Dependencies{}, err
	}
	return Dependencies{
		Start:         accessRuntime.start,
		Authenticator: authenticator,
		Authorizer:    authorizer,
		Resolver:      buildResolver(accessRuntime.resolver),
		Backend:       backend,
		AuditRecorder: audit.NewStdoutRecorder(),
		Metrics:       metricsRecorder,
	}, nil
}

type accessPolicyRuntime struct {
	start         func(context.Context) error
	authenticator authn.SSHAuthenticator
	authorizer    authz.Authorizer
	resolver      target.Resolver
}

func buildAccessPolicyRuntime(opts *Options, kubeClient kubernetes.Interface, restConfig *rest.Config) (accessPolicyRuntime, error) {
	if opts == nil || !opts.AccessPolicy.Enabled {
		return accessPolicyRuntime{}, nil
	}
	accessClient, err := generatedclient.NewForConfig(restConfig)
	if err != nil {
		return accessPolicyRuntime{}, err
	}
	factoryOptions := []generatedinformers.SharedInformerOption{}
	if opts.AccessPolicy.Namespace != "" {
		factoryOptions = append(factoryOptions, generatedinformers.WithNamespace(opts.AccessPolicy.Namespace))
	}
	factory := generatedinformers.NewSharedInformerFactoryWithOptions(accessClient, 0, factoryOptions...)
	accessInformer := factory.Ssh().V1().Accesses()
	store := accesspolicy.NewInformerStore(accessInformer.Lister(), opts.AccessPolicy.Namespace)
	index := accesspolicy.NewCredentialIndex(store, accesspolicy.NewKubernetesSecretReader(kubeClient))
	return accessPolicyRuntime{
		start: func(ctx context.Context) error {
			factory.Start(ctx.Done())
			for _, ok := range factory.WaitForCacheSync(ctx.Done()) {
				if !ok {
					return fmt.Errorf("access informer cache sync failed")
				}
			}
			return nil
		},
		authenticator: accesspolicy.NewAuthenticator(index),
		authorizer:    accesspolicy.NewAuthorizer(store),
		resolver:      accesspolicy.NewResolver(store, accesspolicy.NewKubernetesPodLister(kubeClient)),
	}, nil
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

func buildResolver(accessResolver target.Resolver) target.Resolver {
	resolvers := target.Chain{}
	if accessResolver != nil {
		resolvers = append(resolvers, accessResolver)
	}
	resolvers = append(resolvers, kube.NewUsernameResolver(), target.NewTargetHintResolver())
	return resolvers
}

func buildAuthorizer(opts *Options, kubeClient kubernetes.Interface, accessAuthorizer authz.Authorizer) (authz.Authorizer, error) {
	allow, err := parseCapabilities(opts.Authorization.Allow)
	if err != nil {
		return nil, err
	}
	deny, err := parseCapabilities(opts.Authorization.Deny)
	if err != nil {
		return nil, err
	}
	chain := authz.Chain{}
	if len(allow) > 0 || len(deny) > 0 {
		chain = append(chain, authz.StaticCapabilities{Allow: allow, Deny: deny})
	}
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
		return chain, nil
	}
	if opts.Authorization.Webhook.Enabled() {
		webhookAuthorizer, err := authz.NewWebhookAuthorizer(opts.Authorization.Webhook)
		if err != nil {
			return nil, err
		}
		chain = append(chain, webhookAuthorizer)
		return chain, nil
	}
	if len(allow) > 0 || len(deny) > 0 {
		chain = append(chain, authz.AllowAll{})
		return chain, nil
	}
	if opts.Authorization.AllowAll {
		chain = append(chain, authz.AllowAll{})
		return chain, nil
	}
	if len(chain) > 0 {
		return chain, nil
	}
	return nil, fmt.Errorf("authorization is not configured")
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

func buildBackend(opts *Options, kubeClient kubernetes.Interface, restConfig *rest.Config, recorder metrics.Recorder) (backend.Backend, error) {
	kubeBackend := kube.NewBackend(kubeClient, restConfig, kube.Options{
		HelperPath:      opts.Helper.Path,
		HelperRemoteDir: opts.Helper.RemoteDir,
		Metrics:         recorder,
	})
	return backend.WithMetrics(kubeBackend, recorder), nil
}

func parseCapabilities(values []string) ([]authz.Capability, error) {
	capabilities := make([]authz.Capability, 0, len(values))
	for _, value := range values {
		capability, err := authz.ParseCapability(value)
		if err != nil {
			return nil, err
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities, nil
}
