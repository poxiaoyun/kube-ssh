package server

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	clientgocache "k8s.io/client-go/tools/cache"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
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
	AccessPolicy  accessSessionPolicyGetter
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
	backend, err := buildBackend(opts, kubeClient, restConfig, metricsRecorder)
	if err != nil {
		return Dependencies{}, err
	}
	return Dependencies{
		Start:         accessRuntime.start,
		Authenticator: authenticator,
		Authorizer:    authorizer,
		Resolver:      buildResolver(accessRuntime.resolver),
		AccessPolicy:  accessRuntime.accessPolicy,
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
	accessPolicy  accessSessionPolicyGetter
}

func buildAccessPolicyRuntime(opts *Options, kubeClient kubernetes.Interface, restConfig *rest.Config, recorder metrics.Recorder) (accessPolicyRuntime, error) {
	if opts == nil || !opts.AccessPolicy.Enabled {
		return accessPolicyRuntime{}, nil
	}
	if recorder == nil {
		recorder = metrics.NopRecorder{}
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

	kubeFactoryOptions := []kubeinformers.SharedInformerOption{}
	if opts.AccessPolicy.Namespace != "" {
		kubeFactoryOptions = append(kubeFactoryOptions, kubeinformers.WithNamespace(opts.AccessPolicy.Namespace))
	}
	kubeFactory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, 0, kubeFactoryOptions...)
	podInformer := kubeFactory.Core().V1().Pods()
	secretInformer := kubeFactory.Core().V1().Secrets()

	if err := accessInformer.Informer().AddIndexers(accesspolicy.AccessPolicyIndexers()); err != nil {
		return accessPolicyRuntime{}, err
	}
	if err := secretInformer.Informer().AddIndexers(accesspolicy.SecretPolicyIndexers()); err != nil {
		return accessPolicyRuntime{}, err
	}
	accessIndexer := accessInformer.Informer().GetIndexer()
	podIndexer := podInformer.Informer().GetIndexer()
	secretIndexer := secretInformer.Informer().GetIndexer()
	podLister := accesspolicy.NewInformerPodLister(podIndexer)
	policyCache := accesspolicy.NewPolicyCache(
		accessIndexer,
		secretIndexer,
		opts.AccessPolicy.Namespace,
	)
	statusController := accesspolicy.NewAccessStatusController(
		policyCache,
		podLister,
		secretIndexer,
		func(ctx context.Context, access *sshv1.Access) (*sshv1.Access, error) {
			return accessClient.SshV1().Accesses(access.Namespace).UpdateStatus(ctx, access, metav1.UpdateOptions{})
		},
	)
	if _, err := accessInformer.Informer().AddEventHandler(cacheMetricHandler(func() {
		recorder.AccessPolicyObjects("access", len(accessIndexer.List()))
	})); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := accessInformer.Informer().AddEventHandler(statusController.AccessEventHandler()); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := podInformer.Informer().AddEventHandler(cacheMetricHandler(func() {
		recorder.AccessPolicyObjects("pod", len(podIndexer.List()))
	})); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := podInformer.Informer().AddEventHandler(statusController.PodEventHandler()); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := secretInformer.Informer().AddEventHandler(cacheMetricHandler(func() {
		recorder.AccessPolicyObjects("secret", len(secretIndexer.List()))
	})); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := secretInformer.Informer().AddEventHandler(statusController.SecretEventHandler()); err != nil {
		return accessPolicyRuntime{}, err
	}
	return accessPolicyRuntime{
		start: func(ctx context.Context) error {
			factory.Start(ctx.Done())
			kubeFactory.Start(ctx.Done())
			accessSyncStart := time.Now()
			for _, ok := range factory.WaitForCacheSync(ctx.Done()) {
				if !ok {
					recorder.AccessPolicyCacheSyncFinished("access", cacheSyncResult(ctx), time.Since(accessSyncStart))
					return fmt.Errorf("access informer cache sync failed")
				}
			}
			recorder.AccessPolicyCacheSyncFinished("access", metrics.ResultSuccess, time.Since(accessSyncStart))
			recorder.AccessPolicyObjects("access", len(accessIndexer.List()))

			secretSyncStart := time.Now()
			for _, ok := range kubeFactory.WaitForCacheSync(ctx.Done()) {
				if !ok {
					recorder.AccessPolicyCacheSyncFinished("secret", cacheSyncResult(ctx), time.Since(secretSyncStart))
					return fmt.Errorf("secret informer cache sync failed")
				}
			}
			recorder.AccessPolicyCacheSyncFinished("secret", metrics.ResultSuccess, time.Since(secretSyncStart))
			recorder.AccessPolicyObjects("secret", len(secretIndexer.List()))
			recorder.AccessPolicyObjects("pod", len(podIndexer.List()))
			statusController.Start(ctx)
			return nil
		},
		authenticator: accesspolicy.WithAuthenticatorMetrics(accesspolicy.NewAuthenticator(policyCache), recorder),
		authorizer:    accesspolicy.WithAuthorizerMetrics(accesspolicy.NewAuthorizer(policyCache), recorder),
		resolver:      accesspolicy.WithResolverMetrics(accesspolicy.NewResolver(policyCache, podLister), recorder),
		accessPolicy:  policyCache,
	}, nil
}

func cacheSyncResult(ctx context.Context) string {
	if ctx.Err() != nil {
		return metrics.ResultCanceled
	}
	return metrics.ResultError
}

func cacheMetricHandler(record func()) clientgocache.ResourceEventHandlerFuncs {
	return clientgocache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { record() },
		UpdateFunc: func(_, _ any) {
			record()
		},
		DeleteFunc: func(any) { record() },
	}
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
