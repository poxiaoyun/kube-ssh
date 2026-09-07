package gateway

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
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	generatedclient "xiaoshiai.cn/kube-ssh/pkg/generated/clientset/versioned"
	generatedinformers "xiaoshiai.cn/kube-ssh/pkg/generated/informers/externalversions"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type accessPolicyRuntime struct {
	start          func(context.Context) error
	authenticator  authn.SSHAuthenticator
	authorizer     authz.Authorizer
	resolver       target.Resolver
	directResolver target.Resolver
	accessPolicy   accesspolicy.AccessGetter
	sshProxy       sshproxy.ConnectionConnector
}

func buildAccessPolicyRuntime(opts *Options, kubeClient kubernetes.Interface, restConfig *rest.Config, recorder metrics.Recorder) (accessPolicyRuntime, error) {
	if !opts.AccessPolicy.Enabled {
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
	accessInformer := factory.Ssh().
		V1().
		Accesses()

	kubeFactoryOptions := []kubeinformers.SharedInformerOption{}
	if opts.AccessPolicy.Namespace != "" {
		kubeFactoryOptions = append(kubeFactoryOptions, kubeinformers.WithNamespace(opts.AccessPolicy.Namespace))
	}
	kubeFactory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, 0, kubeFactoryOptions...)
	podInformer := kubeFactory.Core().
		V1().
		Pods()
	secretInformer := kubeFactory.Core().
		V1().
		Secrets()

	accessIndexer := accessInformer.Informer().
		GetIndexer()
	podIndexer := podInformer.Informer().
		GetIndexer()
	secretIndexer := secretInformer.Informer().
		GetIndexer()
	podLister := accesspolicy.NewInformerPodLister(podIndexer)
	advertisedEndpoints, err := advertisedAccessEndpoints(opts.AdvertiseAddresses)
	if err != nil {
		return accessPolicyRuntime{}, err
	}
	policyCache := accesspolicy.NewPolicyCache(
		accessIndexer,
		secretIndexer,
		accesspolicy.PolicyCacheOptions{
			Namespace:        opts.AccessPolicy.Namespace,
			GatewayClassName: opts.GatewayClassName,
		},
	)
	sshConnector := sshproxy.NewConnector(policyCache, opts.SSHProxy.ConnectTimeout)
	statusController := accesspolicy.NewAccessStatusController(
		policyCache,
		podLister,
		secretIndexer,
		func(ctx context.Context, access *sshv1.Access) (*sshv1.Access, error) {
			return accessClient.SshV1().
				Accesses(access.Namespace).
				UpdateStatus(ctx, access, metav1.UpdateOptions{})
		},
		accesspolicy.AccessStatusControllerOptions{
			Policy: accesspolicy.ContainerPolicy{
				DefaultMode: opts.Policy.Defaults.ContainerMode,
				LimitMode:   opts.Policy.Limits.ContainerMode,
			},
			Endpoints: advertisedEndpoints,
		},
	)
	if _, err := accessInformer.Informer().
		AddEventHandler(cacheMetricHandler(func() {
			recorder.AccessPolicyObjects("access", accessCount(policyCache))
		})); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := accessInformer.Informer().
		AddEventHandler(statusController.AccessEventHandler()); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := podInformer.Informer().
		AddEventHandler(cacheMetricHandler(func() {
			recorder.AccessPolicyObjects("pod", len(podIndexer.List()))
		})); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := podInformer.Informer().
		AddEventHandler(statusController.PodEventHandler()); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := secretInformer.Informer().
		AddEventHandler(cacheMetricHandler(func() {
			recorder.AccessPolicyObjects("secret", len(secretIndexer.List()))
		})); err != nil {
		return accessPolicyRuntime{}, err
	}
	if _, err := secretInformer.Informer().
		AddEventHandler(statusController.SecretEventHandler()); err != nil {
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
			recorder.AccessPolicyObjects("access", accessCount(policyCache))

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
		authorizer: accesspolicy.WithAuthorizerMetrics(accesspolicy.NewAuthorizer(policyCache, accesspolicy.CapabilityDefaults{
			Allow:                    accessCapabilities(opts.Policy.Defaults.Capabilities),
			LocalForwardDestinations: opts.Policy.Defaults.LocalForwardDestinations,
			RemoteForwardBinds:       opts.Policy.Defaults.RemoteForwardBinds,
		}), recorder),
		resolver: accesspolicy.WithResolverMetrics(accesspolicy.NewResolver(policyCache, podLister, accesspolicy.ContainerPolicy{
			DefaultMode: opts.Policy.Defaults.ContainerMode,
			LimitMode:   opts.Policy.Limits.ContainerMode,
		}), recorder),
		directResolver: podtarget.NewUsernameResolver(),
		accessPolicy:   policyCache,
		sshProxy:       sshConnector,
	}, nil
}

func accessCount(store accesspolicy.Store) int {
	accesses, err := store.List(context.Background())
	if err != nil {
		return 0
	}
	return len(accesses)
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

func accessCapabilities(values []string) []sshv1.Capability {
	result := make([]sshv1.Capability, 0, len(values))
	for _, value := range values {
		result = append(result, sshv1.Capability(value))
	}
	return result
}
