package accesspolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/kube"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
	"xiaoshiai.cn/kube-ssh/pkg/util/pattern"
)

type Resolver struct {
	store    AccessGetter
	pods     PodLister
	selector *StrategySelector
	policy   ContainerPolicy
}

type ContainerPolicy struct {
	DefaultMode string
	LimitMode   string
}

type AccessLocator struct {
	namespace string
	access    string
	pod       string
	container string
}

func NewResolver(store AccessGetter, pods PodLister, policies ...ContainerPolicy) *Resolver {
	r := &Resolver{store: store, pods: pods, selector: NewStrategySelector(), policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}}
	if len(policies) > 0 {
		r.policy = policies[0]
	}
	return r
}

func (r *Resolver) Resolve(ctx context.Context, req target.ResolveRequest) (*target.Target, error) {
	if r == nil || r.store == nil {
		return nil, fmt.Errorf("access resolver requires a store")
	}
	locator, access, provided, err := resolveRequestedAccess(ctx, r.store, req.SSHUser, req.AuthExtra)
	if err != nil {
		return nil, err
	}
	if !provided {
		return nil, target.ErrNotProvided
	}
	if !isPodAccess(access) {
		return nil, target.ErrNotProvided
	}
	if r.pods == nil {
		return nil, fmt.Errorf("access resolver requires a pod lister")
	}
	pods, err := r.pods.List(ctx, locator.namespace, access.Spec.Selector)
	if err != nil {
		return nil, err
	}
	if locator.pod != "" {
		podName, explicitContainer, found := resolveExplicitPodLocator(pods, locator.pod)
		if !found {
			return nil, status.InvalidTarget("pod %q is not available through access %s/%s", locator.pod, locator.namespace, locator.access)
		}
		locator.pod = podName
		locator.container = explicitContainer
	}
	var selection podSelection
	var selected bool
	if locator.pod != "" {
		selection, selected = r.selector.SelectPodByName(access, pods, locator.pod)
	} else {
		selection, selected = r.selector.SelectPod(access, pods, req)
	}
	if !selected {
		if locator.pod != "" {
			return nil, status.InvalidTarget("pod %q is not available through access %s/%s", locator.pod, locator.namespace, locator.access)
		}
		return nil, status.InvalidTarget("access %s/%s matched no available pods", locator.namespace, locator.access)
	}
	requestedContainer := locator.container
	container, defaultContainer, err := kube.ResolvePodContainer(&selection.pod, locator.container)
	if err != nil {
		selection.release()
		return nil, err
	}
	credential := findCredential(access, GetExtra(req.AuthExtra, ExtraCredentialUser))
	accessAllowed := kube.ContainerModeAllows(r.policy.DefaultMode, requestedContainer != "", container, defaultContainer)
	if len(access.Spec.Containers) > 0 {
		accessAllowed = containerAllowed(access.Spec.Containers, container)
	}
	if !accessAllowed || !kube.ContainerModeAllows(r.policy.LimitMode, requestedContainer != "", container, defaultContainer) || (credential != nil && !containerAllowed(credential.Containers, container)) {
		selection.release()
		return nil, status.InvalidTarget("container %q is not allowed by access %s/%s", container, locator.namespace, locator.access)
	}
	return target.WithRelease(kube.NewTarget(locator.namespace, selection.pod.Name, container), selection.release), nil
}

func resolveRequestedAccess(ctx context.Context, store AccessGetter, sshUser string, extra map[string][]string) (AccessLocator, *sshv1.Access, bool, error) {
	authNamespace := GetExtra(extra, ExtraAccessNamespace)
	authName := GetExtra(extra, ExtraAccessName)
	if authNamespace != "" || authName != "" {
		if authNamespace == "" || authName == "" {
			return AccessLocator{}, nil, false, status.InvalidTarget("authenticated access identity is incomplete")
		}
		locator, ok := parseAccessLocatorFor(sshUser, authNamespace, authName)
		if !ok {
			return AccessLocator{}, nil, false, status.InvalidTarget("target %q does not match authenticated access %s/%s", sshUser, authNamespace, authName)
		}
		access, err := store.Get(ctx, authNamespace, authName)
		if errors.Is(err, ErrAccessNotFound) {
			return AccessLocator{}, nil, false, nil
		}
		return locator, access, err == nil, err
	}
	return resolveAccessLocator(ctx, store, sshUser)
}

// resolveAccessLocator identifies the Access before credentials are checked.
// An exact Access name wins; only when it does not exist is the final dot
// interpreted as a container separator.
func resolveAccessLocator(ctx context.Context, store AccessGetter, sshUser string) (AccessLocator, *sshv1.Access, bool, error) {
	namespace, remainder, ok := strings.Cut(sshUser, ".")
	if !ok || namespace == "" || remainder == "" {
		return AccessLocator{}, nil, false, nil
	}
	if name, pod, explicit := strings.Cut(remainder, "~"); explicit {
		if name == "" || pod == "" {
			return AccessLocator{}, nil, false, nil
		}
		access, err := store.Get(ctx, namespace, name)
		if errors.Is(err, ErrAccessNotFound) {
			return AccessLocator{}, nil, false, nil
		}
		return AccessLocator{namespace: namespace, access: name, pod: pod}, access, err == nil, err
	}
	access, err := store.Get(ctx, namespace, remainder)
	if err == nil {
		return AccessLocator{namespace: namespace, access: remainder}, access, true, nil
	}
	if !errors.Is(err, ErrAccessNotFound) {
		return AccessLocator{}, nil, false, err
	}
	idx := strings.LastIndexByte(remainder, '.')
	if idx <= 0 || idx == len(remainder)-1 {
		return AccessLocator{}, nil, false, nil
	}
	name, container := remainder[:idx], remainder[idx+1:]
	access, err = store.Get(ctx, namespace, name)
	if errors.Is(err, ErrAccessNotFound) {
		return AccessLocator{}, nil, false, nil
	}
	return AccessLocator{namespace: namespace, access: name, container: container}, access, err == nil, err
}

func parseAccessLocatorFor(sshUser, namespace, name string) (AccessLocator, bool) {
	prefix := namespace + "." + name
	switch {
	case sshUser == prefix:
		return AccessLocator{namespace: namespace, access: name}, true
	case strings.HasPrefix(sshUser, prefix+"~"):
		pod := strings.TrimPrefix(sshUser, prefix+"~")
		return AccessLocator{namespace: namespace, access: name, pod: pod}, pod != ""
	case strings.HasPrefix(sshUser, prefix+"."):
		container := strings.TrimPrefix(sshUser, prefix+".")
		return AccessLocator{namespace: namespace, access: name, container: container}, container != "" && !strings.Contains(container, ".")
	default:
		return AccessLocator{}, false
	}
}

// resolveExplicitPodLocator interprets an explicit locator against active Pods
// already selected by the Access. An exact Pod name wins; otherwise the final
// dot separates the Pod and container names.
func resolveExplicitPodLocator(pods []corev1.Pod, locator string) (string, string, bool) {
	active := activePods(pods)
	for i := range active {
		if active[i].Name == locator {
			return locator, "", true
		}
	}
	pod, container, ok := strings.Cut(locator, ".")
	if !ok || pod == "" || container == "" {
		return "", "", false
	}
	if strings.Contains(container, ".") {
		idx := strings.LastIndex(locator, ".")
		pod, container = locator[:idx], locator[idx+1:]
	}
	if pod == "" || container == "" {
		return "", "", false
	}
	for i := range active {
		if active[i].Name == pod {
			return pod, container, true
		}
	}
	return "", "", false
}

func containerAllowed(allow []string, container string) bool {
	return len(allow) == 0 || pattern.MatchAny(allow, container)
}

func GetExtra(extra map[string][]string, key string) string {
	values := extra[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
