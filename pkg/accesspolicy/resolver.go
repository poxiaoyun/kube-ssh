package accesspolicy

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
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
	locator, provided, err := ParseAccessLocator(req.SSHUser, req.AuthExtra)
	if err != nil {
		return nil, err
	}
	if !provided {
		return nil, target.ErrNotProvided
	}
	if err := requireAuthAccess(req.AuthExtra, locator.namespace, locator.access); err != nil {
		return nil, err
	}
	if r == nil || r.store == nil {
		return nil, fmt.Errorf("access resolver requires a store")
	}
	access, err := r.store.Get(ctx, locator.namespace, locator.access)
	if err != nil {
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

func ParseAccessLocator(sshUser string, extra map[string][]string) (AccessLocator, bool, error) {
	authNamespace := GetExtra(extra, ExtraAccessNamespace)
	authName := GetExtra(extra, ExtraAccessName)
	if authNamespace != "" || authName != "" {
		if authNamespace == "" || authName == "" {
			return AccessLocator{}, false, status.InvalidTarget("authenticated access identity is incomplete")
		}
		prefix := authNamespace + "." + authName
		switch {
		case sshUser == prefix:
			return AccessLocator{namespace: authNamespace, access: authName}, true, nil
		case strings.HasPrefix(sshUser, prefix+"~"):
			pod := strings.TrimPrefix(sshUser, prefix+"~")
			if pod != "" {
				return AccessLocator{namespace: authNamespace, access: authName, pod: pod}, true, nil
			}
		case strings.HasPrefix(sshUser, prefix+"."):
			container := strings.TrimPrefix(sshUser, prefix+".")
			if container != "" && !strings.Contains(container, ".") {
				return AccessLocator{namespace: authNamespace, access: authName, container: container}, true, nil
			}
		}
		return AccessLocator{}, false, status.InvalidTarget("target %q does not match authenticated access %s/%s", sshUser, authNamespace, authName)
	}
	namespace, name, ok := strings.Cut(sshUser, ".")
	if !ok || namespace == "" || name == "" {
		return AccessLocator{}, false, nil
	}
	return AccessLocator{namespace: namespace, access: name}, true, nil
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

func requireAuthAccess(extra map[string][]string, namespace, name string) error {
	authNamespace := GetExtra(extra, ExtraAccessNamespace)
	authName := GetExtra(extra, ExtraAccessName)
	if authNamespace == "" && authName == "" {
		return nil
	}
	if authNamespace != namespace || authName != name {
		return status.InvalidTarget("authenticated access %s/%s does not match requested access %s/%s", authNamespace, authName, namespace, name)
	}
	return nil
}

func GetExtra(extra map[string][]string, key string) string {
	values := extra[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
