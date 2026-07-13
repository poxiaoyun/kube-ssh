package accesspolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"xiaoshiai.cn/kube-ssh/pkg/kube"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
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

func NewResolver(store AccessGetter, pods PodLister, policies ...ContainerPolicy) *Resolver {
	r := &Resolver{store: store, pods: pods, selector: NewStrategySelector(), policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}}
	if len(policies) > 0 {
		r.policy = policies[0]
	}
	return r
}

func (r *Resolver) Resolve(ctx context.Context, req target.ResolveRequest) (*target.Target, error) {
	namespace, name, container, ok, err := parseAccessLocator(req.SSHUser, req.AuthExtra)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, target.ErrNotProvided
	}
	if err := requireAuthAccess(req.AuthExtra, namespace, name); err != nil {
		return nil, err
	}
	if r == nil || r.store == nil {
		return nil, fmt.Errorf("access resolver requires a store")
	}
	access, err := r.store.Get(ctx, namespace, name)
	if err != nil {
		return nil, target.ErrNotProvided
	}
	if !isPodAccess(access) {
		return nil, target.ErrNotProvided
	}
	if r.pods == nil {
		return nil, fmt.Errorf("access resolver requires a pod lister")
	}
	pods, err := r.pods.List(ctx, namespace, access.Spec.Selector)
	if err != nil {
		return nil, err
	}
	selection, ok := r.selector.SelectPod(access, pods, req)
	if !ok {
		return nil, status.InvalidTarget("access %s/%s matched no available pods", namespace, name)
	}
	requestedContainer := container
	container, defaultContainer, err := kube.ResolvePodContainer(&selection.pod, container)
	if err != nil {
		selection.release()
		return nil, err
	}
	credential := findCredential(access, firstExtra(req.AuthExtra, ExtraCredentialUser))
	accessAllowed := kube.ContainerModeAllows(r.policy.DefaultMode, requestedContainer != "", container, defaultContainer)
	if len(access.Spec.Containers) > 0 {
		accessAllowed = containerAllowed(access.Spec.Containers, container)
	}
	if !accessAllowed || !kube.ContainerModeAllows(r.policy.LimitMode, requestedContainer != "", container, defaultContainer) || (credential != nil && !containerAllowed(credential.Containers, container)) {
		selection.release()
		return nil, status.InvalidTarget("container %q is not allowed by access %s/%s", container, namespace, name)
	}
	return target.WithRelease(kube.NewTarget(namespace, selection.pod.Name, container), selection.release), nil
}

func parseAccessLocator(sshUser string, extra map[string][]string) (string, string, string, bool, error) {
	authNamespace := firstExtra(extra, ExtraAccessNamespace)
	authName := firstExtra(extra, ExtraAccessName)
	if authNamespace != "" || authName != "" {
		if authNamespace == "" || authName == "" {
			return "", "", "", false, status.InvalidTarget("authenticated access identity is incomplete")
		}
		prefix := authNamespace + "." + authName
		switch {
		case sshUser == prefix:
			return authNamespace, authName, "", true, nil
		case strings.HasPrefix(sshUser, prefix+"."):
			container := strings.TrimPrefix(sshUser, prefix+".")
			if container != "" && !strings.Contains(container, ".") {
				return authNamespace, authName, container, true, nil
			}
		}
		return "", "", "", false, status.InvalidTarget("target %q does not match authenticated access %s/%s", sshUser, authNamespace, authName)
	}
	namespace, name, ok := strings.Cut(sshUser, ".")
	if !ok || namespace == "" || name == "" {
		return "", "", "", false, nil
	}
	return namespace, name, "", true, nil
}

func containerAllowed(allow []string, container string) bool {
	return len(allow) == 0 || slices.Contains(allow, "*") || slices.Contains(allow, container)
}

func requireAuthAccess(extra map[string][]string, namespace, name string) error {
	authNamespace := firstExtra(extra, ExtraAccessNamespace)
	authName := firstExtra(extra, ExtraAccessName)
	if authNamespace == "" && authName == "" {
		return nil
	}
	if authNamespace != namespace || authName != name {
		return status.InvalidTarget("authenticated access %s/%s does not match requested access %s/%s", authNamespace, authName, namespace, name)
	}
	return nil
}

func firstExtra(extra map[string][]string, key string) string {
	values := extra[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
