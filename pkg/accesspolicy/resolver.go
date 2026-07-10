package accesspolicy

import (
	"context"
	"fmt"
	"strings"

	"xiaoshiai.cn/kube-ssh/pkg/kube"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type Resolver struct {
	store    AccessGetter
	pods     PodLister
	selector *StrategySelector
}

func NewResolver(store AccessGetter, pods PodLister) *Resolver {
	return &Resolver{store: store, pods: pods, selector: NewStrategySelector()}
}

func (r *Resolver) Resolve(ctx context.Context, req target.ResolveRequest) (*target.Target, error) {
	namespace, name, ok := parseAccessLocator(req.SSHUser)
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
	return target.WithRelease(kube.NewTarget(namespace, selection.pod.Name, ""), selection.release), nil
}

func parseAccessLocator(sshUser string) (string, string, bool) {
	namespace, name, ok := strings.Cut(sshUser, ".")
	if !ok || namespace == "" || name == "" {
		return "", "", false
	}
	return namespace, name, true
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
