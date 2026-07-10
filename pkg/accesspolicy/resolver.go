package accesspolicy

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"xiaoshiai.cn/kube-ssh/pkg/kube"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type Resolver struct {
	store Store
	pods  PodLister
}

func NewResolver(store Store, pods PodLister) *Resolver {
	return &Resolver{store: store, pods: pods}
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
	pod, ok := choosePod(pods)
	if !ok {
		return nil, status.InvalidTarget("access %s/%s matched no available pods", namespace, name)
	}
	return kube.NewTarget(namespace, pod.Name, ""), nil
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

func choosePod(pods []corev1.Pod) (corev1.Pod, bool) {
	active := make([]corev1.Pod, 0, len(pods))
	ready := make([]corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		active = append(active, pod)
		if podReady(pod) {
			ready = append(ready, pod)
		}
	}
	candidates := active
	if len(ready) > 0 {
		candidates = ready
	}
	if len(candidates) == 0 {
		return corev1.Pod{}, false
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Name < candidates[j].Name
	})
	return candidates[rand.Intn(len(candidates))], true
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func firstExtra(extra map[string][]string, key string) string {
	values := extra[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
