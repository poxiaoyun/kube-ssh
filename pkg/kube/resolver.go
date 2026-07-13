package kube

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// UsernameResolver parses the SSH username as a Kubernetes target:
// "namespace.pod" or "namespace.pod.container".
type PodGetter interface {
	Get(context.Context, string, string) (*corev1.Pod, error)
}

type UsernameResolver struct {
	pods        PodGetter
	defaultMode string
	limitMode   string
}

func NewUsernameResolver() *UsernameResolver { return &UsernameResolver{} }

func NewPolicyUsernameResolver(pods PodGetter, defaultMode, limitMode string) *UsernameResolver {
	return &UsernameResolver{pods: pods, defaultMode: defaultMode, limitMode: limitMode}
}

// Resolve parses the SSH username as a kube target locator.
//
//	"default.nginx"     -> kind=kube, options={namespace:default,pod:nginx}
//	"default.nginx.app" -> kind=kube, options={namespace:default,pod:nginx,container:app}
func (r *UsernameResolver) Resolve(ctx context.Context, req target.ResolveRequest) (*target.Target, error) {
	username := req.SSHUser
	if !strings.Contains(username, ".") {
		return nil, target.ErrNotProvided
	}
	parts := strings.Split(username, ".")
	var namespace, pod, container string
	switch len(parts) {
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return nil, status.InvalidTarget("invalid target %q: namespace and pod are required", username)
		}
		namespace, pod = parts[0], parts[1]
	case 3:
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, status.InvalidTarget("invalid target %q: namespace, pod, and container are required", username)
		}
		namespace, pod, container = parts[0], parts[1], parts[2]
	default:
		return nil, status.InvalidTarget("invalid target %q: expected namespace.pod or namespace.pod.container", username)
	}
	if r == nil || r.pods == nil {
		return NewTarget(namespace, pod, container), nil
	}
	podObject, err := r.pods.Get(ctx, namespace, pod)
	if err != nil {
		return nil, status.InvalidTarget("pod %s/%s is not available", namespace, pod)
	}
	requested := container != ""
	container, defaultContainer, err := ResolvePodContainer(podObject, container)
	if err != nil {
		return nil, err
	}
	if !ContainerModeAllows(r.defaultMode, requested, container, defaultContainer) || !ContainerModeAllows(r.limitMode, requested, container, defaultContainer) {
		return nil, status.InvalidTarget("container %q is not allowed by global policy", container)
	}
	return NewTarget(namespace, pod, container), nil
}

// ResolvePodContainer resolves an explicitly requested or Kubernetes-default
// regular container and verifies that it exists in the Pod.
func ResolvePodContainer(pod *corev1.Pod, requested string) (string, string, error) {
	if pod == nil {
		return "", "", status.InvalidTarget("pod is required")
	}
	defaultContainer := pod.Annotations["kubectl.kubernetes.io/default-container"]
	if defaultContainer == "" && len(pod.Spec.Containers) > 0 {
		defaultContainer = pod.Spec.Containers[0].Name
	}
	container := requested
	if container == "" {
		container = defaultContainer
	}
	if container == "" {
		return "", "", status.InvalidTarget("pod %s/%s has no regular containers", pod.Namespace, pod.Name)
	}
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == container {
			return container, defaultContainer, nil
		}
	}
	return "", "", status.InvalidTarget("pod %s/%s has no regular container %q", pod.Namespace, pod.Name, container)
}

// ContainerModeAllows reports whether a resolved container is permitted by a
// global container selection mode.
func ContainerModeAllows(mode string, explicit bool, container, defaultContainer string) bool {
	switch mode {
	case "", "All":
		return true
	case "KubernetesDefault":
		return !explicit || container == defaultContainer
	case "None":
		return false
	default:
		return false
	}
}
