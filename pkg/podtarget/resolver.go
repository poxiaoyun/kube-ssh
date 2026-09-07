package podtarget

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// PodGetter returns the current Pod with a logical namespace and name.
type PodGetter interface {
	// Get returns the current Pod for namespace and name.
	Get(ctx context.Context, namespace, name string) (*corev1.Pod, error)
}

// UsernameResolver parses an SSH username into a logical Pod target.
type UsernameResolver struct{}

// ResolverOptions configures Pod lookup and container-selection policy.
type ResolverOptions struct {
	Pods                 PodGetter
	DefaultContainerMode string
	LimitContainerMode   string
}

// BindingResolver resolves a logical Pod target to one live Pod instance and
// applies global container policy. Targets already bound by an inner resolver
// retain their selected identity.
type BindingResolver struct {
	resolver    target.Resolver
	pods        PodGetter
	defaultMode string
	limitMode   string
}

// NewBindingResolver binds every Kubernetes target, including authentication
// hints and Access selections, to the live Pod UID and node for one SSH
// connection.
func NewBindingResolver(resolver target.Resolver, options ResolverOptions) *BindingResolver {
	return &BindingResolver{resolver: resolver, pods: options.Pods, defaultMode: options.DefaultContainerMode, limitMode: options.LimitContainerMode}
}

func (r *BindingResolver) Resolve(ctx context.Context, input target.ResolveInput) (*target.Target, error) {
	tgt, err := r.resolver.Resolve(ctx, input)
	if err != nil || tgt.Kind != target.KindPod {
		return tgt, err
	}
	if BoundIdentity(tgt).UID != "" {
		return tgt, nil
	}
	podTarget, err := Parse(tgt)
	if err != nil {
		return nil, err
	}
	pod, err := r.pods.Get(ctx, podTarget.Namespace, podTarget.Pod)
	if err != nil {
		return nil, fmt.Errorf("get target pod %s/%s: %w", podTarget.Namespace, podTarget.Pod, err)
	}
	explicit := podTarget.Container != ""
	container, defaultContainer, err := ResolveContainer(pod, podTarget.Container)
	if err != nil {
		return nil, err
	}
	if !ContainerAllowed(r.defaultMode, explicit, container, defaultContainer) || !ContainerAllowed(r.limitMode, explicit, container, defaultContainer) {
		return nil, apierrors.NewForbidden(corev1.Resource("pods"), pod.Name, fmt.Errorf("container %q is not allowed by global policy", container))
	}
	if !explicit {
		tgt.Options = append(tgt.Options, target.Option{Key: OptionContainers, Value: container})
	}
	bind(tgt, pod)
	return tgt, nil
}

// NewUsernameResolver creates a logical Pod locator resolver.
func NewUsernameResolver() *UsernameResolver { return &UsernameResolver{} }

// Resolve parses the SSH username as a kube target locator.
//
//	"default.nginx"     -> kind=kube, options={namespace:default,pod:nginx}
//	"default.nginx.app" -> kind=kube, options={namespace:default,pod:nginx,container:app}
func (*UsernameResolver) Resolve(_ context.Context, input target.ResolveInput) (*target.Target, error) {
	username := input.SSHUser
	if !strings.Contains(username, ".") {
		return nil, target.ErrNotProvided
	}
	parts := strings.Split(username, ".")
	var namespace, pod, container string
	switch len(parts) {
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return nil, apierrors.NewBadRequest(fmt.Sprintf("invalid target %q: namespace and pod are required", username))
		}
		namespace, pod = parts[0], parts[1]
	case 3:
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, apierrors.NewBadRequest(fmt.Sprintf("invalid target %q: namespace, pod, and container are required", username))
		}
		namespace, pod, container = parts[0], parts[1], parts[2]
	default:
		return nil, apierrors.NewBadRequest(fmt.Sprintf("invalid target %q: expected namespace.pod or namespace.pod.container", username))
	}
	return New(namespace, pod, container), nil
}

// ResolveContainer resolves an explicitly requested or Kubernetes-default
// regular container and verifies that it exists in the Pod.
func ResolveContainer(pod *corev1.Pod, requested string) (string, string, error) {
	if pod == nil {
		return "", "", apierrors.NewBadRequest("pod is required")
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
		return "", "", apierrors.NewBadRequest(fmt.Sprintf("pod %s/%s has no regular containers", pod.Namespace, pod.Name))
	}
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == container {
			return container, defaultContainer, nil
		}
	}
	return "", "", apierrors.NewBadRequest(fmt.Sprintf("pod %s/%s has no regular container %q", pod.Namespace, pod.Name, container))
}

// ContainerAllowed reports whether a resolved container is permitted by a
// global container selection mode.
func ContainerAllowed(mode string, explicit bool, container, defaultContainer string) bool {
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
