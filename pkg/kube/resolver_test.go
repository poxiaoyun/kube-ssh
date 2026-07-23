package kube

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestUsernameResolverResolve(t *testing.T) {
	resolver := NewUsernameResolver(UsernameResolverOptions{})

	tgt, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default.nginx"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if tgt.Kind != KindTarget {
		t.Fatalf("Kind = %q, want %q", tgt.Kind, KindTarget)
	}
	if got := tgt.Option(OptionNamespaces); got != "default" {
		t.Fatalf("namespace = %q, want default", got)
	}
	if got := tgt.Option(OptionPods); got != "nginx" {
		t.Fatalf("pod = %q, want nginx", got)
	}
	if got := tgt.Option(OptionContainers); got != "" {
		t.Fatalf("container = %q, want empty", got)
	}

	tgt, err = resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default.nginx.app"})
	if err != nil {
		t.Fatalf("Resolve(container) error = %v", err)
	}
	if got := tgt.Option(OptionContainers); got != "app" {
		t.Fatalf("container = %q, want app", got)
	}

	if _, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "nginx"}); !errors.Is(err, target.ErrNotProvided) {
		t.Fatalf("Resolve() error = %v, want ErrNotProvided", err)
	}
	if _, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default."}); err == nil {
		t.Fatal("Resolve() succeeded for empty pod")
	} else if !status.IsReason(err, status.ReasonInvalidTarget) {
		t.Fatalf("Resolve() error reason = %q, want InvalidTarget", status.ReasonForError(err))
	}
}

func TestPolicyUsernameResolverUsesKubernetesDefaultContainer(t *testing.T) {
	pods := fakePodGetter{pod: &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "nginx", Annotations: map[string]string{"kubectl.kubernetes.io/default-container": "sidecar"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "sidecar"}}},
	}}
	resolver := NewUsernameResolver(UsernameResolverOptions{
		Pods:                 pods,
		DefaultContainerMode: "KubernetesDefault",
		LimitContainerMode:   "All",
	})
	tgt, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default.nginx"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.Option(OptionContainers); got != "sidecar" {
		t.Fatalf("container = %q, want sidecar", got)
	}
	if _, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default.nginx.app"}); err == nil {
		t.Fatal("Resolve(app) error = nil, want default-container policy denial")
	}
	if _, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default.nginx.sidecar"}); err != nil {
		t.Fatalf("Resolve(sidecar) error = %v", err)
	}
}

func TestBindingResolverPinsPodInstance(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "nginx", UID: "uid-1"},
		Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{HostIP: "10.0.0.2"},
	}
	resolver := NewBindingResolver(NewUsernameResolver(UsernameResolverOptions{}), UsernameResolverOptions{
		Pods: fakePodGetter{pod: pod}, DefaultContainerMode: "All", LimitContainerMode: "All",
	})
	tgt, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default.nginx"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.Option(OptionContainers); got != "app" {
		t.Fatalf("container = %q, want app", got)
	}
	if got := tgt.RuntimeValue(RuntimePodUID); got != "uid-1" {
		t.Fatalf("pod UID = %q, want uid-1", got)
	}
	if got := tgt.RuntimeValue(RuntimeNodeName); got != "node-a" {
		t.Fatalf("node = %q, want node-a", got)
	}
	if got := tgt.RuntimeValue(RuntimeHostIP); got != "10.0.0.2" {
		t.Fatalf("host IP = %q, want 10.0.0.2", got)
	}
}

func TestBindingResolverReleasesSelectionOnBindFailure(t *testing.T) {
	released := 0
	inner := resolverFunc(func(context.Context, target.ResolveRequest) (*target.Target, error) {
		return target.WithRelease(NewTarget("default", "missing", "app"), func() { released++ }), nil
	})
	resolver := NewBindingResolver(inner, UsernameResolverOptions{Pods: fakePodGetter{}, DefaultContainerMode: "All", LimitContainerMode: "All"})
	if _, err := resolver.Resolve(context.Background(), target.ResolveRequest{}); err == nil {
		t.Fatal("Resolve() error = nil")
	}
	if released != 1 {
		t.Fatalf("release count = %d, want 1", released)
	}
}

type resolverFunc func(context.Context, target.ResolveRequest) (*target.Target, error)

func (f resolverFunc) Resolve(ctx context.Context, req target.ResolveRequest) (*target.Target, error) {
	return f(ctx, req)
}

type fakePodGetter struct{ pod *corev1.Pod }

func (g fakePodGetter) Get(_ context.Context, namespace, name string) (*corev1.Pod, error) {
	if g.pod != nil && g.pod.Namespace == namespace && g.pod.Name == name {
		return g.pod.DeepCopy(), nil
	}
	return nil, errors.New("not found")
}
