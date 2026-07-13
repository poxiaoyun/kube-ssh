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
	resolver := NewUsernameResolver()

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
	resolver := NewPolicyUsernameResolver(pods, "KubernetesDefault", "All")
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

type fakePodGetter struct{ pod *corev1.Pod }

func (g fakePodGetter) Get(_ context.Context, namespace, name string) (*corev1.Pod, error) {
	if g.pod != nil && g.pod.Namespace == namespace && g.pod.Name == name {
		return g.pod.DeepCopy(), nil
	}
	return nil, errors.New("not found")
}
