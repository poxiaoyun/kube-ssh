package podtarget_test

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestUsernameResolverResolve(t *testing.T) {
	resolver := podtarget.NewUsernameResolver()

	tgt, err := resolver.Resolve(context.Background(), target.ResolveInput{SSHUser: "default.nginx"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if tgt.Kind != target.KindPod {
		t.Fatalf("Kind = %q, want %q", tgt.Kind, target.KindPod)
	}
	if got := tgt.Option(podtarget.OptionNamespaces); got != "default" {
		t.Fatalf("namespace = %q, want default", got)
	}
	if got := tgt.Option(podtarget.OptionPods); got != "nginx" {
		t.Fatalf("pod = %q, want nginx", got)
	}
	if got := tgt.Option(podtarget.OptionContainers); got != "" {
		t.Fatalf("container = %q, want empty", got)
	}

	tgt, err = resolver.Resolve(context.Background(), target.ResolveInput{SSHUser: "default.nginx.app"})
	if err != nil {
		t.Fatalf("Resolve(container) error = %v", err)
	}
	if got := tgt.Option(podtarget.OptionContainers); got != "app" {
		t.Fatalf("container = %q, want app", got)
	}

	if _, err := resolver.Resolve(context.Background(), target.ResolveInput{SSHUser: "nginx"}); !errors.Is(err, target.ErrNotProvided) {
		t.Fatalf("Resolve() error = %v, want ErrNotProvided", err)
	}
	if _, err := resolver.Resolve(context.Background(), target.ResolveInput{SSHUser: "default."}); !apierrors.IsBadRequest(err) {
		t.Fatalf("Resolve() error = %v, want BadRequest", err)
	}
}

func TestBindingResolverUsesKubernetesDefaultContainer(t *testing.T) {
	pods := fakePodGetter{pod: &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "nginx", Annotations: map[string]string{"kubectl.kubernetes.io/default-container": "sidecar"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "sidecar"}}},
	}}
	resolver := podtarget.NewBindingResolver(podtarget.NewUsernameResolver(), podtarget.ResolverOptions{
		Pods:                 pods,
		DefaultContainerMode: "KubernetesDefault",
		LimitContainerMode:   "All",
	})
	tgt, err := resolver.Resolve(context.Background(), target.ResolveInput{SSHUser: "default.nginx"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.Option(podtarget.OptionContainers); got != "sidecar" {
		t.Fatalf("container = %q, want sidecar", got)
	}
	if _, err := resolver.Resolve(context.Background(), target.ResolveInput{SSHUser: "default.nginx.app"}); !apierrors.IsForbidden(err) {
		t.Fatalf("Resolve(app) error = %v, want Forbidden", err)
	}
	if _, err := resolver.Resolve(context.Background(), target.ResolveInput{SSHUser: "default.nginx.sidecar"}); err != nil {
		t.Fatalf("Resolve(sidecar) error = %v", err)
	}
}

func TestBindingResolverPinsPodInstance(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "nginx", UID: "uid-1"},
		Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{HostIP: "10.0.0.2"},
	}
	resolver := podtarget.NewBindingResolver(podtarget.NewUsernameResolver(), podtarget.ResolverOptions{
		Pods: fakePodGetter{pod: pod}, DefaultContainerMode: "All", LimitContainerMode: "All",
	})
	tgt, err := resolver.Resolve(context.Background(), target.ResolveInput{SSHUser: "default.nginx"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.Option(podtarget.OptionContainers); got != "app" {
		t.Fatalf("container = %q, want app", got)
	}
	binding := podtarget.BoundIdentity(tgt)
	if binding.UID != "uid-1" || binding.NodeName != "node-a" || binding.HostIP != "10.0.0.2" {
		t.Fatalf("binding = %+v", binding)
	}
}

func TestBindingResolverPreservesExistingBinding(t *testing.T) {
	inner := resolverFunc(func(context.Context, target.ResolveInput) (*target.Target, error) {
		return podtarget.Bind(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "selected", UID: "selected-uid"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		}, "app"), nil
	})
	resolver := podtarget.NewBindingResolver(inner, podtarget.ResolverOptions{
		Pods: fakePodGetter{pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "replacement", UID: "replacement-uid"},
		}},
		DefaultContainerMode: "All",
		LimitContainerMode:   "All",
	})
	tgt, err := resolver.Resolve(context.Background(), target.ResolveInput{})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := podtarget.BoundIdentity(tgt).UID; got != "selected-uid" {
		t.Fatalf("bound UID = %q, want selected-uid", got)
	}
}

type resolverFunc func(context.Context, target.ResolveInput) (*target.Target, error)

func (f resolverFunc) Resolve(ctx context.Context, req target.ResolveInput) (*target.Target, error) {
	return f(ctx, req)
}

func TestBindingResolverPreservesLookupErrors(t *testing.T) {
	for name, cause := range map[string]error{
		"missing pod": apierrors.NewNotFound(corev1.Resource("pods"), "nginx"),
		"forbidden":   apierrors.NewForbidden(corev1.Resource("pods"), "nginx", errors.New("access denied")),
		"canceled":    context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			resolver := podtarget.NewBindingResolver(podtarget.NewUsernameResolver(), podtarget.ResolverOptions{
				Pods: fakePodGetter{err: cause}, DefaultContainerMode: "All", LimitContainerMode: "All",
			})
			_, err := resolver.Resolve(context.Background(), target.ResolveInput{SSHUser: "default.nginx"})
			if !errors.Is(err, cause) {
				t.Fatalf("Resolve() error = %v, want cause %v", err, cause)
			}
			if got, want := apierrors.ReasonForError(err), apierrors.ReasonForError(cause); got != want {
				t.Fatalf("Resolve() reason = %q, want %q", got, want)
			}
		})
	}
}

type fakePodGetter struct {
	pod *corev1.Pod
	err error
}

func (g fakePodGetter) Get(_ context.Context, namespace, name string) (*corev1.Pod, error) {
	if g.err != nil {
		return nil, g.err
	}
	if g.pod != nil && g.pod.Namespace == namespace && g.pod.Name == name {
		return g.pod.DeepCopy(), nil
	}
	return nil, errors.New("not found")
}
