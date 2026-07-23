package nodebackend

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"xiaoshiai.cn/kube-ssh/pkg/kube"
)

func TestLocateRejectsReplacedPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", UID: types.UID("new-uid")},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, HostIP: "10.0.0.2"},
	}
	tgt := kube.NewTarget("default", "app", "app")
	// Model a target resolved before the Pod was recreated.
	old := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", UID: types.UID("old-uid")},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{HostIP: "10.0.0.2"},
	}
	bound := kube.NewTargetForPod(old, "app")
	if tgt.ToPath() != bound.ToPath() {
		t.Fatalf("test targets differ: %s != %s", tgt.ToPath(), bound.ToPath())
	}
	transport := &transport{client: fake.NewSimpleClientset(pod)}
	_, err := transport.locate(context.Background(), bound)
	if err == nil || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("locate() error = %v", err)
	}
}

func TestLocateRejectsUnboundTarget(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", UID: types.UID("uid-1")},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, HostIP: "10.0.0.2"},
	}
	transport := &transport{client: fake.NewSimpleClientset(pod)}
	_, err := transport.locate(context.Background(), kube.NewTarget("default", "app", "app"))
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("locate() error = %v", err)
	}
}

func TestEndpointSupportsIPv6NodeAddress(t *testing.T) {
	transport := &transport{options: Options{Port: 10443}}
	u := transport.endpoint(podLocation{Namespace: "default", Pod: "app", UID: "uid-1", HostIP: "2001:db8::1"}, "exec", "app")
	if got := u.String(); got != "https://[2001:db8::1]:10443/v1/exec/default/app/uid-1/app" {
		t.Fatalf("endpoint = %q", got)
	}
}
