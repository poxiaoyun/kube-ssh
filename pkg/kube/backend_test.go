package kube

import (
	"testing"

	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestIsPodLocalForwardHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{want: true},
		{host: "localhost", want: true},
		{host: "127.0.0.1", want: true},
		{host: "::1", want: true},
		{host: "kubernetes.default.svc"},
		{host: "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := IsPodLocalForwardHost(tt.host)
			if got != tt.want {
				t.Fatalf("IsPodLocalForwardHost(%q) = %t, want %t", tt.host, got, tt.want)
			}
		})
	}
}

func TestKubeTarget(t *testing.T) {
	namespace, pod, container, err := kubeTarget(kubeTargetFixture())
	if err != nil {
		t.Fatalf("kubeTarget() error = %v", err)
	}
	if namespace != "default" || pod != "nginx" || container != "app" {
		t.Fatalf("kubeTarget() = %q, %q, %q", namespace, pod, container)
	}

	if _, _, _, err := kubeTarget(nil); err == nil {
		t.Fatal("kubeTarget(nil) succeeded")
	}
	if _, _, _, err := kubeTarget(&target.Target{Kind: "other"}); err == nil {
		t.Fatal("kubeTarget(non-kube) succeeded")
	}
	if _, _, _, err := kubeTarget(NewTarget("", "nginx", "")); err == nil {
		t.Fatal("kubeTarget(missing namespace) succeeded")
	}
	if _, _, _, err := kubeTarget(NewTarget("default", "", "")); err == nil {
		t.Fatal("kubeTarget(missing pod) succeeded")
	}
}

func kubeTargetFixture() *target.Target {
	return NewTarget("default", "nginx", "app")
}
