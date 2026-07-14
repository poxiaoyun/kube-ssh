package kube

import (
	"testing"

	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestIsPodLoopbackHost(t *testing.T) {
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
			got := isPodLoopbackHost(tt.host)
			if got != tt.want {
				t.Fatalf("isPodLoopbackHost(%q) = %t, want %t", tt.host, got, tt.want)
			}
		})
	}
}

func TestKubeTarget(t *testing.T) {
	got, err := ParseTarget(kubeTargetFixture())
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	if got.Namespace != "default" || got.Pod != "nginx" || got.Container != "app" {
		t.Fatalf("ParseTarget() = %+v", got)
	}

	if _, err := ParseTarget(nil); err == nil {
		t.Fatal("kubeTarget(nil) succeeded")
	}
	if _, err := ParseTarget(&target.Target{Kind: "other"}); err == nil {
		t.Fatal("kubeTarget(non-kube) succeeded")
	}
	if _, err := ParseTarget(NewTarget("", "nginx", "")); err == nil {
		t.Fatal("kubeTarget(missing namespace) succeeded")
	}
	if _, err := ParseTarget(NewTarget("default", "", "")); err == nil {
		t.Fatal("kubeTarget(missing pod) succeeded")
	}
}

func kubeTargetFixture() *target.Target {
	return NewTarget("default", "nginx", "app")
}
