package kube

import "testing"

func TestTargetToPath(t *testing.T) {
	tgt := NewTarget("default", "nginx", "app")
	if got, want := tgt.ToPath(), "kube/namespaces/default/pods/nginx/containers/app"; got != want {
		t.Fatalf("ToPath() = %q, want %q", got, want)
	}
}
