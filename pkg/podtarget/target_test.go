package podtarget_test

import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestTargetRoundTrip(t *testing.T) {
	tgt := podtarget.New("default", "nginx", "app")
	if got, want := tgt.String(), "kube/namespaces/default/pods/nginx/containers/app"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	reference, err := podtarget.Parse(tgt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if reference.Namespace != "default" || reference.Pod != "nginx" || reference.Container != "app" {
		t.Fatalf("Parse() = %+v", reference)
	}
}

func TestParseRejectsNonPodAndIncompleteTargets(t *testing.T) {
	for name, tgt := range map[string]*target.Target{
		"missing":           nil,
		"other kind":        {Kind: "other"},
		"missing namespace": podtarget.New("", "nginx", ""),
		"missing pod":       podtarget.New("default", "", ""),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := podtarget.Parse(tgt); !apierrors.IsBadRequest(err) {
				t.Fatalf("Parse() error = %v, want BadRequest", err)
			}
		})
	}
}
