package sshproxy_test

import (
	"context"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestConnectorRejectsMalformedTargets(t *testing.T) {
	unbound := sshproxy.NewTarget(&sshv1.Access{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "notebook"}}, "main")
	for name, tgt := range map[string]*target.Target{
		"missing":        nil,
		"other kind":     {Kind: target.KindPod},
		"missing Access": {Kind: target.KindExternalSSH},
		"unbound Access": unbound,
	} {
		t.Run(name, func(t *testing.T) {
			connector := sshproxy.NewConnector(&connectorSource{}, time.Second)
			if _, err := connector.Connect(context.Background(), tgt); !apierrors.IsBadRequest(err) {
				t.Fatalf("Connect() error = %v, want BadRequest", err)
			}
		})
	}
}
