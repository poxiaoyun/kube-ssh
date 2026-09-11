package accesspolicy

import (
	"context"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
)

func TestAuthenticationMethodsUsesInboundCredentials(t *testing.T) {
	access := &sshv1.Access{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "notebook"},
		Spec: sshv1.AccessSpec{Credentials: []sshv1.AccessCredential{{
			Username:       "alice",
			PublicKeysFrom: []sshv1.LocalSecretKeyRef{{Name: "keys", Key: "authorized_keys"}},
			Passwords:      []string{""},
		}}},
	}
	store := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	for _, user := range []string{"default.notebook", "default.notebook.container", "default.notebook~pod.container"} {
		methods, found, err := AuthenticationMethods(context.Background(), store, user)
		if err != nil || !found || !reflect.DeepEqual(methods, []string{"publickey"}) {
			t.Fatalf("%s: methods=%v found=%v err=%v", user, methods, found, err)
		}
	}
	methods, found, err := AuthenticationMethods(context.Background(), store, "default.direct-pod")
	if err != nil || found || len(methods) != 0 {
		t.Fatalf("direct Pod: methods=%v found=%v err=%v", methods, found, err)
	}
}
