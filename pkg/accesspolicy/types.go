package accesspolicy

import (
	"context"

	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
)

type AccessGetter interface {
	Get(ctx context.Context, namespace, name string) (*sshv1.Access, error)
}

type Store interface {
	AccessGetter
	List(ctx context.Context) ([]*sshv1.Access, error)
}

type CredentialMatcher interface {
	MatchPassword(ctx context.Context, token string) (*CredentialMatch, error)
	MatchPublicKey(ctx context.Context, pubkey cryptossh.PublicKey) (*CredentialMatch, error)
}

type PodLister interface {
	List(ctx context.Context, namespace string, selector map[string]string) ([]corev1.Pod, error)
}

type CredentialMatch struct {
	Access     *sshv1.Access
	Credential *sshv1.AccessCredential
}

func copyStringSliceMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}
