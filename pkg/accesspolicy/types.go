// Package accesspolicy applies Access resources to authentication, target
// resolution, authorization, and readiness status.
package accesspolicy

import (
	"context"
	"errors"

	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
)

var ErrAccessNotFound = errors.New("access not found")

type AccessGetter interface {
	// Get returns one Access or ErrAccessNotFound.
	Get(ctx context.Context, namespace, name string) (*sshv1.Access, error)
}

type Store interface {
	AccessGetter
	// List returns the Access objects visible to this gateway.
	List(ctx context.Context) ([]*sshv1.Access, error)
}

type CredentialMatcher interface {
	// MatchPassword resolves one SSH password token to an Access credential.
	MatchPassword(ctx context.Context, sshUser, token string) (*CredentialMatch, error)
	// MatchPublicKey resolves one SSH public key to an Access credential.
	MatchPublicKey(ctx context.Context, sshUser string, pubkey cryptossh.PublicKey) (*CredentialMatch, error)
}

type PodLister interface {
	// List returns Pods matching selector in namespace.
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
