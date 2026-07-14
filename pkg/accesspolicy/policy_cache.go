package accesspolicy

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

type PolicyCache struct {
	accessIndexer    cache.Indexer
	secretIndexer    cache.Indexer
	namespace        string
	gatewayClassName string
}

type PolicyCacheOptions struct {
	Namespace        string
	GatewayClassName string
}

func NewPolicyCache(accessIndexer, secretIndexer cache.Indexer, options PolicyCacheOptions) *PolicyCache {
	return &PolicyCache{
		accessIndexer:    accessIndexer,
		secretIndexer:    secretIndexer,
		namespace:        options.Namespace,
		gatewayClassName: options.GatewayClassName,
	}
}

func (c *PolicyCache) Get(_ context.Context, namespace, name string) (*sshv1.Access, error) {
	if c == nil || c.accessIndexer == nil {
		return nil, fmt.Errorf("access policy cache requires an access indexer")
	}
	if c.namespace != "" && namespace != c.namespace {
		return nil, fmt.Errorf("%w: %s/%s", ErrAccessNotFound, namespace, name)
	}
	obj, exists, err := c.accessIndexer.GetByKey(accessKey(namespace, name))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("%w: %s/%s", ErrAccessNotFound, namespace, name)
	}
	access, ok := obj.(*sshv1.Access)
	if !ok {
		return nil, fmt.Errorf("access cache object %s/%s has unexpected type %T", namespace, name, obj)
	}
	if !c.acceptAccess(access) {
		return nil, fmt.Errorf("%w: %s/%s", ErrAccessNotFound, namespace, name)
	}
	return access.DeepCopy(), nil
}

func (c *PolicyCache) List(context.Context) ([]*sshv1.Access, error) {
	if c == nil || c.accessIndexer == nil {
		return nil, fmt.Errorf("access policy cache requires an access indexer")
	}
	objects := c.accessIndexer.List()
	accesses := make([]*sshv1.Access, 0, len(objects))
	for _, obj := range objects {
		access, ok := obj.(*sshv1.Access)
		if !ok {
			return nil, fmt.Errorf("access cache object has unexpected type %T", obj)
		}
		if !c.acceptAccess(access) {
			continue
		}
		accesses = append(accesses, access.DeepCopy())
	}
	sortAccesses(accesses)
	return accesses, nil
}

func (c *PolicyCache) MatchPassword(ctx context.Context, sshUser, token string) (*CredentialMatch, error) {
	if token == "" {
		return nil, authn.ErrNotProvided
	}
	_, access, provided, err := resolveAccessLocator(ctx, c, sshUser)
	if err != nil {
		return nil, err
	}
	if !provided {
		return nil, authn.ErrNotProvided
	}
	matches := make([]int, 0, 1)
	for i := range access.Spec.Credentials {
		values, err := c.credentialPasswords(access.Namespace, access.Spec.Credentials[i])
		if err != nil {
			return nil, err
		}
		for value := range values {
			if subtle.ConstantTimeCompare([]byte(value), []byte(token)) == 1 {
				matches = append(matches, i)
				break
			}
		}
	}
	return credentialMatch(access, matches, "password")
}

func (c *PolicyCache) MatchPublicKey(ctx context.Context, sshUser string, pubkey cryptossh.PublicKey) (*CredentialMatch, error) {
	if pubkey == nil {
		return nil, authn.ErrNotProvided
	}
	_, access, provided, err := resolveAccessLocator(ctx, c, sshUser)
	if err != nil {
		return nil, err
	}
	if !provided {
		return nil, authn.ErrNotProvided
	}
	fingerprint := cryptossh.FingerprintSHA256(pubkey)
	matches := make([]int, 0, 1)
	for i := range access.Spec.Credentials {
		values, err := c.credentialPublicKeys(access.Namespace, access.Spec.Credentials[i])
		if err != nil {
			return nil, err
		}
		if _, ok := values[fingerprint]; ok {
			matches = append(matches, i)
		}
	}
	return credentialMatch(access, matches, "public key")
}

func credentialMatch(access *sshv1.Access, matches []int, kind string) (*CredentialMatch, error) {
	if len(matches) == 0 {
		return nil, authn.ErrNotProvided
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("%s maps to multiple credential identities in access %s/%s", kind, access.Namespace, access.Name)
	}
	copied := access.DeepCopy()
	return &CredentialMatch{Access: copied, Credential: &copied.Spec.Credentials[matches[0]]}, nil
}

func (c *PolicyCache) credentialPasswords(namespace string, credential sshv1.AccessCredential) (map[string]struct{}, error) {
	values := make(map[string]struct{}, len(credential.Passwords))
	for _, value := range credential.Passwords {
		if value != "" {
			values[value] = struct{}{}
		}
	}
	for _, ref := range credential.PasswordsFrom {
		value, err := c.secretValue(namespace, ref)
		if err != nil {
			return nil, err
		}
		for _, token := range splitSecretLines(string(value)) {
			values[token] = struct{}{}
		}
	}
	return values, nil
}

func (c *PolicyCache) credentialPublicKeys(namespace string, credential sshv1.AccessCredential) (map[string]struct{}, error) {
	values := make(map[string]struct{}, len(credential.PublicKeys))
	for _, line := range credential.PublicKeys {
		fingerprint := keyFingerprint(line)
		if fingerprint == "" {
			return nil, fmt.Errorf("credential %q in namespace %q contains an invalid public key", credential.Username, namespace)
		}
		values[fingerprint] = struct{}{}
	}
	for _, ref := range credential.PublicKeysFrom {
		value, err := c.secretValue(namespace, ref)
		if err != nil {
			return nil, err
		}
		for _, line := range splitSecretLines(string(value)) {
			fingerprint := keyFingerprint(line)
			if fingerprint == "" {
				return nil, fmt.Errorf("credential %q public key reference %s/%s:%s contains an invalid public key", credential.Username, namespace, ref.Name, ref.Key)
			}
			values[fingerprint] = struct{}{}
		}
	}
	return values, nil
}

func (c *PolicyCache) secretValue(namespace string, ref sshv1.LocalSecretKeyRef) ([]byte, error) {
	if ref.Name == "" || ref.Key == "" {
		return nil, fmt.Errorf("incomplete secret reference in namespace %q", namespace)
	}
	if c == nil || c.secretIndexer == nil {
		return nil, fmt.Errorf("access policy cache requires a secret indexer")
	}
	obj, exists, err := c.secretIndexer.GetByKey(accessKey(namespace, ref.Name))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("secret %s/%s not found", namespace, ref.Name)
	}
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil, fmt.Errorf("secret cache object %s/%s has unexpected type %T", namespace, ref.Name, obj)
	}
	value, ok := secret.Data[ref.Key]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s has no key %q", namespace, ref.Name, ref.Key)
	}
	return value, nil
}

func (c *PolicyCache) acceptAccess(access *sshv1.Access) bool {
	if !isPodAccess(access) {
		return false
	}
	if c.namespace != "" && access.Namespace != c.namespace {
		return false
	}
	return gatewayClassName(access) == c.gatewayClassName
}

func gatewayClassName(access *sshv1.Access) string {
	if access == nil || access.Spec.GatewayClassName == nil {
		return ""
	}
	return *access.Spec.GatewayClassName
}

func keyFingerprint(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	pubkey, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return cryptossh.FingerprintSHA256(pubkey)
}

func splitSecretLines(value string) []string {
	lines := strings.Split(value, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
