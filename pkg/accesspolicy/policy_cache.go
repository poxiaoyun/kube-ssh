package accesspolicy

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

const (
	accessPasswordIndex     = "accesspolicy.kube-ssh.io/access-password"
	accessPublicKeyIndex    = "accesspolicy.kube-ssh.io/access-public-key"
	accessPasswordRefIndex  = "accesspolicy.kube-ssh.io/access-password-ref"
	accessPublicKeyRefIndex = "accesspolicy.kube-ssh.io/access-public-key-ref"
	secretPasswordIndex     = "accesspolicy.kube-ssh.io/secret-password"
	secretPublicKeyIndex    = "accesspolicy.kube-ssh.io/secret-public-key"
)

type PolicyCache struct {
	accessIndexer cache.Indexer
	secretIndexer cache.Indexer
	namespace     string
}

func NewPolicyCache(accessIndexer, secretIndexer cache.Indexer, namespace string) *PolicyCache {
	return &PolicyCache{
		accessIndexer: accessIndexer,
		secretIndexer: secretIndexer,
		namespace:     namespace,
	}
}

func AccessPolicyIndexers() cache.Indexers {
	return cache.Indexers{
		accessPasswordIndex:     indexAccessPasswords,
		accessPublicKeyIndex:    indexAccessPublicKeys,
		accessPasswordRefIndex:  indexAccessPasswordRefs,
		accessPublicKeyRefIndex: indexAccessPublicKeyRefs,
	}
}

func SecretPolicyIndexers() cache.Indexers {
	return cache.Indexers{
		secretPasswordIndex:  indexSecretPasswords,
		secretPublicKeyIndex: indexSecretPublicKeys,
	}
}

func (c *PolicyCache) Get(_ context.Context, namespace, name string) (*sshv1.Access, error) {
	if c == nil || c.accessIndexer == nil {
		return nil, fmt.Errorf("access policy cache requires an access indexer")
	}
	if c.namespace != "" && namespace != c.namespace {
		return nil, fmt.Errorf("access %s/%s outside configured namespace %s", namespace, name, c.namespace)
	}
	obj, exists, err := c.accessIndexer.GetByKey(accessKey(namespace, name))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("access %s/%s not found", namespace, name)
	}
	access, ok := obj.(*sshv1.Access)
	if !ok {
		return nil, fmt.Errorf("access cache object %s/%s has unexpected type %T", namespace, name, obj)
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
		if c.namespace != "" && access.Namespace != c.namespace {
			continue
		}
		accesses = append(accesses, access.DeepCopy())
	}
	sortAccesses(accesses)
	return accesses, nil
}

func (c *PolicyCache) MatchPassword(_ context.Context, token string) (*CredentialMatch, error) {
	if token == "" {
		return nil, authn.ErrNotProvided
	}
	seen := map[string]struct{}{}
	matches := []*CredentialMatch{}
	if err := c.matchAccessPassword(token, &matches, seen); err != nil {
		return nil, err
	}
	if err := c.matchSecretPassword(token, &matches, seen); err != nil {
		return nil, err
	}
	sortMatches(matches)
	return chooseMatch("password token", token, matches)
}

func (c *PolicyCache) MatchPublicKey(_ context.Context, pubkey cryptossh.PublicKey) (*CredentialMatch, error) {
	if pubkey == nil {
		return nil, authn.ErrNotProvided
	}
	fingerprint := cryptossh.FingerprintSHA256(pubkey)
	seen := map[string]struct{}{}
	matches := []*CredentialMatch{}
	if err := c.matchAccessPublicKey(fingerprint, &matches, seen); err != nil {
		return nil, err
	}
	if err := c.matchSecretPublicKey(fingerprint, &matches, seen); err != nil {
		return nil, err
	}
	sortMatches(matches)
	return chooseMatch("public key", fingerprint, matches)
}

func (c *PolicyCache) matchAccessPassword(token string, matches *[]*CredentialMatch, seen map[string]struct{}) error {
	objects, err := c.accessObjectsByIndex(accessPasswordIndex, token)
	if err != nil {
		return err
	}
	for _, access := range objects {
		if !c.acceptAccess(access) {
			continue
		}
		for idx := range access.Spec.Credentials {
			credential := access.Spec.Credentials[idx]
			for _, password := range credential.Passwords {
				if password == token {
					addCredentialMatch(matches, seen, access, idx)
					break
				}
			}
		}
	}
	return nil
}

func (c *PolicyCache) matchAccessPublicKey(fingerprint string, matches *[]*CredentialMatch, seen map[string]struct{}) error {
	objects, err := c.accessObjectsByIndex(accessPublicKeyIndex, fingerprint)
	if err != nil {
		return err
	}
	for _, access := range objects {
		if !c.acceptAccess(access) {
			continue
		}
		for idx := range access.Spec.Credentials {
			credential := access.Spec.Credentials[idx]
			for _, key := range credential.PublicKeys {
				if keyFingerprint(key) == fingerprint {
					addCredentialMatch(matches, seen, access, idx)
					break
				}
			}
		}
	}
	return nil
}

func (c *PolicyCache) matchSecretPassword(token string, matches *[]*CredentialMatch, seen map[string]struct{}) error {
	secrets, err := c.secretsByValueIndex(secretPasswordIndex, token)
	if err != nil {
		return err
	}
	for _, secret := range secrets {
		if !c.acceptSecret(secret) {
			continue
		}
		for _, key := range secretKeysContainingPassword(secret, token) {
			if err := c.matchAccessPasswordRef(secret.Namespace, secret.Name, key, matches, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *PolicyCache) matchSecretPublicKey(fingerprint string, matches *[]*CredentialMatch, seen map[string]struct{}) error {
	secrets, err := c.secretsByValueIndex(secretPublicKeyIndex, fingerprint)
	if err != nil {
		return err
	}
	for _, secret := range secrets {
		if !c.acceptSecret(secret) {
			continue
		}
		for _, key := range secretKeysContainingPublicKey(secret, fingerprint) {
			if err := c.matchAccessPublicKeyRef(secret.Namespace, secret.Name, key, matches, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *PolicyCache) matchAccessPasswordRef(namespace, name, key string, matches *[]*CredentialMatch, seen map[string]struct{}) error {
	objects, err := c.accessObjectsByIndex(accessPasswordRefIndex, secretRefKey(namespace, name, key))
	if err != nil {
		return err
	}
	for _, access := range objects {
		if !c.acceptAccess(access) {
			continue
		}
		for idx := range access.Spec.Credentials {
			for _, ref := range access.Spec.Credentials[idx].PasswordsFrom {
				if ref.Name == name && ref.Key == key {
					addCredentialMatch(matches, seen, access, idx)
					break
				}
			}
		}
	}
	return nil
}

func (c *PolicyCache) matchAccessPublicKeyRef(namespace, name, key string, matches *[]*CredentialMatch, seen map[string]struct{}) error {
	objects, err := c.accessObjectsByIndex(accessPublicKeyRefIndex, secretRefKey(namespace, name, key))
	if err != nil {
		return err
	}
	for _, access := range objects {
		if !c.acceptAccess(access) {
			continue
		}
		for idx := range access.Spec.Credentials {
			for _, ref := range access.Spec.Credentials[idx].PublicKeysFrom {
				if ref.Name == name && ref.Key == key {
					addCredentialMatch(matches, seen, access, idx)
					break
				}
			}
		}
	}
	return nil
}

func (c *PolicyCache) accessObjectsByIndex(indexName, key string) ([]*sshv1.Access, error) {
	if c == nil || c.accessIndexer == nil {
		return nil, fmt.Errorf("access policy cache requires an access indexer")
	}
	objects, err := c.accessIndexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	accesses := make([]*sshv1.Access, 0, len(objects))
	for _, obj := range objects {
		access, ok := obj.(*sshv1.Access)
		if !ok {
			return nil, fmt.Errorf("access cache index %q has unexpected object type %T", indexName, obj)
		}
		accesses = append(accesses, access)
	}
	return accesses, nil
}

func (c *PolicyCache) secretsByValueIndex(indexName, key string) ([]*corev1.Secret, error) {
	if c == nil || c.secretIndexer == nil {
		return nil, nil
	}
	objects, err := c.secretIndexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	secrets := make([]*corev1.Secret, 0, len(objects))
	for _, obj := range objects {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			continue
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

func (c *PolicyCache) acceptAccess(access *sshv1.Access) bool {
	if !isPodAccess(access) {
		return false
	}
	return c.namespace == "" || access.Namespace == c.namespace
}

func (c *PolicyCache) acceptSecret(secret *corev1.Secret) bool {
	if secret == nil {
		return false
	}
	return c.namespace == "" || secret.Namespace == c.namespace
}

func addCredentialMatch(matches *[]*CredentialMatch, seen map[string]struct{}, access *sshv1.Access, credentialIndex int) {
	if access == nil || credentialIndex < 0 || credentialIndex >= len(access.Spec.Credentials) {
		return
	}
	credential := access.Spec.Credentials[credentialIndex]
	key := accessKey(access.Namespace, access.Name) + "\x00" + credential.Username
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	copied := access.DeepCopy()
	*matches = append(*matches, &CredentialMatch{
		Access:     copied,
		Credential: &copied.Spec.Credentials[credentialIndex],
	})
}

func indexAccessPasswords(obj any) ([]string, error) {
	access, ok := obj.(*sshv1.Access)
	if !ok || !isPodAccess(access) {
		return nil, nil
	}
	values := map[string]struct{}{}
	for _, credential := range access.Spec.Credentials {
		for _, password := range credential.Passwords {
			if password != "" {
				values[password] = struct{}{}
			}
		}
	}
	return stringSetValues(values), nil
}

func indexAccessPublicKeys(obj any) ([]string, error) {
	access, ok := obj.(*sshv1.Access)
	if !ok || !isPodAccess(access) {
		return nil, nil
	}
	values := map[string]struct{}{}
	for _, credential := range access.Spec.Credentials {
		for _, key := range credential.PublicKeys {
			if fingerprint := keyFingerprint(key); fingerprint != "" {
				values[fingerprint] = struct{}{}
			}
		}
	}
	return stringSetValues(values), nil
}

func indexAccessPasswordRefs(obj any) ([]string, error) {
	access, ok := obj.(*sshv1.Access)
	if !ok || !isPodAccess(access) {
		return nil, nil
	}
	values := map[string]struct{}{}
	for _, credential := range access.Spec.Credentials {
		for _, ref := range credential.PasswordsFrom {
			values[secretRefKey(access.Namespace, ref.Name, ref.Key)] = struct{}{}
		}
	}
	return stringSetValues(values), nil
}

func indexAccessPublicKeyRefs(obj any) ([]string, error) {
	access, ok := obj.(*sshv1.Access)
	if !ok || !isPodAccess(access) {
		return nil, nil
	}
	values := map[string]struct{}{}
	for _, credential := range access.Spec.Credentials {
		for _, ref := range credential.PublicKeysFrom {
			values[secretRefKey(access.Namespace, ref.Name, ref.Key)] = struct{}{}
		}
	}
	return stringSetValues(values), nil
}

func indexSecretPasswords(obj any) ([]string, error) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil, nil
	}
	values := map[string]struct{}{}
	for _, value := range secret.Data {
		for _, password := range splitSecretLines(string(value)) {
			values[password] = struct{}{}
		}
	}
	return stringSetValues(values), nil
}

func indexSecretPublicKeys(obj any) ([]string, error) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil, nil
	}
	values := map[string]struct{}{}
	for _, value := range secret.Data {
		for _, line := range splitSecretLines(string(value)) {
			if fingerprint := keyFingerprint(line); fingerprint != "" {
				values[fingerprint] = struct{}{}
			}
		}
	}
	return stringSetValues(values), nil
}

func secretKeysContainingPassword(secret *corev1.Secret, token string) []string {
	keys := []string{}
	for key, value := range secret.Data {
		for _, password := range splitSecretLines(string(value)) {
			if password == token {
				keys = append(keys, key)
				break
			}
		}
	}
	sort.Strings(keys)
	return keys
}

func secretKeysContainingPublicKey(secret *corev1.Secret, fingerprint string) []string {
	keys := []string{}
	for key, value := range secret.Data {
		for _, line := range splitSecretLines(string(value)) {
			if keyFingerprint(line) == fingerprint {
				keys = append(keys, key)
				break
			}
		}
	}
	sort.Strings(keys)
	return keys
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

func secretRefKey(namespace, name, key string) string {
	return namespace + "/" + name + "/" + key
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

func stringSetValues(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func chooseMatch(kind, key string, matches []*CredentialMatch) (*CredentialMatch, error) {
	if len(matches) == 0 {
		return nil, authn.ErrNotProvided
	}
	if len(matches) > 1 {
		chosen := matches[0]
		slog.Warn("duplicate access credential material, using oldest access",
			"kind", kind,
			"key", key,
			"access", accessKey(chosen.Access.Namespace, chosen.Access.Name),
			"credential", chosen.Credential.Username,
			"matches", len(matches),
		)
	}
	return matches[0], nil
}

func sortMatches(matches []*CredentialMatch) {
	sort.Slice(matches, func(i, j int) bool {
		a := matches[i]
		b := matches[j]
		if accessLess(a.Access, b.Access) {
			return true
		}
		if accessLess(b.Access, a.Access) {
			return false
		}
		return a.Credential.Username < b.Credential.Username
	})
}
