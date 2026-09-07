package accesspolicy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

func TestPolicyCacheScopesDuplicatePasswordToRequestedAccess(t *testing.T) {
	newer := accessFixture("default", "newer", "bob", sshv1.AccessCredential{Passwords: []string{"shared"}}, time.Unix(20, 0))
	older := accessFixture("default", "older", "alice", sshv1.AccessCredential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{newer, older}, nil)

	match, err := policyCache.MatchPassword(context.Background(), "default.older", "shared")
	if err != nil {
		t.Fatalf("MatchPassword() error = %v", err)
	}
	if match.Access.Name != "older" || match.Credential.Username != "alice" {
		t.Fatalf("match = %s/%s %s", match.Access.Namespace, match.Access.Name, match.Credential.Username)
	}
	match, err = policyCache.MatchPassword(context.Background(), "default.newer", "shared")
	if err != nil {
		t.Fatalf("MatchPassword(newer) error = %v", err)
	}
	if match.Access.Name != "newer" || match.Credential.Username != "bob" {
		t.Fatalf("newer match = %s/%s %s", match.Access.Namespace, match.Access.Name, match.Credential.Username)
	}
}

func TestPolicyCacheScopesDuplicatePublicKeyToRequestedAccess(t *testing.T) {
	pubkey := testPublicKey(t)
	keyLine := string(cryptossh.MarshalAuthorizedKey(pubkey))
	first := accessFixture("default", "first", "alice", sshv1.AccessCredential{PublicKeys: []string{keyLine}}, time.Unix(10, 0))
	second := accessFixture("default", "second", "bob", sshv1.AccessCredential{PublicKeys: []string{keyLine}}, time.Unix(20, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{first, second}, nil)

	for _, tc := range []struct {
		sshUser string
		want    string
	}{
		{sshUser: "default.first", want: "alice"},
		{sshUser: "default.second", want: "bob"},
	} {
		match, err := policyCache.MatchPublicKey(context.Background(), tc.sshUser, pubkey)
		if err != nil {
			t.Fatalf("MatchPublicKey(%s) error = %v", tc.sshUser, err)
		}
		if match.Credential.Username != tc.want {
			t.Fatalf("MatchPublicKey(%s) username = %q, want %q", tc.sshUser, match.Credential.Username, tc.want)
		}
	}
}

func TestPolicyCacheRejectsCredentialMaterialSharedByIdentitiesWithinAccess(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	access.Spec.Credentials = append(access.Spec.Credentials, sshv1.AccessCredential{
		Username:  "bob",
		Passwords: []string{"shared"},
	})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)

	if _, err := policyCache.MatchPassword(context.Background(), "default.notebook", "shared"); err == nil {
		t.Fatal("MatchPassword() error = nil, want ambiguous credential identity error")
	}
}

func TestPolicyCachePrefersExactDottedAccessName(t *testing.T) {
	prefix := accessFixture("default", "database", "prefix-user", sshv1.AccessCredential{Passwords: []string{"prefix-token"}}, time.Unix(10, 0))
	exact := accessFixture("default", "database.readonly", "exact-user", sshv1.AccessCredential{Passwords: []string{"exact-token"}}, time.Unix(20, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{prefix, exact}, nil)

	match, err := policyCache.MatchPassword(context.Background(), "default.database.readonly", "exact-token")
	if err != nil {
		t.Fatalf("MatchPassword() error = %v", err)
	}
	if match.Access.Name != "database.readonly" {
		t.Fatalf("matched Access = %q, want database.readonly", match.Access.Name)
	}
	if _, err := policyCache.MatchPassword(context.Background(), "default.database.readonly", "prefix-token"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("prefix credential error = %v, want ErrNotProvided", err)
	}
}

func TestPolicyCacheAuthenticatesExternalAccess(t *testing.T) {
	access := accessFixture("default", "external", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Type = sshv1.AccessTypeExternal
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)

	match, err := policyCache.MatchPassword(context.Background(), "default.external", "token")
	if err != nil {
		t.Fatalf("MatchPassword() error = %v", err)
	}
	if match.Access.Name != "external" || match.Credential.Username != "alice" {
		t.Fatalf("match = %#v", match)
	}
}

func TestPolicyCacheMatchesGatewayClassExactly(t *testing.T) {
	className := "default-gateway"
	classed := accessFixture("default", "classed", "alice", sshv1.AccessCredential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	classed.Spec.GatewayClassName = &className
	classless := accessFixture("default", "default", "bob", sshv1.AccessCredential{Passwords: []string{"shared"}}, time.Unix(20, 0))

	classedCache := newTestPolicyCacheForGateway(t, "", className, []*sshv1.Access{classless, classed}, nil)
	match, err := classedCache.MatchPassword(context.Background(), "default.classed", "shared")
	if err != nil {
		t.Fatalf("MatchPassword() error = %v", err)
	}
	if match.Access.Name != "classed" {
		t.Fatalf("matched Access = %q, want classed", match.Access.Name)
	}
	if _, err := classedCache.Get(context.Background(), "default", "default"); err == nil {
		t.Fatal("Get() error = nil for classless Access on classed gateway")
	}

	defaultCache := newTestPolicyCacheForGateway(t, "", "", []*sshv1.Access{classless, classed}, nil)
	match, err = defaultCache.MatchPassword(context.Background(), "default.default", "shared")
	if err != nil {
		t.Fatalf("classless MatchPassword() error = %v", err)
	}
	if match.Access.Name != "default" {
		t.Fatalf("matched Access = %q, want default", match.Access.Name)
	}
}

func TestPolicyCacheSecretMustBeReferenced(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "access", Key: "passwords"}},
	}, time.Unix(10, 0))
	secret := secretFixture("default", "access", map[string]string{
		"other": "secret-token",
	})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, []*corev1.Secret{secret})

	if _, err := policyCache.MatchPassword(context.Background(), "default.notebook", "secret-token"); err == nil {
		t.Fatal("MatchPassword() error = nil, want invalid secret reference error")
	}
}

func TestPolicyCacheNamespaceScope(t *testing.T) {
	allowed := accessFixture("allowed", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"allowed-token"}}, time.Unix(10, 0))
	other := accessFixture("other", "notebook", "bob", sshv1.AccessCredential{Passwords: []string{"other-token"}}, time.Unix(20, 0))
	policyCache := newTestPolicyCache(t, "allowed", []*sshv1.Access{allowed, other}, nil)

	match, err := policyCache.MatchPassword(context.Background(), "allowed.notebook", "allowed-token")
	if err != nil {
		t.Fatalf("MatchPassword() error = %v", err)
	}
	if match.Access.Namespace != "allowed" || match.Credential.Username != "alice" {
		t.Fatalf("match = %s/%s %s", match.Access.Namespace, match.Access.Name, match.Credential.Username)
	}
	if _, err := policyCache.MatchPassword(context.Background(), "other.notebook", "other-token"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("MatchPassword() other namespace error = %v, want ErrNotProvided", err)
	}
}

func TestPolicyCacheScopesDuplicateSecretRefToRequestedAccess(t *testing.T) {
	newer := accessFixture("default", "newer", "bob", sshv1.AccessCredential{
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "access", Key: "passwords"}},
	}, time.Unix(20, 0))
	older := accessFixture("default", "older", "alice", sshv1.AccessCredential{
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "access", Key: "passwords"}},
	}, time.Unix(10, 0))
	secret := secretFixture("default", "access", map[string]string{
		"passwords": "shared",
	})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{newer, older}, []*corev1.Secret{secret})

	match, err := policyCache.MatchPassword(context.Background(), "default.older", "shared")
	if err != nil {
		t.Fatalf("MatchPassword() error = %v", err)
	}
	if match.Access.Name != "older" || match.Credential.Username != "alice" {
		t.Fatalf("match = %s/%s %s", match.Access.Namespace, match.Access.Name, match.Credential.Username)
	}
}

func TestPolicyCacheSecretPublicKeyMustBeReferenced(t *testing.T) {
	pubkey := testPublicKey(t)
	keyLine := string(cryptossh.MarshalAuthorizedKey(pubkey))
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{
		PublicKeysFrom: []sshv1.LocalSecretKeyRef{{Name: "access", Key: "keys"}},
	}, time.Unix(10, 0))
	secret := secretFixture("default", "access", map[string]string{
		"other": keyLine,
	})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, []*corev1.Secret{secret})

	if _, err := policyCache.MatchPublicKey(context.Background(), "default.notebook", pubkey); err == nil {
		t.Fatal("MatchPublicKey() error = nil, want invalid secret reference error")
	}
}

func TestPolicyCacheUpdatesWithIndexer(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token-a"}}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)

	if _, err := policyCache.MatchPassword(context.Background(), "default.notebook", "token-a"); err != nil {
		t.Fatalf("MatchPassword() token-a error = %v", err)
	}

	access = access.DeepCopy()
	access.Spec.Credentials[0].Passwords = []string{"token-b"}
	if err := policyCache.accessIndexer.Update(access); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if _, err := policyCache.MatchPassword(context.Background(), "default.notebook", "token-a"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("MatchPassword() token-a error = %v, want ErrNotProvided", err)
	}
	if _, err := policyCache.MatchPassword(context.Background(), "default.notebook", "token-b"); err != nil {
		t.Fatalf("MatchPassword() token-b error = %v", err)
	}
}

func accessFixture(namespace, name, username string, credential sshv1.AccessCredential, created time.Time) *sshv1.Access {
	credential.Username = username
	credential.Groups = []string{"dev"}
	return &sshv1.Access{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         namespace,
			Name:              name,
			CreationTimestamp: metav1.NewTime(created),
		},
		Spec: sshv1.AccessSpec{
			Selector:    map[string]string{"app": name},
			Credentials: []sshv1.AccessCredential{credential},
		},
	}
}

func secretFixture(namespace, name string, data map[string]string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: map[string][]byte{},
	}
	for key, value := range data {
		secret.Data[key] = []byte(value)
	}
	return secret
}

func newTestPolicyCache(t *testing.T, namespace string, accesses []*sshv1.Access, secrets []*corev1.Secret) *PolicyCache {
	return newTestPolicyCacheForGateway(t, namespace, "", accesses, secrets)
}

func newTestPolicyCacheForGateway(t *testing.T, namespace, gatewayClassName string, accesses []*sshv1.Access, secrets []*corev1.Secret) *PolicyCache {
	t.Helper()
	accessIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)
	for _, access := range accesses {
		if err := accessIndexer.Add(access); err != nil {
			t.Fatalf("add access %s/%s: %v", access.Namespace, access.Name, err)
		}
	}
	secretIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)
	for _, secret := range secrets {
		if err := secretIndexer.Add(secret); err != nil {
			t.Fatalf("add secret %s/%s: %v", secret.Namespace, secret.Name, err)
		}
	}
	return NewPolicyCache(accessIndexer, secretIndexer, PolicyCacheOptions{
		Namespace:        namespace,
		GatewayClassName: gatewayClassName,
	})
}

func testPublicKey(t *testing.T) cryptossh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	key, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	return key
}
