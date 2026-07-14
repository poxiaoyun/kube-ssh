package accesspolicy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/kube"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestAuthenticatorMatchesPasswordToken(t *testing.T) {
	policyCache := newTestPolicyCache(t, "",
		[]*sshv1.Access{accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"dev-token"}}, time.Unix(10, 0))},
		nil,
	)
	authenticator := NewAuthenticator(policyCache)

	info, err := authenticator.AuthenticateBasic(context.Background(), "default.notebook", "dev-token")
	if err != nil {
		t.Fatalf("AuthenticateBasic() error = %v", err)
	}
	if info.User.Name != "alice" || info.Method != "crd-password" {
		t.Fatalf("info = %#v", info)
	}
	if GetExtra(info.Extra, ExtraAccessNamespace) != "default" || GetExtra(info.Extra, ExtraAccessName) != "notebook" {
		t.Fatalf("extra = %#v", info.Extra)
	}
}

func TestAuthenticatorMatchesPublicKey(t *testing.T) {
	pubkey := testPublicKey(t)
	keyLine := string(cryptossh.MarshalAuthorizedKey(pubkey))
	policyCache := newTestPolicyCache(t, "",
		[]*sshv1.Access{accessFixture("default", "notebook", "alice", sshv1.Credential{PublicKeys: []string{keyLine}}, time.Unix(10, 0))},
		nil,
	)
	authenticator := NewAuthenticator(policyCache)

	info, err := authenticator.AuthenticatePublicKey(context.Background(), "default.notebook", pubkey)
	if err != nil {
		t.Fatalf("AuthenticatePublicKey() error = %v", err)
	}
	if info.User.Name != "alice" || info.Method != "crd-publickey" {
		t.Fatalf("info = %#v", info)
	}
}

func TestAuthenticatorMatchesSecretRefs(t *testing.T) {
	pubkey := testPublicKey(t)
	keyLine := string(cryptossh.MarshalAuthorizedKey(pubkey))
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{
		PasswordsFrom:  []sshv1.LocalSecretKeyRef{{Name: "access", Key: "passwords"}},
		PublicKeysFrom: []sshv1.LocalSecretKeyRef{{Name: "access", Key: "keys"}},
	}, time.Unix(10, 0))
	secret := secretFixture("default", "access", map[string]string{
		"passwords": "ignored\nsecret-token\n",
		"keys":      keyLine + "\n",
	})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, []*corev1.Secret{secret})
	authenticator := NewAuthenticator(policyCache)

	if _, err := authenticator.AuthenticateBasic(context.Background(), "default.notebook", "secret-token"); err != nil {
		t.Fatalf("AuthenticateBasic() error = %v", err)
	}
	info, err := authenticator.AuthenticatePublicKey(context.Background(), "default.notebook", pubkey)
	if err != nil {
		t.Fatalf("AuthenticatePublicKey() error = %v", err)
	}
	if info.User.Name != "alice" || info.Method != "crd-publickey" {
		t.Fatalf("info = %#v", info)
	}
}

func TestPolicyCacheScopesDuplicatePasswordToRequestedAccess(t *testing.T) {
	newer := accessFixture("default", "newer", "bob", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(20, 0))
	older := accessFixture("default", "older", "alice", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(10, 0))
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
	first := accessFixture("default", "first", "alice", sshv1.Credential{PublicKeys: []string{keyLine}}, time.Unix(10, 0))
	second := accessFixture("default", "second", "bob", sshv1.Credential{PublicKeys: []string{keyLine}}, time.Unix(20, 0))
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
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	access.Spec.Credentials = append(access.Spec.Credentials, sshv1.AccessCredential{
		Username:   "bob",
		Credential: sshv1.Credential{Passwords: []string{"shared"}},
	})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)

	if _, err := policyCache.MatchPassword(context.Background(), "default.notebook", "shared"); err == nil {
		t.Fatal("MatchPassword() error = nil, want ambiguous credential identity error")
	}
}

func TestPolicyCachePrefersExactDottedAccessName(t *testing.T) {
	prefix := accessFixture("default", "database", "prefix-user", sshv1.Credential{Passwords: []string{"prefix-token"}}, time.Unix(10, 0))
	exact := accessFixture("default", "database.readonly", "exact-user", sshv1.Credential{Passwords: []string{"exact-token"}}, time.Unix(20, 0))
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

func TestPolicyCacheIgnoresExternalAccess(t *testing.T) {
	access := accessFixture("default", "external", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Type = sshv1.AccessTypeExternal
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)

	if _, err := policyCache.MatchPassword(context.Background(), "default.external", "token"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("MatchPassword() error = %v, want ErrNotProvided", err)
	}
}

func TestPolicyCacheMatchesGatewayClassExactly(t *testing.T) {
	className := "default-gateway"
	classed := accessFixture("default", "classed", "alice", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	classed.Spec.GatewayClassName = &className
	classless := accessFixture("default", "default", "bob", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(20, 0))

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
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{
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
	allowed := accessFixture("allowed", "notebook", "alice", sshv1.Credential{Passwords: []string{"allowed-token"}}, time.Unix(10, 0))
	other := accessFixture("other", "notebook", "bob", sshv1.Credential{Passwords: []string{"other-token"}}, time.Unix(20, 0))
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
	newer := accessFixture("default", "newer", "bob", sshv1.Credential{
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "access", Key: "passwords"}},
	}, time.Unix(20, 0))
	older := accessFixture("default", "older", "alice", sshv1.Credential{
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
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{
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
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token-a"}}, time.Unix(10, 0))
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

func TestResolverResolvesAccessToPodTarget(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Selector = map[string]string{"app": "notebook"}
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{
		"default": {
			readyPod("notebook-a", map[string]string{"app": "notebook"}),
		},
	})

	tgt, err := resolver.Resolve(context.Background(), target.ResolveRequest{
		SSHUser:   "default.notebook",
		AuthExtra: authExtra(&CredentialMatch{Access: access, Credential: &access.Spec.Credentials[0]}, CredentialTypePassword),
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if tgt.Kind != kube.KindTarget || tgt.Option(kube.OptionNamespaces) != "default" || tgt.Option(kube.OptionPods) != "notebook-a" {
		t.Fatalf("target = %#v", tgt)
	}
}

func TestResolverSelectsExplicitPodAndContainer(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Containers = []string{"app", "sidecar"}
	podA := readyPod("notebook-a", map[string]string{"app": "notebook"})
	podB := readyPod("notebook-b", map[string]string{"app": "notebook"})
	podB.Spec.Containers = append(podB.Spec.Containers, corev1.Container{Name: "sidecar"})
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {podA, podB}})

	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook~notebook-b.sidecar"
	tgt, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve(explicit pod/container) error = %v", err)
	}
	defer tgt.Release()
	if got := tgt.Option(kube.OptionPods); got != "notebook-b" {
		t.Fatalf("pod = %q, want notebook-b", got)
	}
	if got := tgt.Option(kube.OptionContainers); got != "sidecar" {
		t.Fatalf("container = %q, want sidecar", got)
	}
}

func TestResolverExplicitPodAllowsActiveUnreadyPod(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	ready := readyPod("notebook-a", map[string]string{"app": "notebook"})
	unready := readyPod("notebook-b", map[string]string{"app": "notebook"})
	unready.Status.Conditions = nil
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {ready, unready}})
	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook~notebook-b"

	tgt, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve(active unready pod) error = %v", err)
	}
	defer tgt.Release()
	if got := tgt.Option(kube.OptionPods); got != "notebook-b" {
		t.Fatalf("pod = %q, want notebook-b", got)
	}
}

func TestResolverExplicitPodRejectsUnavailablePods(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	deleting := readyPod("notebook-deleting", map[string]string{"app": "notebook"})
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	succeeded := readyPod("notebook-succeeded", map[string]string{"app": "notebook"})
	succeeded.Status.Phase = corev1.PodSucceeded
	failed := readyPod("notebook-failed", map[string]string{"app": "notebook"})
	failed.Status.Phase = corev1.PodFailed
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {deleting, succeeded, failed}})

	for _, pod := range []string{"notebook-missing", deleting.Name, succeeded.Name, failed.Name} {
		t.Run(pod, func(t *testing.T) {
			req := accessResolveRequest(access)
			req.SSHUser = "default.notebook~" + pod
			if _, err := resolver.Resolve(context.Background(), req); err == nil {
				t.Fatalf("Resolve(%s) error = nil, want unavailable error", pod)
			}
		})
	}
}

func TestResolverExplicitPodMustMatchAccessSelector(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	resolver := NewResolver(NewMemoryStore(access), newTestInformerPodLister(t,
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
		readyPod("other", map[string]string{"app": "other"}),
	))
	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook~other"

	if _, err := resolver.Resolve(context.Background(), req); err == nil {
		t.Fatal("Resolve(selector-external pod) error = nil, want unavailable error")
	}
}

func TestResolverExplicitPodSupportsDottedPodNames(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Containers = []string{"app", "sidecar"}
	pod := readyPod("notebook.a", map[string]string{"app": "notebook"})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar"})
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})

	for _, tc := range []struct {
		user          string
		wantContainer string
	}{
		{user: "default.notebook~notebook.a", wantContainer: "app"},
		{user: "default.notebook~notebook.a.sidecar", wantContainer: "sidecar"},
	} {
		req := accessResolveRequest(access)
		req.SSHUser = tc.user
		tgt, err := resolver.Resolve(context.Background(), req)
		if err != nil {
			t.Fatalf("Resolve(%s) error = %v", tc.user, err)
		}
		if got := tgt.Option(kube.OptionPods); got != pod.Name {
			t.Fatalf("Resolve(%s) pod = %q, want %q", tc.user, got, pod.Name)
		}
		if got := tgt.Option(kube.OptionContainers); got != tc.wantContainer {
			t.Fatalf("Resolve(%s) container = %q, want %q", tc.user, got, tc.wantContainer)
		}
		tgt.Release()
	}
}

func TestResolverRejectsMalformedExplicitPodLocator(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {readyPod("notebook-a", map[string]string{"app": "notebook"})}})

	for _, user := range []string{"default.notebook~", "default.notebook~notebook-a."} {
		t.Run(user, func(t *testing.T) {
			req := accessResolveRequest(access)
			req.SSHUser = user
			if _, err := resolver.Resolve(context.Background(), req); err == nil {
				t.Fatalf("Resolve(%s) error = nil, want invalid target", user)
			}
		})
	}
}

func TestResolverRejectsAccessMismatch(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{})

	_, err := resolver.Resolve(context.Background(), target.ResolveRequest{
		SSHUser: "default.other",
		AuthExtra: map[string][]string{
			ExtraAccessNamespace: {"default"},
			ExtraAccessName:      {"notebook"},
		},
	})
	if err == nil {
		t.Fatal("Resolve() error = nil, want mismatch error")
	}
}

func TestResolverSelectsAndRestrictsContainers(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Containers = []string{"app", "debug"}
	access.Spec.Credentials[0].Containers = []string{"app"}
	pod := readyPod("notebook-a", map[string]string{"app": "notebook"})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "debug"})
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})

	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook.app"
	tgt, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve(app) error = %v", err)
	}
	if got := tgt.Option(kube.OptionContainers); got != "app" {
		t.Fatalf("container = %q, want app", got)
	}
	tgt.Release()

	req.SSHUser = "default.notebook.debug"
	if _, err := resolver.Resolve(context.Background(), req); err == nil {
		t.Fatal("Resolve(debug) error = nil, want credential container denial")
	}
	req.SSHUser = "default.notebook~notebook-a.debug"
	if _, err := resolver.Resolve(context.Background(), req); err == nil {
		t.Fatal("Resolve(explicit pod/debug) error = nil, want credential container denial")
	}
}

func TestResolverUsesKubernetesDefaultContainer(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	pod := readyPod("notebook-a", map[string]string{"app": "notebook"})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar"})
	pod.Annotations = map[string]string{"kubectl.kubernetes.io/default-container": "sidecar"}
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})

	tgt, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	defer tgt.Release()
	if got := tgt.Option(kube.OptionContainers); got != "sidecar" {
		t.Fatalf("container = %q, want sidecar", got)
	}
}

func TestResolverContainerDefaultModeRequiresAccessOverride(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	pod := readyPod("notebook-a", map[string]string{"app": "notebook"})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar"})
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})
	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook.sidecar"
	if _, err := resolver.Resolve(context.Background(), req); err == nil {
		t.Fatal("Resolve(sidecar) error = nil, want default-container policy denial")
	}

	access.Spec.Containers = []string{"sidecar"}
	resolver = NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})
	if _, err := resolver.Resolve(context.Background(), req); err != nil {
		t.Fatalf("Resolve(sidecar) with Access override error = %v", err)
	}
}

func TestResolverRoundRobinStrategyHonorsWeights(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{
		Type: sshv1.AccessStrategyTypeRoundRobin,
		Weights: []sshv1.AccessStrategyWeight{
			{Selector: map[string]string{"track": "blue"}, Weight: 2},
			{Selector: map[string]string{"track": "green"}, Weight: 1},
		},
	}
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{
		"default": {
			readyPod("notebook-a", map[string]string{"app": "notebook", "track": "blue"}),
			readyPod("notebook-b", map[string]string{"app": "notebook", "track": "green"}),
		},
	})

	got := []string{}
	for range 3 {
		tgt, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		got = append(got, tgt.Option(kube.OptionPods))
		tgt.Release()
	}
	want := []string{"notebook-a", "notebook-a", "notebook-b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pods = %v, want %v", got, want)
	}
}

func TestResolverNewestAndOldestStrategies(t *testing.T) {
	pods := fakePodLister{
		"default": {
			readyPodAt("notebook-a", map[string]string{"app": "notebook"}, time.Unix(10, 0)),
			readyPodAt("notebook-b", map[string]string{"app": "notebook"}, time.Unix(20, 0)),
		},
	}
	for _, tc := range []struct {
		name     string
		strategy sshv1.AccessStrategyType
		wantPod  string
	}{
		{name: "newest", strategy: sshv1.AccessStrategyTypeNewest, wantPod: "notebook-b"},
		{name: "oldest", strategy: sshv1.AccessStrategyTypeOldest, wantPod: "notebook-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
			access.Spec.Strategy = &sshv1.AccessStrategy{Type: tc.strategy}
			resolver := NewResolver(NewMemoryStore(access), pods)

			tgt, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			defer tgt.Release()
			if got := tgt.Option(kube.OptionPods); got != tc.wantPod {
				t.Fatalf("pod = %q, want %q", got, tc.wantPod)
			}
		})
	}
}

func TestResolverLeastConnectionsTracksConnectionRelease(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{Type: sshv1.AccessStrategyTypeLeastConnections}
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{
		"default": {
			readyPod("notebook-a", map[string]string{"app": "notebook"}),
			readyPod("notebook-b", map[string]string{"app": "notebook"}),
		},
	})

	first, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	if got := first.Option(kube.OptionPods); got != "notebook-a" {
		t.Fatalf("first pod = %q, want notebook-a", got)
	}
	second, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	defer second.Release()
	if got := second.Option(kube.OptionPods); got != "notebook-b" {
		t.Fatalf("second pod = %q, want notebook-b", got)
	}

	first.Release()
	third, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("third Resolve() error = %v", err)
	}
	defer third.Release()
	if got := third.Option(kube.OptionPods); got != "notebook-a" {
		t.Fatalf("third pod = %q, want notebook-a", got)
	}
}

func TestResolverExplicitPodParticipatesInLeastConnections(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{Type: sshv1.AccessStrategyTypeLeastConnections}
	pods := fakePodLister{"default": {
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
		readyPod("notebook-b", map[string]string{"app": "notebook"}),
	}}
	resolver := NewResolver(NewMemoryStore(access), pods)

	explicitReq := accessResolveRequest(access)
	explicitReq.SSHUser = "default.notebook~notebook-a"
	explicit, err := resolver.Resolve(context.Background(), explicitReq)
	if err != nil {
		t.Fatalf("explicit Resolve() error = %v", err)
	}
	automatic, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("automatic Resolve() error = %v", err)
	}
	if got := automatic.Option(kube.OptionPods); got != "notebook-b" {
		t.Fatalf("automatic pod with explicit connection = %q, want notebook-b", got)
	}
	automatic.Release()
	explicit.Release()

	afterRelease, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("Resolve() after release error = %v", err)
	}
	defer afterRelease.Release()
	if got := afterRelease.Option(kube.OptionPods); got != "notebook-a" {
		t.Fatalf("pod after release = %q, want notebook-a", got)
	}
}

func TestResolverSessionAffinityReusesCredentialBackend(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{
		Type: sshv1.AccessStrategyTypeRandom,
		SessionAffinity: &sshv1.AccessSessionAffinity{
			Type: sshv1.AccessSessionAffinityTypeCredential,
		},
	}
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{
		"default": {
			readyPod("notebook-a", map[string]string{"app": "notebook"}),
			readyPod("notebook-b", map[string]string{"app": "notebook"}),
		},
	})

	first, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	defer first.Release()
	second, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	defer second.Release()
	if first.Option(kube.OptionPods) != second.Option(kube.OptionPods) {
		t.Fatalf("affinity pods = %q and %q, want same", first.Option(kube.OptionPods), second.Option(kube.OptionPods))
	}
}

func TestResolverExplicitPodDoesNotReadOrWriteSessionAffinity(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{
		Type: sshv1.AccessStrategyTypeRandom,
		SessionAffinity: &sshv1.AccessSessionAffinity{
			Type: sshv1.AccessSessionAffinityTypeCredential,
		},
	}
	pods := fakePodLister{"default": {
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
		readyPod("notebook-b", map[string]string{"app": "notebook"}),
	}}
	resolver := NewResolver(NewMemoryStore(access), pods)
	key := accessKey(access.Namespace, access.Name) + "\x00" + string(sshv1.AccessSessionAffinityTypeCredential) + "\x00alice"
	entry := affinityEntry{backendKey: "default/notebook-a", expiresAt: time.Now().Add(time.Hour)}
	resolver.selector.affinity[key] = entry

	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook~notebook-b"
	tgt, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("explicit Resolve() error = %v", err)
	}
	defer tgt.Release()
	if got := tgt.Option(kube.OptionPods); got != "notebook-b" {
		t.Fatalf("explicit pod = %q, want notebook-b", got)
	}
	if got := resolver.selector.affinity[key]; got != entry {
		t.Fatalf("affinity = %#v, want unchanged %#v", got, entry)
	}
}

func TestAuthorizerCapabilities(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Credentials[0].Capabilities = sshv1.CapabilityPolicy{
		Allow: []sshv1.Capability{sshv1.CapabilityShell, sshv1.CapabilityLocalForward, sshv1.CapabilityRemoteForward, sshv1.CapabilityAgentForward},
		LocalForward: &sshv1.LocalForwardPolicy{
			AllowDestinations: []string{"*:8080"},
		},
		RemoteForward: &sshv1.RemoteForwardPolicy{
			AllowBinds: []string{"127.0.0.1:*"},
		},
	}
	authorizer := NewAuthorizer(NewMemoryStore(access))
	req := authz.Request{
		AuthExtra: authExtra(&CredentialMatch{Access: access, Credential: &access.Spec.Credentials[0]}, CredentialTypePassword),
		Attributes: authz.Attributes{
			Action: string(authz.CapabilityLocalForward),
			Extra:  map[string][]string{"destination_port": {"8080"}},
		},
	}

	decision, reason, err := authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionAllow {
		t.Fatalf("decision = %q, reason = %q", decision, reason)
	}
	req.Attributes.Extra["destination_port"] = []string{"9090"}
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
	req.Attributes = authz.Attributes{
		Action: string(authz.CapabilityRemoteForward),
		Extra:  map[string][]string{"bind_host": {"127.0.0.1"}, "bind_port": {"2222"}},
	}
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionAllow {
		t.Fatalf("decision = %q, want Allow", decision)
	}
	req.Attributes = authz.Attributes{Action: string(authz.CapabilityAgentForward)}
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionAllow {
		t.Fatalf("decision = %q, want Allow", decision)
	}
	req.Attributes.Action = string(authz.CapabilityExec)
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
}

func TestAuthorizerEmptyCapabilitiesInheritDefaults(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	authorizer := NewAuthorizer(NewMemoryStore(access), CapabilityDefaults{Allow: []sshv1.Capability{sshv1.CapabilityExec}})
	req := authz.Request{
		AuthExtra:  authExtra(&CredentialMatch{Access: access, Credential: &access.Spec.Credentials[0]}, CredentialTypePassword),
		Attributes: authz.Attributes{Action: string(authz.CapabilityExec)},
	}
	decision, _, err := authorizer.Authorize(context.Background(), req)
	if err != nil || decision != authz.DecisionAllow {
		t.Fatalf("exec decision = %q, err = %v, want Allow", decision, err)
	}
	req.Attributes.Action = string(authz.CapabilitySFTP)
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil || decision != authz.DecisionDeny {
		t.Fatalf("sftp decision = %q, err = %v, want Deny", decision, err)
	}
}

func TestAuthorizerNoOpinionWithoutAccessContext(t *testing.T) {
	decision, _, err := NewAuthorizer(NewMemoryStore()).Authorize(context.Background(), authz.Request{})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionNoOpinion {
		t.Fatalf("decision = %q, want NoOpinion", decision)
	}
}

func TestAccessStatusControllerReportsReadyBackend(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "access", Key: "passwords"}},
	}, time.Unix(10, 0))
	secret := secretFixture("default", "access", map[string]string{"passwords": "token"})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, []*corev1.Secret{secret})
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"},
		},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionTrue {
		t.Fatalf("Valid condition = %s, want True", got)
	}
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %s, want True", got)
	}
}

func TestAccessStatusControllerReportsActiveUnreadyBackend(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	pod := readyPod("notebook-a", map[string]string{"app": "notebook"})
	pod.Status.Conditions = nil
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, pod),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"},
		},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %s, want True", got)
	}
}

func TestAccessStatusControllerPublishesGatewayEndpoints(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	advertised := []sshv1.AccessStatusEndpoint{
		{Address: "ssh-a.example.com:2222"},
		{Address: "ssh-b.example.com:2222"},
	}
	want := []sshv1.AccessStatusEndpoint{
		{Address: "ssh-a.example.com:2222", Username: "default.notebook"},
		{Address: "ssh-b.example.com:2222", Username: "default.notebook"},
	}
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy:    ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"},
			Endpoints: advertised,
		},
	)

	status := controller.statusFor(context.Background(), access)
	if !reflect.DeepEqual(status.Endpoints, want) {
		t.Fatalf("Endpoints = %#v, want %#v", status.Endpoints, want)
	}
}

func TestAccessStatusControllerReportsMissingSecret(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "missing", Key: "passwords"}},
	}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"},
		},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionFalse {
		t.Fatalf("Valid condition = %s, want False", got)
	}
	if got := conditionReason(status.Conditions, sshv1.AccessConditionValid); got != "SecretNotFound" {
		t.Fatalf("Valid reason = %q, want SecretNotFound", got)
	}
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionFalse {
		t.Fatalf("Ready condition = %s, want False", got)
	}
}

func TestAccessStatusControllerReportsDuplicateCredentialMaterial(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	access.Spec.Credentials = append(access.Spec.Credentials, sshv1.AccessCredential{
		Username:   "bob",
		Credential: sshv1.Credential{Passwords: []string{"shared"}},
	})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionFalse {
		t.Fatalf("Valid condition = %s, want False", got)
	}
	if got := conditionReason(status.Conditions, sshv1.AccessConditionValid); got != "DuplicateCredentialMaterial" {
		t.Fatalf("Valid reason = %q, want DuplicateCredentialMaterial", got)
	}
}

func TestAccessStatusControllerFindsDuplicateMaterialThroughSecretRef(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	access.Spec.Credentials = append(access.Spec.Credentials, sshv1.AccessCredential{
		Username: "bob",
		Credential: sshv1.Credential{
			PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "bob-auth", Key: "passwords"}},
		},
	})
	secret := secretFixture("default", "bob-auth", map[string]string{"passwords": "shared"})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, []*corev1.Secret{secret})
	controller := NewAccessStatusController(policyCache, newTestInformerPodLister(t,
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
	), policyCache.secretIndexer, nil, AccessStatusControllerOptions{Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}})

	status := controller.statusFor(context.Background(), access)
	if got := conditionReason(status.Conditions, sshv1.AccessConditionValid); got != "DuplicateCredentialMaterial" {
		t.Fatalf("Valid reason = %q, want DuplicateCredentialMaterial", got)
	}
}

func TestAccessStatusControllerDeduplicatesMaterialWithinCredential(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{
		Passwords:     []string{"shared"},
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "alice-auth", Key: "passwords"}},
	}, time.Unix(10, 0))
	secret := secretFixture("default", "alice-auth", map[string]string{"passwords": "shared"})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, []*corev1.Secret{secret})
	controller := NewAccessStatusController(policyCache, newTestInformerPodLister(t,
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
	), policyCache.secretIndexer, nil, AccessStatusControllerOptions{Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}})

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionTrue {
		t.Fatalf("Valid condition = %s, want True", got)
	}
}

func TestAccessStatusControllerAllowsMaterialSharedAcrossAccesses(t *testing.T) {
	first := accessFixture("default", "first", "alice", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	second := accessFixture("default", "second", "bob", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(20, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{first, second}, nil)
	controller := NewAccessStatusController(policyCache, newTestInformerPodLister(t,
		readyPod("first-a", map[string]string{"app": "first"}),
		readyPod("second-a", map[string]string{"app": "second"}),
	), policyCache.secretIndexer, nil, AccessStatusControllerOptions{Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}})

	for _, access := range []*sshv1.Access{first, second} {
		status := controller.statusFor(context.Background(), access)
		if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionTrue {
			t.Fatalf("Access %s Valid condition = %s, want True", access.Name, got)
		}
	}
}

func TestAccessStatusControllerAppliesGlobalContainerPolicy(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy: ContainerPolicy{DefaultMode: "None", LimitMode: "All"},
		},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionFalse {
		t.Fatalf("Ready condition = %s, want False", got)
	}
	if got := conditionReason(status.Conditions, sshv1.AccessConditionReady); got != "NoBackends" {
		t.Fatalf("Ready reason = %q, want NoBackends", got)
	}

	access.Spec.Containers = []string{"app"}
	status = controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionTrue {
		t.Fatalf("Ready condition with explicit container = %s, want True", got)
	}
}

func accessFixture(namespace, name, username string, credential sshv1.Credential, created time.Time) *sshv1.Access {
	return &sshv1.Access{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         namespace,
			Name:              name,
			CreationTimestamp: metav1.NewTime(created),
		},
		Spec: sshv1.AccessSpec{
			Selector: map[string]string{"app": name},
			Credentials: []sshv1.AccessCredential{
				{
					Username:   username,
					Groups:     []string{"dev"},
					Credential: credential,
				},
			},
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

func newTestInformerPodLister(t *testing.T, pods ...corev1.Pod) *InformerPodLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	for i := range pods {
		pod := pods[i].DeepCopy()
		if err := indexer.Add(pod); err != nil {
			t.Fatalf("add pod %s/%s: %v", pod.Namespace, pod.Name, err)
		}
	}
	return NewInformerPodLister(indexer)
}

type fakePodLister map[string][]corev1.Pod

func (l fakePodLister) List(_ context.Context, namespace string, _ map[string]string) ([]corev1.Pod, error) {
	return append([]corev1.Pod(nil), l[namespace]...), nil
}

func readyPod(name string, labels map[string]string) corev1.Pod {
	return readyPodAt(name, labels, time.Time{})
}

func readyPodAt(name string, labels map[string]string, created time.Time) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Labels: labels, CreationTimestamp: metav1.NewTime(created)},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
}

func accessResolveRequest(access *sshv1.Access) target.ResolveRequest {
	return target.ResolveRequest{
		SSHUser:   access.Namespace + "." + access.Name,
		AuthExtra: authExtra(&CredentialMatch{Access: access, Credential: &access.Spec.Credentials[0]}, CredentialTypePassword),
	}
}

func conditionStatus(conditions []metav1.Condition, conditionType string) metav1.ConditionStatus {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status
		}
	}
	return ""
}

func conditionReason(conditions []metav1.Condition, conditionType string) string {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Reason
		}
	}
	return ""
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
