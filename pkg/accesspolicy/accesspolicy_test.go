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
	if firstExtra(info.Extra, ExtraAccessNamespace) != "default" || firstExtra(info.Extra, ExtraAccessName) != "notebook" {
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

	info, err := authenticator.AuthenticatePublicKey(context.Background(), pubkey)
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
	info, err := authenticator.AuthenticatePublicKey(context.Background(), pubkey)
	if err != nil {
		t.Fatalf("AuthenticatePublicKey() error = %v", err)
	}
	if info.User.Name != "alice" || info.Method != "crd-publickey" {
		t.Fatalf("info = %#v", info)
	}
}

func TestPolicyCacheDuplicateUsesOldestAccess(t *testing.T) {
	newer := accessFixture("default", "newer", "bob", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(20, 0))
	older := accessFixture("default", "older", "alice", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{newer, older}, nil)

	match, err := policyCache.MatchPassword(context.Background(), "shared")
	if err != nil {
		t.Fatalf("MatchPassword() error = %v", err)
	}
	if match.Access.Name != "older" || match.Credential.Username != "alice" {
		t.Fatalf("match = %s/%s %s", match.Access.Namespace, match.Access.Name, match.Credential.Username)
	}
}

func TestPolicyCacheIgnoresExternalAccess(t *testing.T) {
	access := accessFixture("default", "external", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Type = sshv1.AccessTypeExternal
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)

	if _, err := policyCache.MatchPassword(context.Background(), "token"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("MatchPassword() error = %v, want ErrNotProvided", err)
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

	if _, err := policyCache.MatchPassword(context.Background(), "secret-token"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("MatchPassword() error = %v, want ErrNotProvided", err)
	}
}

func TestPolicyCacheNamespaceScope(t *testing.T) {
	allowed := accessFixture("allowed", "notebook", "alice", sshv1.Credential{Passwords: []string{"allowed-token"}}, time.Unix(10, 0))
	other := accessFixture("other", "notebook", "bob", sshv1.Credential{Passwords: []string{"other-token"}}, time.Unix(20, 0))
	policyCache := newTestPolicyCache(t, "allowed", []*sshv1.Access{allowed, other}, nil)

	match, err := policyCache.MatchPassword(context.Background(), "allowed-token")
	if err != nil {
		t.Fatalf("MatchPassword() error = %v", err)
	}
	if match.Access.Namespace != "allowed" || match.Credential.Username != "alice" {
		t.Fatalf("match = %s/%s %s", match.Access.Namespace, match.Access.Name, match.Credential.Username)
	}
	if _, err := policyCache.MatchPassword(context.Background(), "other-token"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("MatchPassword() other namespace error = %v, want ErrNotProvided", err)
	}
}

func TestPolicyCacheSecretRefDuplicateUsesOldestAccess(t *testing.T) {
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

	match, err := policyCache.MatchPassword(context.Background(), "shared")
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

	if _, err := policyCache.MatchPublicKey(context.Background(), pubkey); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("MatchPublicKey() error = %v, want ErrNotProvided", err)
	}
}

func TestPolicyCacheUpdatesWithIndexer(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token-a"}}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)

	if _, err := policyCache.MatchPassword(context.Background(), "token-a"); err != nil {
		t.Fatalf("MatchPassword() token-a error = %v", err)
	}

	access = access.DeepCopy()
	access.Spec.Credentials[0].Passwords = []string{"token-b"}
	if err := policyCache.accessIndexer.Update(access); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if _, err := policyCache.MatchPassword(context.Background(), "token-a"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("MatchPassword() token-a error = %v, want ErrNotProvided", err)
	}
	if _, err := policyCache.MatchPassword(context.Background(), "token-b"); err != nil {
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

func TestAuthorizerCapabilities(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Credentials[0].Capabilities = sshv1.CapabilityPolicy{
		Allow: []sshv1.Capability{sshv1.CapabilityShell, sshv1.CapabilityLocalForward, sshv1.CapabilityRemoteForward, sshv1.CapabilityAgentForward},
		LocalForward: &sshv1.LocalForwardPolicy{
			AllowPorts: []int32{8080},
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
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionTrue {
		t.Fatalf("Valid condition = %s, want True", got)
	}
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %s, want True", got)
	}
	if status.SelectedBackend != "pod/default/notebook-a" {
		t.Fatalf("SelectedBackend = %q, want pod/default/notebook-a", status.SelectedBackend)
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
	t.Helper()
	accessIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, AccessPolicyIndexers())
	for _, access := range accesses {
		if err := accessIndexer.Add(access); err != nil {
			t.Fatalf("add access %s/%s: %v", access.Namespace, access.Name, err)
		}
	}
	secretIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, SecretPolicyIndexers())
	for _, secret := range secrets {
		if err := secretIndexer.Add(secret); err != nil {
			t.Fatalf("add secret %s/%s: %v", secret.Namespace, secret.Name, err)
		}
	}
	return NewPolicyCache(accessIndexer, secretIndexer, namespace)
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
