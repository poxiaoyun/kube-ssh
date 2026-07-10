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
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/kube"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestAuthenticatorMatchesPasswordToken(t *testing.T) {
	store := NewMemoryStore(accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"dev-token"}}, time.Unix(10, 0)))
	authenticator := NewAuthenticator(NewCredentialIndex(store, nil))

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

func TestAuthenticatorMatchesPublicKeyAndSecretRefs(t *testing.T) {
	pubkey := testPublicKey(t)
	keyLine := string(cryptossh.MarshalAuthorizedKey(pubkey))
	secrets := fakeSecretReader{
		"default/access/passwords": "ignored\nsecret-token\n",
		"default/access/keys":      keyLine + "\n",
	}
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{
		PasswordsFrom:  []sshv1.LocalSecretKeyRef{{Name: "access", Key: "passwords"}},
		PublicKeysFrom: []sshv1.LocalSecretKeyRef{{Name: "access", Key: "keys"}},
	}, time.Unix(10, 0))
	authenticator := NewAuthenticator(NewCredentialIndex(NewMemoryStore(access), secrets))

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

func TestCredentialIndexDuplicateUsesOldestAccess(t *testing.T) {
	newer := accessFixture("default", "newer", "bob", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(20, 0))
	older := accessFixture("default", "older", "alice", sshv1.Credential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	index := NewCredentialIndex(NewMemoryStore(newer, older), nil)

	match, err := index.MatchPassword(context.Background(), "shared")
	if err != nil {
		t.Fatalf("MatchPassword() error = %v", err)
	}
	if match.Access.Name != "older" || match.Credential.Username != "alice" {
		t.Fatalf("match = %s/%s %s", match.Access.Namespace, match.Access.Name, match.Credential.Username)
	}
}

func TestCredentialIndexIgnoresExternalAccess(t *testing.T) {
	access := accessFixture("default", "external", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Type = sshv1.AccessTypeExternal
	index := NewCredentialIndex(NewMemoryStore(access), nil)

	if _, err := index.MatchPassword(context.Background(), "token"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("MatchPassword() error = %v, want ErrNotProvided", err)
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

func TestAuthorizerCapabilities(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.Credential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Credentials[0].Capabilities = sshv1.CapabilityPolicy{
		Allow: []sshv1.Capability{sshv1.CapabilityShell, sshv1.CapabilityLocalForward, sshv1.CapabilityRemoteForward},
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

type fakeSecretReader map[string]string

func (r fakeSecretReader) GetSecretValue(_ context.Context, namespace, name, key string) (string, error) {
	value, ok := r[namespace+"/"+name+"/"+key]
	if !ok {
		return "", errors.New("secret missing")
	}
	return value, nil
}

type fakePodLister map[string][]corev1.Pod

func (l fakePodLister) List(_ context.Context, namespace string, _ map[string]string) ([]corev1.Pod, error) {
	return append([]corev1.Pod(nil), l[namespace]...), nil
}

func readyPod(name string, labels map[string]string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
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
