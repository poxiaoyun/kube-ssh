package accesspolicy

import (
	"context"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
)

func TestAuthenticatorMatchesPasswordToken(t *testing.T) {
	policyCache := newTestPolicyCache(t, "",
		[]*sshv1.Access{accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"dev-token"}}, time.Unix(10, 0))},
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
		[]*sshv1.Access{accessFixture("default", "notebook", "alice", sshv1.AccessCredential{PublicKeys: []string{keyLine}}, time.Unix(10, 0))},
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
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{
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
