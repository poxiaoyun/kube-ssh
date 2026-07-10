package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/ssh"
	webhookclient "xiaoshiai.cn/kube-ssh/pkg/webhook"
)

func TestWebhookAuthenticatorPassword(t *testing.T) {
	var got WebhookAuthenticateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		_ = json.NewEncoder(w).Encode(WebhookAuthenticateResponse{
			Authenticated: true,
			User:          UserInfo{Name: "alice@example.com", Groups: []string{"dev"}},
			Method:        "webhook-password",
			TargetHints: []TargetHint{{
				Kind: "kube",
				Options: []TargetHintOption{
					{Key: "namespaces", Value: "default"},
					{Key: "pods", Value: "nginx"},
				},
			}},
		})
	}))
	defer server.Close()

	authenticator, err := NewWebhookAuthenticator(webhookclient.Options{Server: server.URL})
	if err != nil {
		t.Fatalf("NewWebhookAuthenticator() error = %v", err)
	}
	info, err := authenticator.AuthenticateBasic(context.Background(), "default.nginx", "secret")
	if err != nil {
		t.Fatalf("AuthenticateBasic() error = %v", err)
	}
	if got.Type != WebhookCredentialPassword || got.SSHUser != "default.nginx" || got.Password == nil || got.Password.Password != "secret" {
		t.Fatalf("request = %#v", got)
	}
	if info.User.Name != "alice@example.com" || info.Method != "webhook-password" {
		t.Fatalf("info = %#v", info)
	}
	if len(info.TargetHints) != 1 {
		t.Fatalf("target hints = %#v", info.TargetHints)
	}
}

func TestWebhookAuthenticatorPublicKey(t *testing.T) {
	var got WebhookAuthenticateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		_ = json.NewEncoder(w).Encode(WebhookAuthenticateResponse{
			Authenticated: true,
			User:          UserInfo{Name: "alice@example.com"},
		})
	}))
	defer server.Close()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	sshKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	authenticator, err := NewWebhookAuthenticator(webhookclient.Options{Server: server.URL})
	if err != nil {
		t.Fatalf("NewWebhookAuthenticator() error = %v", err)
	}
	info, err := authenticator.AuthenticatePublicKey(context.Background(), sshKey)
	if err != nil {
		t.Fatalf("AuthenticatePublicKey() error = %v", err)
	}
	if info.Method != "webhook" {
		t.Fatalf("method = %q, want webhook", info.Method)
	}
	if got.Type != WebhookCredentialPublicKey || got.PublicKey == nil {
		t.Fatalf("request = %#v", got)
	}
	if got.PublicKey.Fingerprint != ssh.FingerprintSHA256(sshKey) {
		t.Fatalf("fingerprint = %q", got.PublicKey.Fingerprint)
	}
	if got.PublicKey.AuthorizedKey == "" {
		t.Fatal("authorized key is empty")
	}
}

func TestWebhookAuthenticatorRejects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(WebhookAuthenticateResponse{Reason: "bad credential"})
	}))
	defer server.Close()

	authenticator, err := NewWebhookAuthenticator(webhookclient.Options{Server: server.URL})
	if err != nil {
		t.Fatalf("NewWebhookAuthenticator() error = %v", err)
	}
	if _, err := authenticator.AuthenticateBasic(context.Background(), "default.nginx", "bad"); err == nil {
		t.Fatal("AuthenticateBasic() error = nil, want error")
	}
}
