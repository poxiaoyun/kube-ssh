//go:build e2e

package e2e

import (
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
)

func TestWebhookPasswordAuthentication(t *testing.T) {
	var webhook *TestWebhookServer
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{"--authorization-allow-all"},
		BeforeStart: func(f *Framework) {
			webhook = f.StartWebhookServer()
			webhook.Authenticate = func(req authn.WebhookAuthenticateRequest) authn.WebhookAuthenticateResponse {
				if req.Type != authn.WebhookCredentialPassword || req.SSHUser == "" || req.Password == nil || req.Password.Password != "secret" {
					return authn.WebhookAuthenticateResponse{Reason: "bad credential"}
				}
				return authn.WebhookAuthenticateResponse{
					Authenticated: true,
					User:          authn.UserInfo{Name: "webhook-password@example.com", Groups: []string{"dev"}},
					Method:        "webhook-password",
				}
			}
			f.GatewayArgs = append(f.GatewayArgs, "--authentication-webhook-server", webhook.URL+"/authenticate")
		},
	})
	user := f.Namespace + ".shell.app"

	output, err := f.SSHClientExec(user, cryptossh.Password("secret"), "echo webhook-password-ok")
	if err != nil {
		t.Fatalf("webhook password auth exec failed: %v\n%s", err, output)
	}
	if output != "webhook-password-ok\n" {
		t.Fatalf("output = %q, want webhook-password-ok\\n", output)
	}
	if len(webhook.AuthenticationRequests) == 0 {
		t.Fatal("webhook did not receive authentication request")
	}

	if output, err := f.SSHClientExec(user, cryptossh.Password("bad"), "echo rejected"); err == nil {
		t.Fatalf("unexpected webhook password auth success:\n%s", output)
	}
}

func TestWebhookPublicKeyAuthentication(t *testing.T) {
	signer, authorizedKey := newTestSigner(t)
	var webhook *TestWebhookServer
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{"--authorization-allow-all"},
		BeforeStart: func(f *Framework) {
			webhook = f.StartWebhookServer()
			webhook.Authenticate = func(req authn.WebhookAuthenticateRequest) authn.WebhookAuthenticateResponse {
				if req.Type != authn.WebhookCredentialPublicKey || req.PublicKey == nil || req.PublicKey.AuthorizedKey != authorizedKey {
					return authn.WebhookAuthenticateResponse{Reason: "bad key"}
				}
				return authn.WebhookAuthenticateResponse{
					Authenticated: true,
					User:          authn.UserInfo{Name: "webhook-key@example.com"},
				}
			}
			f.GatewayArgs = append(f.GatewayArgs, "--authentication-webhook-server", webhook.URL+"/authenticate")
		},
	})
	user := f.Namespace + ".shell.app"

	output, err := f.SSHClientExec(user, cryptossh.PublicKeys(signer), "echo webhook-key-ok")
	if err != nil {
		t.Fatalf("webhook public key auth exec failed: %v\n%s", err, output)
	}
	if output != "webhook-key-ok\n" {
		t.Fatalf("output = %q, want webhook-key-ok\\n", output)
	}
	if len(webhook.AuthenticationRequests) == 0 || webhook.AuthenticationRequests[0].PublicKey == nil || webhook.AuthenticationRequests[0].PublicKey.Fingerprint == "" {
		t.Fatalf("webhook public key request = %#v", webhook.AuthenticationRequests)
	}
}

func TestWebhookAuthorizationDeniesExec(t *testing.T) {
	var webhook *TestWebhookServer
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{"--authentication-anonymous"},
		BeforeStart: func(f *Framework) {
			webhook = f.StartWebhookServer()
			webhook.Authorize = func(req authz.WebhookAuthorizeRequest) authz.WebhookAuthorizeResponse {
				if req.Attributes.Action == string(authz.CapabilityExec) {
					return authz.WebhookAuthorizeResponse{Decision: authz.DecisionDeny, Reason: "exec denied by webhook"}
				}
				return authz.WebhookAuthorizeResponse{Decision: authz.DecisionAllow}
			}
			f.GatewayArgs = append(f.GatewayArgs, "--authorization-webhook-server", webhook.URL+"/authorize")
		},
	})
	user := f.Namespace + ".shell.app"

	result := f.SSH(user, "echo denied")
	if result.Code == 0 {
		t.Fatalf("webhook authorization unexpectedly allowed exec:\n%s", result.Dump())
	}
	if !strings.Contains(result.Stderr, "exec denied by webhook") && !strings.Contains(result.Stdout, "exec denied by webhook") {
		t.Fatalf("webhook denial reason missing:\n%s", result.Dump())
	}
	if len(webhook.AuthorizationRequests) == 0 {
		t.Fatal("webhook did not receive authorization request")
	}
}
