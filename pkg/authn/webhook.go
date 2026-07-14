package authn

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	webhookclient "xiaoshiai.cn/kube-ssh/pkg/webhook"
)

const (
	WebhookCredentialPassword  = "password"
	WebhookCredentialPublicKey = "publickey"
)

type WebhookAuthenticator struct {
	client *webhookclient.Client
}

func NewWebhookAuthenticator(opts webhookclient.Options) (*WebhookAuthenticator, error) {
	client, err := webhookclient.NewClient(opts)
	if err != nil {
		return nil, err
	}
	return &WebhookAuthenticator{client: client}, nil
}

type WebhookAuthenticateRequest struct {
	Type    string `json:"type"`
	SSHUser string `json:"sshUser,omitempty"`

	Password  *WebhookPasswordCredential  `json:"password,omitempty"`
	PublicKey *WebhookPublicKeyCredential `json:"publicKey,omitempty"`
}

type WebhookPasswordCredential struct {
	Password string `json:"password,omitempty"`
}

type WebhookPublicKeyCredential struct {
	AuthorizedKey string `json:"authorizedKey,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
}

type WebhookAuthenticateResponse struct {
	Authenticated bool         `json:"authenticated"`
	User          UserInfo     `json:"user,omitempty"`
	Method        string       `json:"method,omitempty"`
	TargetHints   []TargetHint `json:"targetHints,omitempty"`
	Reason        string       `json:"reason,omitempty"`
	Error         string       `json:"error,omitempty"`
}

func (a *WebhookAuthenticator) AuthenticateBasic(ctx context.Context, username, password string) (*AuthenticateInfo, error) {
	return a.authenticate(ctx, &WebhookAuthenticateRequest{
		Type:    WebhookCredentialPassword,
		SSHUser: username,
		Password: &WebhookPasswordCredential{
			Password: password,
		},
	})
}

func (a *WebhookAuthenticator) AuthenticatePublicKey(ctx context.Context, username string, pubkey ssh.PublicKey) (*AuthenticateInfo, error) {
	return a.authenticate(ctx, &WebhookAuthenticateRequest{
		Type:    WebhookCredentialPublicKey,
		SSHUser: username,
		PublicKey: &WebhookPublicKeyCredential{
			AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubkey))),
			Fingerprint:   ssh.FingerprintSHA256(pubkey),
		},
	})
}

func (a *WebhookAuthenticator) authenticate(ctx context.Context, req *WebhookAuthenticateRequest) (*AuthenticateInfo, error) {
	resp := &WebhookAuthenticateResponse{}
	if err := a.client.Post(ctx, req, resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("webhook authentication error: %s", resp.Error)
	}
	if !resp.Authenticated {
		if resp.Reason == "" {
			resp.Reason = "webhook authentication rejected"
		}
		return nil, fmt.Errorf("%s", resp.Reason)
	}
	if resp.User.Name == "" {
		return nil, fmt.Errorf("webhook authentication response requires user.name")
	}
	method := resp.Method
	if method == "" {
		method = "webhook"
	}
	return &AuthenticateInfo{
		User:        resp.User,
		Method:      method,
		TargetHints: resp.TargetHints,
	}, nil
}
