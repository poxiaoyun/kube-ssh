package accesspolicy

import (
	"context"
	"fmt"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

type Authenticator struct {
	matcher CredentialMatcher
}

func NewAuthenticator(matcher CredentialMatcher) *Authenticator {
	return &Authenticator{matcher: matcher}
}

func (a *Authenticator) AuthenticateBasic(ctx context.Context, sshUser, password string) (*authn.AuthenticateInfo, error) {
	if a == nil || a.matcher == nil {
		return nil, fmt.Errorf("access policy authenticator requires a credential matcher")
	}
	match, err := a.matcher.MatchPassword(ctx, sshUser, password)
	if err != nil {
		return nil, err
	}
	return &authn.AuthenticateInfo{
		User:   matchUser(match),
		Method: "crd-password",
		Extra:  authExtra(match, CredentialTypePassword),
	}, nil
}

func (a *Authenticator) AuthenticatePublicKey(ctx context.Context, sshUser string, pubkey cryptossh.PublicKey) (*authn.AuthenticateInfo, error) {
	if a == nil || a.matcher == nil {
		return nil, fmt.Errorf("access policy authenticator requires a credential matcher")
	}
	match, err := a.matcher.MatchPublicKey(ctx, sshUser, pubkey)
	if err != nil {
		return nil, err
	}
	return &authn.AuthenticateInfo{
		User:   matchUser(match),
		Method: "crd-publickey",
		Extra:  authExtra(match, CredentialTypePublicKey),
	}, nil
}
