package accesspolicy

import (
	"context"
	"fmt"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

type Authenticator struct {
	index *CredentialIndex
}

func NewAuthenticator(index *CredentialIndex) *Authenticator {
	return &Authenticator{index: index}
}

func (a *Authenticator) AuthenticateBasic(ctx context.Context, _ string, password string) (*authn.AuthenticateInfo, error) {
	if a == nil || a.index == nil {
		return nil, fmt.Errorf("access policy authenticator requires a credential index")
	}
	match, err := a.index.MatchPassword(ctx, password)
	if err != nil {
		return nil, err
	}
	return &authn.AuthenticateInfo{
		User:   matchUser(match),
		Method: "crd-password",
		Extra:  authExtra(match, CredentialTypePassword),
	}, nil
}

func (a *Authenticator) AuthenticatePublicKey(ctx context.Context, pubkey cryptossh.PublicKey) (*authn.AuthenticateInfo, error) {
	if a == nil || a.index == nil {
		return nil, fmt.Errorf("access policy authenticator requires a credential index")
	}
	match, err := a.index.MatchPublicKey(ctx, pubkey)
	if err != nil {
		return nil, err
	}
	return &authn.AuthenticateInfo{
		User:   matchUser(match),
		Method: "crd-publickey",
		Extra:  authExtra(match, CredentialTypePublicKey),
	}, nil
}
