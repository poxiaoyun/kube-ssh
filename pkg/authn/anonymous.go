package authn

import (
	"context"

	"golang.org/x/crypto/ssh"
)

const AnonymousUserName = "anonymous"

// Anonymous accepts any SSH credential and returns a fixed anonymous identity.
type Anonymous struct{}

func (Anonymous) AuthenticateBasic(context.Context, string, string) (*AuthenticateInfo, error) {
	return anonymousInfo(), nil
}

func (Anonymous) AuthenticatePublicKey(context.Context, ssh.PublicKey) (*AuthenticateInfo, error) {
	return anonymousInfo(), nil
}

func anonymousInfo() *AuthenticateInfo {
	return &AuthenticateInfo{
		User:   UserInfo{Name: AnonymousUserName},
		Method: "anonymous",
	}
}
