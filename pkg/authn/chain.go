package authn

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"
)

// Chain tries authenticators in order and returns the first successful identity.
type Chain struct {
	authenticators []SSHAuthenticator
}

func NewChain(authenticators ...SSHAuthenticator) *Chain {
	chain := &Chain{}
	for _, authenticator := range authenticators {
		if authenticator != nil {
			chain.authenticators = append(chain.authenticators, authenticator)
		}
	}
	return chain
}

func (c *Chain) AuthenticateBasic(ctx context.Context, username, password string) (*AuthenticateInfo, error) {
	for _, authenticator := range c.authenticators {
		info, err := authenticator.AuthenticateBasic(ctx, username, password)
		if err == nil {
			return info, nil
		}
		if errors.Is(err, ErrNotProvided) {
			continue
		}
		return nil, err
	}
	return nil, ErrNotProvided
}

func (c *Chain) AuthenticatePublicKey(ctx context.Context, pubkey ssh.PublicKey) (*AuthenticateInfo, error) {
	for _, authenticator := range c.authenticators {
		info, err := authenticator.AuthenticatePublicKey(ctx, pubkey)
		if err == nil {
			return info, nil
		}
		if errors.Is(err, ErrNotProvided) {
			continue
		}
		return nil, err
	}
	return nil, ErrNotProvided
}
