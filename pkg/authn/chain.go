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
	return &Chain{authenticators: authenticators}
}

func (c *Chain) AuthenticateBasic(ctx context.Context, username, password string) (*AuthenticateInfo, error) {
	for _, authenticator := range c.authenticators {
		info, err := authenticator.AuthenticateBasic(ctx, username, password)
		if err != nil {
			if !errors.Is(err, ErrNotProvided) {
				return nil, err
			}
			continue
		}
		return info, nil
	}
	return nil, ErrNotProvided
}

func (c *Chain) AuthenticatePublicKey(ctx context.Context, username string, pubkey ssh.PublicKey) (*AuthenticateInfo, error) {
	for _, authenticator := range c.authenticators {
		info, err := authenticator.AuthenticatePublicKey(ctx, username, pubkey)
		if err != nil {
			if !errors.Is(err, ErrNotProvided) {
				return nil, err
			}
			continue
		}
		return info, nil
	}
	return nil, ErrNotProvided
}
