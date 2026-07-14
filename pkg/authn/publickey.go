package authn

import (
	"bytes"
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type authorizedEntry struct {
	info         AuthenticateInfo
	marshaledKey []byte
}

// StaticPublicKeyAuthenticator checks public keys against a static list from config.
type StaticPublicKeyAuthenticator struct {
	entries []authorizedEntry
}

// NewStaticPublicKeyAuthenticator parses static authorized keys.
func NewStaticPublicKeyAuthenticator(entries []AuthorizedKeyEntry) (*StaticPublicKeyAuthenticator, error) {
	parsed := make([]authorizedEntry, 0, len(entries))
	for _, e := range entries {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("parse authorized key for %q: %w", e.Subject, err)
		}
		parsed = append(parsed, authorizedEntry{
			info: AuthenticateInfo{
				User: UserInfo{
					Name:   e.Subject,
					Email:  e.Subject,
					Groups: e.Groups,
				},
				Method: "publickey",
			},
			marshaledKey: key.Marshal(),
		})
	}
	return &StaticPublicKeyAuthenticator{entries: parsed}, nil
}

// AuthenticatePublicKey returns the identity matching pubkey, or an error.
func (a *StaticPublicKeyAuthenticator) AuthenticatePublicKey(_ context.Context, _ string, pubkey ssh.PublicKey) (*AuthenticateInfo, error) {
	for _, e := range a.entries {
		if bytes.Equal(e.marshaledKey, pubkey.Marshal()) {
			return &e.info, nil
		}
	}
	return nil, fmt.Errorf("%w: public key %s", ErrNotProvided, ssh.FingerprintSHA256(pubkey))
}

// AuthenticateBasic is not provided by this static public key authenticator.
func (a *StaticPublicKeyAuthenticator) AuthenticateBasic(_ context.Context, _, _ string) (*AuthenticateInfo, error) {
	return nil, ErrNotProvided
}
