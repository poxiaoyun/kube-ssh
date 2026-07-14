package authn

import (
	"context"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type passwordEntry struct {
	info     AuthenticateInfo
	password string
}

// StaticPasswordAuthenticator checks passwords against a static list from config.
type StaticPasswordAuthenticator struct {
	entries []passwordEntry
}

func NewStaticPasswordAuthenticator(entries []PasswordEntry) (*StaticPasswordAuthenticator, error) {
	parsed := make([]passwordEntry, 0, len(entries))
	for _, e := range entries {
		if e.Subject == "" || e.Password == "" {
			return nil, fmt.Errorf("password entry requires subject and password")
		}
		parsed = append(parsed, passwordEntry{
			info: AuthenticateInfo{
				User: UserInfo{
					Name:   e.Subject,
					Email:  e.Subject,
					Groups: e.Groups,
				},
				Method: "password",
			},
			password: e.Password,
		})
	}
	return &StaticPasswordAuthenticator{entries: parsed}, nil
}

func (a *StaticPasswordAuthenticator) AuthenticateBasic(_ context.Context, _, password string) (*AuthenticateInfo, error) {
	for _, e := range a.entries {
		if subtle.ConstantTimeCompare([]byte(e.password), []byte(password)) == 1 {
			return &e.info, nil
		}
	}
	return nil, fmt.Errorf("%w: password rejected", ErrNotProvided)
}

func (a *StaticPasswordAuthenticator) AuthenticatePublicKey(context.Context, string, ssh.PublicKey) (*AuthenticateInfo, error) {
	return nil, ErrNotProvided
}
