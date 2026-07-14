package authn

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

var errRejected = errors.New("rejected")

type testAuthenticator struct {
	info *AuthenticateInfo
	err  error
}

func (a testAuthenticator) AuthenticateBasic(context.Context, string, string) (*AuthenticateInfo, error) {
	return a.info, a.err
}

func (a testAuthenticator) AuthenticatePublicKey(context.Context, string, ssh.PublicKey) (*AuthenticateInfo, error) {
	return a.info, a.err
}

func TestChainAuthenticateBasic(t *testing.T) {
	want := &AuthenticateInfo{User: UserInfo{Name: "alice"}, Method: "password"}
	chain := NewChain(
		testAuthenticator{err: ErrNotProvided},
		testAuthenticator{info: want},
		testAuthenticator{err: errRejected},
	)

	got, err := chain.AuthenticateBasic(context.Background(), "alice", "password")
	if err != nil {
		t.Fatalf("AuthenticateBasic() error = %v", err)
	}
	if got != want {
		t.Fatalf("AuthenticateBasic() = %#v, want %#v", got, want)
	}
}

func TestChainAuthenticateBasicReturnsLastError(t *testing.T) {
	chain := NewChain(
		testAuthenticator{err: ErrNotProvided},
		testAuthenticator{err: errRejected},
	)

	_, err := chain.AuthenticateBasic(context.Background(), "alice", "password")
	if !errors.Is(err, errRejected) {
		t.Fatalf("AuthenticateBasic() error = %v, want %v", err, errRejected)
	}
}

func TestChainAuthenticateBasicStopsOnTerminalError(t *testing.T) {
	want := &AuthenticateInfo{User: UserInfo{Name: "alice"}, Method: "password"}
	chain := NewChain(
		testAuthenticator{err: errRejected},
		testAuthenticator{info: want},
	)

	_, err := chain.AuthenticateBasic(context.Background(), "alice", "password")
	if !errors.Is(err, errRejected) {
		t.Fatalf("AuthenticateBasic() error = %v, want %v", err, errRejected)
	}
}

func TestChainAuthenticateBasicNotProvided(t *testing.T) {
	chain := NewChain(testAuthenticator{err: ErrNotProvided})

	_, err := chain.AuthenticateBasic(context.Background(), "alice", "password")
	if !errors.Is(err, ErrNotProvided) {
		t.Fatalf("AuthenticateBasic() error = %v, want %v", err, ErrNotProvided)
	}
}
