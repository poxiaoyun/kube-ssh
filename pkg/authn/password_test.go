package authn

import (
	"context"
	"errors"
	"testing"
)

func TestStaticPasswordAuthenticator(t *testing.T) {
	authenticator, err := NewStaticPasswordAuthenticator([]PasswordEntry{
		{Subject: "alice@example.com", Password: "secret", Groups: []string{"dev"}},
	})
	if err != nil {
		t.Fatalf("NewStaticPasswordAuthenticator() error = %v", err)
	}

	info, err := authenticator.AuthenticateBasic(context.Background(), "default.shell.app", "secret")
	if err != nil {
		t.Fatalf("AuthenticateBasic() error = %v", err)
	}
	if info.User.Name != "alice@example.com" {
		t.Fatalf("user name = %q, want alice@example.com", info.User.Name)
	}
	if info.User.Email != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", info.User.Email)
	}
	if len(info.User.Groups) != 1 || info.User.Groups[0] != "dev" {
		t.Fatalf("groups = %v, want [dev]", info.User.Groups)
	}
	if info.Method != "password" {
		t.Fatalf("method = %q, want password", info.Method)
	}

	if _, err := authenticator.AuthenticateBasic(context.Background(), "default.shell.app", "bad"); !errors.Is(err, ErrNotProvided) {
		t.Fatalf("AuthenticateBasic() error = %v, want ErrNotProvided", err)
	}
	if _, err := authenticator.AuthenticatePublicKey(context.Background(), testPublicKey(t)); !errors.Is(err, ErrNotProvided) {
		t.Fatalf("AuthenticatePublicKey() error = %v, want ErrNotProvided", err)
	}
}

func TestNewStaticPasswordAuthenticatorRejectsInvalidEntry(t *testing.T) {
	if _, err := NewStaticPasswordAuthenticator([]PasswordEntry{{Subject: "alice"}}); err == nil {
		t.Fatal("NewStaticPasswordAuthenticator() succeeded without password")
	}
	if _, err := NewStaticPasswordAuthenticator([]PasswordEntry{{Password: "secret"}}); err == nil {
		t.Fatal("NewStaticPasswordAuthenticator() succeeded without subject")
	}
}
