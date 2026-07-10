package authn

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseAuthorizedKeyEntry(t *testing.T) {
	pubkey := testPublicKey(t)
	line := string(ssh.MarshalAuthorizedKey(pubkey))

	entry, err := ParseAuthorizedKeyEntry("alice=" + line)
	if err != nil {
		t.Fatalf("ParseAuthorizedKeyEntry() error = %v", err)
	}
	if entry.Subject != "alice" {
		t.Fatalf("Subject = %q, want alice", entry.Subject)
	}
	if entry.PublicKey != line {
		t.Fatalf("PublicKey = %q, want %q", entry.PublicKey, line)
	}

	if _, err := ParseAuthorizedKeyEntry("alice"); err == nil {
		t.Fatal("ParseAuthorizedKeyEntry() succeeded without separator")
	}
	if _, err := ParseAuthorizedKeyEntry("=ssh-ed25519 AAAA"); err == nil {
		t.Fatal("ParseAuthorizedKeyEntry() succeeded without subject")
	}
	if _, err := ParseAuthorizedKeyEntry("alice="); err == nil {
		t.Fatal("ParseAuthorizedKeyEntry() succeeded without key")
	}
}

func TestParsePasswordEntry(t *testing.T) {
	entry, err := ParsePasswordEntry("alice=secret")
	if err != nil {
		t.Fatalf("ParsePasswordEntry() error = %v", err)
	}
	if entry.Subject != "alice" || entry.Password != "secret" {
		t.Fatalf("entry = %#v, want alice secret", entry)
	}

	if _, err := ParsePasswordEntry("alice"); err == nil {
		t.Fatal("ParsePasswordEntry() succeeded without separator")
	}
	if _, err := ParsePasswordEntry("=secret"); err == nil {
		t.Fatal("ParsePasswordEntry() succeeded without subject")
	}
	if _, err := ParsePasswordEntry("alice="); err == nil {
		t.Fatal("ParsePasswordEntry() succeeded without password")
	}
}

func TestStaticPublicKeyAuthenticator(t *testing.T) {
	pubkey := testPublicKey(t)
	authenticator, err := NewStaticPublicKeyAuthenticator([]AuthorizedKeyEntry{
		{
			Subject:   "alice@example.com",
			PublicKey: string(ssh.MarshalAuthorizedKey(pubkey)),
			Groups:    []string{"dev"},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticPublicKeyAuthenticator() error = %v", err)
	}

	info, err := authenticator.AuthenticatePublicKey(context.Background(), pubkey)
	if err != nil {
		t.Fatalf("AuthenticatePublicKey() error = %v", err)
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
	if info.Method != "publickey" {
		t.Fatalf("method = %q, want publickey", info.Method)
	}

	other := testPublicKey(t)
	if _, err := authenticator.AuthenticatePublicKey(context.Background(), other); !errors.Is(err, ErrNotProvided) {
		t.Fatalf("AuthenticatePublicKey() error = %v, want ErrNotProvided", err)
	}
	if _, err := authenticator.AuthenticateBasic(context.Background(), "alice", "password"); !errors.Is(err, ErrNotProvided) {
		t.Fatalf("AuthenticateBasic() error = %v, want ErrNotProvided", err)
	}
}

func TestNewStaticPublicKeyAuthenticatorRejectsInvalidKey(t *testing.T) {
	_, err := NewStaticPublicKeyAuthenticator([]AuthorizedKeyEntry{
		{Subject: "alice", PublicKey: "not-a-key"},
	})
	if err == nil {
		t.Fatal("NewStaticPublicKeyAuthenticator() succeeded with invalid key")
	}
}

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	return key
}
