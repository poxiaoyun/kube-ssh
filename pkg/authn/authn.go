package authn

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ErrNotProvided is returned when an authenticator cannot make a decision.
// It lets callers chain authenticators without treating "not mine" as failure.
var ErrNotProvided = fmt.Errorf("no authentication provided")

// UserInfo is the stable identity returned by authentication.
// It describes the authenticated caller, not the Kubernetes pod/container
// target. In kube-ssh the raw SSH username is a target locator, not a human
// identity source.
type UserInfo struct {
	ID            string              `json:"id,omitempty"`
	Name          string              `json:"name,omitempty"`
	Email         string              `json:"email,omitempty"`
	EmailVerified bool                `json:"email_verified,omitempty"`
	Groups        []string            `json:"groups,omitempty"`
	Extra         map[string][]string `json:"extra,omitempty"`
}

// TargetHint is an optional target locator returned by authentication.
//
// Authenticators may use credentials to suggest default or preferred targets
// (for example, a public key bound to a developer pod). A hint is not an
// authorization decision. The target resolver decides whether and how to use
// hints together with the SSH username and authenticated identity.
//
// This type intentionally mirrors the generic target shape without importing
// the target package, so authentication and target resolution remain decoupled.
type TargetHint struct {
	Kind    string              `json:"kind,omitempty"`
	Options []TargetHintOption  `json:"options,omitempty"`
	Extra   map[string][]string `json:"extra,omitempty"`
}

type TargetHintOption struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// AuthenticateInfo is the authentication result.
// Method should be a stable value such as "anonymous", "publickey",
// "password", "webhook", or an implementation-specific method name.
type AuthenticateInfo struct {
	User        UserInfo            `json:"user"`
	Method      string              `json:"method"`
	TargetHints []TargetHint        `json:"targetHints,omitempty"`
	Extra       map[string][]string `json:"extra,omitempty"`
}

// AuthorizedKeyEntry associates a user identity with one OpenSSH authorized_keys line.
type AuthorizedKeyEntry struct {
	Subject   string   `json:"subject"`
	PublicKey string   `json:"publicKey"`
	Groups    []string `json:"groups,omitempty"`
}

// PasswordEntry associates a user identity with a static password.
type PasswordEntry struct {
	Subject  string   `json:"subject"`
	Password string   `json:"password"`
	Groups   []string `json:"groups,omitempty"`
}

// ParseAuthorizedKeyEntry parses "subject=authorized_keys line".
func ParseAuthorizedKeyEntry(value string) (AuthorizedKeyEntry, error) {
	subject, publicKey, ok := strings.Cut(value, "=")
	if !ok || subject == "" || publicKey == "" {
		return AuthorizedKeyEntry{}, fmt.Errorf("authorized key must be subject=authorized_keys-line")
	}
	return AuthorizedKeyEntry{Subject: subject, PublicKey: publicKey}, nil
}

// ParsePasswordEntry parses "subject=password".
func ParsePasswordEntry(value string) (PasswordEntry, error) {
	subject, password, ok := strings.Cut(value, "=")
	if !ok || subject == "" || password == "" {
		return PasswordEntry{}, fmt.Errorf("password must be subject=password")
	}
	return PasswordEntry{Subject: subject, Password: password}, nil
}

// SSHAuthenticator validates SSH credentials and returns caller identity.
//
// Implementations must not decide whether the caller may access the resolved
// target or perform a shell/SFTP/forward operation. That belongs to target
// resolution and authorization. Returning ErrNotProvided means this
// authenticator cannot handle the credential and lets a chain try the next
// authenticator.
type SSHAuthenticator interface {
	// AuthenticateBasic validates a password presented for the SSH username.
	// The username is the raw SSH login name and is treated as a target locator.
	// Implementations should derive identity from the authenticated credential or
	// an external identity provider, not from username structure.
	AuthenticateBasic(ctx context.Context, username, password string) (*AuthenticateInfo, error)
	// AuthenticatePublicKey validates a public key. Implementations may return
	// TargetHints tied to the key, but must not perform operation authorization.
	AuthenticatePublicKey(ctx context.Context, pubkey ssh.PublicKey) (*AuthenticateInfo, error)
}
