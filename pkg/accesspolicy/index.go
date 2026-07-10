package accesspolicy

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

type CredentialIndex struct {
	store   Store
	secrets SecretReader
}

func NewCredentialIndex(store Store, secrets SecretReader) *CredentialIndex {
	return &CredentialIndex{store: store, secrets: secrets}
}

func (i *CredentialIndex) MatchPassword(ctx context.Context, token string) (*CredentialMatch, error) {
	if token == "" {
		return nil, authn.ErrNotProvided
	}
	snapshot, err := i.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	matches := snapshot.passwords[token]
	return chooseMatch("password token", token, matches)
}

func (i *CredentialIndex) MatchPublicKey(ctx context.Context, pubkey cryptossh.PublicKey) (*CredentialMatch, error) {
	if pubkey == nil {
		return nil, authn.ErrNotProvided
	}
	fingerprint := cryptossh.FingerprintSHA256(pubkey)
	snapshot, err := i.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	matches := snapshot.publicKeys[fingerprint]
	return chooseMatch("public key", fingerprint, matches)
}

type credentialSnapshot struct {
	passwords  map[string][]*CredentialMatch
	publicKeys map[string][]*CredentialMatch
}

func (i *CredentialIndex) snapshot(ctx context.Context) (*credentialSnapshot, error) {
	if i == nil || i.store == nil {
		return nil, fmt.Errorf("credential index requires a store")
	}
	accesses, err := i.store.List(ctx)
	if err != nil {
		return nil, err
	}
	sortAccesses(accesses)
	snapshot := &credentialSnapshot{
		passwords:  map[string][]*CredentialMatch{},
		publicKeys: map[string][]*CredentialMatch{},
	}
	for _, access := range accesses {
		if !isPodAccess(access) {
			continue
		}
		for idx := range access.Spec.Credentials {
			credential := &access.Spec.Credentials[idx]
			match := &CredentialMatch{Access: access, Credential: credential}
			passwords, err := i.passwords(ctx, access.Namespace, credential.Credential)
			if err != nil {
				return nil, err
			}
			for _, password := range passwords {
				if password == "" {
					continue
				}
				snapshot.passwords[password] = append(snapshot.passwords[password], match)
			}
			keys, err := i.publicKeys(ctx, access.Namespace, credential.Credential)
			if err != nil {
				return nil, err
			}
			for _, key := range keys {
				pubkey, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(key))
				if err != nil {
					return nil, fmt.Errorf("parse public key for access %s/%s credential %s: %w", access.Namespace, access.Name, credential.Username, err)
				}
				fingerprint := cryptossh.FingerprintSHA256(pubkey)
				snapshot.publicKeys[fingerprint] = append(snapshot.publicKeys[fingerprint], match)
			}
		}
	}
	for _, matches := range snapshot.passwords {
		sortMatches(matches)
	}
	for _, matches := range snapshot.publicKeys {
		sortMatches(matches)
	}
	return snapshot, nil
}

func (i *CredentialIndex) passwords(ctx context.Context, namespace string, credential sshv1.Credential) ([]string, error) {
	values := append([]string(nil), credential.Passwords...)
	for _, ref := range credential.PasswordsFrom {
		value, err := i.secretValue(ctx, namespace, ref)
		if err != nil {
			return nil, err
		}
		values = append(values, splitSecretLines(value)...)
	}
	return values, nil
}

func (i *CredentialIndex) publicKeys(ctx context.Context, namespace string, credential sshv1.Credential) ([]string, error) {
	values := append([]string(nil), credential.PublicKeys...)
	for _, ref := range credential.PublicKeysFrom {
		value, err := i.secretValue(ctx, namespace, ref)
		if err != nil {
			return nil, err
		}
		values = append(values, splitSecretLines(value)...)
	}
	return values, nil
}

func (i *CredentialIndex) secretValue(ctx context.Context, namespace string, ref sshv1.LocalSecretKeyRef) (string, error) {
	if i.secrets == nil {
		return "", fmt.Errorf("secret reference %s/%s requires a secret reader", ref.Name, ref.Key)
	}
	return i.secrets.GetSecretValue(ctx, namespace, ref.Name, ref.Key)
}

func splitSecretLines(value string) []string {
	lines := strings.Split(value, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func chooseMatch(kind, key string, matches []*CredentialMatch) (*CredentialMatch, error) {
	if len(matches) == 0 {
		return nil, authn.ErrNotProvided
	}
	if len(matches) > 1 {
		chosen := matches[0]
		slog.Warn("duplicate access credential material, using oldest access",
			"kind", kind,
			"key", key,
			"access", accessKey(chosen.Access.Namespace, chosen.Access.Name),
			"credential", chosen.Credential.Username,
			"matches", len(matches),
		)
	}
	return matches[0], nil
}

func sortMatches(matches []*CredentialMatch) {
	sort.Slice(matches, func(i, j int) bool {
		a := matches[i]
		b := matches[j]
		if accessLess(a.Access, b.Access) {
			return true
		}
		if accessLess(b.Access, a.Access) {
			return false
		}
		return a.Credential.Username < b.Credential.Username
	})
}
