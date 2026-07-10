package accesspolicy

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

const defaultCredentialIndexMaxAge = 10 * time.Second

type CredentialIndexOption func(*CredentialIndex)

type CredentialIndex struct {
	store    Store
	secrets  SecretReader
	maxAge   time.Duration
	now      func() time.Time
	mu       sync.RWMutex
	snapshot *credentialSnapshot
	syncedAt time.Time
	dirty    bool
}

func NewCredentialIndex(store Store, secrets SecretReader, opts ...CredentialIndexOption) *CredentialIndex {
	index := &CredentialIndex{
		store:   store,
		secrets: secrets,
		maxAge:  defaultCredentialIndexMaxAge,
		now:     time.Now,
		dirty:   true,
	}
	for _, opt := range opts {
		opt(index)
	}
	if index.now == nil {
		index.now = time.Now
	}
	return index
}

// WithCredentialIndexMaxAge sets how long a built snapshot may be reused before
// it is refreshed. A value less than or equal to zero means snapshots are only
// refreshed when Invalidate or Refresh is called.
func WithCredentialIndexMaxAge(maxAge time.Duration) CredentialIndexOption {
	return func(index *CredentialIndex) {
		index.maxAge = maxAge
	}
}

func withCredentialIndexClock(now func() time.Time) CredentialIndexOption {
	return func(index *CredentialIndex) {
		index.now = now
	}
}

func (i *CredentialIndex) Invalidate() {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.dirty = true
}

func (i *CredentialIndex) Refresh(ctx context.Context) error {
	_, err := i.getSnapshot(ctx, true)
	return err
}

func (i *CredentialIndex) MatchPassword(ctx context.Context, token string) (*CredentialMatch, error) {
	if token == "" {
		return nil, authn.ErrNotProvided
	}
	snapshot, err := i.getSnapshot(ctx, false)
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
	snapshot, err := i.getSnapshot(ctx, false)
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

func (i *CredentialIndex) getSnapshot(ctx context.Context, force bool) (*credentialSnapshot, error) {
	if i == nil || i.store == nil {
		return nil, fmt.Errorf("credential index requires a store")
	}
	now := i.now()
	if !force {
		i.mu.RLock()
		if i.snapshot != nil && !i.dirty && !i.expired(now) {
			snapshot := i.snapshot
			i.mu.RUnlock()
			return snapshot, nil
		}
		i.mu.RUnlock()
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	now = i.now()
	if !force && i.snapshot != nil && !i.dirty && !i.expired(now) {
		return i.snapshot, nil
	}

	snapshot, err := i.buildSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	i.snapshot = snapshot
	i.syncedAt = now
	i.dirty = false
	return snapshot, nil
}

func (i *CredentialIndex) expired(now time.Time) bool {
	if i.maxAge <= 0 || i.syncedAt.IsZero() {
		return false
	}
	return now.Sub(i.syncedAt) >= i.maxAge
}

func (i *CredentialIndex) buildSnapshot(ctx context.Context) (*credentialSnapshot, error) {
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
