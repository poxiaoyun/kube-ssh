package target

import (
	"context"
	"errors"
	"slices"
	"strings"

	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/status"
)

// ErrNotProvided is returned when a resolver cannot resolve the request but
// another resolver in a chain may be able to.
var ErrNotProvided = errors.New("target resolution not provided")

// Target identifies a backend-specific execution target.
//
// A target is the destination of the SSH connection, such as a Kubernetes
// workload instance. It is intentionally separate from authn.UserInfo, which
// identifies the caller.
type Target struct {
	Kind    string     `json:"kind,omitempty"`
	Options []KeyValue `json:"options,omitempty"`
}

type KeyValue struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// ResolveRequest describes the authenticated SSH connection being mapped to a
// backend target.
//
// SSHUser is the raw SSH login name. kube-ssh treats it primarily as a target
// locator because SSH has no better client-compatible field for backend
// selection. More advanced resolvers may combine SSHUser with User, AuthMethod,
// PublicKeyFingerprint, and TargetHints to resolve aliases or credential-bound
// default targets.
type ResolveRequest struct {
	// SSHUser is the target locator derived from the SSH username.
	SSHUser string
	// User is the authenticated caller identity.
	User authn.UserInfo
	// AuthMethod is the method reported by the authenticator.
	AuthMethod string
	// AuthExtra carries authenticator-specific context.
	AuthExtra map[string][]string
	// PublicKeyFingerprint is set for public-key authentication.
	PublicKeyFingerprint string
	// TargetHints are optional locator hints returned by authentication.
	TargetHints []authn.TargetHint
}

// Resolver maps an authenticated SSH connection to exactly one Target.
//
// Resolver implementations may perform alias/default-target lookup, including
// CRD or webhook-backed lookup. They should not decide whether the caller is
// allowed to perform a capability on the resolved target; that is the
// authorizer's responsibility.
type Resolver interface {
	Resolve(ctx context.Context, req ResolveRequest) (*Target, error)
}

type Chain []Resolver

func (c Chain) Resolve(ctx context.Context, req ResolveRequest) (*Target, error) {
	var lastErr error
	for _, resolver := range c {
		if resolver == nil {
			continue
		}
		tgt, err := resolver.Resolve(ctx, req)
		if err == nil {
			return tgt, nil
		}
		if errors.Is(err, ErrNotProvided) {
			lastErr = err
			continue
		}
		return nil, err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNotProvided
}

// TargetHintResolver resolves targets suggested by authentication.
type TargetHintResolver struct{}

func NewTargetHintResolver() *TargetHintResolver { return &TargetHintResolver{} }

func (r *TargetHintResolver) Resolve(_ context.Context, req ResolveRequest) (*Target, error) {
	if len(req.TargetHints) == 0 {
		return nil, ErrNotProvided
	}
	if req.SSHUser != "" {
		for _, hint := range req.TargetHints {
			if hintMatchesSSHUser(hint, req.SSHUser) {
				return TargetFromHint(hint)
			}
		}
	}
	if len(req.TargetHints) == 1 {
		return TargetFromHint(req.TargetHints[0])
	}
	return nil, status.InvalidTarget("target alias %q did not match any authentication target hint", req.SSHUser)
}

func hintMatchesSSHUser(hint authn.TargetHint, sshUser string) bool {
	return slices.Contains(hint.Extra["aliases"], sshUser) || slices.Contains(hint.Extra["names"], sshUser)
}

func TargetFromHint(hint authn.TargetHint) (*Target, error) {
	if hint.Kind == "" {
		return nil, status.InvalidTarget("target hint kind is required")
	}
	options := make([]KeyValue, 0, len(hint.Options))
	for _, option := range hint.Options {
		if option.Key == "" || option.Value == "" {
			return nil, status.InvalidTarget("target hint option requires key and value")
		}
		options = append(options, KeyValue{Key: option.Key, Value: option.Value})
	}
	if len(options) == 0 {
		return nil, status.InvalidTarget("target hint %q requires options", hint.Kind)
	}
	return &Target{Kind: hint.Kind, Options: options}, nil
}

func (t Target) Option(key string) string {
	for _, option := range t.Options {
		if option.Key == key {
			return option.Value
		}
	}
	return ""
}

func (t Target) ToPath() string {
	var path strings.Builder
	path.WriteString(t.Kind)
	for _, option := range t.Options {
		path.WriteString("/")
		path.WriteString(option.Key)
		path.WriteString("/")
		path.WriteString(option.Value)
	}
	return path.String()
}
