// Package target resolves authenticated SSH connections to destinations.
package target

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	// KindPod identifies a Kubernetes Pod/container destination.
	KindPod = "kube"
	// KindExternalSSH identifies an upstream SSH server destination.
	KindExternalSSH = "ssh"
)

// ErrNotProvided is returned when a resolver cannot resolve the request but
// another resolver in a chain may be able to.
var ErrNotProvided = errors.New("target resolution not provided")

// Target identifies a connection destination selected by a resolver.
//
// A target is the destination of the SSH connection, such as a Kubernetes
// workload instance. It is intentionally separate from the authenticated
// caller identity.
type Target struct {
	Kind    string
	Options []Option

	// Runtime contains trusted connection-scoped bindings produced by the resolver.
	Runtime map[string]string
}

// Option is one ordered component of a target locator.
type Option struct {
	Key   string
	Value string
}

// Hint is a candidate target locator returned by authentication.
type Hint struct {
	Kind    string
	Options []Option
	// Aliases are SSH usernames that select this hint when several are present.
	Aliases []string
}

// ResolveInput describes the authenticated SSH connection being mapped to a
// connection target.
//
// SSHUser is the raw SSH login name. kube-ssh treats it primarily as a target
// locator because SSH has no better client-compatible field for target
// selection. Resolvers may combine it with the authenticated user, source, and
// authentication-owned attributes.
type ResolveInput struct {
	// SSHUser is the target locator derived from the SSH username.
	SSHUser string
	// UserName is the stable authenticated caller name.
	UserName string
	// AuthExtra carries authenticator-specific context.
	AuthExtra map[string][]string
	// SourceIP is the peer IP address observed by the kube-ssh gateway. In
	// Kubernetes deployments this may be a node, load balancer, proxy, or NAT
	// address rather than the real SSH client IP, so resolvers should treat it as
	// a best-effort affinity hint instead of a stable caller identity.
	SourceIP string
	// Hints are optional target locators returned by authentication.
	Hints []Hint
}

// Resolver maps an authenticated SSH connection to exactly one Target.
//
// Resolver implementations may perform alias/default-target lookup, including
// CRD or webhook-backed lookup. They should not decide whether the caller is
// allowed to perform a capability on the resolved target; that is the
// authorizer's responsibility.
type Resolver interface {
	// Resolve maps input to exactly one connection target.
	Resolve(ctx context.Context, input ResolveInput) (*Target, error)
}

type Chain []Resolver

func (c Chain) Resolve(ctx context.Context, input ResolveInput) (*Target, error) {
	var lastErr error
	for _, resolver := range c {
		tgt, err := resolver.Resolve(ctx, input)
		if err != nil {
			if !errors.Is(err, ErrNotProvided) {
				return nil, err
			}
			lastErr = err
			continue
		}
		return tgt, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNotProvided
}

// HintResolver resolves targets suggested by authentication.
type HintResolver struct{}

func (HintResolver) Resolve(_ context.Context, input ResolveInput) (*Target, error) {
	if len(input.Hints) == 0 {
		return nil, ErrNotProvided
	}
	if input.SSHUser != "" {
		for _, hint := range input.Hints {
			if slices.Contains(hint.Aliases, input.SSHUser) {
				return newTargetFromHint(hint)
			}
		}
	}
	if len(input.Hints) == 1 {
		return newTargetFromHint(input.Hints[0])
	}
	return nil, apierrors.NewBadRequest(fmt.Sprintf("target alias %q did not match any authentication target hint", input.SSHUser))
}

func newTargetFromHint(hint Hint) (*Target, error) {
	if hint.Kind == "" {
		return nil, apierrors.NewBadRequest("target hint kind is required")
	}
	for _, option := range hint.Options {
		if option.Key == "" || option.Value == "" {
			return nil, apierrors.NewBadRequest("target hint option requires key and value")
		}
	}
	if len(hint.Options) == 0 {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("target hint %q requires options", hint.Kind))
	}
	return &Target{Kind: hint.Kind, Options: hint.Options}, nil
}

// Option returns the value of the first locator option with the given key.
func (t Target) Option(key string) string {
	for _, option := range t.Options {
		if option.Key == key {
			return option.Value
		}
	}
	return ""
}

// String returns the canonical target locator path.
func (t Target) String() string {
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
