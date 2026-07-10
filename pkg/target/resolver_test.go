package target

import (
	"context"
	"errors"
	"testing"

	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/status"
)

func TestTargetHintResolverDefaultHint(t *testing.T) {
	resolver := NewTargetHintResolver()

	tgt, err := resolver.Resolve(context.Background(), ResolveRequest{
		SSHUser:     "devbox",
		TargetHints: []authn.TargetHint{targetHint("dev", "shell", "app", nil)},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.ToPath(); got != "example/scopes/dev/names/shell/units/app" {
		t.Fatalf("target = %q", got)
	}
}

func TestTargetHintResolverAlias(t *testing.T) {
	resolver := NewTargetHintResolver()

	tgt, err := resolver.Resolve(context.Background(), ResolveRequest{
		SSHUser: "prod",
		TargetHints: []authn.TargetHint{
			targetHint("dev", "shell", "app", []string{"dev"}),
			targetHint("prod", "shell", "app", []string{"prod"}),
		},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.Option("scopes"); got != "prod" {
		t.Fatalf("scope = %q, want prod", got)
	}
}

func TestTargetHintResolverAmbiguous(t *testing.T) {
	resolver := NewTargetHintResolver()

	_, err := resolver.Resolve(context.Background(), ResolveRequest{
		SSHUser: "unknown",
		TargetHints: []authn.TargetHint{
			targetHint("dev", "shell", "app", []string{"dev"}),
			targetHint("prod", "shell", "app", []string{"prod"}),
		},
	})
	if !status.IsReason(err, status.ReasonInvalidTarget) {
		t.Fatalf("Resolve() error = %v, want InvalidTarget", err)
	}
}

func TestChainResolverContinuesOnNotProvided(t *testing.T) {
	resolver := Chain{
		notProvidedResolver{},
		NewTargetHintResolver(),
	}

	tgt, err := resolver.Resolve(context.Background(), ResolveRequest{
		SSHUser:     "devbox",
		TargetHints: []authn.TargetHint{targetHint("dev", "shell", "app", nil)},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.Option("names"); got != "shell" {
		t.Fatalf("name = %q, want shell", got)
	}
}

func TestChainResolverStopsOnRealError(t *testing.T) {
	wantErr := status.InvalidTarget("bad target")
	resolver := Chain{
		errorResolver{err: wantErr},
		NewTargetHintResolver(),
	}

	_, err := resolver.Resolve(context.Background(), ResolveRequest{
		SSHUser:     "devbox",
		TargetHints: []authn.TargetHint{targetHint("dev", "shell", "app", nil)},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Resolve() error = %v, want %v", err, wantErr)
	}
}

func TestChainResolverNoResolver(t *testing.T) {
	_, err := (Chain{}).Resolve(context.Background(), ResolveRequest{SSHUser: "devbox"})
	if !errors.Is(err, ErrNotProvided) {
		t.Fatalf("Resolve() error = %v, want ErrNotProvided", err)
	}
}

func targetHint(scope, name, unit string, aliases []string) authn.TargetHint {
	return authn.TargetHint{
		Kind: "example",
		Options: []authn.TargetHintOption{
			{Key: "scopes", Value: scope},
			{Key: "names", Value: name},
			{Key: "units", Value: unit},
		},
		Extra: map[string][]string{"aliases": aliases},
	}
}

type notProvidedResolver struct{}

func (notProvidedResolver) Resolve(context.Context, ResolveRequest) (*Target, error) {
	return nil, ErrNotProvided
}

type errorResolver struct {
	err error
}

func (r errorResolver) Resolve(context.Context, ResolveRequest) (*Target, error) {
	return nil, r.err
}
