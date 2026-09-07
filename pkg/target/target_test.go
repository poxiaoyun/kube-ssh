package target_test

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestHintResolverDefaultHint(t *testing.T) {
	resolver := target.HintResolver{}

	tgt, err := resolver.Resolve(context.Background(), target.ResolveInput{
		SSHUser: "devbox",
		Hints:   []target.Hint{targetHint("dev", "shell", "app", nil)},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.String(); got != "example/scopes/dev/names/shell/units/app" {
		t.Fatalf("target = %q", got)
	}
}

func TestHintResolverAlias(t *testing.T) {
	resolver := target.HintResolver{}

	tgt, err := resolver.Resolve(context.Background(), target.ResolveInput{
		SSHUser: "prod",
		Hints: []target.Hint{
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

func TestHintResolverAmbiguous(t *testing.T) {
	resolver := target.HintResolver{}

	_, err := resolver.Resolve(context.Background(), target.ResolveInput{
		SSHUser: "unknown",
		Hints: []target.Hint{
			targetHint("dev", "shell", "app", []string{"dev"}),
			targetHint("prod", "shell", "app", []string{"prod"}),
		},
	})
	if !apierrors.IsBadRequest(err) {
		t.Fatalf("Resolve() error = %v, want BadRequest", err)
	}
}

func TestChainResolverContinuesOnNotProvided(t *testing.T) {
	resolver := target.Chain{
		notProvidedResolver{},
		target.HintResolver{},
	}

	tgt, err := resolver.Resolve(context.Background(), target.ResolveInput{
		SSHUser: "devbox",
		Hints:   []target.Hint{targetHint("dev", "shell", "app", nil)},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.Option("names"); got != "shell" {
		t.Fatalf("name = %q, want shell", got)
	}
}

func TestChainResolverStopsOnRealError(t *testing.T) {
	wantErr := apierrors.NewBadRequest("bad target")
	resolver := target.Chain{
		errorResolver{err: wantErr},
		target.HintResolver{},
	}

	_, err := resolver.Resolve(context.Background(), target.ResolveInput{
		SSHUser: "devbox",
		Hints:   []target.Hint{targetHint("dev", "shell", "app", nil)},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Resolve() error = %v, want %v", err, wantErr)
	}
}

func TestChainResolverNoResolver(t *testing.T) {
	_, err := (target.Chain{}).Resolve(context.Background(), target.ResolveInput{SSHUser: "devbox"})
	if !errors.Is(err, target.ErrNotProvided) {
		t.Fatalf("Resolve() error = %v, want ErrNotProvided", err)
	}
}

func targetHint(scope, name, unit string, aliases []string) target.Hint {
	return target.Hint{
		Kind: "example",
		Options: []target.Option{
			{Key: "scopes", Value: scope},
			{Key: "names", Value: name},
			{Key: "units", Value: unit},
		},
		Aliases: aliases,
	}
}

type notProvidedResolver struct{}

func (notProvidedResolver) Resolve(context.Context, target.ResolveInput) (*target.Target, error) {
	return nil, target.ErrNotProvided
}

type errorResolver struct {
	err error
}

func (r errorResolver) Resolve(context.Context, target.ResolveInput) (*target.Target, error) {
	return nil, r.err
}

func TestTargetStringKeepsOptionOrder(t *testing.T) {
	tgt := target.Target{
		Kind: "example",
		Options: []target.Option{
			{Key: "zones", Value: "z1"},
			{Key: "units", Value: "app"},
			{Key: "names", Value: "nginx"},
			{Key: "scopes", Value: "default"},
		},
	}
	if got, want := tgt.String(), "example/zones/z1/units/app/names/nginx/scopes/default"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if got, want := tgt.Option("names"), "nginx"; got != want {
		t.Fatalf("Option(%q) = %q, want %q", "names", got, want)
	}
}
