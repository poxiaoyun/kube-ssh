package kube

import (
	"context"
	"errors"
	"testing"

	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestUsernameResolverResolve(t *testing.T) {
	resolver := NewUsernameResolver()

	tgt, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default.nginx"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if tgt.Kind != KindTarget {
		t.Fatalf("Kind = %q, want %q", tgt.Kind, KindTarget)
	}
	if got := tgt.Option(OptionNamespaces); got != "default" {
		t.Fatalf("namespace = %q, want default", got)
	}
	if got := tgt.Option(OptionPods); got != "nginx" {
		t.Fatalf("pod = %q, want nginx", got)
	}
	if got := tgt.Option(OptionContainers); got != "" {
		t.Fatalf("container = %q, want empty", got)
	}

	tgt, err = resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default.nginx.app"})
	if err != nil {
		t.Fatalf("Resolve(container) error = %v", err)
	}
	if got := tgt.Option(OptionContainers); got != "app" {
		t.Fatalf("container = %q, want app", got)
	}

	if _, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "nginx"}); !errors.Is(err, target.ErrNotProvided) {
		t.Fatalf("Resolve() error = %v, want ErrNotProvided", err)
	}
	if _, err := resolver.Resolve(context.Background(), target.ResolveRequest{SSHUser: "default."}); err == nil {
		t.Fatal("Resolve() succeeded for empty pod")
	} else if !status.IsReason(err, status.ReasonInvalidTarget) {
		t.Fatalf("Resolve() error reason = %q, want InvalidTarget", status.ReasonForError(err))
	}
}
