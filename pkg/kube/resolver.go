package kube

import (
	"context"
	"strings"

	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// UsernameResolver parses the SSH username as a Kubernetes target:
// "namespace.pod" or "namespace.pod.container".
type UsernameResolver struct{}

func NewUsernameResolver() *UsernameResolver { return &UsernameResolver{} }

// Resolve parses the SSH username as a kube target locator.
//
//	"default.nginx"     -> kind=kube, options={namespace:default,pod:nginx}
//	"default.nginx.app" -> kind=kube, options={namespace:default,pod:nginx,container:app}
func (r *UsernameResolver) Resolve(_ context.Context, req target.ResolveRequest) (*target.Target, error) {
	username := req.SSHUser
	if !strings.Contains(username, ".") {
		return nil, target.ErrNotProvided
	}
	parts := strings.Split(username, ".")
	switch len(parts) {
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return nil, status.InvalidTarget("invalid target %q: namespace and pod are required", username)
		}
		return NewTarget(parts[0], parts[1], ""), nil
	case 3:
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, status.InvalidTarget("invalid target %q: namespace, pod, and container are required", username)
		}
		return NewTarget(parts[0], parts[1], parts[2]), nil
	default:
		return nil, status.InvalidTarget("invalid target %q: expected namespace.pod or namespace.pod.container", username)
	}
}
