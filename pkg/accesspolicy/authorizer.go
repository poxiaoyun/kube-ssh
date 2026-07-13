package accesspolicy

import (
	"context"
	"fmt"
	"net"

	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
)

type Authorizer struct {
	store    AccessGetter
	defaults CapabilityDefaults
}

type CapabilityDefaults struct {
	Allow                    []sshv1.Capability
	LocalForwardDestinations []string
	RemoteForwardBinds       []string
}

func NewAuthorizer(store AccessGetter, defaults ...CapabilityDefaults) *Authorizer {
	authorizer := &Authorizer{store: store}
	if len(defaults) > 0 {
		authorizer.defaults = defaults[0]
	}
	return authorizer
}

func (a *Authorizer) Authorize(ctx context.Context, req authz.Request) (authz.Decision, string, error) {
	namespace := firstExtra(req.AuthExtra, ExtraAccessNamespace)
	name := firstExtra(req.AuthExtra, ExtraAccessName)
	username := firstExtra(req.AuthExtra, ExtraCredentialUser)
	if namespace == "" || name == "" || username == "" {
		return authz.DecisionNoOpinion, "", nil
	}
	if a == nil || a.store == nil {
		return authz.DecisionNoOpinion, "", fmt.Errorf("access authorizer requires a store")
	}
	access, err := a.store.Get(ctx, namespace, name)
	if err != nil {
		return authz.DecisionDeny, "authenticated access no longer exists", nil
	}
	if !isPodAccess(access) {
		return authz.DecisionNoOpinion, "", nil
	}
	credential := findCredential(access, username)
	if credential == nil {
		return authz.DecisionDeny, "authenticated credential no longer exists", nil
	}
	container := resourceName(req.Attributes.Resources, "containers")
	if container != "" && (!containerAllowed(access.Spec.Containers, container) || !containerAllowed(credential.Containers, container)) {
		return authz.DecisionDeny, "container not allowed", nil
	}
	if allowed, reason := capabilityAllowed(credential.Capabilities, a.defaults, req.Attributes); !allowed {
		return authz.DecisionDeny, reason, nil
	}
	return authz.DecisionAllow, "", nil
}

func findCredential(access *sshv1.Access, username string) *sshv1.AccessCredential {
	for i := range access.Spec.Credentials {
		if access.Spec.Credentials[i].Username == username {
			return &access.Spec.Credentials[i]
		}
	}
	return nil
}

func capabilityAllowed(policy sshv1.CapabilityPolicy, defaults CapabilityDefaults, attrs authz.Attributes) (bool, string) {
	capability := sshv1.Capability(attrs.Action)
	allowedCapabilities := policy.Allow
	if len(allowedCapabilities) == 0 {
		allowedCapabilities = defaults.Allow
	}
	if len(allowedCapabilities) > 0 && !containsCapability(allowedCapabilities, capability) && !containsCapability(allowedCapabilities, "*") {
		return false, "capability not allowed"
	}
	switch capability {
	case sshv1.CapabilityLocalForward:
		allow := defaults.LocalForwardDestinations
		if policy.LocalForward != nil && len(policy.LocalForward.AllowDestinations) > 0 {
			allow = policy.LocalForward.AllowDestinations
		}
		if len(allow) > 0 {
			destination := net.JoinHostPort(firstExtra(attrs.Extra, "destination_host"), firstExtra(attrs.Extra, "destination_port"))
			if !bindAllowed(allow, destination) {
				return false, "local forward destination not allowed"
			}
		}
	case sshv1.CapabilityRemoteForward:
		allow := defaults.RemoteForwardBinds
		if policy.RemoteForward != nil && len(policy.RemoteForward.AllowBinds) > 0 {
			allow = policy.RemoteForward.AllowBinds
		}
		if len(allow) > 0 {
			bind := net.JoinHostPort(firstExtra(attrs.Extra, "bind_host"), firstExtra(attrs.Extra, "bind_port"))
			if !bindAllowed(allow, bind) {
				return false, "remote forward bind not allowed"
			}
		}
	}
	return true, ""
}

func containsCapability(values []sshv1.Capability, capability sshv1.Capability) bool {
	for _, value := range values {
		if value == capability {
			return true
		}
	}
	return false
}

func bindAllowed(patterns []string, bind string) bool {
	for _, pattern := range patterns {
		if pattern == bind || pattern == "*" || pattern == "*:*" {
			return true
		}
		patternHost, patternPort, err := net.SplitHostPort(pattern)
		if err != nil {
			continue
		}
		bindHost, bindPort, err := net.SplitHostPort(bind)
		if err != nil {
			continue
		}
		hostMatches := patternHost == "*" || patternHost == bindHost
		portMatches := patternPort == "*" || patternPort == bindPort
		if hostMatches && portMatches {
			return true
		}
	}
	return false
}

func resourceName(resources []authz.AttributeResource, resource string) string {
	for _, item := range resources {
		if item.Resource == resource {
			return item.Name
		}
	}
	return ""
}
