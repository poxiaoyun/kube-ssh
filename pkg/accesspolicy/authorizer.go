package accesspolicy

import (
	"context"
	"fmt"
	"net"
	"strconv"

	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
)

type Authorizer struct {
	store Store
}

func NewAuthorizer(store Store) *Authorizer {
	return &Authorizer{store: store}
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
	if allowed, reason := capabilityAllowed(credential.Capabilities, req.Attributes); !allowed {
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

func capabilityAllowed(policy sshv1.CapabilityPolicy, attrs authz.Attributes) (bool, string) {
	capability := sshv1.Capability(attrs.Action)
	if len(policy.Allow) > 0 && !containsCapability(policy.Allow, capability) {
		return false, "capability not allowed"
	}
	switch capability {
	case sshv1.CapabilityLocalForward:
		if policy.LocalForward != nil && len(policy.LocalForward.AllowPorts) > 0 {
			port, err := strconv.ParseInt(firstExtra(attrs.Extra, "destination_port"), 10, 32)
			if err != nil || !containsPort(policy.LocalForward.AllowPorts, int32(port)) {
				return false, "local forward port not allowed"
			}
		}
	case sshv1.CapabilityRemoteForward:
		if policy.RemoteForward != nil && len(policy.RemoteForward.AllowBinds) > 0 {
			bind := net.JoinHostPort(firstExtra(attrs.Extra, "bind_host"), firstExtra(attrs.Extra, "bind_port"))
			if !bindAllowed(policy.RemoteForward.AllowBinds, bind) {
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

func containsPort(values []int32, port int32) bool {
	for _, value := range values {
		if value == port {
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
