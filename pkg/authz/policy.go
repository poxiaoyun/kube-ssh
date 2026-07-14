package authz

import (
	"context"
	"net"
	"slices"

	"xiaoshiai.cn/kube-ssh/pkg/util/pattern"
)

// PolicyLimits is a non-bypassable guard around configured authorizers. A
// passing request returns NoOpinion so the configured first-decisive chain
// keeps its existing semantics.
type PolicyLimits struct {
	Capabilities             []Capability
	LocalForwardDestinations []string
	RemoteForwardBinds       []string
	SkipAccess               bool
}

func (p PolicyLimits) Authorize(_ context.Context, req Request) (Decision, string, error) {
	isAccess := len(req.AuthExtra["kube-ssh/access.name"]) > 0
	if p.SkipAccess && isAccess {
		return DecisionNoOpinion, "", nil
	}
	capability := Capability(req.Attributes.Action)
	if !containsOrWildcard(p.Capabilities, capability) {
		return DecisionDeny, "capability exceeds global policy limits", nil
	}
	switch capability {
	case CapabilityLocalForward:
		destination := net.JoinHostPort(extraValue(req.Attributes.Extra, "destination_host"), extraValue(req.Attributes.Extra, "destination_port"))
		if !expressionAllowed(p.LocalForwardDestinations, destination) {
			return DecisionDeny, "local forward destination exceeds global policy limits", nil
		}
	case CapabilityRemoteForward:
		bind := net.JoinHostPort(extraValue(req.Attributes.Extra, "bind_host"), extraValue(req.Attributes.Extra, "bind_port"))
		if !expressionAllowed(p.RemoteForwardBinds, bind) {
			return DecisionDeny, "remote forward bind exceeds global policy limits", nil
		}
	}
	return DecisionNoOpinion, "", nil
}

func containsOrWildcard(values []Capability, value Capability) bool {
	return slices.Contains(values, Capability("*")) || slices.Contains(values, value)
}

func expressionAllowed(patterns []string, value string) bool {
	return pattern.MatchAny(patterns, value)
}
