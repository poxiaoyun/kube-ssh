package authz

import (
	"context"
	"slices"
)

// AllowAll is an Authorizer that permits every request.
// Use only in development and testing.
type AllowAll struct{}

func (AllowAll) Authorize(_ context.Context, _ Request) (Decision, string, error) {
	return DecisionAllow, "", nil
}

// DenyAll is an Authorizer that rejects every request.
type DenyAll struct{}

func (DenyAll) Authorize(_ context.Context, _ Request) (Decision, string, error) {
	return DecisionDeny, "", nil
}

// StaticCapabilities filters operations by capability.
//
// It returns Deny when a capability is explicitly denied, or when an allow
// list exists and the capability is not included. A capability that passes the
// static policy returns NoOpinion so later authorizers, such as Kubernetes SAR
// or webhook-backed policies, can still make the final decision.
type StaticCapabilities struct {
	Allow []Capability
	Deny  []Capability
}

func (a StaticCapabilities) Authorize(_ context.Context, req Request) (Decision, string, error) {
	capability := Capability(req.Attributes.Action)
	if slices.Contains(a.Deny, capability) {
		return DecisionDeny, "capability denied", nil
	}
	if slices.Contains(a.Allow, capability) {
		return DecisionNoOpinion, "", nil
	}
	if len(a.Allow) == 0 {
		return DecisionNoOpinion, "", nil
	}
	return DecisionDeny, "capability not allowed", nil
}
