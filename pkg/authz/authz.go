package authz

import (
	"context"
	"fmt"

	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

// Decision is the result of an authorization check.
type Decision string

const (
	DecisionNoOpinion Decision = "NoOpinion"
	DecisionDeny      Decision = "Deny"
	DecisionAllow     Decision = "Allow"
)

// Capability is the type of SSH operation being requested.
// Each SSH channel or subsystem is authorized independently.
type Capability string

const (
	CapabilityShell         Capability = "shell"
	CapabilityExec          Capability = "exec"
	CapabilitySCP           Capability = "scp"
	CapabilitySFTP          Capability = "sftp"
	CapabilityLocalForward  Capability = "local_forward"
	CapabilityRemoteForward Capability = "remote_forward"
	CapabilityAgentForward  Capability = "agent_forward"
)

// ParseCapability validates a capability string.
func ParseCapability(value string) (Capability, error) {
	capability := Capability(value)
	switch capability {
	case CapabilityShell, CapabilityExec, CapabilitySCP, CapabilitySFTP, CapabilityLocalForward, CapabilityRemoteForward, CapabilityAgentForward:
		return capability, nil
	default:
		return "", fmt.Errorf("unknown capability %q", value)
	}
}

// AttributeResource identifies a resource participating in an authorization
// check. It is intentionally generic so authorizers can model Kubernetes
// resources, target options, hosts, ports, or future backend resources.
type AttributeResource struct {
	Resource string `json:"resource,omitempty"`
	Name     string `json:"name,omitempty"`
}

// Attributes describe the SSH operation being authorized.
//
// Action is normally one of the Capability values. Resources and Path describe
// the resolved target and operation-specific resource, while Extra carries
// protocol details such as forwarded host/port. Implementations should treat
// this as an authorization input, not as an authentication credential.
type Attributes struct {
	Action    string              `json:"action,omitempty"`
	Resources []AttributeResource `json:"resources,omitempty"`
	Path      string              `json:"path,omitempty"`
	Extra     map[string][]string `json:"extra,omitempty"`
}

// Request is the complete authorization input for one SSH operation.
type Request struct {
	User       authn.UserInfo      `json:"user,omitempty"`
	AuthMethod string              `json:"authMethod,omitempty"`
	AuthExtra  map[string][]string `json:"authExtra,omitempty"`
	Attributes Attributes          `json:"attributes,omitempty"`
}

// Authorizer evaluates whether an authenticated user may perform one operation.
//
// The target has already been resolved before Authorize is called. Authorizers
// should return DecisionNoOpinion when they cannot decide, DecisionAllow to
// permit the operation, or DecisionDeny to reject it. The reason is user-visible
// on denied operations and should be concise.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (Decision, string, error)
}

type AuthorizerFunc func(ctx context.Context, req Request) (Decision, string, error)

func (f AuthorizerFunc) Authorize(ctx context.Context, req Request) (Decision, string, error) {
	return f(ctx, req)
}

type Chain []Authorizer

func (c Chain) Authorize(ctx context.Context, req Request) (Decision, string, error) {
	for _, authorizer := range c {
		if authorizer == nil {
			continue
		}
		decision, reason, err := authorizer.Authorize(ctx, req)
		if err != nil {
			return decision, reason, err
		}
		if decision == DecisionAllow || decision == DecisionDeny {
			return decision, reason, nil
		}
	}
	return DecisionNoOpinion, "", nil
}
