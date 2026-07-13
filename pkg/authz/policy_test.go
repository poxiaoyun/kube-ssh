package authz

import (
	"context"
	"testing"
)

func TestPolicyLimitsDenyCapabilityAndForwardDestination(t *testing.T) {
	policy := PolicyLimits{
		Capabilities:             []Capability{CapabilityExec, CapabilityLocalForward},
		LocalForwardDestinations: []string{"127.0.0.1:8080"},
		RemoteForwardBinds:       []string{"*"},
	}
	decision, _, _ := policy.Authorize(context.Background(), Request{Attributes: Attributes{Action: string(CapabilitySFTP)}})
	if decision != DecisionDeny {
		t.Fatalf("SFTP decision = %q, want Deny", decision)
	}
	decision, _, _ = policy.Authorize(context.Background(), Request{Attributes: Attributes{
		Action: string(CapabilityLocalForward),
		Extra:  map[string][]string{"destination_host": {"127.0.0.1"}, "destination_port": {"9090"}},
	}})
	if decision != DecisionDeny {
		t.Fatalf("local forward decision = %q, want Deny", decision)
	}
}

func TestPolicyDefaultsSkipAccessIdentity(t *testing.T) {
	policy := PolicyLimits{Capabilities: []Capability{}, SkipAccess: true}
	decision, _, _ := policy.Authorize(context.Background(), Request{AuthExtra: map[string][]string{"kube-ssh/access.name": {"notebook"}}})
	if decision != DecisionNoOpinion {
		t.Fatalf("decision = %q, want NoOpinion", decision)
	}
}
