package accesspolicy

import (
	"context"
	"testing"
	"time"

	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
)

func TestAuthorizerCapabilities(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Credentials[0].Capabilities = sshv1.CapabilityPolicy{
		Allow: []sshv1.Capability{sshv1.CapabilityShell, sshv1.CapabilityLocalForward, sshv1.CapabilityRemoteForward, sshv1.CapabilityAgentForward},
		LocalForward: &sshv1.LocalForwardPolicy{
			AllowDestinations: []string{"*:8080"},
		},
		RemoteForward: &sshv1.RemoteForwardPolicy{
			AllowBinds: []string{"127.0.0.1:*"},
		},
	}
	authorizer := NewAuthorizer(NewMemoryStore(access))
	req := authz.Request{
		AuthExtra: authExtra(&CredentialMatch{Access: access, Credential: &access.Spec.Credentials[0]}, CredentialTypePassword),
		Attributes: authz.Attributes{
			Action: string(authz.CapabilityLocalForward),
			Extra:  map[string][]string{"destination_port": {"8080"}},
		},
	}

	decision, reason, err := authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionAllow {
		t.Fatalf("decision = %q, reason = %q", decision, reason)
	}
	req.Attributes.Extra["destination_port"] = []string{"9090"}
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
	req.Attributes = authz.Attributes{
		Action: string(authz.CapabilityRemoteForward),
		Extra:  map[string][]string{"bind_host": {"127.0.0.1"}, "bind_port": {"2222"}},
	}
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionAllow {
		t.Fatalf("decision = %q, want Allow", decision)
	}
	req.Attributes = authz.Attributes{Action: string(authz.CapabilityAgentForward)}
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionAllow {
		t.Fatalf("decision = %q, want Allow", decision)
	}
	req.Attributes.Action = string(authz.CapabilityExec)
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
}

func TestAuthorizerEmptyCapabilitiesInheritDefaults(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	authorizer := NewAuthorizer(NewMemoryStore(access), CapabilityDefaults{Allow: []sshv1.Capability{sshv1.CapabilityExec}})
	req := authz.Request{
		AuthExtra:  authExtra(&CredentialMatch{Access: access, Credential: &access.Spec.Credentials[0]}, CredentialTypePassword),
		Attributes: authz.Attributes{Action: string(authz.CapabilityExec)},
	}
	decision, _, err := authorizer.Authorize(context.Background(), req)
	if err != nil || decision != authz.DecisionAllow {
		t.Fatalf("exec decision = %q, err = %v, want Allow", decision, err)
	}
	req.Attributes.Action = string(authz.CapabilitySFTP)
	decision, _, err = authorizer.Authorize(context.Background(), req)
	if err != nil || decision != authz.DecisionDeny {
		t.Fatalf("sftp decision = %q, err = %v, want Deny", decision, err)
	}
}

func TestAuthorizerNoOpinionWithoutAccessContext(t *testing.T) {
	decision, _, err := NewAuthorizer(NewMemoryStore()).
		Authorize(context.Background(), authz.Request{})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionNoOpinion {
		t.Fatalf("decision = %q, want NoOpinion", decision)
	}
}
