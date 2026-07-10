package authz

import (
	"context"
	"errors"
	"testing"
)

var errAuthorize = errors.New("authorize failed")

func TestChainAuthorizeAllowsFirstTerminalDecision(t *testing.T) {
	called := false
	chain := Chain{
		AuthorizerFunc(func(context.Context, Request) (Decision, string, error) {
			return DecisionNoOpinion, "", nil
		}),
		AuthorizerFunc(func(context.Context, Request) (Decision, string, error) {
			return DecisionAllow, "allowed", nil
		}),
		AuthorizerFunc(func(context.Context, Request) (Decision, string, error) {
			called = true
			return DecisionDeny, "denied", nil
		}),
	}

	decision, reason, err := chain.Authorize(context.Background(), Request{})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionAllow {
		t.Fatalf("decision = %q, want %q", decision, DecisionAllow)
	}
	if reason != "allowed" {
		t.Fatalf("reason = %q, want allowed", reason)
	}
	if called {
		t.Fatalf("authorizer after allow was called")
	}
}

func TestChainAuthorizeDeniesFirstTerminalDecision(t *testing.T) {
	chain := Chain{
		AuthorizerFunc(func(context.Context, Request) (Decision, string, error) {
			return DecisionDeny, "denied", nil
		}),
		AllowAll{},
	}

	decision, reason, err := chain.Authorize(context.Background(), Request{})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionDeny {
		t.Fatalf("decision = %q, want %q", decision, DecisionDeny)
	}
	if reason != "denied" {
		t.Fatalf("reason = %q, want denied", reason)
	}
}

func TestChainAuthorizeNoOpinion(t *testing.T) {
	decision, reason, err := (Chain{}).Authorize(context.Background(), Request{})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionNoOpinion {
		t.Fatalf("decision = %q, want %q", decision, DecisionNoOpinion)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestChainAuthorizeReturnsError(t *testing.T) {
	chain := Chain{
		AuthorizerFunc(func(context.Context, Request) (Decision, string, error) {
			return DecisionNoOpinion, "broken", errAuthorize
		}),
	}

	decision, reason, err := chain.Authorize(context.Background(), Request{})
	if !errors.Is(err, errAuthorize) {
		t.Fatalf("Authorize() error = %v, want %v", err, errAuthorize)
	}
	if decision != DecisionNoOpinion {
		t.Fatalf("decision = %q, want %q", decision, DecisionNoOpinion)
	}
	if reason != "broken" {
		t.Fatalf("reason = %q, want broken", reason)
	}
}

func TestParseCapability(t *testing.T) {
	capability, err := ParseCapability("agent_forward")
	if err != nil {
		t.Fatalf("ParseCapability() error = %v", err)
	}
	if capability != CapabilityAgentForward {
		t.Fatalf("capability = %q, want agent_forward", capability)
	}
	if _, err := ParseCapability("unknown"); err == nil {
		t.Fatal("ParseCapability() error = nil, want error")
	}
}

func TestStaticCapabilitiesDenyWins(t *testing.T) {
	authorizer := StaticCapabilities{
		Allow: []Capability{CapabilityExec},
		Deny:  []Capability{CapabilityExec},
	}
	decision, reason, err := authorizer.Authorize(context.Background(), Request{Attributes: Attributes{Action: string(CapabilityExec)}})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
	if reason == "" {
		t.Fatal("reason is empty")
	}
}

func TestStaticCapabilitiesAllowListPassesWithNoOpinion(t *testing.T) {
	authorizer := StaticCapabilities{Allow: []Capability{CapabilityExec}}
	decision, _, err := authorizer.Authorize(context.Background(), Request{Attributes: Attributes{Action: string(CapabilityExec)}})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionNoOpinion {
		t.Fatalf("decision = %q, want NoOpinion", decision)
	}
	decision, _, err = authorizer.Authorize(context.Background(), Request{Attributes: Attributes{Action: string(CapabilitySFTP)}})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
}

func TestStaticCapabilitiesDenyListPassesRestWithNoOpinion(t *testing.T) {
	authorizer := StaticCapabilities{Deny: []Capability{CapabilitySFTP}}
	decision, _, err := authorizer.Authorize(context.Background(), Request{Attributes: Attributes{Action: string(CapabilityExec)}})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionNoOpinion {
		t.Fatalf("decision = %q, want NoOpinion", decision)
	}
}
