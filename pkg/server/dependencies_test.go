package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
)

func TestDependenciesValidate(t *testing.T) {
	if err := (Dependencies{}).Validate(); err == nil {
		t.Fatalf("Validate() error = nil, want error")
	}
}

func TestParseCapabilities(t *testing.T) {
	capabilities, err := parseCapabilities([]string{"exec", "sftp"})
	if err != nil {
		t.Fatalf("parseCapabilities() error = %v", err)
	}
	want := []authz.Capability{authz.CapabilityExec, authz.CapabilitySFTP}
	if len(capabilities) != len(want) {
		t.Fatalf("capabilities = %v, want %v", capabilities, want)
	}
	for i := range want {
		if capabilities[i] != want[i] {
			t.Fatalf("capabilities = %v, want %v", capabilities, want)
		}
	}

	if _, err := parseCapabilities([]string{"bad"}); err == nil {
		t.Fatal("parseCapabilities() error = nil, want error")
	}
}

func TestValidatePolicyOptions(t *testing.T) {
	opts := NewDefaultOptions()
	if err := validatePolicyOptions(opts); err != nil {
		t.Fatalf("validatePolicyOptions() error = %v", err)
	}
	opts.Policy.Limits.ContainerMode = "invalid"
	if err := validatePolicyOptions(opts); err == nil {
		t.Fatal("validatePolicyOptions() error = nil for invalid container mode")
	}
	opts = NewDefaultOptions()
	opts.Policy.Limits.RemoteForwardBinds = []string{"bad"}
	if err := validatePolicyOptions(opts); err == nil {
		t.Fatal("validatePolicyOptions() error = nil for invalid bind")
	}
	opts = NewDefaultOptions()
	opts.GatewayClassName = "Invalid Class"
	if err := validatePolicyOptions(opts); err == nil {
		t.Fatal("validatePolicyOptions() error = nil for invalid gateway class")
	}
	opts = NewDefaultOptions()
	opts.AdvertiseAddresses = []string{"ssh.example.com"}
	if err := validatePolicyOptions(opts); err == nil {
		t.Fatal("validatePolicyOptions() error = nil for advertise address without port")
	}
}

func TestAdvertisedAccessEndpoints(t *testing.T) {
	got, err := advertisedAccessEndpoints([]string{
		" ssh.example.com:2222 ",
		"ssh.example.com:2222",
		"[2001:db8::1]:22",
	})
	if err != nil {
		t.Fatalf("advertisedAccessEndpoints() error = %v", err)
	}
	if len(got) != 2 || got[0].Address != "ssh.example.com:2222" || got[1].Address != "[2001:db8::1]:22" {
		t.Fatalf("endpoints = %#v", got)
	}
}

func TestBuildAuthorizerStaticPolicyOverridesAllowAll(t *testing.T) {
	opts := NewDefaultOptions()
	opts.Policy.Limits.Capabilities = []string{"exec"}

	authorizer, err := buildAuthorizer(opts, nil, nil)
	if err != nil {
		t.Fatalf("buildAuthorizer() error = %v", err)
	}
	decision, _, err := authorizer.Authorize(context.Background(), testAuthzRequest(authz.Attributes{Action: string(authz.CapabilitySFTP)}))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
}

func TestBuildAuthorizerStaticPolicyAllowsConfiguredCapabilitiesWithoutSAR(t *testing.T) {
	opts := NewDefaultOptions()
	opts.Policy.Limits.Capabilities = []string{"exec"}

	authorizer, err := buildAuthorizer(opts, nil, nil)
	if err != nil {
		t.Fatalf("buildAuthorizer() error = %v", err)
	}
	decision, _, err := authorizer.Authorize(context.Background(), testAuthzRequest(authz.Attributes{Action: string(authz.CapabilityExec)}))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionAllow {
		t.Fatalf("decision = %q, want Allow", decision)
	}
	decision, _, err = authorizer.Authorize(context.Background(), testAuthzRequest(authz.Attributes{Action: string(authz.CapabilitySFTP)}))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
}

func TestBuildAuthorizerKubernetesSARDoesNotFallThroughToAllowAll(t *testing.T) {
	opts := NewDefaultOptions()
	opts.Authorization.KubernetesSAR = true

	authorizer, err := buildAuthorizer(opts, fake.NewSimpleClientset(), nil)
	if err != nil {
		t.Fatalf("buildAuthorizer() error = %v", err)
	}
	decision, reason, err := authorizer.Authorize(context.Background(), testAuthzRequest(authz.Attributes{
		Action: string(authz.CapabilityExec),
		Resources: []authz.AttributeResource{
			{Resource: "targets", Name: "other"},
		},
	}))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionNoOpinion {
		t.Fatalf("decision = %q, want NoOpinion, reason %q", decision, reason)
	}
}

func TestBuildAuthenticatorWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(authn.WebhookAuthenticateResponse{
			Authenticated: true,
			User:          authn.UserInfo{Name: "alice"},
			Method:        "webhook",
		})
	}))
	defer server.Close()

	opts := NewDefaultOptions()
	opts.Authentication.Webhook.Server = server.URL

	authenticator, err := buildAuthenticator(opts, nil)
	if err != nil {
		t.Fatalf("buildAuthenticator() error = %v", err)
	}
	info, err := authenticator.AuthenticateBasic(context.Background(), "default.nginx", "secret")
	if err != nil {
		t.Fatalf("AuthenticateBasic() error = %v", err)
	}
	if info.User.Name != "alice" {
		t.Fatalf("user = %#v", info.User)
	}
}

func TestBuildAuthorizerWebhookDoesNotFallThroughToAllowAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(authz.WebhookAuthorizeResponse{Decision: authz.DecisionNoOpinion})
	}))
	defer server.Close()

	opts := NewDefaultOptions()
	opts.Authorization.Webhook.Server = server.URL

	authorizer, err := buildAuthorizer(opts, fake.NewSimpleClientset(), nil)
	if err != nil {
		t.Fatalf("buildAuthorizer() error = %v", err)
	}
	decision, reason, err := authorizer.Authorize(context.Background(), testAuthzRequest(authz.Attributes{Action: string(authz.CapabilityExec)}))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionNoOpinion {
		t.Fatalf("decision = %q, want NoOpinion, reason %q", decision, reason)
	}
}

func testUserInfo() authn.UserInfo {
	return authn.UserInfo{Name: "alice"}
}

func testAuthzRequest(attrs authz.Attributes) authz.Request {
	return authz.Request{User: testUserInfo(), Attributes: attrs}
}
