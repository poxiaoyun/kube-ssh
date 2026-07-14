package accesspolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestMetricsAuthenticatorRecordsNotProvided(t *testing.T) {
	recorder := &accessPolicyMetricsRecorder{}
	authenticator := WithAuthenticatorMetrics(accessPolicyTestAuthenticator{err: authn.ErrNotProvided}, recorder)

	if _, err := authenticator.AuthenticateBasic(context.Background(), "default.access", "bad"); !errors.Is(err, authn.ErrNotProvided) {
		t.Fatalf("AuthenticateBasic() error = %v, want ErrNotProvided", err)
	}
	if recorder.authCredential != metrics.CredentialPassword {
		t.Fatalf("credential = %q, want password", recorder.authCredential)
	}
	if recorder.authResult != metrics.ResultNotProvided {
		t.Fatalf("auth result = %q, want not_provided", recorder.authResult)
	}
}

func TestMetricsResolverRecordsSuccess(t *testing.T) {
	recorder := &accessPolicyMetricsRecorder{}
	resolver := WithResolverMetrics(accessPolicyTestResolver(func(context.Context, target.ResolveRequest) (*target.Target, error) {
		return &target.Target{Kind: "kube"}, nil
	}), recorder)

	if _, err := resolver.Resolve(context.Background(), target.ResolveRequest{}); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if recorder.resolveResult != metrics.ResultSuccess {
		t.Fatalf("resolve result = %q, want success", recorder.resolveResult)
	}
}

func TestMetricsAuthorizerRecordsDecision(t *testing.T) {
	recorder := &accessPolicyMetricsRecorder{}
	authorizer := WithAuthorizerMetrics(authz.AuthorizerFunc(func(context.Context, authz.Request) (authz.Decision, string, error) {
		return authz.DecisionDeny, "no", nil
	}), recorder)

	decision, _, err := authorizer.Authorize(context.Background(), authz.Request{
		Attributes: authz.Attributes{Action: string(authz.CapabilitySFTP)},
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != authz.DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
	if recorder.authorizeCapability != string(authz.CapabilitySFTP) {
		t.Fatalf("capability = %q, want sftp", recorder.authorizeCapability)
	}
	if recorder.authorizeDecision != string(authz.DecisionDeny) {
		t.Fatalf("decision metric = %q, want Deny", recorder.authorizeDecision)
	}
	if recorder.authorizeResult != metrics.ResultDenied {
		t.Fatalf("authorize result = %q, want denied", recorder.authorizeResult)
	}
}

type accessPolicyMetricsRecorder struct {
	metrics.NopRecorder

	authCredential string
	authResult     string

	resolveResult string

	authorizeCapability string
	authorizeDecision   string
	authorizeResult     string
}

func (r *accessPolicyMetricsRecorder) AccessPolicyAuthFinished(credential, result string, _ time.Duration) {
	r.authCredential = credential
	r.authResult = result
}

func (r *accessPolicyMetricsRecorder) AccessPolicyResolveFinished(result string, _ time.Duration) {
	r.resolveResult = result
}

func (r *accessPolicyMetricsRecorder) AccessPolicyAuthorizeFinished(capability, decision, result string, _ time.Duration) {
	r.authorizeCapability = capability
	r.authorizeDecision = decision
	r.authorizeResult = result
}

type accessPolicyTestAuthenticator struct {
	err error
}

func (a accessPolicyTestAuthenticator) AuthenticateBasic(context.Context, string, string) (*authn.AuthenticateInfo, error) {
	return nil, a.err
}

func (a accessPolicyTestAuthenticator) AuthenticatePublicKey(context.Context, string, cryptossh.PublicKey) (*authn.AuthenticateInfo, error) {
	return nil, a.err
}

type accessPolicyTestResolver func(context.Context, target.ResolveRequest) (*target.Target, error)

func (r accessPolicyTestResolver) Resolve(ctx context.Context, req target.ResolveRequest) (*target.Target, error) {
	return r(ctx, req)
}
