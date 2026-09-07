package accesspolicy

import (
	"context"
	"errors"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func WithAuthenticatorMetrics(next authn.SSHAuthenticator, recorder metrics.AccessPolicyRecorder) authn.SSHAuthenticator {
	if recorder == nil {
		recorder = metrics.NopRecorder{}
	}
	return &metricsAuthenticator{next: next, recorder: recorder}
}

func WithResolverMetrics(next target.Resolver, recorder metrics.AccessPolicyRecorder) target.Resolver {
	if recorder == nil {
		recorder = metrics.NopRecorder{}
	}
	return &metricsResolver{next: next, recorder: recorder}
}

func WithAuthorizerMetrics(next authz.Authorizer, recorder metrics.AccessPolicyRecorder) authz.Authorizer {
	if recorder == nil {
		recorder = metrics.NopRecorder{}
	}
	return &metricsAuthorizer{next: next, recorder: recorder}
}

type metricsAuthenticator struct {
	next     authn.SSHAuthenticator
	recorder metrics.AccessPolicyRecorder
}

func (a *metricsAuthenticator) AuthenticateBasic(ctx context.Context, username, password string) (*authn.AuthenticateInfo, error) {
	start := time.Now()
	info, err := a.next.AuthenticateBasic(ctx, username, password)
	a.recorder.AccessPolicyAuthFinished(metrics.CredentialPassword, authResult(err), time.Since(start))
	return info, err
}

func (a *metricsAuthenticator) AuthenticatePublicKey(ctx context.Context, sshUser string, pubkey cryptossh.PublicKey) (*authn.AuthenticateInfo, error) {
	start := time.Now()
	info, err := a.next.AuthenticatePublicKey(ctx, sshUser, pubkey)
	a.recorder.AccessPolicyAuthFinished(metrics.CredentialPublicKey, authResult(err), time.Since(start))
	return info, err
}

type metricsResolver struct {
	next     target.Resolver
	recorder metrics.AccessPolicyRecorder
}

func (r *metricsResolver) Resolve(ctx context.Context, input target.ResolveInput) (*target.Target, error) {
	start := time.Now()
	tgt, err := r.next.Resolve(ctx, input)
	r.recorder.AccessPolicyResolveFinished(resolveResult(err), time.Since(start))
	return tgt, err
}

type metricsAuthorizer struct {
	next     authz.Authorizer
	recorder metrics.AccessPolicyRecorder
}

func (a *metricsAuthorizer) Authorize(ctx context.Context, req authz.Request) (authz.Decision, string, error) {
	start := time.Now()
	decision, reason, err := a.next.Authorize(ctx, req)
	a.recorder.AccessPolicyAuthorizeFinished(req.Attributes.Action, string(decision), authorizeResult(decision, err), time.Since(start))
	return decision, reason, err
}

func authResult(err error) string {
	if err != nil {
		if errors.Is(err, authn.ErrNotProvided) {
			return metrics.ResultNotProvided
		}
		return metrics.ResultError
	}
	return metrics.ResultSuccess
}

func resolveResult(err error) string {
	if err != nil {
		if errors.Is(err, target.ErrNotProvided) {
			return metrics.ResultNotProvided
		}
		return metrics.ResultError
	}
	return metrics.ResultSuccess
}

func authorizeResult(decision authz.Decision, err error) string {
	if err != nil {
		return metrics.ResultError
	}
	switch decision {
	case authz.DecisionAllow:
		return metrics.ResultSuccess
	case authz.DecisionDeny:
		return metrics.ResultDenied
	case authz.DecisionNoOpinion:
		return metrics.ResultNotProvided
	default:
		return metrics.ResultUnknown
	}
}
