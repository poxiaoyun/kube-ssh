package authz

import (
	"context"
	"fmt"

	"xiaoshiai.cn/kube-ssh/pkg/authn"
	webhookclient "xiaoshiai.cn/kube-ssh/pkg/webhook"
)

type WebhookAuthorizer struct {
	client *webhookclient.Client
}

func NewWebhookAuthorizer(opts webhookclient.Options) (*WebhookAuthorizer, error) {
	client, err := webhookclient.NewClient(opts)
	if err != nil {
		return nil, err
	}
	return &WebhookAuthorizer{client: client}, nil
}

type WebhookAuthorizeRequest struct {
	User       authn.UserInfo `json:"user"`
	Attributes Attributes     `json:"attributes"`
}

type WebhookAuthorizeResponse struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func (a *WebhookAuthorizer) Authorize(ctx context.Context, req Request) (Decision, string, error) {
	resp := &WebhookAuthorizeResponse{}
	if err := a.client.Post(ctx, &WebhookAuthorizeRequest{User: req.User, Attributes: req.Attributes}, resp); err != nil {
		return DecisionNoOpinion, "", err
	}
	if resp.Error != "" {
		return DecisionNoOpinion, resp.Reason, fmt.Errorf("webhook authorization error: %s", resp.Error)
	}
	switch resp.Decision {
	case DecisionAllow, DecisionDeny, DecisionNoOpinion:
		return resp.Decision, resp.Reason, nil
	case "":
		return DecisionNoOpinion, resp.Reason, nil
	default:
		return DecisionNoOpinion, resp.Reason, fmt.Errorf("webhook returned invalid decision %q", resp.Decision)
	}
}
