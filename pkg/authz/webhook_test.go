package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"xiaoshiai.cn/kube-ssh/pkg/authn"
	webhookclient "xiaoshiai.cn/kube-ssh/pkg/webhook"
)

func TestWebhookAuthorizer(t *testing.T) {
	var got WebhookAuthorizeRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		_ = json.NewEncoder(w).Encode(WebhookAuthorizeResponse{
			Decision: DecisionAllow,
			Reason:   "ok",
		})
	}))
	defer server.Close()

	authorizer, err := NewWebhookAuthorizer(webhookclient.Options{Server: server.URL})
	if err != nil {
		t.Fatalf("NewWebhookAuthorizer() error = %v", err)
	}
	decision, reason, err := authorizer.Authorize(context.Background(), Request{
		User: authn.UserInfo{Name: "alice"},
		Attributes: Attributes{
			Action: string(CapabilityExec),
			Path:   "kube/namespaces/default/pods/nginx",
		},
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionAllow || reason != "ok" {
		t.Fatalf("decision = %q, reason = %q", decision, reason)
	}
	if got.User.Name != "alice" || got.Attributes.Action != string(CapabilityExec) {
		t.Fatalf("request = %#v", got)
	}
}

func TestWebhookAuthorizerInvalidDecision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(WebhookAuthorizeResponse{Decision: Decision("bad")})
	}))
	defer server.Close()

	authorizer, err := NewWebhookAuthorizer(webhookclient.Options{Server: server.URL})
	if err != nil {
		t.Fatalf("NewWebhookAuthorizer() error = %v", err)
	}
	if _, _, err := authorizer.Authorize(context.Background(), Request{User: authn.UserInfo{Name: "alice"}, Attributes: Attributes{Action: string(CapabilityExec)}}); err == nil {
		t.Fatal("Authorize() error = nil, want error")
	}
}
