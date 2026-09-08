//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
)

type TestWebhookServer struct {
	URL                    string
	Authenticate           func(authn.WebhookAuthenticateRequest) authn.WebhookAuthenticateResponse
	Authorize              func(authz.WebhookAuthorizeRequest) authz.WebhookAuthorizeResponse
	AuthenticationRequests []authn.WebhookAuthenticateRequest
	AuthorizationRequests  []authz.WebhookAuthorizeRequest
}

func (f *Framework) StartWebhookServer() *TestWebhookServer {
	f.T.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.T.Fatalf("listen webhook: %v", err)
	}
	webhook := &TestWebhookServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		req := authn.WebhookAuthenticateRequest{}
		if err := json.NewDecoder(r.Body).
			Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		webhook.AuthenticationRequests = append(webhook.AuthenticationRequests, req)
		resp := authn.WebhookAuthenticateResponse{Reason: "not configured"}
		if webhook.Authenticate != nil {
			resp = webhook.Authenticate(req)
		}
		_ = json.NewEncoder(w).
			Encode(resp)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		req := authz.WebhookAuthorizeRequest{}
		if err := json.NewDecoder(r.Body).
			Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		webhook.AuthorizationRequests = append(webhook.AuthorizationRequests, req)
		resp := authz.WebhookAuthorizeResponse{Decision: authz.DecisionNoOpinion}
		if webhook.Authorize != nil {
			resp = webhook.Authorize(req)
		}
		_ = json.NewEncoder(w).
			Encode(resp)
	})
	server := &http.Server{Handler: mux}
	webhook.URL = "http://" + listener.Addr().
		String()
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			f.T.Logf("webhook server error: %v", err)
		}
	}()
	f.T.Cleanup(func() {
		_ = server.Shutdown(context.Background())
	})
	return webhook
}
