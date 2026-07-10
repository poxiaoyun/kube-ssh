package authz

import (
	"context"
	"errors"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

func TestKubernetesSARAuthorizerMapsCapabilities(t *testing.T) {
	tests := []struct {
		name            string
		capability      Capability
		extra           map[string][]string
		wantSubresource string
	}{
		{name: "shell", capability: CapabilityShell, wantSubresource: kubernetesSubresourceExec},
		{name: "exec", capability: CapabilityExec, wantSubresource: kubernetesSubresourceExec},
		{name: "sftp", capability: CapabilitySFTP, wantSubresource: kubernetesSubresourceExec},
		{name: "scp", capability: CapabilitySCP, wantSubresource: kubernetesSubresourceExec},
		{name: "remote forward", capability: CapabilityRemoteForward, wantSubresource: kubernetesSubresourceExec},
		{
			name:            "local forward pod local",
			capability:      CapabilityLocalForward,
			extra:           map[string][]string{"destination_host": {"127.0.0.1"}},
			wantSubresource: kubernetesSubresourcePortForward,
		},
		{
			name:            "local forward helper dial",
			capability:      CapabilityLocalForward,
			extra:           map[string][]string{"destination_host": {"echo.default.svc.cluster.local"}},
			wantSubresource: kubernetesSubresourceExec,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			var got *authorizationv1.SubjectAccessReview
			client.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				create := action.(k8stesting.CreateAction)
				got = create.GetObject().(*authorizationv1.SubjectAccessReview)
				return true, &authorizationv1.SubjectAccessReview{
					ObjectMeta: metav1.ObjectMeta{Name: got.Name},
					Status:     authorizationv1.SubjectAccessReviewStatus{Allowed: true},
				}, nil
			})

			decision, reason, err := NewKubernetesSARAuthorizer(client).Authorize(context.Background(), kubeSARRequest(testSARUser(), kubeSARAttrs(tt.capability, tt.extra)))
			if err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}
			if decision != DecisionAllow {
				t.Fatalf("decision = %q, want Allow, reason %q", decision, reason)
			}
			if got == nil || got.Spec.ResourceAttributes == nil {
				t.Fatal("SAR request was not captured")
			}
			attrs := got.Spec.ResourceAttributes
			if got.Spec.User != "alice@example.com" {
				t.Fatalf("SAR user = %q, want alice@example.com", got.Spec.User)
			}
			if len(got.Spec.Groups) != 1 || got.Spec.Groups[0] != "dev" {
				t.Fatalf("SAR groups = %#v, want [dev]", got.Spec.Groups)
			}
			if attrs.Namespace != "default" || attrs.Name != "nginx" || attrs.Verb != "create" || attrs.Resource != "pods" {
				t.Fatalf("SAR resource attrs = %#v", attrs)
			}
			if attrs.Subresource != tt.wantSubresource {
				t.Fatalf("SAR subresource = %q, want %q", attrs.Subresource, tt.wantSubresource)
			}
		})
	}
}

func TestKubernetesSARAuthorizerNoOpinionForNonKubeTarget(t *testing.T) {
	client := fake.NewSimpleClientset()
	decision, reason, err := NewKubernetesSARAuthorizer(client).Authorize(context.Background(), kubeSARRequest(testSARUser(), Attributes{
		Action: string(CapabilityExec),
		Resources: []AttributeResource{
			{Resource: "targets", Name: "other"},
		},
	}))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionNoOpinion {
		t.Fatalf("decision = %q, want NoOpinion", decision)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if len(client.Actions()) != 0 {
		t.Fatalf("actions = %#v, want none", client.Actions())
	}
}

func TestKubernetesSARAuthorizerNoOpinionForUnknownCapability(t *testing.T) {
	client := fake.NewSimpleClientset()
	decision, reason, err := NewKubernetesSARAuthorizer(client).Authorize(context.Background(), kubeSARRequest(testSARUser(), kubeSARAttrs(Capability("unknown"), nil)))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionNoOpinion {
		t.Fatalf("decision = %q, want NoOpinion", decision)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if len(client.Actions()) != 0 {
		t.Fatalf("actions = %#v, want none", client.Actions())
	}
}

func TestKubernetesSARAuthorizerDenyReason(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{
				Denied: true,
				Reason: "rbac denied",
			},
		}, nil
	})

	decision, reason, err := NewKubernetesSARAuthorizer(client).Authorize(context.Background(), kubeSARRequest(testSARUser(), kubeSARAttrs(CapabilityExec, nil)))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision != DecisionDeny {
		t.Fatalf("decision = %q, want Deny", decision)
	}
	if reason != "rbac denied" {
		t.Fatalf("reason = %q, want rbac denied", reason)
	}
}

func TestKubernetesSARAuthorizerReturnsCreateError(t *testing.T) {
	wantErr := errors.New("apiserver unavailable")
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, wantErr
	})

	_, _, err := NewKubernetesSARAuthorizer(client).Authorize(context.Background(), kubeSARRequest(testSARUser(), kubeSARAttrs(CapabilityExec, nil)))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Authorize() error = %v, want %v", err, wantErr)
	}
}

func TestKubernetesSARAuthorizerRequiresUser(t *testing.T) {
	decision, reason, err := NewKubernetesSARAuthorizer(fake.NewSimpleClientset()).Authorize(context.Background(), kubeSARRequest(authn.UserInfo{}, kubeSARAttrs(CapabilityExec, nil)))
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

func testSARUser() authn.UserInfo {
	return authn.UserInfo{Name: "alice@example.com", Groups: []string{"dev"}}
}

func kubeSARAttrs(capability Capability, extra map[string][]string) Attributes {
	return Attributes{
		Action: string(capability),
		Resources: []AttributeResource{
			{Resource: "targets", Name: kubernetesTargetKind},
			{Resource: kubernetesNamespaces, Name: "default"},
			{Resource: kubernetesPods, Name: "nginx"},
			{Resource: "containers", Name: "app"},
		},
		Extra: extra,
	}
}

func kubeSARRequest(user authn.UserInfo, attrs Attributes) Request {
	return Request{User: user, Attributes: attrs}
}
