package authz

import (
	"context"
	"fmt"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	kubernetesTargetKind = "kube"
	kubernetesNamespaces = "namespaces"
	kubernetesPods       = "pods"

	kubernetesVerbCreate             = "create"
	kubernetesResourcePods           = "pods"
	kubernetesSubresourceExec        = "exec"
	kubernetesSubresourcePortForward = "portforward"
)

// KubernetesSARAuthorizer checks whether the authenticated user has Kubernetes
// RBAC permission for the Kubernetes operation that backs the SSH capability.
//
// It only handles kube targets and capabilities that map to Kubernetes
// subresources. Other targets or capabilities return DecisionNoOpinion so
// another authorizer in the chain can decide.
type KubernetesSARAuthorizer struct {
	client kubernetes.Interface
}

func NewKubernetesSARAuthorizer(client kubernetes.Interface) *KubernetesSARAuthorizer {
	return &KubernetesSARAuthorizer{client: client}
}

func (a *KubernetesSARAuthorizer) Authorize(ctx context.Context, req Request) (Decision, string, error) {
	if a == nil || a.client == nil {
		return DecisionNoOpinion, "", fmt.Errorf("kubernetes SAR authorizer requires a client")
	}
	user := req.User
	attrs := req.Attributes
	if resourceValue(attrs.Resources, "targets") != kubernetesTargetKind {
		return DecisionNoOpinion, "", nil
	}

	subresource, ok := kubernetesSARSubresource(attrs)
	if !ok {
		return DecisionNoOpinion, "", nil
	}

	namespace := resourceValue(attrs.Resources, kubernetesNamespaces)
	pod := resourceValue(attrs.Resources, kubernetesPods)
	if namespace == "" || pod == "" {
		return DecisionDeny, "kubernetes target requires namespace and pod", fmt.Errorf("kubernetes SAR requires namespace and pod")
	}
	if user.Name == "" {
		return DecisionDeny, "kubernetes user is required", nil
	}

	sar, err := a.client.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   user.Name,
			Groups: user.Groups,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace:   namespace,
				Verb:        kubernetesVerbCreate,
				Group:       "",
				Resource:    kubernetesResourcePods,
				Subresource: subresource,
				Name:        pod,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return DecisionNoOpinion, "", err
	}
	if sar.Status.Allowed {
		return DecisionAllow, "", nil
	}
	reason := sar.Status.Reason
	if reason == "" {
		reason = sar.Status.EvaluationError
	}
	if reason == "" {
		reason = "kubernetes rbac denied"
	}
	return DecisionDeny, reason, nil
}

func kubernetesSARSubresource(attrs Attributes) (string, bool) {
	switch Capability(attrs.Action) {
	case CapabilityShell, CapabilityExec, CapabilitySFTP, CapabilitySCP, CapabilityRemoteForward:
		return kubernetesSubresourceExec, true
	case CapabilityLocalForward:
		if isKubernetesPodLocalForwardHost(extraValue(attrs.Extra, "destination_host")) {
			return kubernetesSubresourcePortForward, true
		}
		return kubernetesSubresourceExec, true
	default:
		return "", false
	}
}

func isKubernetesPodLocalForwardHost(host string) bool {
	switch strings.ToLower(host) {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func resourceValue(resources []AttributeResource, resource string) string {
	for _, item := range resources {
		if item.Resource == resource {
			return item.Name
		}
	}
	return ""
}

func extraValue(extra map[string][]string, key string) string {
	values := extra[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
