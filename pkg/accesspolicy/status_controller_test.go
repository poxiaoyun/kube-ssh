package accesspolicy

import (
	"context"
	"reflect"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
)

func TestAccessStatusControllerReportsReadyTarget(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "access", Key: "passwords"}},
	}, time.Unix(10, 0))
	secret := secretFixture("default", "access", map[string]string{"passwords": "token"})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, []*corev1.Secret{secret})
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"},
		},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionTrue {
		t.Fatalf("Valid condition = %s, want True", got)
	}
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %s, want True", got)
	}
}

func TestAccessStatusControllerReportsConfiguredExternalEndpointReady(t *testing.T) {
	hostKey := string(cryptossh.MarshalAuthorizedKey(testPublicKey(t)))
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Type = sshv1.AccessTypeExternal
	access.Spec.Selector = nil
	access.Spec.Endpoints = []sshv1.AccessEndpoint{{
		Name:       "main",
		Address:    "notebook-ssh.default.svc",
		Port:       22,
		Username:   "jovyan",
		Passwords:  []string{"upstream-secret"},
		PublicKeys: []string{hostKey},
	}}
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	controller := NewAccessStatusController(policyCache, nil, policyCache.secretIndexer, nil, AccessStatusControllerOptions{})

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionTrue {
		t.Fatalf("Valid condition = %s, want True", got)
	}
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %s, want True", got)
	}
	if got := conditionReason(status.Conditions, sshv1.AccessConditionReady); got != "EndpointsConfigured" {
		t.Fatalf("Ready reason = %q, want EndpointsConfigured", got)
	}
}

func TestAccessStatusControllerReportsActiveUnreadyTarget(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	pod := readyPod("notebook-a", map[string]string{"app": "notebook"})
	pod.Status.Conditions = nil
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, pod),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"},
		},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %s, want True", got)
	}
}

func TestAccessStatusControllerPublishesGatewayEndpoints(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	advertised := []sshv1.AccessStatusEndpoint{
		{Address: "ssh-a.example.com:2222"},
		{Address: "ssh-b.example.com:2222"},
	}
	want := []sshv1.AccessStatusEndpoint{
		{Address: "ssh-a.example.com:2222", Username: "default.notebook"},
		{Address: "ssh-b.example.com:2222", Username: "default.notebook"},
	}
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy:    ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"},
			Endpoints: advertised,
		},
	)

	status := controller.statusFor(context.Background(), access)
	if !reflect.DeepEqual(status.Endpoints, want) {
		t.Fatalf("Endpoints = %#v, want %#v", status.Endpoints, want)
	}
}

func TestAccessStatusControllerReportsMissingSecret(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "missing", Key: "passwords"}},
	}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"},
		},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionFalse {
		t.Fatalf("Valid condition = %s, want False", got)
	}
	if got := conditionReason(status.Conditions, sshv1.AccessConditionValid); got != "SecretNotFound" {
		t.Fatalf("Valid reason = %q, want SecretNotFound", got)
	}
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionFalse {
		t.Fatalf("Ready condition = %s, want False", got)
	}
}

func TestAccessStatusControllerReportsDuplicateCredentialMaterial(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	access.Spec.Credentials = append(access.Spec.Credentials, sshv1.AccessCredential{
		Username:  "bob",
		Passwords: []string{"shared"},
	})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionFalse {
		t.Fatalf("Valid condition = %s, want False", got)
	}
	if got := conditionReason(status.Conditions, sshv1.AccessConditionValid); got != "DuplicateCredentialMaterial" {
		t.Fatalf("Valid reason = %q, want DuplicateCredentialMaterial", got)
	}
}

func TestAccessStatusControllerFindsDuplicateMaterialThroughSecretRef(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	access.Spec.Credentials = append(access.Spec.Credentials, sshv1.AccessCredential{
		Username:      "bob",
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "bob-auth", Key: "passwords"}},
	})
	secret := secretFixture("default", "bob-auth", map[string]string{"passwords": "shared"})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, []*corev1.Secret{secret})
	controller := NewAccessStatusController(policyCache, newTestInformerPodLister(t,
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
	), policyCache.secretIndexer, nil, AccessStatusControllerOptions{Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}})

	status := controller.statusFor(context.Background(), access)
	if got := conditionReason(status.Conditions, sshv1.AccessConditionValid); got != "DuplicateCredentialMaterial" {
		t.Fatalf("Valid reason = %q, want DuplicateCredentialMaterial", got)
	}
}

func TestAccessStatusControllerDeduplicatesMaterialWithinCredential(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{
		Passwords:     []string{"shared"},
		PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "alice-auth", Key: "passwords"}},
	}, time.Unix(10, 0))
	secret := secretFixture("default", "alice-auth", map[string]string{"passwords": "shared"})
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, []*corev1.Secret{secret})
	controller := NewAccessStatusController(policyCache, newTestInformerPodLister(t,
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
	), policyCache.secretIndexer, nil, AccessStatusControllerOptions{Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}})

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionTrue {
		t.Fatalf("Valid condition = %s, want True", got)
	}
}

func TestAccessStatusControllerAllowsMaterialSharedAcrossAccesses(t *testing.T) {
	first := accessFixture("default", "first", "alice", sshv1.AccessCredential{Passwords: []string{"shared"}}, time.Unix(10, 0))
	second := accessFixture("default", "second", "bob", sshv1.AccessCredential{Passwords: []string{"shared"}}, time.Unix(20, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{first, second}, nil)
	controller := NewAccessStatusController(policyCache, newTestInformerPodLister(t,
		readyPod("first-a", map[string]string{"app": "first"}),
		readyPod("second-a", map[string]string{"app": "second"}),
	), policyCache.secretIndexer, nil, AccessStatusControllerOptions{Policy: ContainerPolicy{DefaultMode: "KubernetesDefault", LimitMode: "All"}})

	for _, access := range []*sshv1.Access{first, second} {
		status := controller.statusFor(context.Background(), access)
		if got := conditionStatus(status.Conditions, sshv1.AccessConditionValid); got != metav1.ConditionTrue {
			t.Fatalf("Access %s Valid condition = %s, want True", access.Name, got)
		}
	}
}

func TestAccessStatusControllerAppliesGlobalContainerPolicy(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	policyCache := newTestPolicyCache(t, "", []*sshv1.Access{access}, nil)
	controller := NewAccessStatusController(
		policyCache,
		newTestInformerPodLister(t, readyPod("notebook-a", map[string]string{"app": "notebook"})),
		policyCache.secretIndexer,
		nil,
		AccessStatusControllerOptions{
			Policy: ContainerPolicy{DefaultMode: "None", LimitMode: "All"},
		},
	)

	status := controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionFalse {
		t.Fatalf("Ready condition = %s, want False", got)
	}
	if got := conditionReason(status.Conditions, sshv1.AccessConditionReady); got != "NoTargets" {
		t.Fatalf("Ready reason = %q, want NoTargets", got)
	}

	access.Spec.Containers = []string{"app"}
	status = controller.statusFor(context.Background(), access)
	if got := conditionStatus(status.Conditions, sshv1.AccessConditionReady); got != metav1.ConditionTrue {
		t.Fatalf("Ready condition with explicit container = %s, want True", got)
	}
}

func conditionStatus(conditions []metav1.Condition, conditionType string) metav1.ConditionStatus {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status
		}
	}
	return ""
}

func conditionReason(conditions []metav1.Condition, conditionType string) string {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Reason
		}
	}
	return ""
}
