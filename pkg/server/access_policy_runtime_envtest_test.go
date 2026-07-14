//go:build envtest

package server

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cryptossh "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/retry"
	"xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

var _ = Describe("Access policy runtime", func() {
	It("authenticates inline passwords from Access informer cache", func() {
		ns := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntime("")

		createEnvtestAccess(ns, "inline-password", "alice", v1.Credential{
			Passwords: []string{"inline-token"},
		})

		EventuallyBasicAuth(runtime, "inline-token").Should(SucceedWithUser("alice"))
	})

	It("authenticates password secret refs from Secret and Access informer caches", func() {
		ns := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntime("")

		createEnvtestSecret(ns, "access-secret", map[string]string{
			"passwords": "ignored\nsecret-token\n",
		})
		createEnvtestAccess(ns, "secret-password", "alice", v1.Credential{
			PasswordsFrom: []v1.LocalSecretKeyRef{{Name: "access-secret", Key: "passwords"}},
		})

		EventuallyBasicAuth(runtime, "secret-token").Should(SucceedWithUser("alice"))
	})

	It("requires a Secret key to be referenced by Access", func() {
		ns := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntime("")

		createEnvtestSecret(ns, "access-secret", map[string]string{
			"other": "unreferenced-token",
		})
		createEnvtestAccess(ns, "secret-password", "alice", v1.Credential{
			PasswordsFrom: []v1.LocalSecretKeyRef{{Name: "access-secret", Key: "passwords"}},
		})

		ConsistentlyBasicAuth(runtime, "unreferenced-token").Should(FailWithAuthError(authn.ErrNotProvided))
	})

	It("refreshes password matches when a Secret changes", func() {
		ns := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntime("")
		tokenA := ns + "-token-a"
		tokenB := ns + "-token-b"

		createEnvtestSecret(ns, "access-secret", map[string]string{
			"passwords": tokenA,
		})
		createEnvtestAccess(ns, "secret-password", "alice", v1.Credential{
			PasswordsFrom: []v1.LocalSecretKeyRef{{Name: "access-secret", Key: "passwords"}},
		})
		EventuallyBasicAuth(runtime, tokenA).Should(SucceedWithUser("alice"))

		updateEnvtestSecret(ns, "access-secret", map[string]string{
			"passwords": tokenB,
		})

		EventuallyBasicAuth(runtime, tokenA).Should(FailWithAuthError(authn.ErrNotProvided))
		EventuallyBasicAuth(runtime, tokenB).Should(SucceedWithUser("alice"))
	})

	It("refreshes password matches when an Access changes", func() {
		ns := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntime("")
		tokenA := ns + "-token-a"
		tokenB := ns + "-token-b"

		createEnvtestAccess(ns, "inline-password", "alice", v1.Credential{
			Passwords: []string{tokenA},
		})
		EventuallyBasicAuth(runtime, tokenA).Should(SucceedWithUser("alice"))

		updateEnvtestAccessCredential(ns, "inline-password", v1.Credential{
			Passwords: []string{tokenB},
		})

		EventuallyBasicAuth(runtime, tokenA).Should(FailWithAuthError(authn.ErrNotProvided))
		EventuallyBasicAuth(runtime, tokenB).Should(SucceedWithUser("alice"))
	})

	It("stops authenticating after an Access is deleted", func() {
		ns := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntime("")

		createEnvtestAccess(ns, "inline-password", "alice", v1.Credential{
			Passwords: []string{"deleted-access-token"},
		})
		EventuallyBasicAuth(runtime, "deleted-access-token").Should(SucceedWithUser("alice"))

		Expect(envtestAccessClient.SshV1().Accesses(ns).Delete(context.Background(), "inline-password", metav1.DeleteOptions{})).To(Succeed())
		EventuallyBasicAuth(runtime, "deleted-access-token").Should(FailWithAuthError(authn.ErrNotProvided))
	})

	It("stops authenticating after a referenced Secret is deleted", func() {
		ns := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntime("")

		createEnvtestSecret(ns, "access-secret", map[string]string{
			"passwords": "deleted-secret-token",
		})
		createEnvtestAccess(ns, "secret-password", "alice", v1.Credential{
			PasswordsFrom: []v1.LocalSecretKeyRef{{Name: "access-secret", Key: "passwords"}},
		})
		EventuallyBasicAuth(runtime, "deleted-secret-token").Should(SucceedWithUser("alice"))

		Expect(envtestKubeClient.CoreV1().Secrets(ns).Delete(context.Background(), "access-secret", metav1.DeleteOptions{})).To(Succeed())
		EventuallyBasicAuth(runtime, "deleted-secret-token").Should(FailWithAuthError(authn.ErrNotProvided))
	})

	It("honors configured namespace scope", func() {
		allowedNS := createEnvtestNamespace()
		otherNS := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntime(allowedNS)

		createEnvtestAccess(allowedNS, "inline-password", "alice", v1.Credential{
			Passwords: []string{"allowed-token"},
		})
		createEnvtestAccess(otherNS, "inline-password", "bob", v1.Credential{
			Passwords: []string{"other-token"},
		})

		EventuallyBasicAuth(runtime, "allowed-token").Should(SucceedWithUser("alice"))
		ConsistentlyBasicAuth(runtime, "other-token").Should(FailWithAuthError(authn.ErrNotProvided))
	})

	It("authenticates public key secret refs from informer caches", func() {
		ns := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntime("")
		pubkey := newEnvtestPublicKey()
		keyLine := string(cryptossh.MarshalAuthorizedKey(pubkey))

		createEnvtestSecret(ns, "access-secret", map[string]string{
			"keys": keyLine,
		})
		createEnvtestAccess(ns, "secret-key", "alice", v1.Credential{
			PublicKeysFrom: []v1.LocalSecretKeyRef{{Name: "access-secret", Key: "keys"}},
		})

		EventuallyPublicKeyAuth(runtime, pubkey).Should(SucceedWithUser("alice"))
	})

	It("updates Access status from informer caches", func() {
		ns := createEnvtestNamespace()
		startEnvtestAccessPolicyRuntime("")

		createEnvtestReadyPod(ns, "notebook-a", map[string]string{"app": "status-ready"})
		createEnvtestAccess(ns, "status-ready", "alice", v1.Credential{Passwords: []string{"status-token"}})

		Eventually(func(g Gomega) {
			access, err := envtestAccessClient.SshV1().Accesses(ns).Get(context.Background(), "status-ready", metav1.GetOptions{})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(envtestConditionStatus(access.Status.Conditions, v1.AccessConditionValid)).To(Equal(metav1.ConditionTrue))
			g.Expect(envtestConditionStatus(access.Status.Conditions, v1.AccessConditionReady)).To(Equal(metav1.ConditionTrue))
			g.Expect(access.Status.ObservedGeneration).To(Equal(access.Generation))
		}, 10*time.Second, 100*time.Millisecond).Should(Succeed())
	})

	It("isolates gateway classes and publishes the owning gateway endpoints", func() {
		ns := createEnvtestNamespace()
		runtime := startEnvtestAccessPolicyRuntimeForGateway(ns, "default-gateway", []string{
			"ssh-a.example.com:2222",
			"[2001:db8::1]:22",
		})

		createEnvtestReadyPod(ns, "public-access-pod", map[string]string{"app": "public-access"})
		className := "default-gateway"
		classed := envtestAccess(ns, "public-access", "alice", v1.Credential{Passwords: []string{"public-token"}})
		classed.Spec.GatewayClassName = &className
		_, err := envtestAccessClient.SshV1().Accesses(ns).Create(context.Background(), classed, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		createEnvtestAccess(ns, "classless-access", "bob", v1.Credential{Passwords: []string{"classless-token"}})

		EventuallyBasicAuth(runtime, "public-token").Should(SucceedWithUser("alice"))
		ConsistentlyBasicAuth(runtime, "classless-token").Should(FailWithAuthError(authn.ErrNotProvided))

		Eventually(func(g Gomega) {
			access, err := envtestAccessClient.SshV1().Accesses(ns).Get(context.Background(), "public-access", metav1.GetOptions{})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(access.Status.Endpoints).To(Equal([]v1.AccessStatusEndpoint{
				{Address: "ssh-a.example.com:2222", Username: ns + ".public-access"},
				{Address: "[2001:db8::1]:22", Username: ns + ".public-access"},
			}))
			g.Expect(envtestConditionStatus(access.Status.Conditions, v1.AccessConditionReady)).To(Equal(metav1.ConditionTrue))
		}, 10*time.Second, 100*time.Millisecond).Should(Succeed())

		Consistently(func(g Gomega) {
			access, err := envtestAccessClient.SshV1().Accesses(ns).Get(context.Background(), "classless-access", metav1.GetOptions{})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(access.Status.ObservedGeneration).To(BeZero())
			g.Expect(access.Status.Endpoints).To(BeEmpty())
		}, time.Second, 100*time.Millisecond).Should(Succeed())
	})
})

var _ = Describe("Access CRD schema", func() {
	It("rejects Pod Access objects without selectors", func() {
		ns := createEnvtestNamespace()
		access := &v1.Access{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      "missing-selector",
			},
			Spec: v1.AccessSpec{
				Type: v1.AccessTypePod,
				Credentials: []v1.AccessCredential{{
					Username: "alice",
					Credential: v1.Credential{
						Passwords: []string{"token"},
					},
				}},
			},
		}

		_, err := envtestAccessClient.SshV1().Accesses(ns).Create(context.Background(), access, metav1.CreateOptions{})
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
	})

	It("rejects mutually exclusive selectors and endpoints", func() {
		ns := createEnvtestNamespace()
		access := envtestAccess(ns, "mixed-targets", "alice", v1.Credential{Passwords: []string{"token"}})
		access.Spec.Endpoints = []v1.AccessEndpoint{{Address: "127.0.0.1"}}

		_, err := envtestAccessClient.SshV1().Accesses(ns).Create(context.Background(), access, metav1.CreateOptions{})
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
	})

	It("accepts session policy timeouts", func() {
		ns := createEnvtestNamespace()
		access := envtestAccess(ns, "session-timeouts", "alice", v1.Credential{Passwords: []string{"token"}})
		access.Spec.Session = &v1.SessionPolicy{
			IdleTimeout: &metav1.Duration{Duration: 30 * time.Minute},
			MaxDuration: &metav1.Duration{Duration: 8 * time.Hour},
		}

		created, err := envtestAccessClient.SshV1().Accesses(ns).Create(context.Background(), access, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(created.Spec.Session).NotTo(BeNil())
		Expect(created.Spec.Session.IdleTimeout.Duration).To(Equal(30 * time.Minute))
		Expect(created.Spec.Session.MaxDuration.Duration).To(Equal(8 * time.Hour))
	})

	It("rejects invalid gateway class names", func() {
		ns := createEnvtestNamespace()
		access := envtestAccess(ns, "invalid-class", "alice", v1.Credential{Passwords: []string{"token"}})
		className := "Invalid Class"
		access.Spec.GatewayClassName = &className

		_, err := envtestAccessClient.SshV1().Accesses(ns).Create(context.Background(), access, metav1.CreateOptions{})
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
	})

	It("accepts container and forwarding policies", func() {
		ns := createEnvtestNamespace()
		access := envtestAccess(ns, "container-policy", "alice", v1.Credential{Passwords: []string{"token"}})
		access.Spec.Containers = []string{"app", "sidecar"}
		access.Spec.Credentials[0].Containers = []string{"app"}
		access.Spec.Credentials[0].Capabilities = v1.CapabilityPolicy{
			LocalForward:  &v1.LocalForwardPolicy{AllowDestinations: []string{"127.0.0.1:8080", "*:8443"}},
			RemoteForward: &v1.RemoteForwardPolicy{AllowBinds: []string{"127.0.0.1:*"}},
		}

		created, err := envtestAccessClient.SshV1().Accesses(ns).Create(context.Background(), access, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(created.Spec.Containers).To(ConsistOf("app", "sidecar"))
		Expect(created.Spec.Credentials[0].Containers).To(Equal([]string{"app"}))
		Expect(created.Spec.Credentials[0].Capabilities.Allow).To(BeEmpty())
		Expect(created.Spec.Credentials[0].Capabilities.LocalForward.AllowDestinations).To(ConsistOf("127.0.0.1:8080", "*:8443"))
	})

	It("preserves explicit empty session env allowlists from manifests", func() {
		ns := createEnvtestNamespace()
		dynamicClient, err := dynamic.NewForConfig(envtestConfig)
		Expect(err).NotTo(HaveOccurred())

		access := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "ssh.xiaoshiai.cn/v1",
			"kind":       "Access",
			"metadata": map[string]any{
				"namespace": ns,
				"name":      "empty-env",
			},
			"spec": map[string]any{
				"type":     "Pod",
				"selector": map[string]any{"app": "empty-env"},
				"session": map[string]any{
					"envAllowlist": []any{},
				},
				"credentials": []any{map[string]any{
					"username":  "alice",
					"passwords": []any{"token"},
				}},
			},
		}}

		created, err := dynamicClient.Resource(accessGVR()).Namespace(ns).Create(context.Background(), access, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		values, found, err := unstructured.NestedSlice(created.Object, "spec", "session", "envAllowlist")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(values).To(BeEmpty())
	})

	It("accepts Valid status conditions through the status subresource", func() {
		ns := createEnvtestNamespace()
		access := createEnvtestAccess(ns, "status-valid", "alice", v1.Credential{Passwords: []string{"token"}})
		access.Status.Conditions = []metav1.Condition{{
			Type:               v1.AccessConditionValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: access.Generation,
			Reason:             "Validated",
			Message:            "access is valid",
			LastTransitionTime: metav1.Now(),
		}}

		updated, err := envtestAccessClient.SshV1().Accesses(ns).UpdateStatus(context.Background(), access, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(updated.Status.Conditions).To(HaveLen(1))
		Expect(updated.Status.Conditions[0].Type).To(Equal(v1.AccessConditionValid))
		Expect(updated.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
	})
})

func accessGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: "ssh.xiaoshiai.cn", Version: "v1", Resource: "accesses"}
}

func createEnvtestNamespace() string {
	GinkgoHelper()
	name := fmt.Sprintf("ks-env-%d", time.Now().UnixNano())
	_, err := envtestKubeClient.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	return name
}

func createEnvtestAccess(namespace, name, username string, credential v1.Credential) *v1.Access {
	GinkgoHelper()
	access, err := envtestAccessClient.SshV1().Accesses(namespace).Create(
		context.Background(),
		envtestAccess(namespace, name, username, credential),
		metav1.CreateOptions{},
	)
	Expect(err).NotTo(HaveOccurred())
	return access
}

func envtestAccess(namespace, name, username string, credential v1.Credential) *v1.Access {
	return &v1.Access{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: v1.AccessSpec{
			Type:     v1.AccessTypePod,
			Selector: map[string]string{"app": name},
			Credentials: []v1.AccessCredential{{
				Username:   username,
				Credential: credential,
			}},
		},
	}
}

func updateEnvtestAccessCredential(namespace, name string, credential v1.Credential) {
	GinkgoHelper()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		access, err := envtestAccessClient.SshV1().Accesses(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		access.Spec.Credentials[0].Credential = credential
		_, err = envtestAccessClient.SshV1().Accesses(namespace).Update(context.Background(), access, metav1.UpdateOptions{})
		return err
	})
	Expect(err).NotTo(HaveOccurred())
}

func createEnvtestSecret(namespace, name string, data map[string]string) *corev1.Secret {
	GinkgoHelper()
	secret, err := envtestKubeClient.CoreV1().Secrets(namespace).Create(
		context.Background(),
		envtestSecret(namespace, name, data),
		metav1.CreateOptions{},
	)
	Expect(err).NotTo(HaveOccurred())
	return secret
}

func createEnvtestReadyPod(namespace, name string, labels map[string]string) *corev1.Pod {
	GinkgoHelper()
	pod, err := envtestKubeClient.CoreV1().Pods(namespace).Create(
		context.Background(),
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    labels,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "app",
					Image: "busybox",
				}},
			},
		},
		metav1.CreateOptions{},
	)
	Expect(err).NotTo(HaveOccurred())
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{
		Type:   corev1.PodReady,
		Status: corev1.ConditionTrue,
	}}
	pod, err = envtestKubeClient.CoreV1().Pods(namespace).UpdateStatus(context.Background(), pod, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())
	return pod
}

func updateEnvtestSecret(namespace, name string, data map[string]string) {
	GinkgoHelper()
	secret, err := envtestKubeClient.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	secret.Data = envtestSecretData(data)
	_, err = envtestKubeClient.CoreV1().Secrets(namespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func envtestSecret(namespace, name string, data map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: envtestSecretData(data),
	}
}

func envtestSecretData(data map[string]string) map[string][]byte {
	out := map[string][]byte{}
	for key, value := range data {
		out[key] = []byte(value)
	}
	return out
}

func EventuallyBasicAuth(runtime accessPolicyRuntime, token string) AsyncAssertion {
	GinkgoHelper()
	return Eventually(func() *authResult {
		info, err := runtime.authenticator.AuthenticateBasic(context.Background(), "ignored", token)
		return &authResult{username: userName(info), err: err}
	}, 10*time.Second, 100*time.Millisecond)
}

func ConsistentlyBasicAuth(runtime accessPolicyRuntime, token string) AsyncAssertion {
	GinkgoHelper()
	return Consistently(func() *authResult {
		info, err := runtime.authenticator.AuthenticateBasic(context.Background(), "ignored", token)
		return &authResult{username: userName(info), err: err}
	}, time.Second, 100*time.Millisecond)
}

func EventuallyPublicKeyAuth(runtime accessPolicyRuntime, pubkey cryptossh.PublicKey) AsyncAssertion {
	GinkgoHelper()
	return Eventually(func() *authResult {
		info, err := runtime.authenticator.AuthenticatePublicKey(context.Background(), pubkey)
		return &authResult{username: userName(info), err: err}
	}, 10*time.Second, 100*time.Millisecond)
}

type authResult struct {
	username string
	err      error
}

func SucceedWithUser(username string) OmegaMatcher {
	return WithTransform(func(result *authResult) any {
		if result.err != nil {
			return result.err
		}
		return result.username
	}, Equal(username))
}

func FailWithAuthError(expected error) OmegaMatcher {
	return WithTransform(func(result *authResult) error {
		return result.err
	}, MatchError(expected))
}

func userName(info *authn.AuthenticateInfo) string {
	if info == nil {
		return ""
	}
	return info.User.Name
}

func newEnvtestPublicKey() cryptossh.PublicKey {
	GinkgoHelper()
	pub, _, err := ed25519.GenerateKey(nil)
	Expect(err).NotTo(HaveOccurred())
	key, err := cryptossh.NewPublicKey(pub)
	Expect(err).NotTo(HaveOccurred())
	return key
}

func envtestConditionStatus(conditions []metav1.Condition, conditionType string) metav1.ConditionStatus {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status
		}
	}
	return ""
}
