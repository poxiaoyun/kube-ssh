package accesspolicy

import (
	"context"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestResolverSelectsExternalEndpoint(t *testing.T) {
	access := accessFixture("default", "external", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.UID = "access-uid"
	access.Generation = 7
	access.Spec.Type = sshv1.AccessTypeExternal
	access.Spec.Selector = nil
	access.Spec.Endpoints = []sshv1.AccessEndpoint{{Name: "upstream", Address: "notebook-ssh.default.svc", Username: "jovyan"}}
	resolver := NewResolver(NewMemoryStore(access), nil)

	tgt, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if tgt.Kind != target.KindExternalSSH || tgt.Option("endpoints") != "upstream" {
		t.Fatalf("target = %#v", tgt)
	}
}

func TestResolverExternalEndpointLeastConnections(t *testing.T) {
	access := accessFixture("default", "external", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.UID = "access-uid"
	access.Spec.Type = sshv1.AccessTypeExternal
	access.Spec.Selector = nil
	access.Spec.Strategy = &sshv1.AccessStrategy{Type: sshv1.AccessStrategyTypeLeastConnections}
	access.Spec.Endpoints = []sshv1.AccessEndpoint{{Name: "a"}, {Name: "b"}}
	resolver := NewResolver(NewMemoryStore(access), nil)

	first, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatal(err)
	}
	if first.Option("endpoints") != "a" || second.Option("endpoints") != "b" {
		t.Fatalf("selected endpoints = %q, %q", first.Option("endpoints"), second.Option("endpoints"))
	}
}

func TestResolverResolvesAccessToPodTarget(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Selector = map[string]string{"app": "notebook"}
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{
		"default": {
			readyPod("notebook-a", map[string]string{"app": "notebook"}),
		},
	})

	tgt, err := resolver.Resolve(context.Background(), target.ResolveInput{
		SSHUser:   "default.notebook",
		AuthExtra: authExtra(&CredentialMatch{Access: access, Credential: &access.Spec.Credentials[0]}, CredentialTypePassword),
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if tgt.Kind != target.KindPod || tgt.Option(podtarget.OptionNamespaces) != "default" || tgt.Option(podtarget.OptionPods) != "notebook-a" {
		t.Fatalf("target = %#v", tgt)
	}
}

func TestResolverSelectsExplicitPodAndContainer(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Containers = []string{"app", "sidecar"}
	podA := readyPod("notebook-a", map[string]string{"app": "notebook"})
	podB := readyPod("notebook-b", map[string]string{"app": "notebook"})
	podB.Spec.Containers = append(podB.Spec.Containers, corev1.Container{Name: "sidecar"})
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {podA, podB}})

	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook~notebook-b.sidecar"
	tgt, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve(explicit pod/container) error = %v", err)
	}
	if got := tgt.Option(podtarget.OptionPods); got != "notebook-b" {
		t.Fatalf("pod = %q, want notebook-b", got)
	}
	if got := tgt.Option(podtarget.OptionContainers); got != "sidecar" {
		t.Fatalf("container = %q, want sidecar", got)
	}
}

func TestResolverExplicitPodAllowsActiveUnreadyPod(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	ready := readyPod("notebook-a", map[string]string{"app": "notebook"})
	unready := readyPod("notebook-b", map[string]string{"app": "notebook"})
	unready.Status.Conditions = nil
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {ready, unready}})
	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook~notebook-b"

	tgt, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve(active unready pod) error = %v", err)
	}
	if got := tgt.Option(podtarget.OptionPods); got != "notebook-b" {
		t.Fatalf("pod = %q, want notebook-b", got)
	}
}

func TestResolverExplicitPodRejectsUnavailablePods(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	deleting := readyPod("notebook-deleting", map[string]string{"app": "notebook"})
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	succeeded := readyPod("notebook-succeeded", map[string]string{"app": "notebook"})
	succeeded.Status.Phase = corev1.PodSucceeded
	failed := readyPod("notebook-failed", map[string]string{"app": "notebook"})
	failed.Status.Phase = corev1.PodFailed
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {deleting, succeeded, failed}})

	for _, pod := range []string{"notebook-missing", deleting.Name, succeeded.Name, failed.Name} {
		t.Run(pod, func(t *testing.T) {
			req := accessResolveRequest(access)
			req.SSHUser = "default.notebook~" + pod
			if _, err := resolver.Resolve(context.Background(), req); !apierrors.IsServiceUnavailable(err) {
				t.Fatalf("Resolve(%s) error = %v, want ServiceUnavailable", pod, err)
			}
		})
	}
}

func TestResolverExplicitPodMustMatchAccessSelector(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	resolver := NewResolver(NewMemoryStore(access), newTestInformerPodLister(t,
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
		readyPod("other", map[string]string{"app": "other"}),
	))
	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook~other"

	if _, err := resolver.Resolve(context.Background(), req); !apierrors.IsServiceUnavailable(err) {
		t.Fatalf("Resolve(selector-external pod) error = %v, want ServiceUnavailable", err)
	}
}

func TestResolverExplicitPodSupportsDottedPodNames(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Containers = []string{"app", "sidecar"}
	pod := readyPod("notebook.a", map[string]string{"app": "notebook"})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar"})
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})

	for _, tc := range []struct {
		user          string
		wantContainer string
	}{
		{user: "default.notebook~notebook.a", wantContainer: "app"},
		{user: "default.notebook~notebook.a.sidecar", wantContainer: "sidecar"},
	} {
		req := accessResolveRequest(access)
		req.SSHUser = tc.user
		tgt, err := resolver.Resolve(context.Background(), req)
		if err != nil {
			t.Fatalf("Resolve(%s) error = %v", tc.user, err)
		}
		if got := tgt.Option(podtarget.OptionPods); got != pod.Name {
			t.Fatalf("Resolve(%s) pod = %q, want %q", tc.user, got, pod.Name)
		}
		if got := tgt.Option(podtarget.OptionContainers); got != tc.wantContainer {
			t.Fatalf("Resolve(%s) container = %q, want %q", tc.user, got, tc.wantContainer)
		}
	}
}

func TestResolverRejectsMalformedExplicitPodLocator(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {readyPod("notebook-a", map[string]string{"app": "notebook"})}})

	for _, user := range []string{"default.notebook~", "default.notebook~notebook-a."} {
		t.Run(user, func(t *testing.T) {
			req := accessResolveRequest(access)
			req.SSHUser = user
			if _, err := resolver.Resolve(context.Background(), req); err == nil {
				t.Fatalf("Resolve(%s) error = nil, want invalid target", user)
			}
		})
	}
}

func TestResolverRejectsAccessMismatch(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{})

	_, err := resolver.Resolve(context.Background(), target.ResolveInput{
		SSHUser: "default.other",
		AuthExtra: map[string][]string{
			ExtraAccessNamespace: {"default"},
			ExtraAccessName:      {"notebook"},
		},
	})
	if !apierrors.IsBadRequest(err) {
		t.Fatalf("Resolve() error = %v, want BadRequest", err)
	}
}

func TestResolverSelectsAndRestrictsContainers(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Containers = []string{"app", "debug"}
	access.Spec.Credentials[0].Containers = []string{"app"}
	pod := readyPod("notebook-a", map[string]string{"app": "notebook"})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "debug"})
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})

	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook.app"
	tgt, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve(app) error = %v", err)
	}
	if got := tgt.Option(podtarget.OptionContainers); got != "app" {
		t.Fatalf("container = %q, want app", got)
	}

	req.SSHUser = "default.notebook.debug"
	if _, err := resolver.Resolve(context.Background(), req); !apierrors.IsForbidden(err) {
		t.Fatalf("Resolve(debug) error = %v, want Forbidden", err)
	}
	req.SSHUser = "default.notebook~notebook-a.debug"
	if _, err := resolver.Resolve(context.Background(), req); !apierrors.IsForbidden(err) {
		t.Fatalf("Resolve(explicit pod/debug) error = %v, want Forbidden", err)
	}
}

func TestResolverUsesKubernetesDefaultContainer(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	pod := readyPod("notebook-a", map[string]string{"app": "notebook"})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar"})
	pod.Annotations = map[string]string{"kubectl.kubernetes.io/default-container": "sidecar"}
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})

	tgt, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := tgt.Option(podtarget.OptionContainers); got != "sidecar" {
		t.Fatalf("container = %q, want sidecar", got)
	}
}

func TestResolverContainerDefaultModeRequiresAccessOverride(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	pod := readyPod("notebook-a", map[string]string{"app": "notebook"})
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar"})
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})
	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook.sidecar"
	if _, err := resolver.Resolve(context.Background(), req); err == nil {
		t.Fatal("Resolve(sidecar) error = nil, want default-container policy denial")
	}

	access.Spec.Containers = []string{"sidecar"}
	resolver = NewResolver(NewMemoryStore(access), fakePodLister{"default": {pod}})
	if _, err := resolver.Resolve(context.Background(), req); err != nil {
		t.Fatalf("Resolve(sidecar) with Access override error = %v", err)
	}
}

func TestResolverRoundRobinStrategyHonorsWeights(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{
		Type: sshv1.AccessStrategyTypeRoundRobin,
		Weights: []sshv1.AccessStrategyWeight{
			{Selector: map[string]string{"track": "blue"}, Weight: 2},
			{Selector: map[string]string{"track": "green"}, Weight: 1},
		},
	}
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{
		"default": {
			readyPod("notebook-a", map[string]string{"app": "notebook", "track": "blue"}),
			readyPod("notebook-b", map[string]string{"app": "notebook", "track": "green"}),
		},
	})

	got := []string{}
	for range 3 {
		tgt, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		got = append(got, tgt.Option(podtarget.OptionPods))
	}
	want := []string{"notebook-a", "notebook-a", "notebook-b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pods = %v, want %v", got, want)
	}
}

func TestResolverNewestAndOldestStrategies(t *testing.T) {
	pods := fakePodLister{
		"default": {
			readyPodAt("notebook-a", map[string]string{"app": "notebook"}, time.Unix(10, 0)),
			readyPodAt("notebook-b", map[string]string{"app": "notebook"}, time.Unix(20, 0)),
		},
	}
	for _, tc := range []struct {
		name     string
		strategy sshv1.AccessStrategyType
		wantPod  string
	}{
		{name: "newest", strategy: sshv1.AccessStrategyTypeNewest, wantPod: "notebook-b"},
		{name: "oldest", strategy: sshv1.AccessStrategyTypeOldest, wantPod: "notebook-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
			access.Spec.Strategy = &sshv1.AccessStrategy{Type: tc.strategy}
			resolver := NewResolver(NewMemoryStore(access), pods)

			tgt, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if got := tgt.Option(podtarget.OptionPods); got != tc.wantPod {
				t.Fatalf("pod = %q, want %q", got, tc.wantPod)
			}
		})
	}
}

func TestResolverSessionAffinityReusesCredentialTarget(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{
		Type: sshv1.AccessStrategyTypeRandom,
		SessionAffinity: &sshv1.AccessSessionAffinity{
			Type: sshv1.AccessSessionAffinityTypeCredential,
		},
	}
	resolver := NewResolver(NewMemoryStore(access), fakePodLister{
		"default": {
			readyPod("notebook-a", map[string]string{"app": "notebook"}),
			readyPod("notebook-b", map[string]string{"app": "notebook"}),
		},
	})

	first, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	second, err := resolver.Resolve(context.Background(), accessResolveRequest(access))
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if first.Option(podtarget.OptionPods) != second.Option(podtarget.OptionPods) {
		t.Fatalf("affinity pods = %q and %q, want same", first.Option(podtarget.OptionPods), second.Option(podtarget.OptionPods))
	}
}

func TestResolverExplicitPodDoesNotReadOrWriteSessionAffinity(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{
		Type: sshv1.AccessStrategyTypeRandom,
		SessionAffinity: &sshv1.AccessSessionAffinity{
			Type: sshv1.AccessSessionAffinityTypeCredential,
		},
	}
	pods := fakePodLister{"default": {
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
		readyPod("notebook-b", map[string]string{"app": "notebook"}),
	}}
	resolver := NewResolver(NewMemoryStore(access), pods)
	key := accessKey(access.Namespace, access.Name) + "\x00" + string(sshv1.AccessSessionAffinityTypeCredential) + "\x00alice"
	entry := affinityEntry{targetKey: "default/notebook-a", expiresAt: time.Now().
		Add(time.Hour)}
	resolver.selector.affinity[key] = entry

	req := accessResolveRequest(access)
	req.SSHUser = "default.notebook~notebook-b"
	tgt, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("explicit Resolve() error = %v", err)
	}
	if got := tgt.Option(podtarget.OptionPods); got != "notebook-b" {
		t.Fatalf("explicit pod = %q, want notebook-b", got)
	}
	if got := resolver.selector.affinity[key]; got != entry {
		t.Fatalf("affinity = %#v, want unchanged %#v", got, entry)
	}
}

func newTestInformerPodLister(t *testing.T, pods ...corev1.Pod) *InformerPodLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	for i := range pods {
		pod := pods[i].DeepCopy()
		if err := indexer.Add(pod); err != nil {
			t.Fatalf("add pod %s/%s: %v", pod.Namespace, pod.Name, err)
		}
	}
	return NewInformerPodLister(indexer)
}

type fakePodLister map[string][]corev1.Pod

func (l fakePodLister) List(_ context.Context, namespace string, _ map[string]string) ([]corev1.Pod, error) {
	return append([]corev1.Pod(nil), l[namespace]...), nil
}

func readyPod(name string, labels map[string]string) corev1.Pod {
	return readyPodAt(name, labels, time.Time{})
}

func readyPodAt(name string, labels map[string]string, created time.Time) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Labels: labels, CreationTimestamp: metav1.NewTime(created)},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
}

func accessResolveRequest(access *sshv1.Access) target.ResolveInput {
	return target.ResolveInput{
		SSHUser:   access.Namespace + "." + access.Name,
		AuthExtra: authExtra(&CredentialMatch{Access: access, Credential: &access.Spec.Credentials[0]}, CredentialTypePassword),
	}
}
