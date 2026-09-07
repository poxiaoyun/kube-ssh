package accesspolicy

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
)

func TestStrategyLeastConnectionsTracksSelectionRelease(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{Type: sshv1.AccessStrategyTypeLeastConnections}
	pods := []corev1.Pod{
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
		readyPod("notebook-b", map[string]string{"app": "notebook"}),
	}
	selector := newStrategySelector()

	first, selected := selector.selectPod(access, pods, accessResolveRequest(access))
	if !selected || first.pod.Name != "notebook-a" {
		t.Fatalf("first selection = %q, %t; want notebook-a", first.pod.Name, selected)
	}
	second, selected := selector.selectPod(access, pods, accessResolveRequest(access))
	if !selected || second.pod.Name != "notebook-b" {
		t.Fatalf("second selection = %q, %t; want notebook-b", second.pod.Name, selected)
	}

	first.release()
	third, selected := selector.selectPod(access, pods, accessResolveRequest(access))
	if !selected || third.pod.Name != "notebook-a" {
		t.Fatalf("third selection = %q, %t; want notebook-a", third.pod.Name, selected)
	}
	second.release()
	third.release()
}

func TestStrategyExplicitPodParticipatesInLeastConnections(t *testing.T) {
	access := accessFixture("default", "notebook", "alice", sshv1.AccessCredential{Passwords: []string{"token"}}, time.Unix(10, 0))
	access.Spec.Strategy = &sshv1.AccessStrategy{Type: sshv1.AccessStrategyTypeLeastConnections}
	pods := []corev1.Pod{
		readyPod("notebook-a", map[string]string{"app": "notebook"}),
		readyPod("notebook-b", map[string]string{"app": "notebook"}),
	}
	selector := newStrategySelector()

	explicit, selected := selector.selectPodByName(access, pods, "notebook-a")
	if !selected {
		t.Fatal("explicit Pod was not selected")
	}
	automatic, selected := selector.selectPod(access, pods, accessResolveRequest(access))
	if !selected || automatic.pod.Name != "notebook-b" {
		t.Fatalf("automatic selection = %q, %t; want notebook-b", automatic.pod.Name, selected)
	}
	explicit.release()
	automatic.release()

	afterRelease, selected := selector.selectPod(access, pods, accessResolveRequest(access))
	if !selected || afterRelease.pod.Name != "notebook-a" {
		t.Fatalf("selection after release = %q, %t; want notebook-a", afterRelease.pod.Name, selected)
	}
	afterRelease.release()
}
