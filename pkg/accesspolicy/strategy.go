package accesspolicy

import (
	"math/rand"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

const defaultAffinityTimeout = time.Hour

type StrategySelector struct {
	mu          sync.Mutex
	roundRobin  map[string]int
	connections map[string]int
	affinity    map[string]affinityEntry
}

type affinityEntry struct {
	backendKey string
	expiresAt  time.Time
}

type podSelection struct {
	pod     corev1.Pod
	release func()
}

func NewStrategySelector() *StrategySelector {
	return &StrategySelector{
		roundRobin:  map[string]int{},
		connections: map[string]int{},
		affinity:    map[string]affinityEntry{},
	}
}

func (s *StrategySelector) SelectPod(access *sshv1.Access, pods []corev1.Pod, req target.ResolveRequest) (podSelection, bool) {
	candidates := candidatePods(pods)
	if len(candidates) == 0 {
		return podSelection{}, false
	}
	if s == nil {
		s = NewStrategySelector()
	}
	key := accessKey(access.Namespace, access.Name)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if pod, ok := s.affinityPodLocked(access, candidates, req, now); ok {
		return s.trackPodLocked(key, access.Namespace, pod), true
	}

	var pod corev1.Pod
	switch strategyType(access) {
	case sshv1.AccessStrategyTypeRoundRobin:
		pod = s.roundRobinPodLocked(key, access, candidates)
	case sshv1.AccessStrategyTypeLeastConnections:
		pod = s.leastConnectionsPodLocked(access, candidates)
	case sshv1.AccessStrategyTypeNewest:
		pod = newestPod(candidates)
	case sshv1.AccessStrategyTypeOldest:
		pod = oldestPod(candidates)
	default:
		pod = randomPod(access, candidates)
	}
	if affinityKey := accessAffinityKey(access, req); affinityKey != "" {
		s.affinity[affinityKey] = affinityEntry{
			backendKey: podBackendKey(access.Namespace, pod),
			expiresAt:  now.Add(affinityTimeout(access)),
		}
	}
	return s.trackPodLocked(key, access.Namespace, pod), true
}

// SelectPodByName selects an explicitly requested active Pod. Explicit
// selections bypass strategy and session affinity, but are tracked so that
// LeastConnections observes all active connections.
func (s *StrategySelector) SelectPodByName(access *sshv1.Access, pods []corev1.Pod, name string) (podSelection, bool) {
	for _, pod := range activePods(pods) {
		if pod.Name != name {
			continue
		}
		if s == nil {
			s = NewStrategySelector()
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.trackPodLocked(accessKey(access.Namespace, access.Name), access.Namespace, pod), true
	}
	return podSelection{}, false
}

func (s *StrategySelector) affinityPodLocked(access *sshv1.Access, candidates []corev1.Pod, req target.ResolveRequest, now time.Time) (corev1.Pod, bool) {
	affinityKey := accessAffinityKey(access, req)
	if affinityKey == "" {
		return corev1.Pod{}, false
	}
	entry, ok := s.affinity[affinityKey]
	if !ok {
		return corev1.Pod{}, false
	}
	if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
		delete(s.affinity, affinityKey)
		return corev1.Pod{}, false
	}
	for _, pod := range candidates {
		if podBackendKey(access.Namespace, pod) == entry.backendKey {
			return pod, true
		}
	}
	delete(s.affinity, affinityKey)
	return corev1.Pod{}, false
}

func (s *StrategySelector) roundRobinPodLocked(key string, access *sshv1.Access, candidates []corev1.Pod) corev1.Pod {
	total := totalPodWeight(access, candidates)
	if total <= 0 {
		return candidates[0]
	}
	idx := s.roundRobin[key] % total
	s.roundRobin[key] = s.roundRobin[key] + 1
	for _, pod := range candidates {
		weight := podWeight(access, pod)
		if idx < weight {
			return pod
		}
		idx -= weight
	}
	return candidates[0]
}

func (s *StrategySelector) leastConnectionsPodLocked(access *sshv1.Access, candidates []corev1.Pod) corev1.Pod {
	best := candidates[0]
	for _, pod := range candidates[1:] {
		if podConnectionLess(access, pod, best, s.connections) {
			best = pod
		}
	}
	return best
}

func (s *StrategySelector) trackPodLocked(accessKeyValue, namespace string, pod corev1.Pod) podSelection {
	backendKey := podBackendKey(namespace, pod)
	connectionKey := accessKeyValue + "\x00" + backendKey
	s.connections[connectionKey]++
	var once sync.Once
	return podSelection{
		pod: pod,
		release: func() {
			once.Do(func() {
				s.mu.Lock()
				defer s.mu.Unlock()
				if s.connections[connectionKey] <= 1 {
					delete(s.connections, connectionKey)
					return
				}
				s.connections[connectionKey]--
			})
		},
	}
}

func candidatePods(pods []corev1.Pod) []corev1.Pod {
	active := activePods(pods)
	ready := make([]corev1.Pod, 0, len(pods))
	for _, pod := range active {
		if podReady(pod) {
			ready = append(ready, pod)
		}
	}
	candidates := active
	if len(ready) > 0 {
		candidates = ready
	}
	sortPods(candidates)
	return candidates
}

func activePods(pods []corev1.Pod) []corev1.Pod {
	active := make([]corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		active = append(active, pod)
	}
	sortPods(active)
	return active
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func sortPods(pods []corev1.Pod) {
	sort.Slice(pods, func(i, j int) bool {
		if pods[i].Namespace != pods[j].Namespace {
			return pods[i].Namespace < pods[j].Namespace
		}
		return pods[i].Name < pods[j].Name
	})
}

func newestPod(pods []corev1.Pod) corev1.Pod {
	out := append([]corev1.Pod(nil), pods...)
	sort.Slice(out, func(i, j int) bool {
		it := podCreationTime(out[i])
		jt := podCreationTime(out[j])
		if !it.Equal(&jt) {
			return jt.Before(&it)
		}
		return podBackendKey(out[i].Namespace, out[i]) < podBackendKey(out[j].Namespace, out[j])
	})
	return out[0]
}

func oldestPod(pods []corev1.Pod) corev1.Pod {
	out := append([]corev1.Pod(nil), pods...)
	sort.Slice(out, func(i, j int) bool {
		it := podCreationTime(out[i])
		jt := podCreationTime(out[j])
		if !it.Equal(&jt) {
			return it.Before(&jt)
		}
		return podBackendKey(out[i].Namespace, out[i]) < podBackendKey(out[j].Namespace, out[j])
	})
	return out[0]
}

func randomPod(access *sshv1.Access, pods []corev1.Pod) corev1.Pod {
	total := totalPodWeight(access, pods)
	if total <= 0 {
		return pods[rand.Intn(len(pods))]
	}
	idx := rand.Intn(total)
	for _, pod := range pods {
		weight := podWeight(access, pod)
		if idx < weight {
			return pod
		}
		idx -= weight
	}
	return pods[0]
}

func podConnectionLess(access *sshv1.Access, a, b corev1.Pod, connections map[string]int) bool {
	accessKeyValue := accessKey(access.Namespace, access.Name)
	aWeight := podWeight(access, a)
	bWeight := podWeight(access, b)
	aConnections := connections[accessKeyValue+"\x00"+podBackendKey(access.Namespace, a)]
	bConnections := connections[accessKeyValue+"\x00"+podBackendKey(access.Namespace, b)]
	left := aConnections * bWeight
	right := bConnections * aWeight
	if left != right {
		return left < right
	}
	return podBackendKey(access.Namespace, a) < podBackendKey(access.Namespace, b)
}

func totalPodWeight(access *sshv1.Access, pods []corev1.Pod) int {
	total := 0
	for _, pod := range pods {
		total += podWeight(access, pod)
	}
	return total
}

func podWeight(access *sshv1.Access, pod corev1.Pod) int {
	if access == nil || access.Spec.Strategy == nil {
		return 1
	}
	for _, weight := range access.Spec.Strategy.Weights {
		if selectorMatches(weight.Selector, pod.Labels) {
			if weight.Weight > 0 {
				return int(weight.Weight)
			}
			return 1
		}
	}
	return 1
}

func selectorMatches(selector, values map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	return labels.SelectorFromSet(selector).Matches(labels.Set(values))
}

func strategyType(access *sshv1.Access) sshv1.AccessStrategyType {
	if access == nil || access.Spec.Strategy == nil || access.Spec.Strategy.Type == "" {
		return sshv1.AccessStrategyTypeRandom
	}
	return access.Spec.Strategy.Type
}

func accessAffinityKey(access *sshv1.Access, req target.ResolveRequest) string {
	if access == nil || access.Spec.Strategy == nil || access.Spec.Strategy.SessionAffinity == nil {
		return ""
	}
	var value string
	switch access.Spec.Strategy.SessionAffinity.Type {
	case sshv1.AccessSessionAffinityTypeUser:
		value = req.User.Name
	case sshv1.AccessSessionAffinityTypeCredential:
		value = GetExtra(req.AuthExtra, ExtraCredentialUser)
	case sshv1.AccessSessionAffinityTypeSourceIP:
		value = req.SourceIP
	case sshv1.AccessSessionAffinityTypeSSHUser, "":
		value = req.SSHUser
	default:
		return ""
	}
	if value == "" {
		return ""
	}
	return accessKey(access.Namespace, access.Name) + "\x00" + string(access.Spec.Strategy.SessionAffinity.Type) + "\x00" + value
}

func affinityTimeout(access *sshv1.Access) time.Duration {
	if access == nil || access.Spec.Strategy == nil || access.Spec.Strategy.SessionAffinity == nil || access.Spec.Strategy.SessionAffinity.TimeoutSeconds == nil {
		return defaultAffinityTimeout
	}
	return time.Duration(*access.Spec.Strategy.SessionAffinity.TimeoutSeconds) * time.Second
}

func podBackendKey(namespace string, pod corev1.Pod) string {
	if pod.Namespace != "" {
		namespace = pod.Namespace
	}
	return namespace + "/" + pod.Name
}

func podCreationTime(pod corev1.Pod) metav1.Time {
	return pod.CreationTimestamp
}
