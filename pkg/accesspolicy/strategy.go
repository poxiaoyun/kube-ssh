package accesspolicy

import (
	"math/rand"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

const defaultAffinityTimeout = time.Hour

type strategySelector struct {
	mu          sync.Mutex
	roundRobin  map[string]int
	connections map[string]int
	affinity    map[string]affinityEntry
}

type affinityEntry struct {
	targetKey string
	expiresAt time.Time
}

type targetCandidate struct {
	key       string
	weight    int
	createdAt time.Time
}

type targetSelection struct {
	index   int
	release func()
}

type podSelection struct {
	pod     corev1.Pod
	release func()
}

type endpointSelection struct {
	endpoint sshv1.AccessEndpoint
	release  func()
}

func newStrategySelector() *strategySelector {
	return &strategySelector{
		roundRobin:  map[string]int{},
		connections: map[string]int{},
		affinity:    map[string]affinityEntry{},
	}
}

func (s *strategySelector) selectPod(access *sshv1.Access, pods []corev1.Pod, req target.ResolveInput) (podSelection, bool) {
	pods = candidatePods(pods)
	if len(pods) == 0 {
		return podSelection{}, false
	}
	candidates := make([]targetCandidate, len(pods))
	for i, pod := range pods {
		candidates[i] = targetCandidate{
			key:       podTargetKey(access.Namespace, pod),
			weight:    podWeight(access, pod),
			createdAt: pod.CreationTimestamp.Time,
		}
	}
	selection := s.selectTarget(access, req, candidates, strategyType(access))
	return podSelection{pod: pods[selection.index], release: selection.release}, true
}

// selectPodByName bypasses strategy and affinity but tracks the connection so
// LeastConnections observes explicitly selected Pods.
func (s *strategySelector) selectPodByName(access *sshv1.Access, pods []corev1.Pod, name string) (podSelection, bool) {
	for _, pod := range activePods(pods) {
		if pod.Name == name {
			selection := s.trackTarget(accessKey(access.Namespace, access.Name), podTargetKey(access.Namespace, pod), 0)
			return podSelection{pod: pod, release: selection.release}, true
		}
	}
	return podSelection{}, false
}

func (s *strategySelector) selectEndpoint(access *sshv1.Access, req target.ResolveInput) (endpointSelection, bool) {
	if len(access.Spec.Endpoints) == 0 {
		return endpointSelection{}, false
	}
	endpoints := append([]sshv1.AccessEndpoint(nil), access.Spec.Endpoints...)
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].Name < endpoints[j].Name })
	candidates := make([]targetCandidate, len(endpoints))
	for i, endpoint := range endpoints {
		candidates[i] = targetCandidate{key: endpoint.Name, weight: endpointWeight(endpoint)}
	}
	selection := s.selectTarget(access, req, candidates, endpointStrategyType(access))
	return endpointSelection{endpoint: endpoints[selection.index], release: selection.release}, true
}

func (s *strategySelector) selectTarget(access *sshv1.Access, req target.ResolveInput, candidates []targetCandidate, strategy sshv1.AccessStrategyType) targetSelection {
	accessKeyValue := accessKey(access.Namespace, access.Name)
	affinityKey := accessAffinityKey(access, req)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if index, found := s.affinityCandidateIndex(affinityKey, candidates, now); found {
		return s.trackTargetLocked(accessKeyValue, candidates[index].key, index)
	}

	var index int
	switch strategy {
	case sshv1.AccessStrategyTypeRoundRobin:
		index = s.roundRobinCandidateIndex(accessKeyValue, candidates)
	case sshv1.AccessStrategyTypeLeastConnections:
		index = s.leastConnectionsCandidateIndex(accessKeyValue, candidates)
	case sshv1.AccessStrategyTypeNewest:
		index = newestCandidateIndex(candidates)
	case sshv1.AccessStrategyTypeOldest:
		index = oldestCandidateIndex(candidates)
	default:
		index = randomCandidateIndex(candidates)
	}
	if affinityKey != "" {
		s.affinity[affinityKey] = affinityEntry{
			targetKey: candidates[index].key,
			expiresAt: now.Add(affinityTimeout(access)),
		}
	}
	return s.trackTargetLocked(accessKeyValue, candidates[index].key, index)
}

func (s *strategySelector) affinityCandidateIndex(affinityKey string, candidates []targetCandidate, now time.Time) (int, bool) {
	if affinityKey == "" {
		return 0, false
	}
	entry, found := s.affinity[affinityKey]
	if !found {
		return 0, false
	}
	if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
		delete(s.affinity, affinityKey)
		return 0, false
	}
	for i, candidate := range candidates {
		if candidate.key == entry.targetKey {
			return i, true
		}
	}
	delete(s.affinity, affinityKey)
	return 0, false
}

func (s *strategySelector) roundRobinCandidateIndex(key string, candidates []targetCandidate) int {
	index := s.roundRobin[key] % totalCandidateWeight(candidates)
	s.roundRobin[key]++
	return weightedCandidateIndex(candidates, index)
}

func (s *strategySelector) leastConnectionsCandidateIndex(accessKeyValue string, candidates []targetCandidate) int {
	best := 0
	for i := 1; i < len(candidates); i++ {
		left := s.connections[targetConnectionKey(accessKeyValue, candidates[i].key)] * candidates[best].weight
		right := s.connections[targetConnectionKey(accessKeyValue, candidates[best].key)] * candidates[i].weight
		if left < right || (left == right && candidates[i].key < candidates[best].key) {
			best = i
		}
	}
	return best
}

func randomCandidateIndex(candidates []targetCandidate) int {
	return weightedCandidateIndex(candidates, rand.Intn(totalCandidateWeight(candidates)))
}

func weightedCandidateIndex(candidates []targetCandidate, weightIndex int) int {
	for i, candidate := range candidates {
		if weightIndex < candidate.weight {
			return i
		}
		weightIndex -= candidate.weight
	}
	return 0
}

func totalCandidateWeight(candidates []targetCandidate) int {
	total := 0
	for _, candidate := range candidates {
		total += candidate.weight
	}
	return total
}

func newestCandidateIndex(candidates []targetCandidate) int {
	best := 0
	for i := 1; i < len(candidates); i++ {
		if candidates[i].createdAt.After(candidates[best].createdAt) ||
			(candidates[i].createdAt.Equal(candidates[best].createdAt) && candidates[i].key < candidates[best].key) {
			best = i
		}
	}
	return best
}

func oldestCandidateIndex(candidates []targetCandidate) int {
	best := 0
	for i := 1; i < len(candidates); i++ {
		if candidates[i].createdAt.Before(candidates[best].createdAt) ||
			(candidates[i].createdAt.Equal(candidates[best].createdAt) && candidates[i].key < candidates[best].key) {
			best = i
		}
	}
	return best
}

func (s *strategySelector) trackTarget(accessKeyValue, targetKey string, index int) targetSelection {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trackTargetLocked(accessKeyValue, targetKey, index)
}

func (s *strategySelector) trackTargetLocked(accessKeyValue, targetKey string, index int) targetSelection {
	connectionKey := targetConnectionKey(accessKeyValue, targetKey)
	s.connections[connectionKey]++
	var once sync.Once
	return targetSelection{
		index: index,
		release: func() {
			once.Do(func() {
				s.mu.Lock()
				defer s.mu.Unlock()
				if s.connections[connectionKey] == 1 {
					delete(s.connections, connectionKey)
					return
				}
				s.connections[connectionKey]--
			})
		},
	}
}

func targetConnectionKey(accessKeyValue, targetKey string) string {
	return accessKeyValue + "\x00" + targetKey
}

func candidatePods(pods []corev1.Pod) []corev1.Pod {
	active := activePods(pods)
	ready := make([]corev1.Pod, 0, len(pods))
	for _, pod := range active {
		if podReady(pod) {
			ready = append(ready, pod)
		}
	}
	if len(ready) > 0 {
		active = ready
	}
	sortPods(active)
	return active
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

func podWeight(access *sshv1.Access, pod corev1.Pod) int {
	if access.Spec.Strategy == nil {
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

func endpointWeight(endpoint sshv1.AccessEndpoint) int {
	if endpoint.Weight == nil {
		return 1
	}
	return int(*endpoint.Weight)
}

func selectorMatches(selector, values map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	return labels.SelectorFromSet(selector).Matches(labels.Set(values))
}

func strategyType(access *sshv1.Access) sshv1.AccessStrategyType {
	if access.Spec.Strategy == nil || access.Spec.Strategy.Type == "" {
		return sshv1.AccessStrategyTypeRandom
	}
	return access.Spec.Strategy.Type
}

func endpointStrategyType(access *sshv1.Access) sshv1.AccessStrategyType {
	strategy := strategyType(access)
	if strategy == sshv1.AccessStrategyTypeRoundRobin || strategy == sshv1.AccessStrategyTypeLeastConnections {
		return strategy
	}
	return sshv1.AccessStrategyTypeRandom
}

func accessAffinityKey(access *sshv1.Access, req target.ResolveInput) string {
	if access.Spec.Strategy == nil || access.Spec.Strategy.SessionAffinity == nil {
		return ""
	}
	var value string
	switch access.Spec.Strategy.SessionAffinity.Type {
	case sshv1.AccessSessionAffinityTypeUser:
		value = req.UserName
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
	if access.Spec.Strategy == nil || access.Spec.Strategy.SessionAffinity == nil || access.Spec.Strategy.SessionAffinity.TimeoutSeconds == nil {
		return defaultAffinityTimeout
	}
	return time.Duration(*access.Spec.Strategy.SessionAffinity.TimeoutSeconds) * time.Second
}

func podTargetKey(namespace string, pod corev1.Pod) string {
	if pod.Namespace != "" {
		namespace = pod.Namespace
	}
	return namespace + "/" + pod.Name
}
