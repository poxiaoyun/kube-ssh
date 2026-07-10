package accesspolicy

import (
	"context"
	"fmt"
	"sort"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
)

type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]*sshv1.Access
}

func NewMemoryStore(accesses ...*sshv1.Access) *MemoryStore {
	s := &MemoryStore{entries: map[string]*sshv1.Access{}}
	for _, access := range accesses {
		s.Set(access)
	}
	return s
}

func (s *MemoryStore) Set(access *sshv1.Access) {
	if s == nil || access == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = map[string]*sshv1.Access{}
	}
	s.entries[accessKey(access.Namespace, access.Name)] = access.DeepCopy()
}

func (s *MemoryStore) Get(_ context.Context, namespace, name string) (*sshv1.Access, error) {
	if s == nil {
		return nil, fmt.Errorf("access store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	access := s.entries[accessKey(namespace, name)]
	if access == nil {
		return nil, fmt.Errorf("access %s/%s not found", namespace, name)
	}
	return access.DeepCopy(), nil
}

func (s *MemoryStore) List(context.Context) ([]*sshv1.Access, error) {
	if s == nil {
		return nil, fmt.Errorf("access store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*sshv1.Access, 0, len(s.entries))
	for _, access := range s.entries {
		out = append(out, access.DeepCopy())
	}
	sortAccesses(out)
	return out, nil
}

func accessKey(namespace, name string) string {
	return namespace + "/" + name
}

func sortAccesses(accesses []*sshv1.Access) {
	sort.Slice(accesses, func(i, j int) bool {
		return accessLess(accesses[i], accesses[j])
	})
}

func accessLess(a, b *sshv1.Access) bool {
	at := creationTime(a)
	bt := creationTime(b)
	if !at.Equal(&bt) {
		return at.Before(&bt)
	}
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	return a.Name < b.Name
}

func creationTime(access *sshv1.Access) metav1.Time {
	if access == nil {
		return metav1.Time{}
	}
	return access.CreationTimestamp
}

func isPodAccess(access *sshv1.Access) bool {
	if access == nil {
		return false
	}
	return access.Spec.Type == "" || access.Spec.Type == sshv1.AccessTypePod
}
