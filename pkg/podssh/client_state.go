package podssh

import (
	"sync"

	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
)

// clientState owns remote forwards whose lifecycle is bounded by one SSH
// connection.
type clientState struct {
	mu             sync.Mutex
	closed         bool
	remoteForwards map[remoteForwardBind]backend.RemoteForward
}

func newClientState() *clientState {
	return &clientState{remoteForwards: make(map[remoteForwardBind]backend.RemoteForward)}
}

func (s *clientState) AddRemoteForward(bind remoteForwardBind, forward backend.RemoteForward) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if _, exists := s.remoteForwards[bind]; exists {
		return false
	}
	s.remoteForwards[bind] = forward
	return true
}

func (s *clientState) RemoveRemoteForward(bind remoteForwardBind) (backend.RemoteForward, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	forward, ok := s.remoteForwards[bind]
	if ok {
		delete(s.remoteForwards, bind)
	}
	return forward, ok
}

func (s *clientState) Close() {
	var forwards []backend.RemoteForward

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	for _, forward := range s.remoteForwards {
		forwards = append(forwards, forward)
	}
	s.remoteForwards = nil
	s.mu.Unlock()

	for _, forward := range forwards {
		_ = forward.Close()
	}
}
