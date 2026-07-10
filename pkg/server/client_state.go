package server

import (
	"sync"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
)

// clientState owns resources whose lifecycle is bounded by one SSH connection.
type clientState struct {
	conn *cryptossh.ServerConn

	mu             sync.Mutex
	closed         bool
	remoteForwards map[remoteForwardBind]backend.RemoteForward
}

func newClientState(conn *cryptossh.ServerConn) *clientState {
	return &clientState{
		conn:           conn,
		remoteForwards: make(map[remoteForwardBind]backend.RemoteForward),
	}
}

func (s *Server) getClientState(ctx gossh.Context, conn *cryptossh.ServerConn) *clientState {
	s.clientStateMu.Lock()
	defer s.clientStateMu.Unlock()
	if state := s.clientStates[conn]; state != nil {
		return state
	}
	state := newClientState(conn)
	s.clientStates[conn] = state
	go func() {
		<-ctx.Done()
		s.closeClientState(conn, state)
	}()
	return state
}

func (s *Server) findClientState(conn *cryptossh.ServerConn) *clientState {
	s.clientStateMu.Lock()
	defer s.clientStateMu.Unlock()
	return s.clientStates[conn]
}

func (s *Server) closeClientState(conn *cryptossh.ServerConn, state *clientState) {
	s.clientStateMu.Lock()
	if s.clientStates[conn] == state {
		delete(s.clientStates, conn)
	}
	s.clientStateMu.Unlock()
	state.Close()
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
