package podssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/anmitsu/go-shlex"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
)

var _ sshprotocol.ServerSession = (*serverSession)(nil)

func (p *Protocol) handleSessionChannel(conn cryptossh.Conn, newChan cryptossh.NewChannel) {
	channel, requests, err := newChan.Accept()
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(p.ctx)
	session := &serverSession{Channel: channel, protocol: p, conn: conn, ctx: ctx, cancel: cancel}
	session.handleRequests(requests)
}

// The request loop owns session parameters until it starts the operation.
// Afterwards those parameters are immutable; only resize events are published.
// handleRequests does not return until the operation and agent forwarding end.
type serverSession struct {
	cryptossh.Channel
	protocol *Protocol
	conn     cryptossh.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	tasks    sync.WaitGroup
	exitOnce sync.Once
	exitErr  error

	started      bool
	pty          *sshprotocol.PTY
	winch        chan sshprotocol.Window
	env          []string
	rawCmd       string
	requestType  string
	agentForward *sessionAgentForward
}

func (s *serverSession) Write(p []byte) (int, error) {
	if s.pty == nil {
		return s.Channel.Write(p)
	}
	size := len(p)
	p = bytes.ReplaceAll(p, []byte{'\n'}, []byte{'\r', '\n'})
	p = bytes.ReplaceAll(p, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'})
	n, err := s.Channel.Write(p)
	return min(n, size), err
}

func (s *serverSession) Context() context.Context { return s.ctx }
func (s *serverSession) Exit(code int) error {
	s.exitOnce.Do(func() {
		defer s.cancel()
		_, err := s.SendRequest(sshprotocol.RequestExitStatus, false, cryptossh.Marshal(struct{ Status uint32 }{uint32(code)}))
		s.exitErr = errors.Join(err, s.Channel.Close())
	})
	return s.exitErr
}
func (s *serverSession) Environ() []string  { return append([]string(nil), s.env...) }
func (s *serverSession) RawCommand() string { return s.rawCmd }
func (s *serverSession) Command() []string {
	command, _ := shlex.Split(s.rawCmd, true)
	return command
}
func (s *serverSession) RequestType() string { return s.requestType }
func (s *serverSession) Pty() (sshprotocol.PTY, <-chan sshprotocol.Window, bool) {
	if s.pty == nil {
		return sshprotocol.PTY{}, nil, false
	}
	return *s.pty, s.winch, true
}
func (s *serverSession) AgentForwardSocket() string {
	if s.agentForward == nil {
		return ""
	}
	return s.agentForward.forward.SocketPath()
}

func (s *serverSession) handleRequests(requests <-chan *cryptossh.Request) {
	stop := context.AfterFunc(s.ctx, func() { _ = s.Channel.Close() })
	defer func() {
		s.cancel()
		_ = s.Channel.Close()
		stop()
		if s.winch != nil {
			close(s.winch)
		}
		if s.agentForward != nil {
			s.agentForward.Close()
		}
		s.tasks.Wait()
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case request, ok := <-requests:
			if !ok {
				return
			}
			switch request.Type {
			case sshprotocol.RequestShell, sshprotocol.RequestExec, sshprotocol.RequestSubsystem:
				s.handleStartRequest(request)
			case sshprotocol.RequestEnvironment:
				s.handleEnvRequest(request)
			case sshprotocol.RequestPTY:
				s.handlePTYRequest(request)
			case sshprotocol.RequestWindowChange:
				s.handleWindowChangeRequest(request)
			case sshprotocol.RequestAgentForward:
				s.handleAgentForwardRequest(request)
			default:
				// The Pod backend has no signal/break operation.
				_ = request.Reply(false, nil)
			}
		}
	}
}

func (s *serverSession) handleStartRequest(request *cryptossh.Request) {
	if s.started {
		_ = request.Reply(false, nil)
		return
	}
	var payload struct{ Value string }
	handler := s.protocol.handleSession
	switch request.Type {
	case sshprotocol.RequestShell:
		if len(request.Payload) != 0 {
			_ = request.Reply(false, nil)
			return
		}
	case sshprotocol.RequestExec, sshprotocol.RequestSubsystem:
		if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil)
			return
		}
		if request.Type == sshprotocol.RequestSubsystem {
			if payload.Value != sshprotocol.SubsystemSFTP {
				_ = request.Reply(false, nil)
				return
			}
			handler = s.protocol.handleSFTP
		}
	}
	s.requestType = request.Type
	if request.Type == sshprotocol.RequestExec {
		s.rawCmd = payload.Value
	}
	s.started = true
	if err := request.Reply(true, nil); err != nil {
		s.cancel()
		return
	}
	s.tasks.Go(func() { _ = s.Exit(handler(s)) })
}

func (s *serverSession) handleEnvRequest(request *cryptossh.Request) {
	var payload struct{ Key, Value string }
	if s.started || cryptossh.Unmarshal(request.Payload, &payload) != nil {
		_ = request.Reply(false, nil)
		return
	}
	s.env = append(s.env, fmt.Sprintf("%s=%s", payload.Key, payload.Value))
	_ = request.Reply(true, nil)
}

func (s *serverSession) handlePTYRequest(request *cryptossh.Request) {
	if s.started || s.pty != nil {
		_ = request.Reply(false, nil)
		return
	}
	pty, ok := parseSessionPTYRequest(request.Payload)
	if !ok {
		_ = request.Reply(false, nil)
		return
	}
	s.pty = &pty
	// The initial size comes from Pty; this queue contains only later changes.
	s.winch = make(chan sshprotocol.Window, 1)
	_ = request.Reply(true, nil)
}

func (s *serverSession) handleWindowChangeRequest(request *cryptossh.Request) {
	if s.pty == nil {
		_ = request.Reply(false, nil)
		return
	}
	window, ok := parseSessionWindowChangeRequest(request.Payload)
	if ok {
		// A resize describes current state. Replace a stale queued size so a slow
		// backend cannot block other requests or session shutdown.
		select {
		case <-s.winch:
		default:
		}
		s.winch <- window // one producer; draining above guarantees capacity
	}
	_ = request.Reply(ok, nil)
}

func (s *serverSession) handleAgentForwardRequest(request *cryptossh.Request) {
	if s.started || s.agentForward != nil || len(request.Payload) != 0 {
		_ = request.Reply(false, nil)
		return
	}
	forward, ok := s.protocol.acceptAgentForward(s.ctx, s.conn)
	if ok {
		s.agentForward = forward
	}
	_ = request.Reply(ok, nil)
}

func parseSessionPTYRequest(payload []byte) (sshprotocol.PTY, bool) {
	var request struct {
		Term                                   string
		Width, Height, PixelWidth, PixelHeight uint32
		Modes                                  string
	}
	if cryptossh.Unmarshal(payload, &request) != nil || request.Width > math.MaxUint16 || request.Height > math.MaxUint16 {
		return sshprotocol.PTY{}, false
	}
	return sshprotocol.PTY{Term: request.Term, Window: sshprotocol.Window{Width: int(request.Width), Height: int(request.Height)}}, true
}

func parseSessionWindowChangeRequest(payload []byte) (sshprotocol.Window, bool) {
	var request struct{ Width, Height, PixelWidth, PixelHeight uint32 }
	if cryptossh.Unmarshal(payload, &request) != nil || request.Width < 1 || request.Height < 1 || request.Width > math.MaxUint16 || request.Height > math.MaxUint16 {
		return sshprotocol.Window{}, false
	}
	return sshprotocol.Window{Width: int(request.Width), Height: int(request.Height)}, true
}
