package podssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/anmitsu/go-shlex"
	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
)

const maxSignalBufferSize = 128

type sessionRequestTyper interface {
	// SessionRequestType identifies the request that started this session.
	SessionRequestType() string
}

func (s *Protocol) handleSessionChannel(conn cryptossh.Conn, newChan cryptossh.NewChannel) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	sess := &serverSession{
		Channel:  ch,
		protocol: s,
		conn:     conn,
		ctx:      s.ctx,
	}
	sess.handleRequests(reqs)
}

type serverSession struct {
	sync.Mutex
	cryptossh.Channel

	protocol     *Protocol
	conn         cryptossh.Conn
	handled      bool
	exited       bool
	pty          *gossh.Pty
	winch        chan gossh.Window
	env          []string
	rawCmd       string
	subsystem    string
	requestType  string
	ctx          gossh.Context
	sigCh        chan<- gossh.Signal
	sigBuf       []gossh.Signal
	breakCh      chan<- bool
	agentForward *sessionAgentForward
}

func (s *serverSession) Write(p []byte) (int, error) {
	if s.pty == nil {
		return s.Channel.Write(p)
	}
	m := len(p)
	p = bytes.ReplaceAll(p, []byte{'\n'}, []byte{'\r', '\n'})
	p = bytes.ReplaceAll(p, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'})
	n, err := s.Channel.Write(p)
	if n > m {
		n = m
	}
	return n, err
}

func (s *serverSession) PublicKey() gossh.PublicKey {
	sessionKey := s.ctx.Value(gossh.ContextKeyPublicKey)
	if sessionKey == nil {
		return nil
	}
	return sessionKey.(gossh.PublicKey)
}

func (s *serverSession) Permissions() gossh.Permissions {
	perms := s.ctx.Value(gossh.ContextKeyPermissions).(*gossh.Permissions)
	return *perms
}

func (s *serverSession) Context() gossh.Context { return s.ctx }

func (s *serverSession) Exit(code int) error {
	s.Lock()
	defer s.Unlock()
	if s.exited {
		return errors.New("Session.Exit called multiple times")
	}
	s.exited = true

	status := struct{ Status uint32 }{uint32(code)}
	_, err := s.SendRequest(sshprotocol.RequestExitStatus, false, cryptossh.Marshal(&status))
	if err != nil {
		return err
	}
	return s.Close()
}

func (s *serverSession) User() string { return s.conn.User() }

func (s *serverSession) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *serverSession) LocalAddr() net.Addr { return s.conn.LocalAddr() }

func (s *serverSession) Environ() []string { return append([]string(nil), s.env...) }

func (s *serverSession) RawCommand() string { return s.rawCmd }

func (s *serverSession) Command() []string {
	cmd, _ := shlex.Split(s.rawCmd, true)
	return append([]string(nil), cmd...)
}

func (s *serverSession) Subsystem() string { return s.subsystem }

func (s *serverSession) Pty() (gossh.Pty, <-chan gossh.Window, bool) {
	if s.pty == nil {
		return gossh.Pty{}, s.winch, false
	}
	return *s.pty, s.winch, true
}

func (s *serverSession) Signals(c chan<- gossh.Signal) {
	s.Lock()
	defer s.Unlock()
	s.sigCh = c
	if len(s.sigBuf) == 0 {
		return
	}
	go func() {
		for _, sig := range s.sigBuf {
			s.sigCh <- sig
		}
	}()
}

func (s *serverSession) Break(c chan<- bool) {
	s.Lock()
	defer s.Unlock()
	s.breakCh = c
}

func (s *serverSession) SessionRequestType() string {
	return s.requestType
}

func (s *serverSession) AgentForward() backend.AgentForward {
	if s.agentForward == nil {
		return nil
	}
	return s.agentForward.forward
}

func (s *serverSession) handleRequests(reqs <-chan *cryptossh.Request) {
	defer func() {
		s.closeAgentForward()
		if s.winch != nil {
			close(s.winch)
		}
	}()
	for req := range reqs {
		switch req.Type {
		case sshprotocol.RequestShell, sshprotocol.RequestExec:
			s.handleShellOrExecRequest(req)
		case sshprotocol.RequestSubsystem:
			s.handleSubsystemRequest(req)
		case sshprotocol.RequestEnvironment:
			s.handleEnvRequest(req)
		case sshprotocol.RequestSignal:
			s.handleSignalRequest(req)
		case sshprotocol.RequestPTY:
			s.handlePTYRequest(req)
		case sshprotocol.RequestWindowChange:
			s.handleWindowChangeRequest(req)
		case sshprotocol.RequestAgentForward:
			s.handleAgentForwardRequest(req)
		case sshprotocol.RequestBreak:
			s.handleBreakRequest(req)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func (s *serverSession) handleShellOrExecRequest(req *cryptossh.Request) {
	if s.handled {
		_ = req.Reply(false, nil)
		return
	}
	var payload struct{ Value string }
	cryptossh.Unmarshal(req.Payload, &payload)
	s.rawCmd = payload.Value
	s.requestType = req.Type

	s.handled = true
	_ = req.Reply(true, nil)
	go func() {
		defer s.closeAgentForward()
		s.protocol.handleSession(s)
		_ = s.Exit(0)
	}()
}

func (s *serverSession) handleSubsystemRequest(req *cryptossh.Request) {
	if s.handled {
		_ = req.Reply(false, nil)
		return
	}
	var payload struct{ Value string }
	cryptossh.Unmarshal(req.Payload, &payload)
	s.subsystem = payload.Value
	s.requestType = req.Type

	if payload.Value != sshprotocol.SubsystemSFTP {
		_ = req.Reply(false, nil)
		return
	}

	s.handled = true
	_ = req.Reply(true, nil)
	go func() {
		defer s.closeAgentForward()
		s.protocol.handleSFTP(s)
		_ = s.Exit(0)
	}()
}

func (s *serverSession) handleEnvRequest(req *cryptossh.Request) {
	if s.handled {
		_ = req.Reply(false, nil)
		return
	}
	var kv struct{ Key, Value string }
	cryptossh.Unmarshal(req.Payload, &kv)
	s.env = append(s.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
	_ = req.Reply(true, nil)
}

func (s *serverSession) handleSignalRequest(req *cryptossh.Request) {
	var payload struct{ Signal string }
	cryptossh.Unmarshal(req.Payload, &payload)
	s.Lock()
	if s.sigCh != nil {
		s.sigCh <- gossh.Signal(payload.Signal)
	} else if len(s.sigBuf) < maxSignalBufferSize {
		s.sigBuf = append(s.sigBuf, gossh.Signal(payload.Signal))
	}
	s.Unlock()
}

func (s *serverSession) handlePTYRequest(req *cryptossh.Request) {
	if s.handled || s.pty != nil {
		_ = req.Reply(false, nil)
		return
	}
	ptyReq, ok := parseSessionPTYRequest(req.Payload)
	if !ok {
		_ = req.Reply(false, nil)
		return
	}
	s.pty = &ptyReq
	s.winch = make(chan gossh.Window, 1)
	s.winch <- ptyReq.Window
	_ = req.Reply(true, nil)
}

func (s *serverSession) handleWindowChangeRequest(req *cryptossh.Request) {
	if s.pty == nil {
		_ = req.Reply(false, nil)
		return
	}
	win, ok := parseSessionWindowChangeRequest(req.Payload)
	if ok {
		s.pty.Window = win
		s.winch <- win
	}
	_ = req.Reply(ok, nil)
}

func (s *serverSession) handleAgentForwardRequest(req *cryptossh.Request) {
	if s.handled || s.agentForward != nil {
		_ = req.Reply(false, nil)
		return
	}
	forward, ok := s.protocol.acceptAgentForward(s.conn)
	if !ok {
		_ = req.Reply(false, nil)
		return
	}
	s.agentForward = forward
	_ = req.Reply(true, nil)
}

func (s *serverSession) handleBreakRequest(req *cryptossh.Request) {
	ok := false
	s.Lock()
	if s.breakCh != nil {
		s.breakCh <- true
		ok = true
	}
	_ = req.Reply(ok, nil)
	s.Unlock()
}

func (s *serverSession) closeAgentForward() {
	if s.agentForward != nil {
		s.agentForward.Close()
	}
}

func parseSessionPTYRequest(payload []byte) (gossh.Pty, bool) {
	term, rest, ok := parseSessionString(payload)
	if !ok {
		return gossh.Pty{}, false
	}
	width, rest, ok := parseSessionUint32(rest)
	if !ok {
		return gossh.Pty{}, false
	}
	height, _, ok := parseSessionUint32(rest)
	if !ok {
		return gossh.Pty{}, false
	}
	return gossh.Pty{
		Term: term,
		Window: gossh.Window{
			Width:  int(width),
			Height: int(height),
		},
	}, true
}

func parseSessionWindowChangeRequest(payload []byte) (gossh.Window, bool) {
	width, rest, ok := parseSessionUint32(payload)
	if !ok || width < 1 {
		return gossh.Window{}, false
	}
	height, _, ok := parseSessionUint32(rest)
	if !ok || height < 1 {
		return gossh.Window{}, false
	}
	return gossh.Window{Width: int(width), Height: int(height)}, true
}

func parseSessionString(in []byte) (string, []byte, bool) {
	if len(in) < 4 {
		return "", nil, false
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return "", nil, false
	}
	return string(in[4 : 4+length]), in[4+length:], true
}

func parseSessionUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func (p *Protocol) handleSFTP(session gossh.Session) {
	operation := sshprotocol.Operation{ChannelType: sshprotocol.ChannelSession, RequestType: sshprotocol.RequestSubsystem, Subsystem: sshprotocol.SubsystemSFTP}
	p.handleStreamOperation(session, operation, func(sc *sessionContext) (int, error) {
		return p.backend.SFTP(sc.ctx, backend.StreamRequest{
			Target: sc.target,
			Stdin:  sc.session,
			Stdout: sc.session,
			Stderr: sc.session.Stderr(),
		})
	})
}
