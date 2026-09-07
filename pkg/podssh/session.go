package podssh

import (
	"fmt"
	"path"
	"strings"

	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
)

func (s *Protocol) handleSession(sess gossh.Session) {
	if requestTypeFromSession(sess) == sshprotocol.RequestExec && isSCPCommand(sess.Command()) {
		s.handleSCP(sess)
		return
	}
	s.handleExecOperation(sess, s.resolveSession)
}

func (s *Protocol) handleSCP(sess gossh.Session) {
	operation := sessionOperation(sshprotocol.RequestExec, sess.RawCommand())
	s.handleStreamOperation(sess, operation, func(sc *sessionContext) (int, error) {
		return s.backend.SCP(sc.ctx, backend.SCPRequest{
			StreamRequest: backend.StreamRequest{
				Target: sc.target,
				Stdin:  sc.session,
				Stdout: sc.session,
				Stderr: sc.session.Stderr(),
			},
			Args: sc.session.Command()[1:],
		})
	})
}

func (s *Protocol) resolveSession(sc *sessionContext) (sshprotocol.Operation, backend.ExecRequest) {
	sess := sc.session

	rawCmd := sess.RawCommand()
	requestType := requestTypeFromSession(sess)
	operation := sessionOperation(requestType, rawCmd)

	ptyInfo, winCh, isPty := sess.Pty()
	env := s.filterEnv(sess.Environ())
	if sc.agentForward != nil && sc.agentForward.SocketPath() != "" {
		env = appendEnvOverride(env, sshprotocol.EnvironmentSSHAuthSock, sc.agentForward.SocketPath())
	}
	if isPty && ptyInfo.Term != "" {
		env = append(env, "TERM="+ptyInfo.Term)
	}

	command := buildCommand(requestType == sshprotocol.RequestExec, rawCmd, env, s.defaultShell)

	req := backend.ExecRequest{
		Target:  sc.target,
		Command: command,
		Stdin:   sess,
		Stdout:  sess,
		TTY:     isPty,
	}
	if isPty {
		req.TerminalSizeQueue = &windowSizeQueue{
			initW: uint16(ptyInfo.Window.Width),
			initH: uint16(ptyInfo.Window.Height),
			ch:    winCh,
		}
	} else {
		req.Stderr = sess.Stderr()
	}

	return operation, req
}

func sessionOperation(requestType, command string) sshprotocol.Operation {
	return sshprotocol.Operation{ChannelType: sshprotocol.ChannelSession, RequestType: requestType, Command: command}
}

func isSCPCommand(argv []string) bool {
	if len(argv) == 0 || path.Base(argv[0]) != "scp" {
		return false
	}
	for _, arg := range argv[1:] {
		if arg == "-t" || arg == "-f" || strings.HasPrefix(arg, "-t") || strings.HasPrefix(arg, "-f") {
			return true
		}
	}
	return false
}

func writeSessionError(sess gossh.Session, isPty bool, err error) {
	if isPty {
		_, _ = fmt.Fprintln(sess, err)
		return
	}
	_, _ = fmt.Fprintln(sess.Stderr(), err)
}

// buildCommand returns the argv to pass to the backend, prepending env(1) pairs
// when env is non-empty.
//
//   - shell request: ["/bin/sh"] or ["env", "K=V", "/bin/sh"]
//   - exec  request: ["/bin/sh", "-c", rawCmd] or ["env", "K=V", "/bin/sh", "-c", rawCmd]
func buildCommand(isExec bool, rawCmd string, env []string, defaultShell string) []string {
	var argv []string
	if len(env) > 0 {
		argv = append([]string{"env"}, env...)
	}
	if isExec {
		return append(argv, defaultShell, "-c", rawCmd)
	}
	return append(argv, defaultShell)
}

func requestTypeFromSession(sess gossh.Session) string {
	if typer, ok := sess.(sessionRequestTyper); ok {
		return typer.SessionRequestType()
	}
	return ""
}

func appendEnvOverride(env []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env)+1)
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			continue
		}
		result = append(result, item)
	}
	return append(result, prefix+value)
}

// windowSizeQueue adapts gliderlabs/ssh window events to backend.TerminalSizeQueue.
// It sends the initial PTY size on the first Next() call, then blocks on the
// channel for subsequent resize events.
type windowSizeQueue struct {
	initialSent bool
	initW       uint16
	initH       uint16
	ch          <-chan gossh.Window
}

func (q *windowSizeQueue) Next() *backend.TerminalSize {
	if !q.initialSent {
		q.initialSent = true
		return &backend.TerminalSize{Width: q.initW, Height: q.initH}
	}
	w, ok := <-q.ch
	if !ok {
		return nil
	}
	return &backend.TerminalSize{Width: uint16(w.Width), Height: uint16(w.Height)}
}

func (p *Protocol) filterEnv(envs []string) []string {
	var result []string
	for _, env := range envs {
		key, _, found := strings.Cut(env, "=")
		if found && !strings.EqualFold(key, sshprotocol.EnvironmentSSHAuthSock) && p.envAllowed(key) {
			result = append(result, env)
		}
	}
	return result
}
