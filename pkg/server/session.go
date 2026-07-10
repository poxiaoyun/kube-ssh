package server

import (
	"fmt"
	"path"
	"strings"

	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func (s *Server) handleSession(sess gossh.Session) {
	if SessionRequestTypeFromContext(sess.Context()) == "exec" && isSCPCommand(sess.Command()) {
		s.handleSCP(sess)
		return
	}
	s.handleExecOperation(sess, s.resolveSession)
}

func (s *Server) handleSCP(sess gossh.Session) {
	s.handleStreamOperation(sess, s.resolveSCP, func(sc *sessionContext) (int, error) {
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

func (s *Server) resolveSCP(sc *sessionContext) (operationSpec, error) {
	rawCmd := sc.session.RawCommand()
	_, attrs := sessionAttributes(*sc.target, "exec", sc.session.Command(), rawCmd)
	return operationSpec{
		name:        "scp",
		capability:  authz.CapabilitySCP,
		attrs:       attrs,
		auditFields: map[string]string{"command": rawCmd},
	}, nil
}

func (s *Server) resolveSession(sc *sessionContext) (operationSpec, backend.ExecRequest, error) {
	sess := sc.session
	ctx := sess.Context()

	rawCmd := sess.RawCommand()
	requestType := SessionRequestTypeFromContext(ctx)
	capability, attrs := sessionAttributes(*sc.target, requestType, sess.Command(), rawCmd)

	// Build env list: filtered client vars + TERM injection for PTY sessions.
	ptyInfo, winCh, isPty := sess.Pty()
	env := filterEnv(sess.Environ(), s.opts.EnvAllowlist)
	if isPty && ptyInfo.Term != "" {
		env = append(env, "TERM="+ptyInfo.Term)
	}

	// Build the full command argv, baking in env vars via env(1).
	command := buildCommand(requestType == "exec", rawCmd, env, s.opts.DefaultShell)

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

	return operationSpec{
		name:        "session",
		capability:  capability,
		attrs:       attrs,
		auditFields: map[string]string{"command": rawCmd},
	}, req, nil
}

func sessionAttributes(tgt target.Target, requestType string, argv []string, command string) (authz.Capability, authz.Attributes) {
	capability := authz.CapabilityExec
	switch requestType {
	case "shell":
		capability = authz.CapabilityShell
	case "exec":
		if isSCPCommand(argv) {
			capability = authz.CapabilitySCP
		}
	}

	extra := map[string][]string{}
	if command != "" {
		extra["command"] = []string{command}
	}
	return capability, authz.Attributes{
		Action:    string(capability),
		Resources: targetResources(tgt),
		Path:      tgt.ToPath(),
		Extra:     extra,
	}
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

func targetResources(tgt target.Target) []authz.AttributeResource {
	resources := []authz.AttributeResource{{Resource: "targets", Name: tgt.Kind}}
	for _, option := range tgt.Options {
		resources = append(resources, authz.AttributeResource{Resource: option.Key, Name: option.Value})
	}
	return resources
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

// filterEnv returns only the env entries whose key matches the allowlist.
// Allowlist patterns ending with '*' are treated as prefixes.
func filterEnv(envs, allowlist []string) []string {
	if len(allowlist) == 0 {
		return nil
	}
	var result []string
	for _, env := range envs {
		key, _, found := strings.Cut(env, "=")
		if !found {
			continue
		}
		if isEnvAllowed(key, allowlist) {
			result = append(result, env)
		}
	}
	return result
}

func isEnvAllowed(key string, allowlist []string) bool {
	upper := strings.ToUpper(key)
	for _, pattern := range allowlist {
		p := strings.ToUpper(pattern)
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(upper, p[:len(p)-1]) {
				return true
			}
		} else if upper == p {
			return true
		}
	}
	return false
}
