package podssh

import (
	"fmt"

	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type sessionContext struct {
	ctx          gossh.Context
	target       *target.Target
	session      gossh.Session
	agentForward backend.AgentForward
}

type execOperationResolver func(ctx *sessionContext) (sshprotocol.Operation, backend.ExecRequest)

func (p *Protocol) handleExecOperation(session gossh.Session, resolve execOperationResolver) {
	ctx := p.newSessionContext(session)
	operation, request := resolve(ctx)
	finish, err := p.begin(operation)
	if err != nil {
		if finish != nil {
			exitCode := 1
			finish(sshprotocol.OperationResult{ExitCode: &exitCode})
		}
		_, _ = fmt.Fprintln(session.Stderr(), err)
		_ = session.Exit(1)
		return
	}

	exitCode, execErr := p.backend.Exec(ctx.ctx, request)
	if execErr != nil {
		writeSessionError(session, request.TTY, execErr)
	}
	finish(sshprotocol.OperationResult{Err: execErr, ExitCode: &exitCode})
	_ = session.Exit(exitCode)
}

func (p *Protocol) handleStreamOperation(
	session gossh.Session,
	operation sshprotocol.Operation,
	execute func(*sessionContext) (int, error),
) {
	ctx := p.newSessionContext(session)
	finish, err := p.begin(operation)
	if err != nil {
		if finish != nil {
			exitCode := 1
			finish(sshprotocol.OperationResult{ExitCode: &exitCode})
		}
		_, _ = fmt.Fprintln(session.Stderr(), err)
		_ = session.Exit(1)
		return
	}

	exitCode, execErr := execute(ctx)
	if execErr != nil {
		writeSessionError(session, false, execErr)
	}
	finish(sshprotocol.OperationResult{Err: execErr, ExitCode: &exitCode})
	_ = session.Exit(exitCode)
}

func (p *Protocol) newSessionContext(session gossh.Session) *sessionContext {
	ctx := &sessionContext{ctx: p.ctx, target: p.target, session: session}
	if agentSession, ok := session.(agentForwardSession); ok {
		ctx.agentForward = agentSession.AgentForward()
	}
	return ctx
}
