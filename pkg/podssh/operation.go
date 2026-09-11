package podssh

import (
	"context"

	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
)

// runSessionOperation owns authorization and the operation result. The session
// owner sends the returned exit status and closes the channel exactly once.
func (p *Protocol) runSessionOperation(
	session sshprotocol.ServerSession,
	operation sshprotocol.Operation,
	tty bool,
	execute func(context.Context) (int, error),
) int {
	finish, err := p.begin(operation)
	if err != nil {
		if finish != nil {
			exitCode := 1
			finish(sshprotocol.OperationResult{ExitCode: &exitCode})
		}
		writeSessionError(session, tty, err)
		return 1
	}
	exitCode, execErr := execute(session.Context())
	if execErr != nil {
		writeSessionError(session, tty, execErr)
	}
	finish(sshprotocol.OperationResult{Err: execErr, ExitCode: &exitCode})
	return exitCode
}
