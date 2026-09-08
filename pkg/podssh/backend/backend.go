// Package backend defines Pod SSH operations against resolved Pod targets.
package backend

import (
	"context"
	"io"

	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// TerminalSize is the PTY window size.
type TerminalSize struct {
	Width  uint16
	Height uint16
}

// TerminalSizeQueue delivers the initial window size and subsequent resize events.
type TerminalSizeQueue interface {
	// Next blocks until the next terminal size or queue closure.
	Next() *TerminalSize
}

// ExecRequest describes a command execution against a target container.
type ExecRequest struct {
	Target *target.Target

	// Command is the full argv, including any env-injection prefix built by the caller.
	// For interactive shells: ["/bin/sh"] or ["env", "TERM=xterm", "/bin/sh"].
	// For user commands:      ["sh", "-c", rawCmd] or ["env", "K=V", "sh", "-c", rawCmd].
	Command []string

	Stdin  io.Reader
	Stdout io.Writer
	// Stderr is only used when TTY is false. PTY backends normally merge it into stdout.
	Stderr io.Writer

	TTY bool

	// TerminalSizeQueue delivers the initial window size and subsequent resize events.
	// Required when TTY is true; nil otherwise.
	TerminalSizeQueue TerminalSizeQueue
}

// PortForwardRequest describes one direct-tcpip connection to a target port.
type PortForwardRequest struct {
	Target *target.Target
	Host   string
	Port   uint32
}

// PodPortForwardRequest identifies one port in a target Pod network namespace.
type PodPortForwardRequest struct {
	Target *target.Target
	Port   uint32
}

// RemoteForwardRequest describes one SSH tcpip-forward listener inside a target.
type RemoteForwardRequest struct {
	Target   *target.Target
	BindHost string
	BindPort uint32
}

// RemoteForwardConnInfo identifies the peer of a target-side connection.
type RemoteForwardConnInfo struct {
	OriginHost string
	OriginPort uint32
}

// RemoteForward owns a target-side listener and its forwarding transport.
type RemoteForward interface {
	// ActualPort returns the bound target-side port.
	ActualPort() uint32
	// Accept returns the next target-side connection.
	Accept(ctx context.Context) (ioproxy.HalfCloser, RemoteForwardConnInfo, error)

	// Cancel stops accepting new connections for this remote forward. Active
	// connections should be allowed to drain.
	Cancel() error
	// Close forcefully closes the remote forward and any transport it owns.
	Close() error
}

// AgentForwardRequest describes one SSH agent forwarding socket in the target.
type AgentForwardRequest struct {
	Target *target.Target
}

// AgentForward proxies connections from a target-local SSH_AUTH_SOCK back to
// the client-side OpenSSH agent channel.
type AgentForward interface {
	// SocketPath returns the target-local SSH_AUTH_SOCK path.
	SocketPath() string
	// Accept returns the next connection opened against the target-local socket.
	Accept(ctx context.Context) (ioproxy.HalfCloser, error)
	// Close stops the target-local socket and its pending accepts.
	Close() error
}

// StreamRequest binds a file-transfer or helper session to its target and I/O.
type StreamRequest struct {
	Target *target.Target
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// SCPRequest supplies the legacy SCP arguments and session streams.
type SCPRequest struct {
	StreamRequest
	Args []string
}

// HelperExecRequest describes one helper command. The transport owns preparing
// and locating a compatible helper before running Command.
type HelperExecRequest struct {
	StreamRequest
	Capability string
	Command    []string
}

// Backend executes operations against already-resolved targets.
type Backend interface {
	// Exec runs one command or shell in the target container.
	Exec(ctx context.Context, req ExecRequest) (int, error)

	// PortForward opens a direct-tcpip stream from the target network context.
	PortForward(ctx context.Context, req PortForwardRequest) (ioproxy.HalfCloser, error)
	// RemoteForward opens a target-side listener.
	RemoteForward(ctx context.Context, req RemoteForwardRequest) (RemoteForward, error)
	// AgentForward opens a target-local agent socket.
	AgentForward(ctx context.Context, req AgentForwardRequest) (AgentForward, error)

	// SFTP serves one SFTP subsystem session.
	SFTP(ctx context.Context, req StreamRequest) (int, error)
	// SCP serves one legacy SCP session.
	SCP(ctx context.Context, req SCPRequest) (int, error)
}

// Transport supplies the execution primitives used by Executor.
type Transport interface {
	// Exec runs a command in the target container.
	Exec(ctx context.Context, req ExecRequest) (int, error)
	// ExecHelper prepares a compatible helper and runs one helper command.
	ExecHelper(ctx context.Context, req HelperExecRequest) (int, error)

	// PortForward opens a stream to one port in the target Pod network namespace.
	PortForward(ctx context.Context, req PodPortForwardRequest) (ioproxy.HalfCloser, error)
}

// Executor implements Pod SSH operations over one transport.
type Executor struct {
	transport Transport
}

// NewExecutor creates a Pod backend that uses transport for every operation.
func NewExecutor(transport Transport) *Executor {
	return &Executor{transport: transport}
}

// Exec runs a command in the target container.
func (e *Executor) Exec(ctx context.Context, req ExecRequest) (int, error) {
	return e.transport.Exec(ctx, req)
}
