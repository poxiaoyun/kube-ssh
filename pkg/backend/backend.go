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

// RemoteForwardRequest describes one SSH tcpip-forward listener inside a target.
type RemoteForwardRequest struct {
	Target   *target.Target
	BindHost string
	BindPort uint32
}

type RemoteForwardConnInfo struct {
	OriginHost string
	OriginPort uint32
}

type RemoteForward interface {
	ActualPort() uint32
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
	SocketPath() string
	Accept(ctx context.Context) (ioproxy.HalfCloser, error)
	Close() error
}

type StreamRequest struct {
	Target *target.Target
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type SCPRequest struct {
	StreamRequest
	Args []string
}

// Backend executes operations against already-resolved targets.
type Backend interface {
	Exec(ctx context.Context, req ExecRequest) (int, error)
	PortForward(ctx context.Context, req PortForwardRequest) (ioproxy.HalfCloser, error)
	RemoteForward(ctx context.Context, req RemoteForwardRequest) (RemoteForward, error)
	AgentForward(ctx context.Context, req AgentForwardRequest) (AgentForward, error)
	SFTP(ctx context.Context, req StreamRequest) (int, error)
	SCP(ctx context.Context, req SCPRequest) (int, error)
}
