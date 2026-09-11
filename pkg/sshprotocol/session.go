package sshprotocol

import (
	"context"
	"io"
)

// Window is an SSH terminal's character-cell dimensions.
type Window struct {
	Width, Height int
}

// PTY describes the terminal requested by an SSH client.
type PTY struct {
	Term   string
	Window Window
}

// ServerSession exposes an accepted session to its operation handler. The
// implementation owns request parsing and channel cleanup. Parameters are fixed
// before execution starts; Pty supplies later sizes as coalesced resize events.
type ServerSession interface {
	io.ReadWriter
	Stderr() io.ReadWriter
	// Context is canceled when this session ends, independently of other sessions.
	Context() context.Context
	// Exit sends the status and closes the session. Repeated calls have no effect.
	Exit(code int) error
	Environ() []string
	RawCommand() string
	Command() []string
	RequestType() string
	Pty() (PTY, <-chan Window, bool)
	// AgentForwardSocket is empty when agent forwarding was not accepted.
	AgentForwardSocket() string
}
