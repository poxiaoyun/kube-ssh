// Package sshprotocol defines the connection-level SSH protocol seam and its
// shared operation lifecycle.
package sshprotocol

import cryptossh "golang.org/x/crypto/ssh"

// SSH channel type identifiers shared by connection protocol adapters.
const (
	ChannelSession        = "session"
	ChannelDirectTCPIP    = "direct-tcpip"
	ChannelForwardedTCPIP = "forwarded-tcpip"
	ChannelAgent          = "auth-agent@openssh.com"
)

// SSH request type identifiers shared by connection protocol adapters.
const (
	RequestShell              = "shell"
	RequestExec               = "exec"
	RequestSubsystem          = "subsystem"
	RequestEnvironment        = "env"
	RequestPTY                = "pty-req"
	RequestWindowChange       = "window-change"
	RequestSignal             = "signal"
	RequestBreak              = "break"
	RequestExitStatus         = "exit-status"
	RequestExitSignal         = "exit-signal"
	RequestTCPIPForward       = "tcpip-forward"
	RequestCancelTCPIPForward = "cancel-tcpip-forward"
	RequestAgentForward       = "auth-agent-req@openssh.com"
	RequestKeepalive          = "keepalive@openssh.com"
	RequestNoMoreSessions     = "no-more-sessions@openssh.com"
)

// SubsystemSFTP is the standard SSH file-transfer subsystem name.
const SubsystemSFTP = "sftp"

// EnvironmentSSHAuthSock is the environment variable used by SSH agent forwarding.
const EnvironmentSSHAuthSock = "SSH_AUTH_SOCK"

// ConnectionProtocol handles the complete protocol lifecycle of one SSH
// connection after authentication and target resolution.
type ConnectionProtocol interface {
	// HandleChannel handles one channel opened by the SSH client.
	HandleChannel(conn cryptossh.Conn, channel cryptossh.NewChannel)
	// HandleGlobalRequest handles one connection-scoped request from the SSH client.
	HandleGlobalRequest(conn cryptossh.Conn, request *cryptossh.Request) (bool, []byte)
	// Close releases all protocol state owned by the connection.
	Close()
}

// Operation describes one authorization unit observed by a connection
// protocol. Payloads and environment values are intentionally excluded.
type Operation struct {
	ChannelType     string
	RequestType     string
	Command         string
	Subsystem       string
	DestinationHost string
	DestinationPort uint32
	OriginHost      string
	OriginPort      uint32
	BindHost        string
	BindPort        uint32
}

// OperationResult reports the protocol-visible result of an operation.
type OperationResult struct {
	Err            error
	ExitCode       *int
	ActualBindPort *uint32
}

// FinishOperation closes a started operation lifecycle.
type FinishOperation func(OperationResult)

// BeginOperationFunc authorizes an operation before its external effect. When
// an operation lifecycle was started, FinishOperation is returned even when
// the operation is denied so the protocol can report its wire-level result.
type BeginOperationFunc func(operation Operation) (FinishOperation, error)
