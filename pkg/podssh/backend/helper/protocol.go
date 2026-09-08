// Package helper implements the target-container companion protocol and commands.
package helper

import (
	"runtime"

	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/version"
)

const ProtocolVersion = "v1alpha1"

const (
	CommandVersion = "version"
	CommandServe   = "serve"
	CommandDial    = "dial"
	CommandSFTP    = "sftp"
	CommandSCP     = "scp"

	CapabilityDial          = "dial"
	CapabilityRemoteForward = "remote-forward"
	CapabilityAgentForward  = "agent-forward"
	CapabilitySFTP          = "sftp"
	CapabilitySCP           = "scp"
)

// Manifest is the helper version command's wire representation.
type Manifest struct {
	Version         string   `json:"version"`
	Commit          string   `json:"commit"`
	BuildDate       string   `json:"buildDate,omitempty"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	ProtocolVersion string   `json:"protocol"`
	Capabilities    []string `json:"capabilities"`
}

// CurrentManifest describes the helper build and the protocol capabilities
// available to its peer.
func CurrentManifest() Manifest {
	info := version.Get()
	return Manifest{
		Version:         info.GitVersion,
		Commit:          info.GitCommit,
		BuildDate:       info.BuildDate,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		ProtocolVersion: ProtocolVersion,
		Capabilities:    Capabilities(),
	}
}

// Capabilities returns an independent list of the helper's supported operations.
func Capabilities() []string {
	return []string{CapabilityDial, CapabilityRemoteForward, CapabilityAgentForward, CapabilitySFTP, CapabilitySCP}
}

// SPDY Close sends FIN; Reset also releases the local read side.
type spdyStreamHalfCloser struct {
	httpstream.Stream
}

func (s spdyStreamHalfCloser) CloseWrite() error { return s.Stream.Close() }
func (s spdyStreamHalfCloser) Close() error      { return s.Stream.Reset() }
