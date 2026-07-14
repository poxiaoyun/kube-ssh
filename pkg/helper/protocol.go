package helper

import (
	"runtime"

	"xiaoshiai.cn/kube-ssh/pkg/version"
)

const ProtocolVersion = "v1alpha1"

const (
	CommandVersion = "version"
	CommandServe   = "serve"

	CapabilityDial          = "dial"
	CapabilityRemoteForward = "remote-forward"
	CapabilityAgentForward  = "agent-forward"
	CapabilitySFTP          = "sftp"
	CapabilitySCP           = "scp"
)

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

func Capabilities() []string {
	return []string{CapabilityDial, CapabilityRemoteForward, CapabilityAgentForward, CapabilitySFTP, CapabilitySCP}
}
