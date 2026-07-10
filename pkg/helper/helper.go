package helper

const ProtocolVersion = "v1alpha1"

const (
	CommandRuntime = "runtime"

	CapabilityHealth        = "health"
	CapabilityChecksum      = "checksum"
	CapabilityDial          = "dial"
	CapabilityRemoteForward = "remote-forward"
	CapabilityAgentForward  = "agent-forward"
	CapabilitySFTP          = "sftp"
	CapabilitySCP           = "scp"
)

type Health struct {
	Version      string   `json:"version"`
	Protocol     string   `json:"protocol"`
	Capabilities []string `json:"capabilities"`
}

func DefaultCapabilities() []string {
	return []string{CapabilityHealth, CapabilityChecksum, CapabilityDial, CapabilityRemoteForward, CapabilityAgentForward, CapabilitySFTP, CapabilitySCP}
}
