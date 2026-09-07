package gateway

import (
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
	webhookclient "xiaoshiai.cn/kube-ssh/pkg/webhook"
)

const (
	// PodSSHTransportAPIServer uses Kubernetes pods/exec and pods/portforward.
	PodSSHTransportAPIServer = "apiserver"
	// PodSSHTransportCRI uses the node-local CRI data plane.
	PodSSHTransportCRI = "cri"
)

// Options configures the kube-ssh gateway.
type Options struct {
	ListenAddress      string
	GatewayClassName   string
	AdvertiseAddresses []string
	HostKeyFile        string
	Kubeconfig         string
	PodSSH             PodSSHOptions
	Helper             HelperOptions
	AccessPolicy       AccessPolicyOptions
	Policy             PolicyOptions
	Metrics            MetricsOptions
	Audit              AuditOptions
	Authentication     AuthenticationOptions
	Authorization      AuthorizationOptions
	SSHProxy           SSHProxyOptions
}

// SSHProxyOptions configures outbound SSH transport establishment.
type SSHProxyOptions struct {
	ConnectTimeout time.Duration
}

// PodSSHOptions selects the transport used by Pod SSH.
type PodSSHOptions struct {
	Transport string
	CRI       CRITransportOptions
}

// CRITransportOptions configures the gateway-to-node CRI transport.
type CRITransportOptions struct {
	Port       int
	ServerName string
	CAFile     string
	CertFile   string
	KeyFile    string
}

type PolicyOptions struct {
	Defaults PolicyRuleOptions
	Limits   PolicyRuleOptions
}

type PolicyRuleOptions struct {
	ContainerMode            string
	Capabilities             []string
	EnvAllowlist             []string
	LocalForwardDestinations []string
	RemoteForwardBinds       []string
	DefaultShell             string
	Shells                   []string
	IdleTimeout              time.Duration
	MaxDuration              time.Duration
}

type AccessPolicyOptions struct {
	Enabled   bool
	Namespace string
}

type AuthenticationOptions struct {
	Anonymous      bool
	AuthorizedKeys []authn.AuthorizedKeyEntry
	Passwords      []authn.PasswordEntry
	Webhook        webhookclient.Options
}

type AuthorizationOptions struct {
	AllowAll      bool
	KubernetesSAR bool
	Webhook       webhookclient.Options
}

type HelperOptions struct {
	Path      string
	RemoteDir string
}

type MetricsOptions struct {
	ListenAddress string
	Path          string
}

type AuditOptions struct {
	QueueSize    int
	FlushTimeout time.Duration
}

func NewDefaultOptions() *Options {
	return &Options{
		ListenAddress: ":2222",
		PodSSH: PodSSHOptions{Transport: PodSSHTransportAPIServer, CRI: CRITransportOptions{
			Port: 10443, ServerName: "kube-ssh-node.kube-ssh.svc",
		}},
		Helper:  HelperOptions{RemoteDir: "/tmp"},
		Metrics: MetricsOptions{Path: "/metrics"},
		Audit:   AuditOptions{QueueSize: 4096, FlushTimeout: 5 * time.Second},
		SSHProxy: SSHProxyOptions{
			ConnectTimeout: sshproxy.DefaultConnectTimeout,
		},
		Authentication: AuthenticationOptions{
			Webhook: webhookclient.Options{Timeout: webhookclient.DefaultTimeout},
		},
		Authorization: AuthorizationOptions{
			AllowAll: true,
			Webhook:  webhookclient.Options{Timeout: webhookclient.DefaultTimeout},
		},
		Policy: PolicyOptions{
			Defaults: PolicyRuleOptions{
				ContainerMode:            "KubernetesDefault",
				Capabilities:             []string{"shell", "exec", "scp", "sftp", "local_forward", "remote_forward", "agent_forward"},
				EnvAllowlist:             []string{"*"},
				LocalForwardDestinations: []string{"*"},
				RemoteForwardBinds:       []string{"*"},
				DefaultShell:             "/bin/sh",
			},
			Limits: PolicyRuleOptions{
				ContainerMode:            "All",
				Capabilities:             []string{"*"},
				EnvAllowlist:             []string{"*"},
				LocalForwardDestinations: []string{"*"},
				RemoteForwardBinds:       []string{"*"},
				Shells:                   []string{"*"},
			},
		},
	}
}
