package server

import (
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/authn"
	webhookclient "xiaoshiai.cn/kube-ssh/pkg/webhook"
)

// Options configures the kube-ssh server.
type Options struct {
	ListenAddress      string                `json:"listenAddress,omitempty"`
	GatewayClassName   string                `json:"gatewayClassName,omitempty"`
	AdvertiseAddresses []string              `json:"advertiseAddresses,omitempty"`
	HostKeyFile        string                `json:"hostKeyFile,omitempty"`
	Kubeconfig         string                `json:"kubeconfig,omitempty"`
	Helper             HelperOptions         `json:"helper,omitempty"`
	AccessPolicy       AccessPolicyOptions   `json:"accessPolicy,omitempty"`
	Policy             PolicyOptions         `json:"policy,omitempty"`
	Metrics            MetricsOptions        `json:"metrics,omitempty"`
	Audit              AuditOptions          `json:"audit,omitempty"`
	Authentication     AuthenticationOptions `json:"authentication,omitempty"`
	Authorization      AuthorizationOptions  `json:"authorization,omitempty"`
}

type PolicyOptions struct {
	Defaults PolicyRuleOptions `json:"defaults,omitempty"`
	Limits   PolicyRuleOptions `json:"limits,omitempty"`
}

type PolicyRuleOptions struct {
	ContainerMode            string        `json:"containerMode,omitempty"`
	Capabilities             []string      `json:"capabilities,omitempty"`
	EnvAllowlist             []string      `json:"envAllowlist,omitempty"`
	LocalForwardDestinations []string      `json:"localForwardDestinations,omitempty"`
	RemoteForwardBinds       []string      `json:"remoteForwardBinds,omitempty"`
	DefaultShell             string        `json:"defaultShell,omitempty"`
	Shells                   []string      `json:"shells,omitempty"`
	IdleTimeout              time.Duration `json:"idleTimeout,omitempty"`
	MaxDuration              time.Duration `json:"maxDuration,omitempty"`
}

type AccessPolicyOptions struct {
	Enabled   bool   `json:"enabled,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type AuthenticationOptions struct {
	Anonymous      bool                       `json:"anonymous,omitempty"`
	AuthorizedKeys []authn.AuthorizedKeyEntry `json:"authorizedKeys,omitempty"`
	Passwords      []authn.PasswordEntry      `json:"passwords,omitempty"`
	Webhook        webhookclient.Options      `json:"webhook,omitempty"`
}

type AuthorizationOptions struct {
	AllowAll      bool                  `json:"allowAll,omitempty"`
	KubernetesSAR bool                  `json:"kubernetesSAR,omitempty"`
	Webhook       webhookclient.Options `json:"webhook,omitempty"`
}

type HelperOptions struct {
	Path      string `json:"path,omitempty"`
	RemoteDir string `json:"remoteDir,omitempty"`
}

type MetricsOptions struct {
	ListenAddress string `json:"listenAddress,omitempty"`
	Path          string `json:"path,omitempty"`
}

type AuditOptions struct {
	QueueSize    int           `json:"queueSize,omitempty"`
	FlushTimeout time.Duration `json:"flushTimeout,omitempty"`
}

func NewDefaultOptions() *Options {
	return &Options{
		ListenAddress: ":2222",
		Helper:        HelperOptions{RemoteDir: "/tmp"},
		Metrics:       MetricsOptions{Path: "/metrics"},
		Audit:         AuditOptions{QueueSize: 4096, FlushTimeout: 5 * time.Second},
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
				Capabilities:             []string{"*"},
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
