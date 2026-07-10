package server

import (
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/authn"
	webhookclient "xiaoshiai.cn/kube-ssh/pkg/webhook"
)

// Options configures the kube-ssh server.
type Options struct {
	ListenAddress  string                `json:"listenAddress,omitempty"`
	HostKeyFile    string                `json:"hostKeyFile,omitempty"`
	Kubeconfig     string                `json:"kubeconfig,omitempty"`
	Helper         HelperOptions         `json:"helper,omitempty"`
	AccessPolicy   AccessPolicyOptions   `json:"accessPolicy,omitempty"`
	SSH            SSHOptions            `json:"ssh,omitempty"`
	Metrics        MetricsOptions        `json:"metrics,omitempty"`
	Authentication AuthenticationOptions `json:"authentication,omitempty"`
	Authorization  AuthorizationOptions  `json:"authorization,omitempty"`
	EnvAllowlist   []string              `json:"envAllowlist,omitempty"`
	DefaultShell   string                `json:"defaultShell,omitempty"`
}

type SSHOptions struct {
	IdleTimeout     time.Duration `json:"idleTimeout,omitempty"`
	MaxDuration     time.Duration `json:"maxDuration,omitempty"`
	AgentForwarding bool          `json:"agentForwarding,omitempty"`
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
	Allow         []string              `json:"allow,omitempty"`
	Deny          []string              `json:"deny,omitempty"`
}

type HelperOptions struct {
	Path      string `json:"path,omitempty"`
	RemoteDir string `json:"remoteDir,omitempty"`
}

type MetricsOptions struct {
	ListenAddress string `json:"listenAddress,omitempty"`
	Path          string `json:"path,omitempty"`
}

func NewDefaultOptions() *Options {
	return &Options{
		ListenAddress: ":2222",
		Helper:        HelperOptions{RemoteDir: "/tmp"},
		Metrics:       MetricsOptions{Path: "/metrics"},
		Authentication: AuthenticationOptions{
			Webhook: webhookclient.Options{Timeout: webhookclient.DefaultTimeout},
		},
		Authorization: AuthorizationOptions{
			AllowAll: true,
			Webhook:  webhookclient.Options{Timeout: webhookclient.DefaultTimeout},
		},
		EnvAllowlist: []string{"*"},
		DefaultShell: "/bin/sh",
	}
}
