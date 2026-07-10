package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/server"
	"xiaoshiai.cn/kube-ssh/pkg/version"
)

const exitFailure = 1

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitFailure)
	}
}

func newRootCmd() *cobra.Command {
	opts := server.NewDefaultOptions()
	var authorizedKeys []string
	var passwords []string

	cmd := &cobra.Command{
		Use:     "kube-ssh",
		Short:   "SSH gateway for Kubernetes pods",
		Version: version.Get().String(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := parseAuthorizedKeys(authorizedKeys)
			if err != nil {
				return err
			}
			opts.Authentication.AuthorizedKeys = entries
			passwordEntries, err := parsePasswords(passwords)
			if err != nil {
				return err
			}
			opts.Authentication.Passwords = passwordEntries

			ctx, stop := signalContext()
			defer stop()
			if err := server.Run(ctx, opts); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.ListenAddress, "listen-address", opts.ListenAddress, "SSH listen address")
	f.StringVar(&opts.Kubeconfig, "kubeconfig", opts.Kubeconfig, "path to kubeconfig")
	f.StringVar(&opts.HostKeyFile, "host-key-file", opts.HostKeyFile, "path to SSH host private key PEM file")
	f.DurationVar(&opts.SSH.IdleTimeout, "ssh-idle-timeout", opts.SSH.IdleTimeout, "maximum idle period for an SSH connection; 0 disables")
	f.DurationVar(&opts.SSH.MaxDuration, "ssh-max-duration", opts.SSH.MaxDuration, "maximum lifetime for an SSH connection; 0 disables")
	f.BoolVar(&opts.SSH.AgentForwarding, "ssh-agent-forwarding", opts.SSH.AgentForwarding, "enable SSH agent forwarding requests")
	f.StringVar(&opts.Metrics.ListenAddress, "metrics-listen-address", opts.Metrics.ListenAddress, "metrics HTTP listen address; empty disables metrics")
	f.StringVar(&opts.Metrics.Path, "metrics-path", opts.Metrics.Path, "metrics HTTP path")
	f.StringVar(&opts.Helper.Path, "helper-path", opts.Helper.Path, "path to local kube-ssh-helper binary for runtime injection")
	f.StringVar(&opts.Helper.RemoteDir, "helper-remote-dir", opts.Helper.RemoteDir, "remote writable directory used for helper injection")
	f.BoolVar(&opts.AccessPolicy.Enabled, "access-policy-enabled", opts.AccessPolicy.Enabled, "enable Access CRD authentication, target resolution, and authorization")
	f.StringVar(&opts.AccessPolicy.Namespace, "access-policy-namespace", opts.AccessPolicy.Namespace, "namespace to watch for Access CRDs; empty watches all namespaces")
	f.BoolVar(&opts.Authentication.Anonymous, "authentication-anonymous", opts.Authentication.Anonymous, "accept any SSH password or public key as anonymous")
	f.StringVar(&opts.Authentication.Webhook.Server, "authentication-webhook-server", opts.Authentication.Webhook.Server, "authentication webhook URL")
	f.StringVar(&opts.Authentication.Webhook.ProxyURL, "authentication-webhook-proxy-url", opts.Authentication.Webhook.ProxyURL, "authentication webhook proxy URL")
	f.StringVar(&opts.Authentication.Webhook.Token, "authentication-webhook-token", opts.Authentication.Webhook.Token, "authentication webhook bearer token")
	f.StringVar(&opts.Authentication.Webhook.Username, "authentication-webhook-username", opts.Authentication.Webhook.Username, "authentication webhook basic auth username")
	f.StringVar(&opts.Authentication.Webhook.Password, "authentication-webhook-password", opts.Authentication.Webhook.Password, "authentication webhook basic auth password")
	f.StringVar(&opts.Authentication.Webhook.CAFile, "authentication-webhook-ca-file", opts.Authentication.Webhook.CAFile, "authentication webhook CA file")
	f.StringVar(&opts.Authentication.Webhook.CertFile, "authentication-webhook-cert-file", opts.Authentication.Webhook.CertFile, "authentication webhook client certificate file")
	f.StringVar(&opts.Authentication.Webhook.KeyFile, "authentication-webhook-key-file", opts.Authentication.Webhook.KeyFile, "authentication webhook client key file")
	f.BoolVar(&opts.Authentication.Webhook.InsecureSkipTLSVerify, "authentication-webhook-insecure-skip-tls-verify", opts.Authentication.Webhook.InsecureSkipTLSVerify, "skip authentication webhook TLS verification")
	f.DurationVar(&opts.Authentication.Webhook.Timeout, "authentication-webhook-timeout", opts.Authentication.Webhook.Timeout, "authentication webhook request timeout")
	f.BoolVar(&opts.Authorization.AllowAll, "authorization-allow-all", opts.Authorization.AllowAll, "allow every authorized SSH operation")
	f.BoolVar(&opts.Authorization.KubernetesSAR, "authorization-kubernetes-sar", opts.Authorization.KubernetesSAR, "authorize SSH operations with Kubernetes SubjectAccessReview")
	f.StringVar(&opts.Authorization.Webhook.Server, "authorization-webhook-server", opts.Authorization.Webhook.Server, "authorization webhook URL")
	f.StringVar(&opts.Authorization.Webhook.ProxyURL, "authorization-webhook-proxy-url", opts.Authorization.Webhook.ProxyURL, "authorization webhook proxy URL")
	f.StringVar(&opts.Authorization.Webhook.Token, "authorization-webhook-token", opts.Authorization.Webhook.Token, "authorization webhook bearer token")
	f.StringVar(&opts.Authorization.Webhook.Username, "authorization-webhook-username", opts.Authorization.Webhook.Username, "authorization webhook basic auth username")
	f.StringVar(&opts.Authorization.Webhook.Password, "authorization-webhook-password", opts.Authorization.Webhook.Password, "authorization webhook basic auth password")
	f.StringVar(&opts.Authorization.Webhook.CAFile, "authorization-webhook-ca-file", opts.Authorization.Webhook.CAFile, "authorization webhook CA file")
	f.StringVar(&opts.Authorization.Webhook.CertFile, "authorization-webhook-cert-file", opts.Authorization.Webhook.CertFile, "authorization webhook client certificate file")
	f.StringVar(&opts.Authorization.Webhook.KeyFile, "authorization-webhook-key-file", opts.Authorization.Webhook.KeyFile, "authorization webhook client key file")
	f.BoolVar(&opts.Authorization.Webhook.InsecureSkipTLSVerify, "authorization-webhook-insecure-skip-tls-verify", opts.Authorization.Webhook.InsecureSkipTLSVerify, "skip authorization webhook TLS verification")
	f.DurationVar(&opts.Authorization.Webhook.Timeout, "authorization-webhook-timeout", opts.Authorization.Webhook.Timeout, "authorization webhook request timeout")
	f.StringArrayVar(&opts.Authorization.Allow, "authorization-allow", nil, "allow SSH capability, repeatable")
	f.StringArrayVar(&opts.Authorization.Deny, "authorization-deny", nil, "deny SSH capability, repeatable")
	f.StringArrayVar(&authorizedKeys, "authorized-key", nil, "authorized key mapping, format subject=authorized_keys-line")
	f.StringArrayVar(&passwords, "authentication-password", nil, "password authentication mapping, format subject=password")

	cmd.AddCommand(newVersionCmd())
	return cmd
}

func parseAuthorizedKeys(values []string) ([]authn.AuthorizedKeyEntry, error) {
	entries := make([]authn.AuthorizedKeyEntry, 0, len(values))
	for _, value := range values {
		entry, err := authn.ParseAuthorizedKeyEntry(value)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func parsePasswords(values []string) ([]authn.PasswordEntry, error) {
	entries := make([]authn.PasswordEntry, 0, len(values))
	for _, value := range values {
		entry, err := authn.ParsePasswordEntry(value)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println(version.Get().String())
			return nil
		},
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
