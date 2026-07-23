package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/anmitsu/go-shlex"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return loadEnv(cmd.Flags())
		},
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
			logEffectiveConfig(cmd.Flags())

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
	f.StringVar(&opts.GatewayClassName, "gateway-class-name", opts.GatewayClassName, "gateway class name; empty handles only Access objects without a class")
	f.StringArrayVar(&opts.AdvertiseAddresses, "advertise-address", opts.AdvertiseAddresses, "gateway address to publish in matching Access status, in host:port form; repeatable")
	f.StringVar(&opts.Kubeconfig, "kubeconfig", opts.Kubeconfig, "path to kubeconfig")
	f.StringVar(&opts.HostKeyFile, "host-key-file", opts.HostKeyFile, "path to SSH host private key PEM file")
	f.StringVar(&opts.Backend.Mode, "backend-mode", opts.Backend.Mode, "data-plane backend: kubernetes or node")
	f.IntVar(&opts.Backend.Node.Port, "node-port", opts.Backend.Node.Port, "node data-plane HTTPS streaming port")
	f.StringVar(&opts.Backend.Node.ServerName, "node-server-name", opts.Backend.Node.ServerName, "node data-plane TLS server name")
	f.StringVar(&opts.Backend.Node.CAFile, "node-ca-file", opts.Backend.Node.CAFile, "node data-plane CA bundle")
	f.StringVar(&opts.Backend.Node.CertFile, "node-cert-file", opts.Backend.Node.CertFile, "gateway client certificate for node data planes")
	f.StringVar(&opts.Backend.Node.KeyFile, "node-key-file", opts.Backend.Node.KeyFile, "gateway client key for node data planes")
	f.StringVar(&opts.Policy.Defaults.ContainerMode, "policy-default-container-mode", opts.Policy.Defaults.ContainerMode, "default container policy: KubernetesDefault, All, or None")
	f.StringArrayVar(&opts.Policy.Defaults.Capabilities, "policy-default-capability", opts.Policy.Defaults.Capabilities, "default SSH capability; repeatable, * allows all")
	f.StringArrayVar(&opts.Policy.Defaults.EnvAllowlist, "policy-default-env", opts.Policy.Defaults.EnvAllowlist, "default client environment pattern; repeatable")
	f.StringArrayVar(&opts.Policy.Defaults.LocalForwardDestinations, "policy-default-local-forward", opts.Policy.Defaults.LocalForwardDestinations, "default local forward host:port expression; repeatable")
	f.StringArrayVar(&opts.Policy.Defaults.RemoteForwardBinds, "policy-default-remote-forward", opts.Policy.Defaults.RemoteForwardBinds, "default remote forward bind expression; repeatable")
	f.StringVar(&opts.Policy.Defaults.DefaultShell, "policy-default-shell", opts.Policy.Defaults.DefaultShell, "default shell executable")
	f.DurationVar(&opts.Policy.Defaults.IdleTimeout, "policy-default-idle-timeout", opts.Policy.Defaults.IdleTimeout, "default maximum idle period; 0 disables")
	f.DurationVar(&opts.Policy.Defaults.MaxDuration, "policy-default-max-duration", opts.Policy.Defaults.MaxDuration, "default maximum connection lifetime; 0 disables")
	f.StringVar(&opts.Policy.Limits.ContainerMode, "policy-limit-container-mode", opts.Policy.Limits.ContainerMode, "container policy limit: KubernetesDefault, All, or None")
	f.StringArrayVar(&opts.Policy.Limits.Capabilities, "policy-limit-capability", opts.Policy.Limits.Capabilities, "allowed SSH capability limit; repeatable, * allows all")
	f.StringArrayVar(&opts.Policy.Limits.EnvAllowlist, "policy-limit-env", opts.Policy.Limits.EnvAllowlist, "allowed client environment limit; repeatable")
	f.StringArrayVar(&opts.Policy.Limits.LocalForwardDestinations, "policy-limit-local-forward", opts.Policy.Limits.LocalForwardDestinations, "allowed local forward host:port limit; repeatable")
	f.StringArrayVar(&opts.Policy.Limits.RemoteForwardBinds, "policy-limit-remote-forward", opts.Policy.Limits.RemoteForwardBinds, "allowed remote forward bind limit; repeatable")
	f.StringArrayVar(&opts.Policy.Limits.Shells, "policy-limit-shell", opts.Policy.Limits.Shells, "allowed shell executable limit; repeatable")
	f.DurationVar(&opts.Policy.Limits.IdleTimeout, "policy-limit-idle-timeout", opts.Policy.Limits.IdleTimeout, "maximum permitted idle timeout; 0 disables the limit")
	f.DurationVar(&opts.Policy.Limits.MaxDuration, "policy-limit-max-duration", opts.Policy.Limits.MaxDuration, "maximum permitted connection lifetime; 0 disables the limit")
	f.StringVar(&opts.Metrics.ListenAddress, "metrics-listen-address", opts.Metrics.ListenAddress, "metrics and health HTTP listen address; empty disables the server")
	f.StringVar(&opts.Metrics.Path, "metrics-path", opts.Metrics.Path, "metrics HTTP path")
	f.IntVar(&opts.Audit.QueueSize, "audit-queue-size", opts.Audit.QueueSize, "maximum queued audit events before new events are dropped")
	f.DurationVar(&opts.Audit.FlushTimeout, "audit-flush-timeout", opts.Audit.FlushTimeout, "maximum shutdown time for flushing audit events")
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
	f.StringArrayVar(&authorizedKeys, "authorized-key", nil, "authorized key mapping, format subject=authorized_keys-line")
	f.StringArrayVar(&passwords, "authentication-password", nil, "password authentication mapping, format subject=password")

	cmd.AddCommand(newVersionCmd())
	return cmd
}

func logEffectiveConfig(flags *pflag.FlagSet) {
	attrs := make([]any, 0, flags.NFlag()*2)
	flags.VisitAll(func(flag *pflag.Flag) {
		attrs = append(attrs, slog.String(flag.Name, printableFlagValue(flag)))
	})
	slog.Info("effective configuration", attrs...)
}

func printableFlagValue(flag *pflag.Flag) string {
	name := strings.ToLower(flag.Name)
	if name == "authorized-key" || name == "authentication-password" {
		if slice, ok := flag.Value.(pflag.SliceValue); ok {
			return fmt.Sprintf("<redacted:%d entries>", len(slice.GetSlice()))
		}
		return "<redacted>"
	}
	if strings.Contains(name, "password") || strings.HasSuffix(name, "token") {
		if flag.Value.String() == "" {
			return ""
		}
		return "<redacted>"
	}
	return flag.Value.String()
}

func loadEnv(flags *pflag.FlagSet) error {
	var loadErr error
	flags.VisitAll(func(flag *pflag.Flag) {
		if loadErr != nil || flag.Changed {
			return
		}
		name := strings.ToUpper(strings.ReplaceAll(flag.Name, "-", "_"))
		value, ok := os.LookupEnv(name)
		if !ok {
			return
		}
		if err := setEnvFlagValue(flag, value); err != nil {
			loadErr = fmt.Errorf("parse environment variable %s: %w", name, err)
		}
	})
	return loadErr
}

func setEnvFlagValue(flag *pflag.Flag, value string) error {
	slice, ok := flag.Value.(pflag.SliceValue)
	if !ok {
		return flag.Value.Set(value)
	}
	values, err := shlex.Split(value, true)
	if err != nil {
		return err
	}
	return slice.Replace(values)
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
