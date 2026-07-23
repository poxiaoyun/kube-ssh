package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"xiaoshiai.cn/kube-ssh/pkg/node"
	"xiaoshiai.cn/kube-ssh/pkg/version"
)

func main() {
	if err := newCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	options := node.ServerOptions{
		ListenAddress:      ":10443",
		ManagementAddress:  ":18080",
		HelperPath:         "/usr/local/bin/kube-ssh-helper",
		HelperRemoteDir:    "/tmp",
		ExpectedClientName: node.DefaultClientName,
		ShutdownTimeout:    30 * time.Second,
		RuntimeTimeout:     10 * time.Second,
	}
	command := &cobra.Command{
		Use: "kube-ssh-node", Short: "Node-local CRI streaming data plane for kube-ssh", Version: version.Get().String(),
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := node.Run(ctx, options); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	f := command.Flags()
	f.StringVar(&options.ListenAddress, "listen-address", options.ListenAddress, "mTLS streaming listen address")
	f.StringVar(&options.ManagementAddress, "management-listen-address", options.ManagementAddress, "health and metrics listen address")
	f.StringArrayVar(&options.RuntimeEndpoints, "runtime-endpoint", options.RuntimeEndpoints, "candidate CRI v1 runtime endpoint; repeatable, checked in order")
	f.StringVar(&options.HelperPath, "helper-path", options.HelperPath, "node-local helper binary")
	f.StringVar(&options.HelperRemoteDir, "helper-remote-dir", options.HelperRemoteDir, "target-container helper directory")
	f.StringVar(&options.TLSCAFile, "tls-ca-file", options.TLSCAFile, "CA used to verify gateway client certificates")
	f.StringVar(&options.TLSCertFile, "tls-cert-file", options.TLSCertFile, "node server certificate")
	f.StringVar(&options.TLSKeyFile, "tls-key-file", options.TLSKeyFile, "node server private key")
	f.StringVar(&options.ExpectedClientName, "tls-client-name", options.ExpectedClientName, "required gateway client certificate common name")
	f.DurationVar(&options.ShutdownTimeout, "shutdown-timeout", options.ShutdownTimeout, "maximum graceful shutdown duration")
	f.DurationVar(&options.RuntimeTimeout, "runtime-timeout", options.RuntimeTimeout, "startup CRI health check timeout")
	return command
}
