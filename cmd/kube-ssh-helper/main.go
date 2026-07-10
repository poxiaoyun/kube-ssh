package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	command := "health"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	var err error
	switch command {
	case "health":
		err = runHealth()
	case "checksum":
		err = runChecksum()
	case "dial":
		err = runDial(ctx, os.Args[2:])
	case helper.CommandRuntime:
		err = runRuntime(ctx)
	case "sftp":
		err = runSFTP(ctx)
	case "scp":
		err = runSCP(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unsupported helper command: %s", command)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func runChecksum() error {
	checksum, err := helper.SelfChecksum()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, checksum)
	return nil
}

func runHealth() error {
	health := helper.Health{
		Version:      version.Get().String(),
		Protocol:     helper.ProtocolVersion,
		Capabilities: helper.DefaultCapabilities(),
	}
	return json.NewEncoder(os.Stdout).Encode(health)
}

func runSFTP(ctx context.Context) error {
	return helper.RunSFTP(ctx, os.Stdin, os.Stdout)
}

func runSCP(ctx context.Context, args []string) error {
	return helper.RunSCP(ctx, args, os.Stdin, os.Stdout)
}

func runRuntime(ctx context.Context) error {
	return helper.RunRuntime(ctx, os.Stdin, os.Stdout)
}

func runDial(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("dial", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	host := flags.String("host", "", "destination host")
	port := flags.Uint("port", 0, "destination port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return helper.RunDial(ctx, *host, *port, os.Stdin, os.Stdout)
}
