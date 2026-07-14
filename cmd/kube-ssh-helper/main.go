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
	"xiaoshiai.cn/kube-ssh/pkg/spdyrpc"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	command := helper.CommandVersion
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	var err error
	switch command {
	case helper.CommandVersion:
		err = runVersion()
	case "dial":
		err = runDial(ctx, os.Args[2:])
	case helper.CommandServe:
		err = serveConnection(ctx)
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

func runVersion() error {
	return json.NewEncoder(os.Stdout).Encode(helper.CurrentManifest())
}

func runSFTP(ctx context.Context) error {
	return helper.RunSFTP(ctx, os.Stdin, os.Stdout)
}

func runSCP(ctx context.Context, args []string) error {
	return helper.RunSCP(ctx, args, os.Stdin, os.Stdout)
}

func serveConnection(ctx context.Context) error {
	return helper.ServeConnection(ctx, os.Stdin, os.Stdout, spdyrpc.ConnectionOptions{})
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
