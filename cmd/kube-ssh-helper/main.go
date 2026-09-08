package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
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
	case helper.CommandDial:
		err = runDial(ctx, os.Args[2:])
	case helper.CommandServe:
		err = helper.ServeConnection(ctx, os.Stdin, os.Stdout)
	case helper.CommandSFTP:
		err = helper.RunSFTP(ctx, os.Stdin, os.Stdout)
	case helper.CommandSCP:
		err = helper.RunSCP(ctx, os.Args[2:], os.Stdin, os.Stdout)
	default:
		err = fmt.Errorf("unsupported helper command: %s", command)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func runVersion() error {
	return json.NewEncoder(os.Stdout).
		Encode(helper.CurrentManifest())
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
