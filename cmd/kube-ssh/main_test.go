package main

import (
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func TestLoadEnv(t *testing.T) {
	t.Setenv("LISTEN_ADDRESS", ":2022")
	t.Setenv("POLICY_DEFAULT_IDLE_TIMEOUT", "15m")
	t.Setenv("POLICY_DEFAULT_CAPABILITY", "shell exec")
	var address string
	var timeout time.Duration
	var capabilities []string
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.StringVar(&address, "listen-address", ":22", "")
	flags.DurationVar(&timeout, "policy-default-idle-timeout", 0, "")
	flags.StringArrayVar(&capabilities, "policy-default-capability", []string{"*"}, "")

	if err := loadEnv(flags); err != nil {
		t.Fatalf("loadEnv() error = %v", err)
	}
	if address != ":2022" {
		t.Fatalf("listen address = %q, want :2022", address)
	}
	if timeout != 15*time.Minute {
		t.Fatalf("idle timeout = %s, want 15m", timeout)
	}
	if len(capabilities) != 2 || capabilities[0] != "shell" || capabilities[1] != "exec" {
		t.Fatalf("capabilities = %#v, want [shell exec]", capabilities)
	}
}

func TestLoadEnvPreservesQuotedSliceValue(t *testing.T) {
	t.Setenv("AUTHORIZED_KEY", `"alice=ssh-ed25519 AAAA comment"`)
	var keys []string
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.StringArrayVar(&keys, "authorized-key", nil, "")

	if err := loadEnv(flags); err != nil {
		t.Fatalf("loadEnv() error = %v", err)
	}
	if len(keys) != 1 || keys[0] != "alice=ssh-ed25519 AAAA comment" {
		t.Fatalf("authorized keys = %#v", keys)
	}
}

func TestLoadEnvDoesNotOverrideCommandLine(t *testing.T) {
	t.Setenv("LISTEN_ADDRESS", ":2022")
	var address string
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.StringVar(&address, "listen-address", ":22", "")
	if err := flags.Parse([]string{"--listen-address=:3022"}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if err := loadEnv(flags); err != nil {
		t.Fatalf("loadEnv() error = %v", err)
	}
	if address != ":3022" {
		t.Fatalf("listen address = %q, want command-line value :3022", address)
	}
}

func TestLoadEnvRejectsInvalidValue(t *testing.T) {
	t.Setenv("POLICY_DEFAULT_IDLE_TIMEOUT", "invalid")
	var timeout time.Duration
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.DurationVar(&timeout, "policy-default-idle-timeout", 0, "")

	if err := loadEnv(flags); err == nil {
		t.Fatal("loadEnv() error = nil, want invalid duration error")
	}
}

func TestPrintableFlagValueRedactsCredentials(t *testing.T) {
	var password string
	var tokens []string
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.StringVar(&password, "authentication-webhook-password", "secret", "")
	flags.StringArrayVar(&tokens, "authentication-password", []string{"alice=secret", "bob=secret"}, "")

	if got := printableFlagValue(flags.Lookup("authentication-webhook-password")); got != "<redacted>" {
		t.Fatalf("webhook password = %q, want redacted", got)
	}
	if got := printableFlagValue(flags.Lookup("authentication-password")); got != "<redacted:2 entries>" {
		t.Fatalf("password entries = %q, want redacted count", got)
	}
}
