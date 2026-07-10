package server

import (
	"reflect"
	"testing"

	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/kube"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestBuildCommand(t *testing.T) {
	tests := []struct {
		name         string
		isExec       bool
		rawCmd       string
		env          []string
		defaultShell string
		want         []string
	}{
		{
			name:         "shell",
			defaultShell: "/bin/sh",
			want:         []string{"/bin/sh"},
		},
		{
			name:         "exec uses configured shell",
			isExec:       true,
			rawCmd:       "echo hi",
			defaultShell: "/bin/bash",
			want:         []string{"/bin/bash", "-c", "echo hi"},
		},
		{
			name:         "empty exec remains exec",
			isExec:       true,
			defaultShell: "/bin/sh",
			want:         []string{"/bin/sh", "-c", ""},
		},
		{
			name:         "env prefix",
			isExec:       true,
			rawCmd:       "locale",
			env:          []string{"LANG=C"},
			defaultShell: "/bin/sh",
			want:         []string{"env", "LANG=C", "/bin/sh", "-c", "locale"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCommand(tt.isExec, tt.rawCmd, tt.env, tt.defaultShell)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("buildCommand() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSessionAttributes(t *testing.T) {
	tests := []struct {
		name        string
		requestType string
		argv        []string
		command     string
		want        authz.Capability
	}{
		{
			name:        "shell",
			requestType: "shell",
			want:        authz.CapabilityShell,
		},
		{
			name:        "exec",
			requestType: "exec",
			argv:        []string{"echo", "hi"},
			command:     "echo hi",
			want:        authz.CapabilityExec,
		},
		{
			name:        "scp upload",
			requestType: "exec",
			argv:        []string{"scp", "-t", "/tmp/file"},
			command:     "scp -t /tmp/file",
			want:        authz.CapabilitySCP,
		},
		{
			name:        "scp download",
			requestType: "exec",
			argv:        []string{"/usr/bin/scp", "-f", "/tmp/file"},
			command:     "scp -f /tmp/file",
			want:        authz.CapabilitySCP,
		},
		{
			name:        "ordinary scp command",
			requestType: "exec",
			argv:        []string{"scp", "--help"},
			command:     "scp --help",
			want:        authz.CapabilityExec,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, attrs := sessionAttributes(targetFixture(), tt.requestType, tt.argv, tt.command)
			if got != tt.want {
				t.Fatalf("sessionAttributes capability = %q, want %q", got, tt.want)
			}
			if attrs.Action != string(tt.want) {
				t.Fatalf("sessionAttributes action = %q, want %q", attrs.Action, tt.want)
			}
			if attrs.Path != "kube/namespaces/default/pods/nginx/containers/app" {
				t.Fatalf("sessionAttributes path = %q", attrs.Path)
			}
			if tt.command != "" && !reflect.DeepEqual(attrs.Extra["command"], []string{tt.command}) {
				t.Fatalf("sessionAttributes command extra = %#v, want %q", attrs.Extra["command"], tt.command)
			}
		})
	}
}

func targetFixture() target.Target {
	return *kube.NewTarget("default", "nginx", "app")
}

func TestWindowSizeQueue(t *testing.T) {
	ch := make(chan gossh.Window, 1)
	ch <- gossh.Window{Width: 120, Height: 40}
	close(ch)

	queue := &windowSizeQueue{initW: 80, initH: 24, ch: ch}

	first := queue.Next()
	if first == nil || first.Width != 80 || first.Height != 24 {
		t.Fatalf("first size = %#v, want 80x24", first)
	}

	second := queue.Next()
	if second == nil || second.Width != 120 || second.Height != 40 {
		t.Fatalf("second size = %#v, want 120x40", second)
	}

	if got := queue.Next(); got != nil {
		t.Fatalf("third size = %#v, want nil", got)
	}
}

func TestFilterEnv(t *testing.T) {
	got := filterEnv(
		[]string{
			"LANG=en_US.UTF-8",
			"LC_TIME=C",
			"TERM_PROGRAM=iTerm.app",
			"PATH=/usr/bin",
			"MALFORMED",
		},
		[]string{"lang", "LC_*", "TERM_PROGRAM"},
	)
	want := []string{
		"LANG=en_US.UTF-8",
		"LC_TIME=C",
		"TERM_PROGRAM=iTerm.app",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterEnv() = %#v, want %#v", got, want)
	}

	if got := filterEnv([]string{"LANG=C"}, nil); got != nil {
		t.Fatalf("filterEnv() with empty allowlist = %#v, want nil", got)
	}
}
