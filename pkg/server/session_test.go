package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"reflect"
	"testing"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
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

func TestResolveSessionUsesEffectiveSessionPolicy(t *testing.T) {
	ctx := newTestSSHContext()
	WithSessionRequestType(ctx, "exec")
	sess := &resolveSessionTestSession{
		ctx:        ctx,
		rawCommand: "locale",
		command:    []string{"locale"},
		env: []string{
			"LANG=C",
			"LC_TIME=C",
			"SECRET=hidden",
			"SSH_AUTH_SOCK=/tmp/client-agent.sock",
		},
		pty: gossh.Pty{
			Term:   "xterm-256color",
			Window: gossh.Window{Width: 120, Height: 40},
		},
		ptyOK: true,
	}
	sc := &sessionContext{
		ctx:     ctx,
		target:  targetFixturePtr(),
		session: sess,
		policy: effectiveSessionPolicy{
			DefaultShell:        "/bin/bash",
			globalEnvAllowlist:  []string{"*"},
			accessEnvConfigured: true,
			accessEnvAllowlist:  []string{"LANG", "SSH_AUTH_SOCK"},
		},
		agentForward: fakeSessionAgentForward{socketPath: "/tmp/kube-ssh-agent/agent.sock"},
	}

	spec, req, err := (&Server{}).resolveSession(sc)
	if err != nil {
		t.Fatalf("resolveSession() error = %v", err)
	}
	if spec.capability != authz.CapabilityExec {
		t.Fatalf("capability = %q, want exec", spec.capability)
	}
	wantCommand := []string{
		"env",
		"LANG=C",
		"SSH_AUTH_SOCK=/tmp/kube-ssh-agent/agent.sock",
		"TERM=xterm-256color",
		"/bin/bash",
		"-c",
		"locale",
	}
	if !reflect.DeepEqual(req.Command, wantCommand) {
		t.Fatalf("command = %#v, want %#v", req.Command, wantCommand)
	}
	if !req.TTY {
		t.Fatal("TTY = false, want true")
	}
	if req.TerminalSizeQueue == nil {
		t.Fatal("TerminalSizeQueue = nil")
	}
	size := req.TerminalSizeQueue.Next()
	if size == nil || size.Width != 120 || size.Height != 40 {
		t.Fatalf("initial terminal size = %#v, want 120x40", size)
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
	got := (effectiveSessionPolicy{globalEnvAllowlist: []string{"lang", "LC_*", "TERM_PROGRAM"}}).filterEnv(
		[]string{
			"LANG=en_US.UTF-8",
			"LC_TIME=C",
			"TERM_PROGRAM=iTerm.app",
			"PATH=/usr/bin",
			"MALFORMED",
		},
	)
	want := []string{
		"LANG=en_US.UTF-8",
		"LC_TIME=C",
		"TERM_PROGRAM=iTerm.app",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterEnv() = %#v, want %#v", got, want)
	}

	if got := (effectiveSessionPolicy{}).filterEnv([]string{"LANG=C"}); got != nil {
		t.Fatalf("filterEnv() with empty allowlist = %#v, want nil", got)
	}
}

type resolveSessionTestSession struct {
	ctx        gossh.Context
	rawCommand string
	command    []string
	env        []string
	pty        gossh.Pty
	ptyOK      bool
	stderr     bytes.Buffer
}

func (s *resolveSessionTestSession) Read([]byte) (int, error) { return 0, io.EOF }

func (s *resolveSessionTestSession) Write(p []byte) (int, error) { return len(p), nil }

func (s *resolveSessionTestSession) Close() error { return nil }

func (s *resolveSessionTestSession) CloseWrite() error { return nil }

func (s *resolveSessionTestSession) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}

func (s *resolveSessionTestSession) Stderr() io.ReadWriter { return &s.stderr }

func (s *resolveSessionTestSession) User() string { return s.ctx.User() }

func (s *resolveSessionTestSession) RemoteAddr() net.Addr { return s.ctx.RemoteAddr() }

func (s *resolveSessionTestSession) LocalAddr() net.Addr { return s.ctx.LocalAddr() }

func (s *resolveSessionTestSession) Environ() []string {
	return append([]string(nil), s.env...)
}

func (s *resolveSessionTestSession) Exit(int) error { return nil }

func (s *resolveSessionTestSession) Command() []string {
	return append([]string(nil), s.command...)
}

func (s *resolveSessionTestSession) RawCommand() string { return s.rawCommand }

func (s *resolveSessionTestSession) Subsystem() string { return "" }

func (s *resolveSessionTestSession) PublicKey() gossh.PublicKey { return nil }

func (s *resolveSessionTestSession) Context() gossh.Context { return s.ctx }

func (s *resolveSessionTestSession) Permissions() gossh.Permissions {
	return gossh.Permissions{}
}

func (s *resolveSessionTestSession) Pty() (gossh.Pty, <-chan gossh.Window, bool) {
	ch := make(chan gossh.Window)
	close(ch)
	return s.pty, ch, s.ptyOK
}

func (s *resolveSessionTestSession) Signals(chan<- gossh.Signal) {}

func (s *resolveSessionTestSession) Break(chan<- bool) {}

var _ gossh.Session = (*resolveSessionTestSession)(nil)
var _ cryptossh.Channel = (*resolveSessionTestSession)(nil)

type fakeSessionAgentForward struct {
	socketPath string
}

func (f fakeSessionAgentForward) SocketPath() string { return f.socketPath }

func (f fakeSessionAgentForward) Accept(context.Context) (ioproxy.HalfCloser, error) {
	return nil, io.EOF
}

func (f fakeSessionAgentForward) Close() error { return nil }
