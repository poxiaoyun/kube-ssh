package server

import (
	"context"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
)

func TestBuildAccessSessionPolicy(t *testing.T) {
	opts := NewDefaultOptions()
	opts.Policy.Limits.EnvAllowlist = []string{"LANG", "LC_*", "PATH"}
	opts.Policy.Defaults.IdleTimeout = time.Hour
	opts.Policy.Defaults.MaxDuration = 8 * time.Hour
	opts.Policy.Limits.MaxDuration = 8 * time.Hour

	access := &sshv1.Access{
		Spec: sshv1.AccessSpec{
			Session: &sshv1.SessionPolicy{
				DefaultShell: "/bin/bash",
				EnvAllowlist: []string{
					"LC_TIME",
					"PATH",
					"SECRET_*",
				},
				IdleTimeout: &metav1.Duration{Duration: 30 * time.Minute},
				MaxDuration: &metav1.Duration{Duration: 12 * time.Hour},
			},
		},
	}

	policy := buildAccessSessionPolicy(opts, access)
	if policy.DefaultShell != "/bin/bash" {
		t.Fatalf("DefaultShell = %q, want /bin/bash", policy.DefaultShell)
	}
	if policy.IdleTimeout != 30*time.Minute {
		t.Fatalf("IdleTimeout = %s, want 30m", policy.IdleTimeout)
	}
	if policy.MaxDuration != 8*time.Hour {
		t.Fatalf("MaxDuration = %s, want 8h", policy.MaxDuration)
	}

	got := policy.filterEnv([]string{
		"LANG=C",
		"LC_TIME=C",
		"LC_NUMERIC=C",
		"PATH=/usr/bin",
		"SECRET_TOKEN=hidden",
		"SSH_AUTH_SOCK=/tmp/client-agent.sock",
	})
	want := []string{
		"LC_TIME=C",
		"PATH=/usr/bin",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterEnv() = %#v, want %#v", got, want)
	}
}

func TestBuildAccessSessionPolicyEnvInheritanceAndExplicitEmpty(t *testing.T) {
	opts := NewDefaultOptions()
	opts.Policy.Defaults.EnvAllowlist = []string{"*"}

	inherited := buildAccessSessionPolicy(opts, &sshv1.Access{
		Spec: sshv1.AccessSpec{Session: &sshv1.SessionPolicy{}},
	})
	if got := inherited.filterEnv([]string{"PATH=/usr/bin", "SECRET=1"}); !reflect.DeepEqual(got, []string{"PATH=/usr/bin", "SECRET=1"}) {
		t.Fatalf("inherited filterEnv() = %#v", got)
	}

	empty := buildAccessSessionPolicy(opts, &sshv1.Access{
		Spec: sshv1.AccessSpec{Session: &sshv1.SessionPolicy{EnvAllowlist: []string{}}},
	})
	if got := empty.filterEnv([]string{"PATH=/usr/bin"}); got != nil {
		t.Fatalf("explicit empty filterEnv() = %#v, want nil", got)
	}
}

func TestBuildAccessSessionPolicyAccessOnlyDurations(t *testing.T) {
	opts := NewDefaultOptions()
	opts.Policy.Defaults.IdleTimeout = 0
	opts.Policy.Defaults.MaxDuration = 0

	policy := buildAccessSessionPolicy(opts, &sshv1.Access{
		Spec: sshv1.AccessSpec{
			Session: &sshv1.SessionPolicy{
				IdleTimeout: &metav1.Duration{Duration: 10 * time.Minute},
				MaxDuration: &metav1.Duration{Duration: 2 * time.Hour},
			},
		},
	})

	if policy.IdleTimeout != 10*time.Minute {
		t.Fatalf("IdleTimeout = %s, want 10m", policy.IdleTimeout)
	}
	if policy.MaxDuration != 2*time.Hour {
		t.Fatalf("MaxDuration = %s, want 2h", policy.MaxDuration)
	}
}

func TestBuildAccessSessionPolicyOverridesDefaultsWithinLimits(t *testing.T) {
	opts := NewDefaultOptions()
	opts.Policy.Defaults.MaxDuration = time.Hour
	opts.Policy.Limits.MaxDuration = 4 * time.Hour
	policy := buildAccessSessionPolicy(opts, &sshv1.Access{Spec: sshv1.AccessSpec{Session: &sshv1.SessionPolicy{
		MaxDuration: &metav1.Duration{Duration: 2 * time.Hour},
	}}})
	if policy.MaxDuration != 2*time.Hour {
		t.Fatalf("MaxDuration = %s, want 2h", policy.MaxDuration)
	}
}

func TestBuildAccessSessionPolicyZeroDurationCannotDisableGlobal(t *testing.T) {
	opts := NewDefaultOptions()
	opts.Policy.Defaults.IdleTimeout = 20 * time.Minute
	opts.Policy.Defaults.MaxDuration = time.Hour

	policy := buildAccessSessionPolicy(opts, &sshv1.Access{
		Spec: sshv1.AccessSpec{
			Session: &sshv1.SessionPolicy{
				IdleTimeout: &metav1.Duration{},
				MaxDuration: &metav1.Duration{},
			},
		},
	})

	if policy.IdleTimeout != 20*time.Minute {
		t.Fatalf("IdleTimeout = %s, want 20m", policy.IdleTimeout)
	}
	if policy.MaxDuration != time.Hour {
		t.Fatalf("MaxDuration = %s, want 1h", policy.MaxDuration)
	}
}

func TestResolveSessionPolicyRejectsShellOutsideLimit(t *testing.T) {
	opts := NewDefaultOptions()
	opts.Policy.Limits.Shells = []string{"/bin/sh"}
	s := &Server{opts: opts, accessPolicy: fakeAccessPolicyGetter{access: &sshv1.Access{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "notebook"},
		Spec:       sshv1.AccessSpec{Session: &sshv1.SessionPolicy{DefaultShell: "/bin/bash"}},
	}}}
	_, err := s.resolveSessionPolicy(context.Background(), "default.notebook", map[string][]string{
		accesspolicy.ExtraAccessNamespace: {"default"},
		accesspolicy.ExtraAccessName:      {"notebook"},
	})
	if err == nil {
		t.Fatal("resolveSessionPolicy() error = nil, want shell limit rejection")
	}
}
