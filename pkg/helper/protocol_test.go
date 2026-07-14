package helper

import (
	"runtime"
	"slices"
	"testing"

	"xiaoshiai.cn/kube-ssh/pkg/version"
)

func TestCurrentManifest(t *testing.T) {
	manifest := CurrentManifest()
	info := version.Get()

	if manifest.Version != info.GitVersion {
		t.Fatalf("Version = %q, want %q", manifest.Version, info.GitVersion)
	}
	if manifest.Commit != info.GitCommit {
		t.Fatalf("Commit = %q, want %q", manifest.Commit, info.GitCommit)
	}
	if manifest.BuildDate != info.BuildDate {
		t.Fatalf("BuildDate = %q, want %q", manifest.BuildDate, info.BuildDate)
	}
	if manifest.OS != runtime.GOOS || manifest.Arch != runtime.GOARCH {
		t.Fatalf("platform = %s/%s, want %s/%s", manifest.OS, manifest.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if manifest.ProtocolVersion != ProtocolVersion {
		t.Fatalf("ProtocolVersion = %q, want %q", manifest.ProtocolVersion, ProtocolVersion)
	}
	if !slices.Equal(manifest.Capabilities, Capabilities()) {
		t.Fatalf("Capabilities = %#v, want %#v", manifest.Capabilities, Capabilities())
	}
}
