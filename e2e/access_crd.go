//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"time"
)

func (f *Framework) InstallAccessCRD() {
	f.T.Helper()
	crdPath := filepath.Join("..", "deploy", "kube-ssh", "crds", "ssh.xiaoshiai.cn_accesses.yaml")
	result := f.Kubectl("apply", "-f", crdPath)
	if result.Code != 0 {
		f.T.Fatalf("install Access CRD failed:\n%s", result.Dump())
	}
}

func (f *Framework) WaitAccessReady(name string, timeout time.Duration) {
	f.T.Helper()
	timeoutArg := fmt.Sprintf("--timeout=%s", timeout)
	result := f.Kubectl("-n", f.Namespace, "wait", "--for=condition=Ready", "access/"+name, timeoutArg)
	if result.Code == 0 {
		return
	}
	describe := f.Kubectl("-n", f.Namespace, "get", "access/"+name, "-o", "yaml")
	f.T.Fatalf("access/%s not ready:\n%s\n%s", name, result.Dump(), describe.Dump())
}
