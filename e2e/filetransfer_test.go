//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSCPUploadDownload(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"

	local := filepath.Join(f.WorkDir, "scp-local.txt")
	downloaded := filepath.Join(f.WorkDir, "scp-downloaded.txt")
	content := "scp-content\n"
	if err := os.WriteFile(local, []byte(content), 0o600); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	remoteFile := f.RemotePath("scp.txt")
	upload := f.SCP(local, user+"@kube-ssh-e2e:"+remoteFile)
	if upload.Code != 0 {
		t.Fatalf("scp upload failed:\n%s", upload.Dump())
	}
	download := f.SCP(user+"@kube-ssh-e2e:"+remoteFile, downloaded)
	if download.Code != 0 {
		t.Fatalf("scp download failed:\n%s", download.Dump())
	}
	assertFileContent(t, downloaded, content)
}

func TestSCPRecursiveUploadDownload(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"

	localRoot := filepath.Join(f.WorkDir, "scp-tree")
	nested := filepath.Join(localRoot, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("create local tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localRoot, "root.txt"), []byte("root\n"), 0o640); err != nil {
		t.Fatalf("write root file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "child.txt"), []byte("child\n"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}

	remoteRoot := f.RemotePath("scp-tree")
	upload := f.SCP("-r", localRoot, user+"@kube-ssh-e2e:"+remoteRoot)
	if upload.Code != 0 {
		t.Fatalf("scp recursive upload failed:\n%s", upload.Dump())
	}
	downloadRoot := filepath.Join(f.WorkDir, "scp-recursive-download")
	if err := os.MkdirAll(downloadRoot, 0o755); err != nil {
		t.Fatalf("create download dir: %v", err)
	}
	download := f.SCP("-r", user+"@kube-ssh-e2e:"+remoteRoot, downloadRoot)
	if download.Code != 0 {
		t.Fatalf("scp recursive download failed:\n%s", download.Dump())
	}

	assertFileContent(t, filepath.Join(downloadRoot, filepath.Base(remoteRoot), "root.txt"), "root\n")
	assertFileContent(t, filepath.Join(downloadRoot, filepath.Base(remoteRoot), "nested", "child.txt"), "child\n")
}

func TestSFTPBatch(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"

	local := filepath.Join(f.WorkDir, "sftp-local.txt")
	downloaded := filepath.Join(f.WorkDir, "sftp-downloaded.txt")
	content := "sftp-content\n"
	if err := os.WriteFile(local, []byte(content), 0o600); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	remoteDir := f.RemotePath("sftp-dir")
	batch := strings.Join([]string{
		"mkdir " + remoteDir,
		"put " + local + " " + remoteDir + "/file.txt",
		"ls " + remoteDir + "/file.txt",
		"rename " + remoteDir + "/file.txt " + remoteDir + "/renamed.txt",
		"get " + remoteDir + "/renamed.txt " + downloaded,
		"rm " + remoteDir + "/renamed.txt",
		"rmdir " + remoteDir,
		"",
	}, "\n")
	result := f.SFTPBatch(user, batch)
	if result.Code != 0 {
		t.Fatalf("sftp batch failed:\n%s", result.Dump())
	}
	assertFileContent(t, downloaded, content)
}
