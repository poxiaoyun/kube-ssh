# kube-ssh E2E

The E2E suite is guarded by the `e2e` build tag and exercises kube-ssh through real OpenSSH clients against a real Kubernetes cluster.

Default usage creates a kind cluster named `kube-ssh-e2e`:

```sh
make test-e2e
```

To reuse an existing cluster from the current kubeconfig:

```sh
KUBE_SSH_E2E_USE_EXISTING_CLUSTER=true make test-e2e
```

Required commands:

- `kubectl`
- `ssh`
- `scp`
- `sftp`
- `ssh-keygen`
- `kind`, unless `KUBE_SSH_E2E_USE_EXISTING_CLUSTER=true`

`make test-e2e` builds the gateway for the host OS and a Linux `kube-ssh-helper` for injection into kind pods. Override the helper path or architecture with:

```sh
KUBE_SSH_E2E_HELPER_PATH=/path/to/kube-ssh-helper make test-e2e
E2E_HELPER_GOARCH=arm64 make test-e2e
KUBE_SSH_E2E_KIND_IMAGE=kindest/node:v1.31.0 make test-e2e
E2E_KIND_CREATE_TIMEOUT=10m E2E_TIMEOUT=15m make test-e2e
```

Filter tests with Kubernetes-style variables:

```sh
make test-e2e FOCUS='TestSSH'
make test-e2e SKIP='TestSFTP'
make test-e2e TEST_ARGS='-count=1'
make test-e2e FOCUS='TestDoesNotExist' E2E_COUNT=0
```

The initial suite covers:

- SSH exec command and exit code propagation
- legacy SCP upload and download through `kube-ssh-helper scp`
- SFTP batch upload and download through `kube-ssh-helper sftp`
