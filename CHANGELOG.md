# Changelog

## [1.1.0] - 2026-09-08

### Added

- Full SSH proxy support for External Access targets, including endpoint
  selection, authorization, and audit.
- Explicit upstream credentials with multiple private keys or passwords,
  inline values or Secret references, and pinned SSH host keys.

### Changed

- Separate gateway connection handling, Pod SSH execution through apiserver or
  node-local CRI, and upstream SSH proxying into independently owned packages.
- Exclude `ssh_extension` from the default capability list; enable it explicitly
  when upstream protocol extensions are required.
- Modernize Go code, generated clients, and sequential benchmarks.

### Fixed

- Default `insecureSkipVerification` to `false` in the Access schema so omitted
  values can be validated with pinned host keys.
- Correct the Access informer resource identifier and use context-aware
  list/watch callbacks.

### Upgrading from 1.0.0

This release includes configuration and Go API changes that are not
backward-compatible with 1.0.0. Review existing settings before upgrading.

| Previous setting | Replacement |
| --- | --- |
| `--backend-mode=kubernetes` | `--managed-transport=apiserver` |
| `--backend-mode=node` | `--managed-transport=cri` |
| `--node-port`, `--node-server-name`, `--node-ca-file`, `--node-cert-file`, `--node-key-file` | Corresponding `--cri-*` flags |
| `kubeSsh.backend.mode` | `kubeSsh.managed.transport`: `kubernetes` becomes `apiserver`, `node` becomes `cri` |
| `kubeSsh.backend.node` | `kubeSsh.managed.cri` |
| `kubeSsh.node.enabled` | Remove this setting; selecting the CRI transport enables the node DaemonSet |

External Access endpoints require a stable `name`, an upstream `username`, and
explicit upstream authentication. Replace singular `privateKey/privateKeyFrom`
fields with `privateKeys/privateKeysFrom` lists. Endpoint `labels` and `params`
have been removed. Configure pinned host public keys unless explicitly opting
into `insecureSkipVerification`. See the [External Access example](examples/access-external.yaml).

Review existing Access resources and update the
[Access CRD](deploy/kube-ssh/crds/ssh.xiaoshiai.cn_accesses.yaml) as part of the
upgrade. Helm does not upgrade existing CRDs from the chart's `crds/` directory;
see [Helm CRD guidance](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/).

Go consumers must update renamed packages and changed interfaces, including
`pkg/server` to `pkg/gateway` and the Pod SSH backend packages.

[1.1.0]: https://github.com/poxiaoyun/kube-ssh/compare/v1.0.0...v1.1.0
