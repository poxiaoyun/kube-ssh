# kube-ssh

kube-ssh exposes Kubernetes Pods through standard OpenSSH clients without
running `sshd` in workload containers.

## Architecture

```text
+------------------+
| OpenSSH clients  |
| ssh / scp / sftp |
+--------+---------+
         |
         v
+------------------------------------------------------------------------+
| kube-ssh gateway                                                       |
|                                                                        |
| +------------+   +--------+   +------------------+     +-------------+ |
| | SSH server |-->| authn  |-->| target selection |     |             | |
| +------------+   +--------+   +---------+--------+     |             | |
|                                          |             |             | |
|                                          v             |    audit    | |
|                                  +-------------+       |             | |
|                                  | authz       |       |             | |
|                                  +------+------+       |             | |
|                                         |              |             | |
|                                         v              |             | |
|                                  +---------------+     |             | |
|                                  | session bridge|     |             | |
|                                  +-------+-------+     +-------------+ |
+------------------------------------------+-----------------------------+
                                           |
                                           v
+------------------------------------------------------------------------+
| Kubernetes API server                                                  |
| pods/exec + pods/portforward                                           |
+-----------+----------------------------------+-------------------------+
            |                                  |
            | pods/exec stdio                  | pods/portforward streams
            v                                  v
+------------------------------------------------------------------------+
| Target Pod / container                                                 |
|                                                                        |
| +-------------------+              +-------------------------------+   |
| | shell / exec      |              | local-forward target port     |   |
| +-------------------+              +-------------------------------+   |
|                                                                        |
| +------------------------------------------------------------------+   |
| | kube-ssh-helper                                                  |   |
| |                                                                  |   |
| | +------------+   +----------------+   +-----------------------+  |   |
| | | sftp / scp |   | remote-forward |   | agent-forward         |  |   |
| | +------------+   +----------------+   +-----------------------+  |   |
| +------------------------------------------------------------------+   |
+------------------------------------------------------------------------+
```

## Features

- Access any Pod/container with standard OpenSSH clients, without application
  changes or a workload-local `sshd`.
- Select targets dynamically and bridge SSH sessions through Kubernetes-native
  APIs.
- Control credentials, authorization, and SSH capabilities with workload-local
  access policies.
- Centralize structured audit logs for all SSH operations.

## Audit

kube-ssh writes versioned JSON audit events to stdout for connection,
authentication, target resolution, authorization, and operation lifecycles.
Events carry UUIDv7 connection and operation IDs. Passwords, tokens,
key material, Secret values, and environment values are not recorded.

Audit delivery is asynchronous. `kube_ssh_audit_events_total` reports written,
dropped, and sink-error outcomes. Configure the queue and shutdown drain with
`--audit-queue-size` and `--audit-flush-timeout`.

## Metrics and Health

The management HTTP server exposes Prometheus metrics at `/metrics`, liveness
at `/healthz`, and readiness at `/readyz`. The Helm chart enables it on container
port `8080`; set `kubeSsh.metrics.enabled=false` to disable it and use SSH TCP
probes instead.

## OpenSSH Compatibility

| SSH feature                                                                | kube-ssh                                                |
| -------------------------------------------------------------------------- | ------------------------------------------------------- |
| Public key and password authentication                                     | Supported through configured authentication providers   |
| Interactive shell (`session` / `shell`)                                    | Kubernetes `pods/exec` with PTY                         |
| Command execution (`session` / `exec`)                                     | Kubernetes `pods/exec`                                  |
| Terminal signals                                                           | Kubernetes `pods/exec` with PTY                         |
| PTY and resize (`pty-req` / `window-change`)                               | Kubernetes `pods/exec`                                  |
| Exit status (`exit-status`)                                                | Kubernetes `pods/exec` exit code                        |
| Environment variables (`env`)                                              | Supported with global and per-Access allowlists         |
| SFTP (`session` / `subsystem: sftp`)                                       | `kube-ssh-helper`                                       |
| Legacy SCP (`session` / `exec`)                                            | Compatibility only via `kube-ssh-helper`; prefer SFTP   |
| Pod-local port forwarding (`direct-tcpip` to localhost/loopback)           | Kubernetes `pods/portforward`                           |
| Network port forwarding (`direct-tcpip` to a hostname/IP)                  | Dialed from the target container by `kube-ssh-helper`   |
| Dynamic forwarding / SOCKS (`direct-tcpip`)                                | OpenSSH client SOCKS over local forwarding              |
| Remote port forwarding (`tcpip-forward` / `forwarded-tcpip`)               | Listener through `kube-ssh-helper`                      |
| Agent forwarding (`auth-agent-req@openssh.com` / `auth-agent@openssh.com`) | Agent socket through `kube-ssh-helper`                  |
| X11 forwarding (`x11-req` / `x11`)                                         | Planned                                                 |
| Session recording                                                          | Planned                                                 |
| `ssh-copy-id` / `authorized_keys` enrollment                               | Not supported; credentials are managed through `Access` |

## Installation

Install with Helm:

```bash
helm install kube-ssh ./deploy/kube-ssh \
  --namespace kube-ssh \
  --create-namespace
```

For a stable server identity, provide an Ed25519 host key through a Kubernetes
Secret and set `kubeSsh.hostKey.existingSecret`. Without a configured host key,
kube-ssh generates an ephemeral key when it starts.

SSH is exposed through NodePort `30022` by default. Override the Service type
or port when needed:

```bash
helm install kube-ssh ./deploy/kube-ssh \
  --namespace kube-ssh \
  --create-namespace \
  --set kubeSsh.service.type=NodePort \
  --set kubeSsh.service.nodePorts.ssh=30022
```

The chart includes the `Access` CRD under `crds/`. You can also apply the
rendered install manifest directly:

```bash
kubectl apply -f deploy/install.yaml
```

Every `kube-ssh` command-line flag can also be set through an environment
variable by uppercasing its name and replacing `-` with `_`. Command-line
flags take precedence over environment variables.

```bash
LISTEN_ADDRESS=:2222 \
ACCESS_POLICY_ENABLED=true \
AUTHORIZATION_KUBERNETES_SAR=true \
kube-ssh
```

Repeatable flags use whitespace-separated environment values. Quote an item
when it contains whitespace or shell-special characters.

## Usage

Deploy a workload and an `Access` object in the same namespace:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: notebook
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: notebook
  template:
    metadata:
      labels:
        app: notebook
    spec:
      containers:
        - name: app
          image: alpine:3.22
          command: ["sh", "-c", "sleep infinity"]
---
apiVersion: ssh.xiaoshiai.cn/v1
kind: Access
metadata:
  name: notebook
  namespace: default
spec:
  selector:
    app: notebook
  containers:
    - app
  strategy:
    type: RoundRobin
  credentials:
    - username: alice
      groups:
        - dev
      publicKeys:
        - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJjO+3uspsX3jrw5xIZmdn3TJJQLrZ68kALV3/9hRXM kube-ssh-example
```

Replace the example public key with your own before applying the manifest.

Check the Access status:

```bash
kubectl get access -n default notebook
```

Connect through the Access target:

```bash
ssh -i ~/.ssh/id_ed25519 default.notebook@<kube-ssh-host>
```

For CRD authentication, the SSH username is the target locator:

- `default.notebook` selects the `notebook` Access in the `default` namespace.
- `default.notebook.app` additionally selects the `app` container from the Pods
  matched by that Access.
- The authenticated user identity comes from the matched credential entry, for example `credentials[0].username: alice`.

The Access username formats are:

- `namespace.access`
- `namespace.access.container`

An Access that selects multiple Pods can also target one Pod explicitly:

```bash
ssh -i ~/.ssh/id_ed25519 'default.notebook~notebook-0'@<kube-ssh-host>
ssh -i ~/.ssh/id_ed25519 'default.notebook~notebook-1.app'@<kube-ssh-host>
```

The explicit Pod username formats are:

- `namespace.access~pod`
- `namespace.access~pod.container`

The requested Pod must be active and belong to the Pods matched by the Access
selector. Explicit selection accepts a matched Pod that is not Ready, but
rejects deleting, succeeded, and failed Pods. It bypasses the Access selection
strategy and session affinity for that connection; the connection still counts
toward `LeastConnections` load.

This is particularly useful for StatefulSets. One Access can select the entire
StatefulSet and expose each stable Pod identity without one Access per ordinal:

```yaml
apiVersion: ssh.xiaoshiai.cn/v1
kind: Access
metadata:
  name: mysql
  namespace: database
spec:
  selector:
    app: mysql
  containers:
    - mysql
  credentials:
    - username: alice
      publicKeys:
        - ssh-ed25519 AAAA... alice
```

```bash
ssh 'database.mysql~mysql-0'@<kube-ssh-host>
ssh 'database.mysql~mysql-1'@<kube-ssh-host>
ssh 'database.mysql~mysql-2.mysql'@<kube-ssh-host>
```

No Service or StatefulSet API lookup is involved; membership is enforced only
through `spec.selector`. If the locator after `~` exactly matches a Pod name,
that exact name wins. Otherwise, the final `.` separates the Pod and container.

Gateways may be partitioned by class. A gateway configured with
`--gateway-class-name=default-gateway` only handles Access objects whose
`spec.gatewayClassName` is `default-gateway`; a classless gateway only handles classless
Access objects. Publish one or more externally reachable addresses with
`--advertise-address=host:port`. The owning gateway reports them as structured
entries under `status.endpoints`.

Each status endpoint contains the advertised `address` and the Access target
base `username`. Append `~pod` or `~pod.container` when an explicit Pod is
needed.

> User identity is derived from the matching public key or password token, not
> from the SSH username. Credential values are expected to be unique. For a
> duplicate, kube-ssh deterministically uses the oldest Access and logs a
> warning; operators should still resolve the conflict.
>
> Public key authentication is recommended. Password authentication treats the
> password as an opaque bearer token and is not recommended.

Static or webhook authentication can also target a Pod directly:

```bash
ssh default.nginx@<kube-ssh-host>
ssh default.nginx.app@<kube-ssh-host>
```

The direct Pod username formats are:

- `namespace.pod`
- `namespace.pod.container`

## Access Policy

Credentials may be declared inline:

```yaml
credentials:
  - username: alice
    publicKeys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJjO+3uspsX3jrw5xIZmdn3TJJQLrZ68kALV3/9hRXM kube-ssh-example
```

Or loaded from same-namespace Secrets:

```yaml
credentials:
  - username: alice
    publicKeysFrom:
      - name: notebook-ssh
        key: authorized_keys
```

`spec.containers` controls which regular Pod containers the Access exposes;
`credentials[].containers` can narrow that set for one identity. These lists
accept exact names and `*` patterns, such as `app-*`.

An empty capability policy inherits the gateway defaults. Set
`capabilities.allow` to switch that credential into whitelist mode:

| Capability       | Allows                                                            |
| ---------------- | ----------------------------------------------------------------- |
| `shell`          | Interactive shell sessions                                        |
| `exec`           | Non-interactive command execution                                 |
| `sftp`           | SFTP file transfer                                                |
| `scp`            | Legacy SCP compatibility; prefer `sftp`                           |
| `local_forward`  | Pod-local, network, and dynamic/SOCKS forwarding (`direct-tcpip`) |
| `remote_forward` | Remote listeners (`tcpip-forward`)                                |
| `agent_forward`  | SSH agent forwarding                                              |

```yaml
capabilities:
  allow:
    - shell
    - exec
    - local_forward
  localForward:
    allowDestinations:
      - "*:8080"
```

String policy patterns use `*` as a wildcard matching any sequence of
characters. For example, forwarding rules can use `db-*:5432`, `*:8080`, or
`*` for every destination.

Current runtime support is focused on Pod-backed `Access` objects. The API has
reserved fields for external endpoints, but external SSH backend support is not
enabled by the current controller/runtime path.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for build, generation, test, and release
workflows.

## License

Licensed under the [Apache License 2.0](LICENSE).
