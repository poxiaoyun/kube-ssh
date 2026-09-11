# kube-ssh

kube-ssh provides one SSH gateway for Kubernetes containers that do not run
`sshd` and for targets that already expose a complete SSH server. Access
resources select the target and define inbound credentials and operation
policy.

## Advertise addresses

Set `kubeSsh.advertiseAddresses` to explicitly publish user-reachable `host:port` addresses:

```yaml
kubeSsh:
  advertiseAddresses:
    - ssh.example.com:2222
```

Multiple addresses are supported. Available addresses are published to Access status for SSH connection details.

## Multiple gateways

The default gateway handles only Access resources without a `gatewayClassName`. Assign a class when deploying gateways for separate network entries:

```yaml
kubeSsh:
  gatewayClassName: default-gateway
  advertiseAddresses:
    - ssh-a.example.com:2222
    - ssh-b.example.com:2222
```

When no explicit address is configured and the Service type is `NodePort`, the
Chart publishes `{NodeIP}:<nodePort>` from `kubeSsh.service.nodePorts.ssh`.
Installer expands that template using the Node Host/IP declarations owned by
Cloud; Access status itself retains the template.

An Access `spec.gatewayClassName` must exactly match the gateway class. Gateway replicas sharing a class should advertise the same addresses.

## Service

The default Service is `NodePort` on port `30022`. Choose `ClusterIP`, `NodePort`, or `LoadBalancer` according to the cluster network. `advertiseAddresses` should contain addresses reachable by users, not an internal-only Service address.

## Advanced gateway options

The Chart configures the Kubernetes entry, host key and Access/SAR integration.
Authentication methods, session policy, Webhooks, metrics path and upstream SSH
timeouts use program defaults. Override them with `kubeSsh.extraArgs`:

```yaml
kubeSsh:
  extraArgs:
    - --authentication-method=publickey
    - --policy-default-idle-timeout=15m
```

The gateway allows `publickey` and `password` by default. Each Access further
limits the advertised methods to its configured credential types, including
Secret references. An Access with only public keys does not prompt for a
password. Credentials must still match.

When upgrading, move overrides from the former `authentication`, `authorization`,
`policy`, `accessPolicy`, `helper`, `externalSSH` and `metrics.path` values to CLI
flags. Use `extraEnvVars` with `secretKeyRef` or `extraEnvVarsSecret` for secrets,
plus `extraVolumes`/`extraVolumeMounts` when a file is needed. CLI flags take
precedence over environment variables. The Chart enables Access and Kubernetes
SAR and disables allow-all; overriding these is an explicit deployment choice.
Node-specific flags use `kubeSsh.node.extraArgs`.

## SSH host key

The Chart automatically generates an Ed25519 host key and stores it in a Secret so the SSH fingerprint remains stable across Pod restarts and upgrades. To reuse a centrally managed key, set `kubeSsh.hostKey.existingSecret`; the Secret must contain the key configured by `kubeSsh.hostKey.secretKey`. Operators may alternatively provide `kubeSsh.hostKey.privateKey` inline. The precedence is `existingSecret`, `privateKey`, then automatic generation. Set `kubeSsh.hostKey.autoGenerate=false` to disable host-key management and let the gateway use an ephemeral key. The static `deploy/install.yaml` does this intentionally so it never distributes a shared private key.

## Pod SSH node-local CRI transport

Set `kubeSsh.managed.transport=cri` to deploy the node-local CRI data plane. SSH
streams then flow from the gateway directly to the selected node on port
`10443`; only Pod lookup/watch, Access policy, Secret watch, and
SubjectAccessReview calls use the Kubernetes API server. There is no automatic
fallback to the API-server streaming path.

The chart mounts the host `/run` directory read-only. By default the Node
process probes common containerd, CRI-O, K3s, K0s, and cri-dockerd sockets in
order. Set `kubeSsh.node.runtimeEndpoints` to an ordered list of
`unix:///...` endpoints to override discovery.

When `kubeSsh.node.tls.existingSecret` is empty, the Chart generates and
preserves a Secret for mutual TLS. Set `existingSecret` to an operator-managed
standard TLS Secret containing `ca.crt`, `tls.crt`, and `tls.key`. The node
server and gateway client use the same certificate. Its SAN must cover the
configured Node server name and its common name must match
`kubeSsh.node.expectedClientName`. The node process
dynamically reloads its certificate and client CA from the mounted files;
rotated credentials are used for new connections without a DaemonSet restart.

## SSH Proxy

An `Access` with `spec.type: External` proxies the complete SSH protocol to an
existing sshd. The server may run in a Pod, elsewhere in the cluster, or on any
reachable host. Configure every endpoint with `address`, `port`, upstream
`username`, an explicitly configured gateway credential, and pinned host keys.
An in-cluster Service is written as its DNS name in `address`; there is no
separate Service field and inbound user credentials are never used upstream.
The connector accepts a plain DNS name or IP only and binds the connection to
the selected endpoint. Use a cluster NetworkPolicy for deployment-level egress
reachability restrictions.
