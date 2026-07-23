# kube-ssh

kube-ssh provides a unified SSH gateway for Kubernetes Pods. Access resources select accessible Pods and authorize users with SSH public keys.

## Advertise addresses

Set `kubeSsh.advertiseAddresses` during installation. Each entry must be a user-reachable `host:port` address:

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

An Access `spec.gatewayClassName` must exactly match the gateway class. Gateway replicas sharing a class should advertise the same addresses.

## Service

The default Service is `NodePort` on port `30022`. Choose `ClusterIP`, `NodePort`, or `LoadBalancer` according to the cluster network. `advertiseAddresses` should contain addresses reachable by users, not an internal-only Service address.

## SSH host key

The Chart automatically generates an Ed25519 host key and stores it in a Secret so the SSH fingerprint remains stable across Pod restarts and upgrades. To reuse a centrally managed key, set `kubeSsh.hostKey.existingSecret`; the Secret must contain the key configured by `kubeSsh.hostKey.secretKey`. Operators may alternatively provide `kubeSsh.hostKey.privateKey` inline. The precedence is `existingSecret`, `privateKey`, then automatic generation. Set `kubeSsh.hostKey.autoGenerate=false` to disable host-key management and let the gateway use an ephemeral key. The static `deploy/install.yaml` does this intentionally so it never distributes a shared private key.

## Node backend

Set `kubeSsh.backend.mode=node` to deploy the node-local CRI data plane. SSH
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
