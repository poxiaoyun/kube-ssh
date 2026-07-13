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

Choose `ClusterIP`, `NodePort`, or `LoadBalancer` according to the cluster network. `advertiseAddresses` should contain addresses reachable by users, not an internal-only Service address.

## SSH host key

The Chart automatically generates an Ed25519 host key and stores it in a Secret so the SSH fingerprint remains stable across Pod restarts and upgrades. To reuse a centrally managed key, set `kubeSsh.hostKey.existingSecret`; the Secret must contain the key configured by `kubeSsh.hostKey.secretKey`. Operators may alternatively provide `kubeSsh.hostKey.privateKey` inline. The precedence is `existingSecret`, `privateKey`, then automatic generation.
