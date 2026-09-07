# sshproxy

`sshproxy` resolves an External Access target and establishes its upstream
SSH transport. Construct a `Connector` with an Access/Secret `Source` and a
connection timeout, then call `Connect` with a target produced by `NewTarget`.
The upstream SSH server may run in a Pod, elsewhere in the cluster, or on any
reachable host; its topology does not change the connector contract.

The source must return current informer-backed Access and Secret snapshots.
Upstream authentication uses either private keys or passwords supplied inline
and/or by Secret reference. The connector accepts only a plain DNS name or IP
as an endpoint address. Connections fail closed when the Access
binding changed, a referenced Secret is missing, the private key or pinned host
key is invalid, or upstream authentication fails. The package never uses
inbound SSH credentials as upstream credentials.

`NewProtocol` creates the connection-level adapter used by an SSH server. It
establishes the upstream transport lazily on the first channel or global
request, authorizes every known protected operation and unknown SSH extension,
and closes both transports when the downstream connection ends. Environment
policy receives only the variable name; extension payloads and environment
values remain wire data and are not exposed to policy or audit callbacks.
