# SSH Proxy design

The module owns the complete SSH proxy implementation: resolving the bound
Access endpoint and referenced Secrets, establishing and verifying one upstream
SSH connection, invoking authorization before protected protocol operations,
and forwarding channel and global-request lifecycles. Its `Protocol` adapter is
selected once for an authenticated downstream connection and implements the
connection protocol seam; callers do not branch on target kind for individual
protocol messages. Inline private keys and passwords are endpoint configuration
and are never derived from inbound authentication. Callers never receive
credential material.

The adapter uses the protocol-neutral operation lifecycle seam. Authorization,
audit, and metrics policy remain owned by the gateway; SSH Proxy does not
define a second operation vocabulary or depend on the gateway implementation.

An endpoint target is bound to the Access UID, generation, and endpoint name at
resolution time. A changed or replaced Access is rejected rather than silently
redirecting an authenticated connection. There is no endpoint failover. The
upstream server may run in a Pod, elsewhere in the cluster, or on any reachable
host; endpoint ownership, not topology, defines SSH Proxy semantics.

The connector accepts only a DNS name or IP address in the endpoint `address`
field. It combines the address with the endpoint port and binds the
TCP and SSH handshakes to that single destination. The downstream SSH protocol
cannot supply or redirect the upstream dial target. Cluster network policy owns
reachability beyond this application boundary.

Endpoint credential and host-key fields are resolved only while establishing a
connection. Kubernetes schema validation owns structural rules such as required
fields and mutually exclusive choices; runtime code validates only referenced
material and address restrictions required for the outbound SSH connection.

The connector returns the raw SSH connection plus its incoming channel and
global-request streams to the connection-scoped proxy. The `Protocol` adapter
owns lazy proxy creation and connection closure; the proxy owns wire request
parsing and bidirectional forwarding. The gateway remains the single owner of
mapping parsed SSH operations to authorization capabilities, resources, audit
fields, and metrics lifecycles.
