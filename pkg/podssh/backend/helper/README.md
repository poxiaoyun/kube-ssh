# podssh/backend/helper

This package owns the `kube-ssh-helper` wire protocol and both of its runtimes.
The Pod backend uses `Client` after starting the helper in a target
container. The `kube-ssh-helper` command uses the server entry points to provide
SFTP, SCP, container-network dialing, remote forwarding, and agent forwarding.

Callers do not configure the underlying SPDY RPC transport. A helper connection
ends with its exec stream or context and owns every listener and forwarded
stream created through it.

`NewClient`, `ServeConnection`, `RunDial`, and `RunSFTP` take ownership of their
input and output streams. Closing those streams must unblock pending reads and
writes; this is how cancellation stops protocol work. A forwarded stream's
`CloseWrite` sends EOF while preserving its read side, and `Close` releases both
directions. In `RunDial`, TCP EOF closes only helper stdout; stdin may continue
carrying the peer's response.
