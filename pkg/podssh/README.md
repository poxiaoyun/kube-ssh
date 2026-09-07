# podssh

`podssh` is the complete connection protocol adapter for SSH access to a Pod
that does not require target-side `sshd`. Construct a `Protocol` with the
resolved target, `backend.Backend`, shared operation callback, stream metrics
recorder, default shell, and environment policy. Send every channel and global
request for that connection to the protocol and call `Close` when the
connection ends.

The adapter implements shell, exec, SFTP, SCP, direct TCP/IP, remote forwarding,
agent forwarding, PTY, environment, signal, and window-change behavior. It
rejects unsupported protocol messages and never connects to an upstream SSH
endpoint.
