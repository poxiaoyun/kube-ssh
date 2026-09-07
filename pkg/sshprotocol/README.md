# sshprotocol

`sshprotocol` defines the connection-level SSH protocol seam. An SSH server
selects one `ConnectionProtocol` after authentication and target resolution,
then sends every channel, global request, and connection close event to that
same adapter.

Pod SSH and SSH Proxy adapters use `BeginOperationFunc` before forwarding or
executing a protected SSH operation. Denial is returned as an error. Whenever
an operation lifecycle was started, the returned `FinishOperation` callback
must be completed once, including on denial, with the protocol-visible result.
