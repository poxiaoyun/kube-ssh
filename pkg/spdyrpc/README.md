# spdyrpc

`spdyrpc` provides bidirectional request/response calls and peer-initiated data
streams over one SPDY connection. Both peers may register handlers and make
calls. `Serve` owns the connection lifetime and waits for registered work to
finish during shutdown.

Use `NewClientConnection` or `NewServerConnection` according to the underlying
SPDY role, register handlers before serving, and close the connection to stop
all work. RPC envelopes and payloads use JSON.

The connection owns its transport. Shutdown closes it to release active stream
reads and writes, then waits for registered work; it does not wait for the peer
to complete outstanding RPC requests.
