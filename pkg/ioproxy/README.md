# ioproxy

`ioproxy` copies bytes in both directions between streams that support
half-close. `Proxy` handles shutdown and terminal results; `ProxyWithObserver`
also reports stream lifecycle and byte counts.

Context cancellation closes both streams and is returned as normal lifecycle
completion. Copy failures and asynchronous terminal failures are returned.
