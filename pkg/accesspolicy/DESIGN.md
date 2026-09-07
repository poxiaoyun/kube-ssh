# Access policy design

The module is the policy projection owner for the `Access` resource. It owns
credential matching, candidate target selection, connection affinity and
least-connection accounting, per-Access authorization, and Valid/Ready status
projection. Each adapter implements the corresponding `authn`, `target`, or
`authz` seam without moving those shared domain interfaces into this package.

A selected target is tied to the resolver context for connection-lifetime
accounting. Pod targets are bound to the selected live Pod identity exactly
once; an outer binding resolver only binds logical targets from other resolver
sources. Target values do not own selection-release callbacks.

The module does not implement SSH protocol state or Pod SSH transport behavior.
