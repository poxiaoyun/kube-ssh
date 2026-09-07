# target

`target.Target` is the resolved destination of one SSH connection. Resolvers
populate its public `Kind`, `Options`, and `Runtime` fields. `String` returns
the canonical target path used by authorization, audit, and logs.

`Target` is not a wire type and has no serialization tags. `Runtime` contains
trusted resolver-to-adapter bindings. Resolver-owned selection state follows
the resolver context and is not stored in this value.

`Hint` represents a candidate locator supplied by authentication. `HintResolver`
matches its aliases against the SSH username and produces a `Target`; a hint is
never an authorization decision.
