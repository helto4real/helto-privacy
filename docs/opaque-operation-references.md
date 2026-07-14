# Opaque protected-operation references

Operation resources may declare RAM-only reference kinds and typed reference
inputs and bounded output groups. Each output group declares one unique kind
and an inclusive minimum/maximum cardinality (up to 256); shared policy reserves
the sum of the maxima before adapter invocation and validates actual candidates
in declaration order. Shared policy owns the `hp-ref-*` identifiers, binds them
to the exact pack fingerprint, resource, scope, reference kind, permitted
operations, and unlocked session, and expires them after five minutes.

Consumers keep their own operation routes. A route calls
`pack.operations(resource).dispatch(...)`; shared policy authorizes the request,
checks stable scope, resolves declared references, invokes the bound adapter,
applies server-resolved private diagnostics or public JSON projection, creates
strict reference shells, and performs declared revoke-on-success behavior.
The fixed shared revoke route accepts reference IDs only in its POST body.
Revoke-on-success inputs are atomically claimed before adapter invocation, so
only one concurrent consumer can proceed; failures release the claim and
success deletes the reference. Output capacity is likewise reserved before
the adapter runs and is consumed only when the declared shells are issued.
Browser handles accept only the exact dispatch response envelope and exact
`{id, kind}` shells in declaration order. Backend-only operations with no route
remain attestable but cannot be invoked from the browser.

Operations may also bind a `SafePayloadProjection`. Its exact, wildcard-free
leaves are typed as boolean, bounded non-negative count, bounded finite number,
or bounded safe text. Safe text rejects paths, traversal, drive prefixes, URL
schemes, encoded separators, and control characters. This channel is independent
of coarse private diagnostics and opaque references. The adapter's conditional
`project_safe_payload` method must return exactly those typed JSON leaves;
undeclared/missing leaves, arrays, bytes, type mismatches, excessive depth, and
payloads over 64 KiB fail closed. The fixed wire
response carries this only as `safePayload: null|object`, alongside `data`,
`references`, `lease`, and `association`; the browser rejects extra fields.

Deferred UI operations have no product route. They require a subject-mode
binding plus safe payload or reference output and create a repr-safe RAM-only
`hp-assoc-*` association with the captured effective mode and current session.
The fixed claim route is five-minute, one-shot, same-session authorized, mints
bounded references atomically, and returns `association: null` on success.
Lock, profile conflict, restart, expiry, and mode-transition admission invalidate
or block associations before their captured mode can drift.

Root-bound source publication is compiled from an operation declaration through
`pack.operations(resource).source_leases(operation)`. The product adapter may
bind a resolved opaque reference to a validated `RootBoundSource`; shared policy
then issues the existing one-use source lease. The legacy publisher constructor
remains available for compatibility but is not used by this profile-bound path.
Dependency-free source operations implement `bind_source(resolved,
declaration)`. A source operation that declares record, singleton, or artifact
dependencies must implement `bind_source_with_dependencies(resolved,
declaration, dependencies)` and receives the same task/session/scope-bound
capability bundle as routed operation dispatch. Missing the dependency-aware
method blocks installation; shared policy never falls back to `bind_source`.
The scope remains admitted from reference claim through root validation and
lease insertion, while the dependency bundle expires immediately when the
binder returns or raises.
