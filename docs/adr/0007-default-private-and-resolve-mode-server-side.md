# Default private and resolve mode server-side

`helto-privacy` uses private as the canonical base default and resolves one
effective privacy mode on the server from a consumer-normalized declaration,
scoped policy, privacy floors, and captured data state. Missing, malformed, or
inherited state resolves private; only a known explicit public declaration is a
durable opt-out, and it applies only when no floor requires privacy. Requests
may strengthen but never weaken the effective mode. Moving between public and
private is an authorized all-or-nothing protection transition that rewrites
registered storage and artifacts before reporting success, while records,
artifacts, and queued executions retain the mode captured at creation.

The server persists only product-data-free established mode and transition
metadata. This prevents a suppressed public declaration from auto-declassifying
when a floor disappears and preserves blocked transitions across process
restart. Product adapters own the domain rewrite, staging, and idempotent
rollback mechanics; shared policy owns authorization, participant ordering,
commit/rollback coordination, durable status, and route blocking.

When an established public surface gains a persistent floor, or its declaration
changes outside the shared transaction, the authority retains the prior public
effective state and blocks protected operations instead of claiming private
protection early. Reconciliation must transactionally establish the floor's
private target. Request-only strengthening does not rewrite the established
scope. Declassification additionally consumes one confirmation capability bound
to the current session, pack, scope, and target.
