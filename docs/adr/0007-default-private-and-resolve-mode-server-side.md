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
