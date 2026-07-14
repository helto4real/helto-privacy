# Coordinate external migration participants with durable rollback authority

Some consumer imports cannot use the internal migration transaction adapter:
the shared backend discovers and normalizes a legacy export, but a browser-owned
editor performs the durable current-state write and read-back. Those imports use
a typed external migration participant bound to one exact `EXPORT` legacy
binding and its declared protected operation.

The shared encrypted migration-state envelope stores a separate external
lifecycle. `prepare` durably records the exact pre-write destination bytes,
expected normalized state, deterministic merge-or-replace context, opaque owner,
and keyed request evidence before the browser writes. The external participant
then reaches exactly one of these terminal paths:

```text
absent -> prepared -> migrated
                   -> rollback-required -> rolled-back
```

Cancellation, failed verification, and the fixed 300-second preparation expiry
move the participant to `rollback-required`; expiry never discards recovery
state. Exact original bytes remain protected until the consumer restores them
and acknowledges an exact-byte read-back. Completed tombstones contain only
opaque profile metadata and keyed digests, never imported content, normalized
state, exact destination bytes, product labels, paths, or export timestamps.

Every call rechecks a current authorization capability for the exact import
operation and pack. Status-changing calls also bind an opaque transaction ID,
opaque owner ID, and a high-entropy resume capability. Idempotency is scoped to
pack, operation, owner, and caller key: an identical retry returns the same
transaction, resume capability, or receipt, while changed inputs fail closed.
Only one unresolved external participant may exist per pack/owner across merge
and replace; unresolved records are capped at 64 per pack and 256 globally.
Expired records count until rollback acknowledgement.

The existing migration-state schema version remains 1. New
`externalTransactions` and `externalTombstones` sections are optional on read,
so historical state files and internal migration transactions retain their
existing behavior. Internal recovery never interprets external participant
records.

Browser rollback uses `workflowHandle.reload(owner, fieldId)`. It rereads the
adapter's exact protected value, invalidates stale snapshots, and refreshes
disposition/reveal state without asking shared privacy to encrypt it again.
Because public status cannot contain product state, the typed private
`resume(...)` seam returns the encrypted journal's expected normalized state,
exact original bytes, and context only after the same operation, pack, owner,
transaction, and resume-capability checks. Consumers must not retain that
material in browser storage.
