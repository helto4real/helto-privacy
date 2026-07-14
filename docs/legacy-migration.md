# Legacy migration and retirement

`helto-privacy` owns legacy-format discovery, protected migration evidence,
historical-key import, and retirement eligibility. Consumer packs own only
product normalization and the transaction that writes their current state.

## Reader units and profile bindings

Register each independently removable format as a separate read-only unit
before installing profiles that use it:

```python
from helto_privacy import LegacyReaderUnit, register_legacy_reader_units

register_legacy_reader_units((
    LegacyReaderUnit(
        "example-state-v1",
        "Example state v1",
        reader=ExampleStateV1Reader(),  # exact probe(source, context), read(source, context)
        dependencies=(),
        key_import_ids=("example-json-key",),
    ),
))
```

A reader with a writer-like callable is rejected. Dependencies must exist and
form an acyclic graph. The unit gets no current writer, profile adapter, or
keystore writer. A key-dependent reader may obtain only its declared imported
decrypt-only key through `context.key_for(import_id)`.

Bind the unit to an exact declared location in `PrivacyProfile`:

```python
LegacyReaderBinding(
    "example-state-v1-workflow",
    "example-state-v1",
    "workflow-state",
    LegacyLocationKind.WORKFLOW_FIELD,
    "private-state",
)
```

Historical keys have their own `LegacyKeyImportBinding` declarations, including
their exact source format and product location. They are independent of reader
bindings so a pack such as Director can import a historical JSON key for an
unchanged current schema without inventing a redundant legacy schema reader.

Installation fails if the binding, protected-field legacy declaration, or
reader registration is incomplete. Legacy reading is no longer a consumer
state-adapter method.

Utils provider credentials have two independently removable container readers:
`utils-provider-settings-plaintext-v1` accepts only the exact v1
`version`/`hf_token` object, and `utils-provider-settings-wrapper-v2` accepts
only the exact v2 wrapper around a current `helto.comfyui-utils` envelope. The
v2 reader returns the opaque envelope; the consumer transaction decrypts it
only while authorized and unlocked, then both sources use the same verified
singleton rewrite. Neither reader has a writer or a fallback-to-empty path.

## Obligations and receipts

An exact probe that matches is persisted as an encrypted migration obligation
before `read` receives control. The protected state contains opaque source
identities and lifecycle facts; its outer file contains only an authenticated
encrypted envelope. A successful read does not resolve the obligation.

The consumer completes it through `pack.migration.complete(...)` with a fixed
transaction object implementing:

```text
capture_original()
stage_current(normalized)
stage_durable_adjuncts(normalized)
commit()
read_back() -> MigrationVerification
rollback(original)
finalize(original)
```

The original recoverable representation is journaled in protected state before
commit. Current format, normalized equality, and every durable adjunct must pass
read-back before a receipt is persisted. Any failure calls `rollback` with the
exact captured representation and keeps the obligation unresolved. `finalize`
receives and retires only that exact original after the verified receipt exists;
it must be idempotent when that same original was already retired. Key pruning
is not part of migration completion. A protected `prepared` journal left by a stopped
process is restored explicitly through `pack.migration.recover_pending(...)`;
completion and recovery share a non-blocking inter-process lock, so recovery
cannot interfere with an active owner. A visible finalize-pending receipt is
re-persisted and its current representation is read back again before source
retirement, including after an earlier durability error.

When one product boundary contains several independently discovered locations,
use `pack.migration.complete_many(...)`. It runs the fixed transaction once,
attaches one receipt to every supplied obligation, and keeps the whole set
unresolved if staging, commit, read-back, receipt persistence, or rollback
fails. Finalization resumes as one group after interruption. The
single-obligation `complete(...)` method uses the same implementation with a
one-item obligation set. Group identity is canonical and independent of caller
ordering; retirement seals remain blocked until grouped finalization finishes.

Every protected migration-state read/modify/write operation uses that same
inter-process lock. Every keystore mutator likewise shares a separate
inter-process lock, preventing concurrent ComfyUI processes from overwriting
obligations, receipts, or independently imported wrapped keys.

## Historical-key import

Use `pack.migration.import_legacy_key_source(...)` with an authorized
`migration.key-import` capability. JSON sources must be the exact historical
`version`, `algorithm`, `keyId`, and `key` object; binary sources must be exactly
32 bytes. The importer:

1. reads a regular non-symlink source and validates its exact format;
2. wraps it as a non-primary decrypt-only keystore entry;
3. durably persists, reopens, decrypts, and constant-time verifies the entry;
4. records protected unlink-pending state;
5. verifies that the source inode did not change, unlinks it, and syncs its
   parent directory; and
6. records completion.

There is no plaintext `.migrated` copy. Failure before unlink leaves the source
authoritative and blocks readers that depend on the import. This does not claim
physical secure erasure on journaling or solid-state filesystems.

## External migration participants

Use an external participant only when an attested browser-owned editor, rather
than a server transaction adapter, owns the durable current-state commit. The
legacy binding must use `LegacyLocationKind.EXPORT`, and its `location_id` must
equal the exact protected import operation:

```python
external = pack.migration.external("legacy-export-binding", "imports.apply")
pending = external.prepare(
    obligation_id,
    expected_normalized,
    original_exact,
    ExternalMigrationContext(
        ExternalMigrationMode.REPLACE,
        "2026-07-13T12:34:56Z",
    ),
    owner_id,
    idempotency_key,
    imports_apply_authorization,
)
```

Call `prepare` before changing the external owner. The caller keeps
`pending.status.id` and `pending.resume_token`; shared state persists only a
hash of the resume capability. A retry with the same pack, operation, owner,
idempotency key, obligation, exact original bytes, normalized target, and
context returns the same transaction and deterministically regenerated resume
capability. Changed inputs under the same idempotency tuple fail with
`migration_idempotency_conflict`.

Normalized targets and finalization proofs are validated before migration state
or capacity is touched. Only exact JSON scalars plus bounded lists, tuples, and
string-keyed mappings are accepted; non-finite numbers, Python scalar aliases,
cycles, oversized strings or containers, excessive depth or item counts, and a
canonical representation above 8 MiB fail with
`external_migration_normalized_invalid`. Exact original, current, and re-export
byte values are separately capped at 16 MiB.

After a process or browser restart, call `external.resume(...)` with the exact
transaction, owner, resume capability, and operation authorization. It returns
an `ExternalMigrationResume` containing the protected expected normalized
state, exact original destination bytes, and context needed to finish or roll
back. This private object intentionally has no `to_payload()` method and hides
those fields from its representation; a consumer route must return them only
under the same exact authorization and resume-capability checks. Public
`status(...)` remains product-data-free. Do not retain recovery material in
browser storage.

After the product write, read back the exact current representation and perform
one deterministic current-format re-export under the same context. Complete
with `ExternalMigrationVerification`. The shared receipt closes the legacy
obligation only when normalized state, context, current-format status, and
durable-adjunct status verify. The consumer remains responsible for proving
that its exact current bytes and re-export bytes represent those product values;
shared privacy records keyed digests because it deliberately does not know the
product encoding.

On cancellation, failed verification, or the 300-second preparation expiry,
restore `original_exact`, call the browser workflow handle's
`reload(owner, fieldId)` to reread those exact bytes without re-encryption, then
acknowledge with:

```python
external.confirm_rollback(
    pending.status.id,
    owner_id,
    pending.resume_token,
    imports_apply_authorization,
    verification=ExternalRollbackVerification(restored_exact),
)
```

Until that acknowledgement, the owner remains blocked and the protected
recovery record counts against the 64-per-pack and 256-global unresolved caps.
Only one unresolved external transaction is allowed per `(pack, owner)` across
merge and replace. `status`, `finalize`, `cancel`, and `confirm_rollback` all
require the exact operation authorization, transaction ID, owner ID, and resume
capability. Completed response-loss retries return the same receipt or
rolled-back status from a product-data-free tombstone.

## Audit scopes and retirement seals

The user explicitly declares an inventory using `AuditItem` values and
`pack.migration.declare_audit_scope(...)`. Each item is checked through
`audit_source(...)`, which uses the same exact reader and protected obligation
path. `confirm_retirement_seal(...)` succeeds only when every declared item was
checked, the scope has zero unresolved obligations, and every key import
required by that reader is complete.

Record bindings are excluded from generic `migration.*` reads and audits.
Check a declared record item through
`pack.records(resource_id).audit_legacy(...)` with `record.audit`
authorization. The typed record audit invokes the exact reader, persists any
obligation, clears reader plaintext internally, and returns only whether the
reader matched. A later normal record reveal or mutation performs the verified
rewrite needed to resolve a matching obligation.

The seal records the reader discovery epoch. Any later matching discovery
increments that epoch and invalidates every prior seal for the reader. A seal
is retirement evidence for a later coordinated release; it never unloads code
or prunes wrapped keys dynamically.

## Operator-blind verification

Automated tests use synthetic normalized values and synthetic keys. During a
real audit the user performs content-level checks. Agents may inspect generic
counts and dispositions, but must not inspect decrypted workflow content,
media, keys, private browser state, or the protected migration-state plaintext.
