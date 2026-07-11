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

## Audit scopes and retirement seals

The user explicitly declares an inventory using `AuditItem` values and
`pack.migration.declare_audit_scope(...)`. Each item is checked through
`audit_source(...)`, which uses the same exact reader and protected obligation
path. `confirm_retirement_seal(...)` succeeds only when every declared item was
checked, the scope has zero unresolved obligations, and every key import
required by that reader is complete.

The seal records the reader discovery epoch. Any later matching discovery
increments that epoch and invalidates every prior seal for the reader. A seal
is retirement evidence for a later coordinated release; it never unloads code
or prunes wrapped keys dynamically.

## Operator-blind verification

Automated tests use synthetic normalized values and synthetic keys. During a
real audit the user performs content-level checks. Agents may inspect generic
counts and dispositions, but must not inspect decrypted workflow content,
media, keys, private browser state, or the protected migration-state plaintext.
