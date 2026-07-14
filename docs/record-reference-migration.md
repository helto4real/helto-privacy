# Private record reference relocation

`RecordReferenceMigration` declares an opt-in migration from a product-owned
legacy reference to a shared opaque `hp-rec-*` identifier. Profiles without a
declaration keep their existing fingerprint and adapter contract.

Relocation requires the declared record store adapter to implement an atomic
CAS boundary. `commit_record_relocation` must commit the protected current
record and protected `helto.private-record-reference-map.v1` mapping together,
while verifying that the legacy source revision is unchanged. It must also be
idempotent for an exact transaction. The paired read-back, rollback, and
legacy-finalization methods must enforce their declared revisions and return
`diverged` instead of overwriting newer state.

The shared crash journal is encrypted and contains no legacy reference or
record plaintext. It records only opaque identifiers, a keyed source identity,
revisions, protected envelopes, and recovery phase. Resolution is authorized,
requires an unlocked active suite and stable private scope, compares decrypted
references in constant time, and returns only a validated current record ID.
The mapping and journal bind that ID to the exact pack, profile fingerprint,
resource, record kind, migration, and legacy binding. Source identities retain
their key ID so an interrupted relocation remains discoverable after primary
key rotation. Verification failures enter a durable `rollback-pending` phase
before the adapter rollback is invoked, allowing an already-applied rollback
to be recovered safely after a crash.

Browser callers use `BrowserRecordHandle.migrateLegacyReference` and
`resolveLegacyReference`. Both use fixed POST routes and place the legacy
reference only in the request body; it is never included in a URL or response.
