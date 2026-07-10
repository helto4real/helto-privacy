# Define legacy read retirement

Type: grilling
Status: resolved
Blocked by: 02, 06

## Question

How will the replacement contracts read legacy workflow data, ensure new writes
use only the current format, make re-saved workflows observable, and let legacy
support be removed safely after the user has checked the workflow set? Include
verified import of JSON and binary legacy keys without retaining plaintext key
files, one-time rewrite of referenced selector masks and pack state, and a
clear removal unit for each independent legacy reader.

## Comments

### Constraints from the stored-data map

- AIO and Smart Prompt legacy state uses the current envelope structure but
  different authenticated schema IDs and pack-local JSON keys. Those readers
  must be schema-bound and cannot be simulated by changing a current envelope's
  schema field.
- Utils has genuinely separate byte generations: the unauthenticated XOR form,
  `HELTO_PRIV1`, `HELTO_PRIV2`, and `HELTO_PRIV3`, plus the workflow prefix and
  queue wrappers that contain those bytes. The earliest decoder is safe only at
  explicitly registered product locations with a discovered historical key.
- Referenced selector masks are durable user edits, not disposable caches. A
  workflow is not fully migrated while its current workflow state still points
  at a mask readable only through a legacy byte reader.
- Director's state schema did not change. Its old JSON key must be imported, but
  the `helto.timeline-director` codec remains part of current-format continuity
  rather than becoming a removable legacy reader.
- ComfyUI has no authoritative inventory of every workflow or Smart Prompt
  export the user possesses. Reader inactivity can support a retirement
  decision but cannot prove that unseen data no longer exists.

### Recommended contract

1. Every legacy format is represented by a stable reader ID in a physically
   separate shared package. A reader exposes only exact `probe` and `read`
   operations over registered locations; it has no writer interface and is not
   reachable from normal current-envelope dispatch. Current writers accept only
   normalized product state and always emit the cutover contract.
2. A detected legacy value becomes a persistent **migration obligation** before
   it is revealed into live product state. The shared lifecycle records only an
   opaque source identity, consumer/profile resource ID, reader ID, disposition,
   and timestamps in protected shared state. Public status exposes sanitized
   counts and reader labels, never workflow content, paths, names, record
   metadata, keys, or ciphertext fingerprints.
3. Successful read alone does not resolve the obligation. A **migration
   receipt** is issued only after the enclosing save or import transaction is
   read back and verified as the current format for the same normalized product
   state. Locked byte preservation, a dirty editor, an attempted save, or a
   current workflow envelope paired with a still-legacy durable adjunct does not
   count.
4. Workflow migration is transactional at the privacy lifecycle level. Shared
   code stages current field envelopes and rewrites every referenced durable
   adjunct such as selector masks before committing the workflow projection.
   Any decrypt, normalization, encryption, artifact rewrite, atomic replacement,
   or verification failure preserves the original recoverable bytes, keeps the
   obligation open, and blocks a success receipt. Regenerable caches and expired
   tokens are purged rather than migrated.
5. Pack-managed state follows the same rule. Utils queue-manager legacy JSON or
   SQLite content is read once, normalized, written and read back through the
   current store, then marked migrated; the original row/file is retired only
   after verification. AIO and Director record entries are rewritten only after
   authorized reveal and successful current-record commit. Smart Prompt legacy
   exports are migrated on explicit import and re-export, not modified in place
   without the user's chosen destination.
6. JSON and binary legacy keys are imported through a keystore transaction,
   never renamed to a plaintext `.migrated` file. The importer validates exact
   shape and key length, wraps the key as decrypt-only, atomically persists and
   reopens the keystore, verifies the wrapped entry against the still-in-memory
   source, then unlinks the plaintext source and syncs its parent directory. A
   failed verification leaves the source file untouched and blocks dependent
   reads. Filesystem-level secure erasure is not claimed; the contract is that
   no additional plaintext copy is retained.
7. The user defines a **legacy audit scope** covering the workflows, libraries,
   exports, and pack state they intend to preserve. Shared UI lists generic
   discovered/resolved/unresolved counts per reader and supports an authorized
   detailed local view. The user may seal a scope only after every declared item
   has been checked and every discovered obligation has a verified receipt.
8. A **retirement seal** is explicit user attestation, not an automatic timeout.
   A sealed reader becomes removal-eligible only when it has zero unresolved
   obligations, all dependent durable artifacts are current, all required key
   imports are verified, and no read occurred after the seal. Any subsequent
   legacy discovery invalidates the seal and reopens the audit.
9. Removal happens in a later coordinated release, never dynamically from the
   running installation. Each reader removal unit contains its implementation,
   registry entry, profile bindings, historical-key dependency declaration,
   genuine golden fixtures, contract tests, audit labels, and migration copy.
   Removing one unit must not edit current codecs or unrelated readers.
10. Proposed independent units are: AIO v1 schema; Smart Prompt v1 schema and
    export wrapper; Utils prefixed workflow state; Utils XOR bytes;
    `HELTO_PRIV1`; `HELTO_PRIV2`; `HELTO_PRIV3`; Utils queue wrapper; Utils JSON
    key import; Utils binary-key import; AIO JSON-key import; Smart Prompt
    JSON-key import; and Director JSON-key import. Wrapper readers declare their
    byte-reader dependencies so a byte generation cannot be removed while a
    retained wrapper may dispatch to it.
11. Wrapped historical keys are not silently deleted with reader code. After
    every dependent scope is sealed and its reader units have shipped as
    removed, the shared keystore may offer a separate authorized key-pruning
    transaction. Until that explicit irreversible action, old keys remain
    decrypt-only and unavailable to current writers.
12. Retirement evidence is backed by genuine historical ciphertext fixtures.
    Each retained reader must prove legacy read, normalized-state equality,
    current-only rewrite, read-back verification, and failure preservation.
    Mutated current envelopes, synthetic prefixes, or tests that only prove
    legacy rejection are insufficient.

The first decision is whether explicit user sealing is mandatory. The strict
recommendation is yes: automated receipts and an inactivity window are useful
evidence, but only the user can define the workflow/export set that was actually
checked.

### Decisions locked

- An explicit user-created retirement seal is mandatory for each reader. The
  seal applies to a user-declared legacy audit scope and requires zero unresolved
  migration obligations plus verified receipts for every discovered legacy
  item. Inactivity is supporting evidence only. Any later read through that
  reader invalidates its seal and reopens the audit automatically.
- Removing a sealed reader never prunes its wrapped historical keys. Key pruning
  is a separate, explicitly authorized irreversible keystore transaction offered
  only after every dependent audit scope is sealed and the corresponding reader
  units have shipped as removed. Until then the keys remain decrypt-only and
  unavailable to current writers. This is distinct from plaintext legacy-key
  cleanup: a source key file is unlinked immediately after its wrapped import is
  persisted, reopened, and verified, with no retained `.migrated` copy.
- Each independently detectable legacy format is a separate reader removal unit.
  AIO v1 and Smart Prompt v1 each have their own schema reader; Utils XOR,
  `HELTO_PRIV1`, `HELTO_PRIV2`, and `HELTO_PRIV3` are separate byte readers; and
  the Utils workflow prefix and queue wrapper are separate container readers.
  Container readers declare exact byte-reader dependencies, so the registry,
  audit UI, seals, fixtures, tests, profile bindings, and code for one generation
  can be removed without editing unrelated readers, while dependency validation
  prevents a required lower-level reader from being removed first.
- A migration receipt is all-or-nothing across the current workflow or
  pack-state representation and every referenced durable adjunct. Shared code
  stages and verifies all current replacements before reporting success. If any
  selector mask, protected field, record entry, queue state, or atomic commit
  fails, the original recoverable bytes remain authoritative, the save/import is
  blocked, and every affected migration obligation stays unresolved. Disposable
  caches are purged and regenerated rather than included in the transaction.

## Answer

Legacy compatibility is implemented as exact, read-only legacy reader units
inside `helto-privacy`, selected only by privacy-profile bindings at registered
product locations. A reader can probe and decode its historical format but has
no writer interface. It produces normalized product state for the current
privacy contract; every save, export, record update, artifact rewrite, and
pack-state commit uses only current writers.

AIO's original authenticated schema and Smart Prompt's original authenticated
schema/export form are separate units. Utils uses separate units for its
workflow prefix and queue wrapper plus the XOR, `HELTO_PRIV1`, `HELTO_PRIV2`,
and `HELTO_PRIV3` byte generations. Wrapper units declare their byte-reader
dependencies. Director's unchanged `helto.timeline-director` schema remains
current-format continuity rather than a removable legacy unit.

Discovering legacy data creates a protected migration obligation before the
plaintext is applied to live product state. Shared status exposes only generic
counts; authorized detail remains local and does not expose workflow contents,
paths, names, keys, or ciphertext fingerprints. Reading legacy data is not
proof of migration. A migration receipt exists only after the normalized state
and every referenced durable adjunct have been written with the current
contract and read back successfully.

Migration is all-or-nothing across its privacy boundary. Workflow fields and
durable referenced selector masks are staged and verified together. Utils queue
state and other valuable pack state are normalized, rewritten, and read back
before their historical form is retired. AIO and Director private records are
rewritten only after authorized reveal and verified current-record commit.
Smart Prompt exports migrate through explicit import and re-export. Any failure
keeps original recoverable bytes authoritative, blocks success, and leaves all
affected obligations unresolved. Regenerable caches, spills, previews, and
expired tokens are purged instead of migrated.

Legacy JSON and binary source keys are validated, wrapped into the shared
keystore as decrypt-only entries, atomically persisted, reopened, and verified
against the still-in-memory source. Only then is the original plaintext key file
unlinked and its directory synced; no plaintext `.migrated` copy is retained.
Failed import leaves the source untouched and dependent reads blocked. The
system does not claim physical secure erasure on journaling or solid-state
storage.

Retirement requires an explicit user-created seal for each legacy reader unit.
The user declares the legacy audit scope—the workflows, libraries, exports, and
pack state intended for preservation—and may seal a reader only when every
declared item has been checked, all discovered obligations have verified
receipts, every required key import succeeded, and all dependent durable
artifacts are current. Inactivity is supporting evidence only. Any subsequent
legacy read invalidates the seal and reopens the audit.

Reader removal occurs only in a later coordinated release. One removable unit
contains the reader implementation, registry entry, profile bindings,
dependency declarations, genuine historical fixtures, contract tests, audit
labels, and migration copy. Dependency validation prevents removing a byte
reader while a retained wrapper can still dispatch to it. Genuine ciphertext
from each historical writer must prove read, normalized equality, current-only
rewrite, read-back verification, and original-byte preservation on failure.

Removing reader code never deletes wrapped historical keys. After every
dependent scope is sealed and the reader units have shipped as removed, the
keystore may offer historical key pruning as a separate explicitly authorized,
irreversible transaction. Until then imported keys remain decrypt-only and
unavailable to current writers. The durable rationale is recorded in
[ADR 0009](../../../docs/adr/0009-retire-legacy-readers-with-sealed-audits.md).
