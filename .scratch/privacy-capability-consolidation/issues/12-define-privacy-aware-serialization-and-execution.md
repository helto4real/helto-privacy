# Define privacy-aware serialization and execution

Type: grilling
Status: resolved
Blocked by: 02, 05

## Question

What shared lifecycle should coordinate encrypted workflow storage with live
plaintext editing and queued execution across ComfyUI's separate save and
prompt-generation passes?

Decide envelope recognition, canonical comparison, concurrent in-memory reuse,
failed-current-envelope state, fail-closed waiting, queue payload replacement,
privacy-safe cache identities, and the boundary where consumer widget/state
projection remains an integration concern.

## Comments

### Current behavior compared

- ComfyUI builds queued data in two distinct passes: `graphToPrompt()` serializes
  workflow metadata and executable inputs separately. Ordinary workflow saving
  is synchronous through graph/node serialization. A private value can therefore
  be correct in one projection and stale, newly re-encrypted, or plaintext in
  the other unless preparation happens before both passes.
- `comfyui-utils` has runtime-only owner/field envelope memoization and canonical
  comparison. Selector serialization generally fails closed, while Prompt
  Enhancer and Privacy Show Any still catch some encryption failures and return
  an old or empty serialized value instead of aborting the save/queue. Its queue
  manager correctly suppresses rewrites when only non-semantic timestamps differ.
- AIO reuses exact prompt envelopes between workflow and executable projections
  and uniquely remembers current-schema envelopes that failed a real decrypt.
  Its Ideogram builder still performs synchronous encryption during serialization
  and can generate fresh ciphertext repeatedly.
- Director flushes live edits before serialization, but synchronously encrypts
  the whole timeline on each commit without shared canonical reuse. A decrypt
  failure replaces live state with a default timeline; a later serialization
  must not be allowed to overwrite the original locked ciphertext with that
  default.
- Smart Prompt has the strongest pending-promise deduplication and queue wait,
  but its execution cache token is an unkeyed SHA-256 projection. Its backend
  may turn a decrypt or token-resolution failure into an empty state plus a
  warning and continue execution instead of rejecting the private run.
- The shared package recognizes envelope structure and remembers exact envelopes,
  but does not yet own concurrent preparation, failed-current state, a graph-wide
  serialization barrier, queue projection replacement, execution grants, or
  private cache invalidation.

### Recommended contract

Adopt a fail-closed privacy snapshot transaction owned by `helto-privacy`:

1. Each save, export, queue, submit, replay, or queue-manager capture begins a
   **privacy snapshot**. The shared coordinator captures every registered field's
   consumer-normalized state at one generation, canonicalizes it, and produces
   one exact current envelope reused by workflow metadata and every executable
   projection in that transaction.
2. Envelope reuse is runtime-memory-only and keyed by owner, field, schema, and
   generation. A memo stores the matching canonical identity, exact envelope,
   and pending encryption. Equal concurrent requests share one promise; a result
   from an older edit generation can never replace the newer state. No plaintext,
   memo, or pending state is written to browser or filesystem storage.
3. Envelope disposition distinguishes current-and-verified, current-but-locked,
   current-but-failed, readable legacy, and unsupported data. A structurally
   current envelope is not considered healthy after a non-lock decrypt failure;
   the exact fingerprint remains in shared failed-current state until successful
   decrypt, recovery, reset, or replacement.
4. A locked or failed envelope may be copied byte-for-byte into a workflow save
   only while its field is unedited and its live UI remains locked. This preserves
   recoverable data without claiming it is usable. Queueing, previewing, exporting
   plaintext, or replacing it is blocked until successful authorized decrypt.
   A successfully read legacy value is normalized in memory and every new write
   uses a current envelope.
5. A graph-wide **serialization barrier** covers autosave, manual save/export,
   `graphToPrompt`, direct API queueing, queue-manager capture/replay, partial
   execution, and subgraphs. Async entry points wait with a bounded failure
   timeout for the privacy snapshot. Synchronous node serialization may emit
   only an already-settled envelope matching the captured generation; otherwise
   the enclosing operation aborts. Synchronous HTTP encryption, swallowed
   failures, empty substitution, stale-envelope substitution, and plaintext
   fallback are forbidden.
6. Queued workflow metadata keeps current envelopes. Executable inputs receive
   only shared protected references or envelopes chosen by the common contract,
   never live plaintext. A shared backend resolver validates the snapshot and
   decrypts only at dispatch into process memory before invoking consumer product
   logic. Missing metadata, locked keys, failed decrypt, reference mismatch, or
   unsupported data rejects the run rather than executing defaults.
7. Consumers declare a canonical **semantic execution projection** containing
   only product state that affects the result. `helto-privacy` derives a
   domain-separated, session-keyed identity from that projection; raw plaintext,
   unkeyed hashes, full editor state, paths, and envelope contents are not cache
   tokens. Private execution caching is restricted to a shared unlocked-session
   RAM partition and is cleared on lock, restart, or key rotation. Persistent or
   external cache providers are disabled for private execution until they
   implement a separately approved encrypted privacy contract.
8. Queue authorization creates a session-bound execution grant. Locking revokes
   grants that have not dispatched, clears live plaintext projections and
   private RAM caches, and requests cancellation of active private runs at safe
   checkpoints; no later stage may newly reveal or persist their private data.
   Replays require unlock and a fresh snapshot/grant.

`helto-privacy` owns snapshot coordination, canonical comparison mechanics,
pending deduplication, envelope disposition, failed-current tracking, save and
queue barriers, protected execution references, keyed identities, backend
resolution, grants, and cache revocation. Consumer integrations own field/widget
location, product normalization, semantic execution projection, applying
decrypted state to live editors, and invoking product logic after successful
shared resolution.

## Answer

The user approved the strict privacy snapshot transaction. Every save, export,
queue, submit, replay, and queue-manager capture uses one shared snapshot of all
registered private fields at a single edit generation. The exact current
envelope produced for that snapshot is reused across workflow metadata and
every executable projection rather than encrypting independently in each pass.

Envelope memoization is runtime-memory-only and keyed by owner, field, schema,
and generation. Canonically equal concurrent requests share one pending
encryption, and an older generation can never overwrite newer live state. No
memo, pending state, or plaintext projection is persisted as a serialization
cache.

The shared lifecycle distinguishes verified current, locked current, failed
current, readable legacy, and unsupported envelopes. Structural validity alone
does not clear a real decrypt failure. An unchanged locked or failed envelope
may be preserved byte-for-byte in workflow storage while its UI remains locked,
but it cannot be executed, revealed, or replaced. Successfully read legacy data
is normalized in memory and all subsequent writes use a current envelope.

A graph-wide serialization barrier covers autosave, manual save/export,
`graphToPrompt`, direct API queueing, queue-manager capture/replay, partial
execution, and subgraphs. Async entry points wait within a bounded failure
window; synchronous serialization can emit only a settled envelope for the
captured generation. Missing or failed encryption aborts the enclosing
operation—synchronous HTTP encryption, swallowed failures, empty/default
substitution, stale-envelope reuse, and plaintext fallback are forbidden.

Queued metadata remains protected, and executable inputs contain only shared
protected references or envelopes. The common backend resolver validates and
decrypts the snapshot into process memory at dispatch before consumer product
logic runs. Missing metadata, a locked key, failed decrypt, reference mismatch,
or unsupported data rejects the run rather than executing an empty/default
state.

Consumers declare only the semantic product projection that affects execution.
`helto-privacy` derives a domain-separated, session-keyed identity from it;
plaintext, unkeyed hashes, full editor state, paths, and envelope contents are
not cache tokens. Private caching is limited to the unlocked session's RAM and
is cleared on lock, restart, or key rotation. Persistent/external caches remain
disabled until a separate encrypted privacy contract is approved.

Queue authorization creates a session-bound execution grant. Locking revokes
undispatched grants, clears live plaintext projections and private RAM caches,
and requests cancellation of active private runs at safe checkpoints. Replays
require unlock and a fresh snapshot/grant. The durable rationale is recorded in
[ADR 0006](../../../docs/adr/0006-coordinate-private-serialization-with-snapshots.md).
