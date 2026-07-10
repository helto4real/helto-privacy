# Define encrypted artifact lifecycle and serving

Type: grilling
Status: resolved
Blocked by: 02, 05

## Question

What shared privacy semantics should govern temporary files, caches, previews,
waveforms, masks, replay data, and execution spills from creation through
authenticated serving and cleanup?

Decide purpose binding, private URLs or tokens, session authorization,
cache-control, off-event-loop I/O, plaintext cleanup, safe errors, and lifecycle
ownership while leaving media decoding, allowed roots, cache keys, and artifact
payload formats to consumer integrations.

## Comments

### Current behavior compared

- `comfyui-utils` encrypts selector masks and thumbnails, load-video caches,
  replay bundles, and private preview copies under distinct purposes. Its
  private-media URL contains a seven-day encrypted token whose plaintext embeds
  an absolute path; the route also requires the current privacy session. Reads
  and decrypts run off the event loop, but the whole file is loaded before the
  response, encrypted preview files have no common retirement owner, and some
  cleanup failures are silently ignored.
- Director encrypts thumbnail and waveform caches with atomic private writes,
  bounds preview concurrency, serves private responses with `private, no-store`,
  purges plaintext cache variants before enabling global privacy, and aborts
  that transition if purge fails. Private preview URLs still carry raw source
  paths, while caches have manual clearing but no shared expiry or orphan sweep.
- Director's encrypted segment spills are run-scoped and use idempotent
  `finally` cleanup so ComfyUI interruptions derived from `BaseException` cannot
  bypass teardown. Cleanup failures remain warnings, and stale spill recovery is
  not a shared startup responsibility.
- Durable selector masks are not ordinary caches: workflows reference them and
  they must survive restarts until their owning mask is removed or migrated.
  Thumbnails, waveforms, and execution spills are regenerable and need no legacy
  reader. AIO and Smart Prompt do not add another artifact lifecycle today.
- The shared package currently supplies purpose-bound byte envelopes but no
  storage, lease, serving, retention, or sweeping abstraction.

### Recommended contract

Adopt a fail-closed managed-artifact service owned by `helto-privacy`:

1. Every generated privacy artifact is declared with a registered consumer,
   versioned purpose, owner, and one of four retention classes:
   **durable adjunct** (for referenced masks), **regenerable cache**,
   **run-scoped spill**, or **served transient** (including replay/preview
   leases). Consumers choose the class and owner from the shared contract; they
   do not invent cleanup semantics.
2. Private-mode artifacts are encrypted before durable filesystem exposure,
   written atomically under `0700` directories and `0600` files, and never fall
   back to plaintext. Purpose binding includes the consumer registration,
   artifact purpose, and format version so bytes cannot be replayed as another
   artifact kind.
3. Generated private bytes are decrypted only into memory or a bounded response
   stream. The shared service never creates a named plaintext staging file.
   Existing user-owned source/output files may be served in place after the
   consumer validates an allowed root, but the service must not copy them into a
   new plaintext artifact.
4. A private URL contains only a random opaque artifact lease ID held in a
   server-side registry—never a path, filename, privacy-session token, or
   self-contained path token. Serving requires both a live, current privacy
   session and an unexpired lease scoped to that artifact and operation. Lock,
   restart, expiry, or revocation invalidates the lease; an authorized caller may
   obtain a fresh one for an artifact that still exists.
5. Private responses use `Cache-Control: private, no-store`, generic filenames,
   stable sanitized errors, and no raw exception/path logging. File I/O,
   encryption, media preparation, and large decrypts run off the event loop with
   bounded concurrency and streaming/backpressure appropriate to the envelope.
6. Durable adjuncts remain until explicit owner deletion or verified migration.
   Regenerable caches use bounded expiry/eviction and may be discarded whenever
   unreadable. Run-scoped spills clean up exactly once in `finally` across every
   exit including `BaseException`, with a startup stale-run sweep. Served
   transients retire on expiry, replacement, consumption where applicable, or
   owner release, with startup sweeping for interrupted sessions.
7. Enabling privacy first removes all registered plaintext derivatives and
   interrupted plaintext temp variants; failure aborts the mode transition.
   Encrypted cleanup failure is sanitized, recorded for retry, and swept later
   rather than exposing data or silently disappearing. No new plaintext
   derivative is created while privacy is authoritative.

`helto-privacy` owns artifact registration, purpose validation, encrypted atomic
storage, lease issuance/revocation, authenticated serving, response policy,
retention enforcement, and sweeping. Consumer integrations own allowed-root
validation for existing media, cache keys, payload encoding/decoding, domain
regeneration, and selecting the registered purpose, owner, and retention class.

## Answer

The user approved the strict managed-artifact contract. Every privacy artifact
has a registered consumer, versioned purpose, owner, and shared retention class:
durable adjunct, regenerable cache, run-scoped spill, or served transient.
`helto-privacy` validates those declarations and enforces their lifecycle rather
than letting consumers invent their own retention and cleanup behavior.

Private-mode artifacts are encrypted before durable filesystem exposure,
written atomically with private directory and file permissions, and never fall
back to plaintext. Their authenticated purpose binds the consumer, artifact
purpose, and format version. Generated private bytes may be decrypted only into
memory or a bounded response stream; named plaintext staging files are not
allowed. Existing user-owned source and output files remain outside this
generated-artifact rule and may be served in place only after consumer-owned
allowed-root validation.

Private URLs expose only a random opaque artifact lease ID backed by a
server-side registry. They never contain a path, filename, privacy-session
token, or self-contained path token. Serving requires both a live current
privacy session and an unexpired operation-scoped lease. Lock, restart, expiry,
or revocation invalidates the lease, while an authorized caller may obtain a
fresh lease for an artifact that remains valid.

All private responses use `Cache-Control: private, no-store`, generic
filenames, sanitized stable errors, and no raw exception or path logging.
Blocking file, crypto, media-preparation, and large-decrypt work stays off the
event loop behind bounded concurrency and streaming backpressure.

Durable adjuncts remain until explicit owner deletion or verified migration.
Regenerable caches are bounded and disposable when stale or unreadable.
Run-scoped spills clean up exactly once in `finally` across every exit,
including `BaseException`, and receive a startup stale-run sweep. Served
transients retire on expiry, replacement, applicable consumption, or owner
release, with startup cleanup after interrupted sessions.

Enabling privacy must first remove every registered plaintext derivative and
interrupted plaintext temp variant; failure aborts the transition. Encrypted
cleanup failures are sanitized, recorded for retry, and swept later rather than
silently ignored. `helto-privacy` owns artifact storage, leases, authenticated
serving, retention, and sweeping; consumers retain allowed-root checks, cache
keys, payload encoding/decoding, regeneration, and lifecycle classification.
The durable rationale is recorded in
[ADR 0005](../../../docs/adr/0005-manage-privacy-artifacts-with-scoped-leases.md).
