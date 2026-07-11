# Tickets: Helto privacy consolidation

These tickets implement the coordinated privacy consolidation specified by the
[completed Wayfinder map](.scratch/privacy-capability-consolidation/map.md) for
`helto-privacy`, `comfyui-utils`, AIO Image Generate, Director, and Smart
Prompt.

Work the **frontier**: any ticket whose blockers are all complete. Tickets use
an expand–migrate–contract sequence so each repository remains testable while
the final profile activation and deletion happen atomically.

## Shared definition of done

Every ticket must satisfy these rules in addition to its own criteria:

- [ ] Affected repository tests, lint, type, static, package, and formatting
      checks pass without skips, waivers, flaky retries, or unrelated failures.
- [ ] Privacy failures remain fail-closed, new or missing mode state resolves
      private, and no plaintext fallback is introduced.
- [ ] Tests use synthetic fixtures only; agents never inspect user workflows,
      media, browser state, credentials, keys, or decrypted values.
- [ ] Documentation and contract evidence are updated with the code, and
      whitespace/diff validation is clean.
- [ ] A ticket that publishes, activates, removes data support, or prunes keys
      obtains the fresh authorization stated in that ticket before acting.

## Compile atomic privacy profiles

**What to build:** A consumer can declare one immutable privacy profile and
receive typed server and browser handles only when the complete declaration and
its product adapters satisfy the fixed shared contract.

**Blocked by:** None — can start immediately.

- [x] Define the fixed contract identity, profile vocabulary, canonical
      validation, deterministic fingerprint, and immutable installed form.
- [x] Make installation atomic, idempotent for identical fingerprints, and
      order-independent across PromptServer and node-definition lifecycle
      timing.
- [x] Return typed readiness, authorization, workflow, record, artifact, mode,
      and execution handles without exposing raw codecs, keys, tokens, or
      policy hooks.
- [x] Block conflicting fingerprints, missing adapters, unknown declarations,
      partial profiles, and browser/server attestation drift with sanitized
      diagnostics.

## Verify and activate exact suites

**What to build:** An installed five-repository suite can prove its exact
identity in verification mode and enable writers only through explicit
authorized activation.

**Blocked by:** Compile atomic privacy profiles.

- [x] Define immutable signed suite manifests that bind exact source and
      artifact identities, profile fingerprints, environment tuples, hashes,
      previous suite, and rollback class.
- [x] Implement publication and installation states for `cutover-pending`,
      `ready`, `activation-required`, `active`, `incomplete`, `mismatch`, and
      `conflict` without inferring version compatibility.
- [x] Give maintenance actors a non-decrypting capability for manifests,
      envelope headers, opaque key availability, encrypted copying, and generic
      readiness only.
- [x] Require explicit activation bound to the manifest digest; activation
      itself must not decrypt user data and must record the rollback boundary.

## Resolve privacy mode and transitions

**What to build:** Every registered product surface receives one
server-authoritative effective mode with private as the base default and
all-or-nothing protection changes.

**Blocked by:** Compile atomic privacy profiles; Verify and activate exact
suites.

- [x] Resolve missing, malformed, and inherited state as private; accept public
      only as a known explicit opt-out when no privacy floor applies.
- [x] Enforce upstream, parent, record, artifact, execution, and global privacy
      floors so request parameters may strengthen but never weaken protection.
- [x] Protect shared route dispatch with one authorization model and sanitized
      typed failures; absence of a keystore cannot imply authorization.
- [x] Make public-to-private and private-to-public transitions transactional
      across registered state and derivatives, preserving the prior mode on any
      failure.

## Deliver the shared browser privacy UI

**What to build:** All consumers use one attested browser client and one Helto
privacy surface for setup, unlock, lock, status, recovery, and mode state.

**Blocked by:** Verify and activate exact suites; Resolve privacy mode and
transitions.

- [x] Provide one fingerprint-attested browser connection and request client
      with bounded unlock retry, header/cookie restoration, and no token in a
      URL or public status payload.
- [x] Mount setup, unlock, password change, lock, readiness, recovery, mode,
      transition, and blocked-installation UI exactly once regardless of pack
      load order.
- [x] Broadcast lock/session changes to every bound consumer and invalidate
      stale browser state without memoizing a temporary missing route forever.
- [x] Apply the Helto design system and prove hide/mask/peek content remains
      visually unreadable, keyboard accessible, and free of sensitive labels or
      diagnostics.

## Coordinate snapshots and serialization

**What to build:** A private edit generation produces one settled protected
snapshot reused consistently by every save, export, queue, and executable
projection.

**Blocked by:** Compile atomic privacy profiles; Resolve privacy mode and
transitions; Deliver the shared browser privacy UI.

- [x] Model verified current, locked current, failed current, readable legacy,
      and unsupported dispositions without treating envelope shape as proof of
      usability.
- [x] Coordinate canonical generation memoization and concurrent encryption in
      runtime memory so stale generations cannot overwrite newer state.
- [x] Gate manual save, autosave, export, graph-to-prompt, direct queueing,
      queue-manager capture, partial execution, and subgraphs on one graph-wide
      settlement barrier.
- [x] Preserve unchanged locked/failed ciphertext byte-for-byte while blocking
      reveal, execution, replacement, stale reuse, default substitution, and
      plaintext fallback.

## Resolve private execution and grants

**What to build:** Product execution receives authorized in-memory plaintext
only after resolving the exact protected snapshot at dispatch time.

**Blocked by:** Resolve privacy mode and transitions; Coordinate snapshots and
serialization.

- [x] Produce protected execution references and reject missing metadata,
      locked keys, decrypt failure, unsupported data, or reference mismatch
      before product logic runs.
- [x] Derive session-keyed, domain-separated identities from consumer semantic
      projections; never use plaintext, unkeyed hashes, paths, or ciphertext as
      public cache tokens.
- [x] Limit private caches to unlocked-session RAM and clear them on lock,
      restart, rotation, or profile invalidation.
- [x] Issue session-bound execution grants, revoke undispatched work on lock,
      request safe cancellation of active work, and require fresh grants for
      replay.

## Provide private records and redaction

**What to build:** Consumers can persist domain records privately while locked
listings disclose only minimal generic shells and authorized operations reveal
validated product projections.

**Blocked by:** Compile atomic privacy profiles; Resolve privacy mode and
transitions.

- [x] Restrict locked shells to opaque generated ID, record kind, private flag,
      and fixed generic label; listing must never decrypt.
- [x] Treat every consumer field as sensitive unless an explicit safe-field
      allowlist passes shared validation for the authorized operation.
- [x] Permit deletion and confirmed destructive replacement while locked, but
      fail closed for use, preview, duplicate, merge, edit, or metadata reveal.
- [x] Standardize stable error codes, fresh correlation IDs, generic filenames,
      safe response headers, and path/value-free logs and diagnostics.

## Manage encrypted artifacts and leases

**What to build:** Generated privacy artifacts are encrypted, retained, served,
and retired by one shared lifecycle without named plaintext staging or
path-bearing capabilities.

**Blocked by:** Compile atomic privacy profiles; Resolve privacy mode and
transitions.

- [x] Implement atomic encrypted writes with private permissions and
      authenticated purpose binding to consumer, artifact kind, and version.
- [x] Enforce durable-adjunct, regenerable-cache, run-scoped-spill, and
      served-transient retention classes with owners, cleanup ledgers, and
      startup sweeps.
- [x] Serve through opaque random leases that require a current session and
      operation scope, expire/revoke on lock or restart, and return private
      no-store responses with generic names.
- [x] Keep blocking work off the event loop with bounded concurrency,
      backpressure, in-memory or streamed reveal, transition-time derivative
      purge, and interruption-safe cleanup.

## Track legacy migration and key import

**What to build:** Exact read-only legacy units can migrate protected data with
verifiable receipts and later become independently removable after explicit
user audits.

**Blocked by:** Compile atomic privacy profiles; Coordinate snapshots and
serialization; Manage encrypted artifacts and leases.

- [ ] Define physically separate reader units with exact probe/read operations,
      dependency validation, declared profile locations, and no writer surface.
- [ ] Create protected migration obligations before reveal and issue receipts
      only after transactional current rewrite plus read-back verification of
      state and durable adjuncts.
- [ ] Provide user-declared audit scopes and per-reader retirement seals that
      require zero unresolved obligations and invalidate on later discovery.
- [ ] Import JSON and binary legacy keys by validate, wrap decrypt-only,
      persist, reopen, verify, unlink the plaintext source, and sync; keep key
      pruning separate and explicitly irreversible.

## Restore AIO, Smart Prompt and Director historical reads

**What to build:** Genuine historical AIO and Smart Prompt data loads through
isolated schema readers, while Director's unchanged schema survives verified
legacy-key import.

**Blocked by:** Track legacy migration and key import.

- [ ] Add the AIO v1 schema reader and JSON-key import for workflow, builder,
      and private-record locations.
- [ ] Add the Smart Prompt v1 schema and export-wrapper readers plus JSON-key
      import for workflow, bare-envelope, and packaged import locations.
- [ ] Preserve Director current-schema continuity after verified JSON-key import
      without creating a redundant removable schema reader.
- [ ] Generate provenance-recorded historical ciphertext from the original
      writers using synthetic data/test keys and prove current-only rewrite,
      failure preservation, and reader isolation.

## Restore Utils historical formats

**What to build:** Utils workflows, queue state, binary artifacts, and durable
selector masks remain recoverable through exact independently removable reader
units.

**Blocked by:** Manage encrypted artifacts and leases; Track legacy migration
and key import.

- [ ] Implement separate raw XOR, `HELTO_PRIV1`, `HELTO_PRIV2`, and
      `HELTO_PRIV3` byte readers with verified binary-key import.
- [ ] Implement workflow-prefix and queue-wrapper container readers with exact
      dependency declarations, plus JSON-key import where applicable.
- [ ] Build genuine synthetic fixtures for every generation, workflow field,
      historical JSON/SQLite queue form, and failure case.
- [ ] Prove one selector migration atomically rewrites its workflow fields and
      referenced historical mask or leaves every original byte authoritative.

## Protect singleton pack state and secrets

**What to build:** Queue state and provider credentials use a reusable opaque
singleton transaction while their consumer schemas and update rules remain
product-owned.

**Blocked by:** Provide private records and redaction; Track legacy migration
and key import.

- [ ] Provide encrypted singleton field/blob storage, optimistic or revisioned
      updates, atomic replacement, and protected generic status projections.
- [ ] Keep domain normalization, SQLite/JSON schema, provider meaning, and
      product update semantics in consumer adapters rather than shared policy.
- [ ] Migrate valuable plaintext or historical state only through verified
      write/read-back transactions before source retirement.
- [ ] Block locked, malformed, partially migrated, or failed persistence without
      resetting, defaulting, or exposing stored values.

## Build the shared acceptance harness

**What to build:** One reusable harness can prove the shared contract and real
consumer adapters with signed, reproducible, zero-waiver evidence.

**Blocked by:** Verify and activate exact suites; Resolve privacy mode and
transitions; Deliver the shared browser privacy UI; Coordinate snapshots and
serialization; Resolve private execution and grants; Provide private records
and redaction; Manage encrypted artifacts and leases; Track legacy migration
and key import; Restore AIO, Smart Prompt and Director historical reads;
Restore Utils historical formats; Protect singleton pack state and secrets.

- [ ] Implement the versioned acceptance catalog, stable evidence IDs, signed
      evidence manifest, supported environment tuples, and exact suite binding.
- [ ] Maintain the genuine historical fixture catalog and reproducible
      generators with source provenance, ciphertext hashes, expected normalized
      state, and clearly labelled derived mutations.
- [ ] Provide contract adapters, synthetic canary leak oracle, deterministic
      fault controls, registration-order runner, and consumer duplication/static
      checks.
- [ ] Treat skips, xfails, unexpected warnings/errors, unrelated failures,
      flaky retries, and support-matrix exclusions as release failures.

## Move selector masks and thumbnails to managed artifacts

**What to build:** Utils selector masks become durable managed adjuncts and
selector thumbnails become regenerable managed caches while product image
encoding, roots, keys, and regeneration stay consumer-owned.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare mask and thumbnail artifact kinds, owners, purposes, retention,
      operations, plaintext derivatives, and allowed-root adapter requirements.
- [ ] Route storage, reads, leases, purge, cleanup, and startup recovery through
      bound artifact handles while retaining PNG/WebP product behavior.
- [ ] Add historical mask and current cache integration tests, including
      regeneration and injected persistence/cleanup failures.
- [ ] Keep the existing selector path live until selector workflow migration is
      ready to consume the new durable-mask transaction.

## Move selector workflow state and operations

**What to build:** Utils selector fields save and execute through one shared
snapshot, with protected product operations and atomic migration of referenced
masks.

**Blocked by:** Move selector masks and thumbnails to managed artifacts.

- [ ] Declare selected images, edited masks, and edited bounding boxes as one
      normalized workflow resource with private-by-default mode and semantic
      execution projection.
- [ ] Implement real locate, normalize, apply, clear, root authorization, and
      product-operation adapters without moving selector domain logic shared.
- [ ] Protect scan, source view, thumbnail, mask, paste, delete, cache, and root
      operations through bound authorization/workflow/artifact handles.
- [ ] Prove every historical byte generation and referenced mask migrates in one
      receipt, and any failure preserves all original workflow and mask bytes.

## Move Prompt Enhancer and provider credentials

**What to build:** Prompt Enhancer scripts/variables use shared workflow and
execution contracts while provider credentials use the shared singleton record
transaction.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare Prompt Enhancer mode, protected workflow fields, semantic
      execution projection, provider-settings record, and safe coarse status
      fields.
- [ ] Bind editor normalization/application/clear and provider-store/dispatch
      adapters while retaining provider selection, models, variables, and
      generation semantics.
- [ ] Replace local memo/encryption and credential persistence behind inactive
      shared handles, preserving the old live path until Utils activation.
- [ ] Prove legacy workflow/key and plaintext credential migrations, current
      snapshot execution, locked failure, and no credential leakage.

## Move Privacy Show Any

**What to build:** Privacy Show Any treats its mirrored widget/property as one
logical protected field and reveals live text only through an authorized
display operation.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare the scope, mirrored workflow locations, fixed normalization, and
      protected display operation as one receipt-bearing resource.
- [ ] Bind value-to-text, locate/mirror, live-display apply/clear, and product
      invocation adapters without duplicating encryption or lifecycle policy.
- [ ] Replace backend direct encryption and per-node serialization patches
      behind the inactive shared workflow handle.
- [ ] Prove one settled envelope is reused across both projections, legacy
      migration produces one receipt, and reveal/save failures remain blocked.

## Replace private-media tokens with leases

**What to build:** Utils previews and authorized source viewing use shared
opaque leases instead of encrypted absolute-path tokens or consumer-owned
private serving.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare private previews, source-serving operations, allowed roots, and
      all old generated preview/temp derivatives.
- [ ] Bind consumer encoders/root validators to shared write, lease, stream,
      revoke, expiry, cleanup, and restart behavior.
- [ ] Replace browser URL construction with opaque lease URLs that contain no
      path, filename, session credential, or self-contained token.
- [ ] Prove lock/restart/expiry/replacement revocation, private no-store headers,
      generic names, bounded streaming, sanitized failures, and startup sweep.

## Move media-node previews, caches and replay spills

**What to build:** Utils image/video save, load, and comparison nodes retain
their product outputs while every generated private preview, cache, staging
area, and replay bundle follows shared artifact lifecycle rules.

**Blocked by:** Replace private-media tokens with leases.

- [ ] Declare node-local mode sources, artifact purposes/retention, ownership,
      and the complete derivative inventory for all affected media nodes.
- [ ] Bind existing encoders, output routing, filename rules, source roots,
      cache keys, replay serialization, and pause/release behavior to mode,
      artifact, lease, and execution handles.
- [ ] Eliminate request-authoritative privacy booleans, named plaintext private
      staging, local encrypted-temp branches, and consumer cleanup policy behind
      the inactive path.
- [ ] Preserve output/media semantics and prove transition purge, replay
      cleanup, interruption, restart, and leak-oracle behavior.

## Move queue persistence, capture and replay

**What to build:** The Utils queue manager persists one protected singleton and
captures/replays only settled snapshots with fresh execution grants.

**Blocked by:** Move selector workflow state and operations; Move Prompt
Enhancer and provider credentials; Move Privacy Show Any.

- [ ] Declare private-by-default queue state, protected operations, sensitive
      fields, generic status projection, and semantic comparison rules.
- [ ] Bind queue normalization, SQLite identity/revision, state transitions,
      batching, capture, replay, rerun, preview, and delete to singleton,
      snapshot, execution, readiness, and authorization handles.
- [ ] Migrate current JSON and genuine historical JSON/SQLite queue forms only
      after current write/read-back verification.
- [ ] Prove all registered workflow barriers settle before capture, replays get
      fresh grants, locked/missing references reject, and queue-domain behavior
      remains unchanged.

## Activate the Utils profile and remove its local privacy core

**What to build:** Utils switches atomically to one complete attested profile
and no longer ships any independent privacy codec, token, route, recovery,
serialization, record, artifact, or policy implementation.

**Blocked by:** Move selector masks and thumbnails to managed artifacts; Move
selector workflow state and operations; Move Prompt Enhancer and provider
credentials; Move Privacy Show Any; Replace private-media tokens with leases;
Move media-node previews, caches and replay spills; Move queue persistence,
capture and replay.

- [ ] Assemble the complete server/browser profile and adapters, verify one
      fingerprint, switch every call site to bound handles, and activate only
      when no slot is missing.
- [ ] Delete obsolete Utils privacy wrappers, local encrypt/decrypt routes,
      recovery catalog, path-token serving, duplicated lifecycle patches, and
      misleading legacy writers/constants.
- [ ] Align project, requirements, manager, documentation, and packaged browser
      metadata to the candidate suite without committing local-path
      dependencies.
- [ ] Run the complete Utils suite plus shared adapter, missing-package,
      mismatch, private-default, legacy, and static-duplication evidence.

## Move Generate and Krea prompts

**What to build:** AIO Generate and Krea prompt fields use shared snapshots,
private floors, protected execution references, and dispatch-time resolution
without per-widget crypto.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare Generate/Krea workflow fields, legacy boolean mapping, upstream
      privacy floor, semantic prompt projections, and protected operations.
- [ ] Bind widget locate/apply/clear, linked-versus-local resolution, unlinked
      workflow recovery, semantic normalization, and existing pipeline dispatch
      to workflow/execution handles.
- [ ] Stage removal of browser serialization memo/encryption and backend direct
      decryption while preserving the product pipeline until AIO activation.
- [ ] Prove genuine AIO v1 migration, one-snapshot identity, private RAM-cache
      policy, linked input behavior, grant/reveal failure, and unchanged outputs.

## Move the Ideogram prompt builder

**What to build:** The Ideogram builder's sensitive widgets and mirrored
whole-editor state serialize as one consistent protected generation while its
prompt, palette, element, coordinate, and preview behavior remains intact.

**Blocked by:** Move Generate and Krea prompts.

- [ ] Declare every sensitive widget and mirrored property/workflow key, mode
      source, semantic execution projection, and Generate-derived floor.
- [ ] Bind DOM/widget normalization, apply/clear, pending-edit flush, semantic
      projection, and product prompt construction to shared workflow/execution
      handles.
- [ ] Stage removal of synchronous field/whole-state writers, custom locked
      preservation, local recovery, and toggle policy until AIO activation.
- [ ] Prove one receipt covers every mirror, AIO v1 migration is current-only,
      locked bytes survive save, failures block, and builder product tests pass.

## Move the Ideogram prompt library

**What to build:** The Ideogram library persists opaque private records and
lists strict minimal shells while preserving product CRUD and normalization.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare the record kind, operations, empty safe projection, current and
      legacy schema bindings, and fixed generic private label.
- [ ] Bind JSON document CRUD/atomic persistence, IDs, naming, payload
      normalization, and authorized product use to shared record handles.
- [ ] Remove consumer shell construction, crypto, token checks, and raw error
      responses behind the inactive adapter path.
- [ ] Prove locked list/delete, authorized use/edit/duplicate, failed decrypt,
      genuine v1 rewrite receipt, no metadata leak, and preserved domain CRUD.

## Move run-info redaction

**What to build:** AIO run-info remains useful while every private diagnostic
field is sensitive by default and only validated coarse product facts are
released.

**Blocked by:** Move Generate and Krea prompts; Move the Ideogram prompt
builder.

- [ ] Declare the protected run-info operation, sensitive field classes, and
      explicit coarse safe projection.
- [ ] Bind existing structure/performance calculations to server-resolved mode
      and shared projection/redaction rather than request authority or ad-hoc
      encryption.
- [ ] Remove direct encryption and one-off debug omission policy behind the
      inactive integration.
- [ ] Prove private canaries never reach UI payloads, logs, metadata, or unsafe
      diagnostics while public/product schema behavior stays stable.

## Activate the AIO profile and remove its local privacy core

**What to build:** AIO switches atomically to one complete profile and no
longer ships its local codec, route/client, synchronous writer, recovery policy,
or fail-open authorization path.

**Blocked by:** Move Generate and Krea prompts; Move the Ideogram prompt
builder; Move the Ideogram prompt library; Move run-info redaction.

- [ ] Assemble and attest the complete server/browser profile, switch all
      prompt, builder, library, run-info, and recovery call sites, and activate
      only with every adapter present.
- [ ] Delete the local privacy service/routes/client/recovery modules and all
      consumer crypto/token/shell/policy branches.
- [ ] Align dependency, project, manager, documentation, and packaged browser
      metadata to the candidate suite without local-path dependencies.
- [ ] Run the full AIO suite and shared profile, legacy, private-default,
      missing/stale-package, leak, and static-duplication evidence.

## Move timeline state and execution

**What to build:** Director timeline state saves, reloads, and executes through
one shared snapshot without substituting defaults when private state is locked
or unreadable.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare the hidden timeline resource, current-schema continuity,
      JSON-key import, global floor, semantic execution projection, and
      save/export/queue/render/replay operations.
- [ ] Bind editor locate/normalize/apply/clear, debounced edit flush,
      validation/planning, and product execution to snapshot/barrier/execution
      handles.
- [ ] Stage removal of synchronous encryption, local unlock behavior, direct
      backend decrypt, and decrypt-failure default substitution.
- [ ] Prove pre-extraction ciphertext continuity, locked byte-preserving saves,
      no execution/default fallback, fresh grants, and unchanged timeline
      normalization/planning behavior.

## Move project and character libraries

**What to build:** Director projects and characters use shared opaque record
storage and strict locked shells while retaining product normalization,
validation, asset rules, preview, and CRUD.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare project and character record kinds, protected operations, empty
      default safe projections, current-schema continuity, and JSON-key import.
- [ ] Bind domain JSON persistence, IDs, embedded-media stripping, referenced
      assets, validation, and authorized preview/use to shared record handles.
- [ ] Stage removal of record crypto, detailed locked shells, ungated private
      routes, direct browser privacy behavior, and raw exception responses.
- [ ] Prove minimal listing, locked deletion, authorized reveal, failed decrypt,
      current rewrite receipts, canary redaction, and preserved product CRUD.

## Move thumbnail and waveform caches

**What to build:** Director thumbnails and waveforms become managed
regenerable artifacts served through opaque leases while media decoding, root
validation, cache keys, and regeneration remain product-owned.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare thumbnail/waveform purposes, owners, retention, operations,
      plaintext derivatives, and global privacy floor.
- [ ] Bind source decode, allowed roots, cache key, WebP/peak encoding, and
      regeneration to shared artifact storage and serving.
- [ ] Stage removal of cache encryption/filesystem/mode/cleanup branches,
      request-authoritative privacy, raw paths, and direct serving URLs.
- [ ] Prove atomic concurrency, purge/regeneration, lease revocation,
      backpressure, startup sweep, allowed-root rejection, and unchanged media
      outputs.

## Move take metadata, redaction and segment spills

**What to build:** Director take registration exposes only a validated safe
projection and timeline segment spills use managed run-scoped artifacts without
changing generation or stitching behavior.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare the protected take operation, sensitive registration/run
      metadata, safe sidecar candidates, segment-spill artifact, owners, and all
      plaintext/debug derivatives.
- [ ] Bind take normalization/output association/sidecar write and tensor
      encode/decode/stitch adapters to shared redaction and spill handles.
- [ ] Stage removal of ad-hoc server/browser redaction and local spill
      encryption/filesystem/cleanup ledgers.
- [ ] Prove canary-safe take/sidecar/UI projections, interruption and
      `BaseException` cleanup, restart sweep, no plaintext staging, and preserved
      LTX/WAN stitching semantics.

## Move media browsing and source serving

**What to build:** Director media browsing, source viewing, previews, and take
discovery/deletion preserve domain behavior without disclosing private paths,
names, metadata, or path-bearing URLs.

**Blocked by:** Move thumbnail and waveform caches; Move take metadata,
redaction and segment spills.

- [ ] Declare every protected media operation and sensitive projection while
      distinguishing user-owned source/output files from generated artifacts.
- [ ] Bind folder configuration, aliases, roots, metadata extraction, take
      discovery/deletion, and domain UI to shared authorization, redaction, and
      lease handles.
- [ ] Stage removal of request mode authority, path URL construction, direct
      private views, local privacy helpers, and raw private errors.
- [ ] Prove opaque view/preview leases, strict projections, traversal/outside-
      root rejection, missing-media deletion rules, no canary leakage, and
      unchanged product discovery/deletion.

## Move the global privacy authority and transitions

**What to build:** Director's global setting becomes a shared privacy floor and
its transitions cover every timeline, record, media, take, cache, and spill
derivative before reporting success.

**Blocked by:** Move timeline state and execution; Move project and character
libraries; Move thumbnail and waveform caches; Move take metadata, redaction
and segment spills; Move media browsing and source serving.

- [ ] Bind the legacy global setting to declared/effective shared mode while
      retaining unrelated settings, validation, roots, and UI placement.
- [ ] Supply complete product enumeration/rewrite/purge adapters for every
      Director value and derivative introduced by the preceding tickets.
- [ ] Remove server/browser token, cache-only transition, and local precedence
      policy behind the inactive shared transition handle.
- [ ] Prove missing/malformed state defaults private, requests cannot weaken the
      floor, declassification is authorized, and either all derivatives change
      or the original mode remains authoritative.

## Activate the Director profile and delete every local fallback

**What to build:** Director activates one complete profile and removes its
vendored keystore, compatibility shim, local codecs/routes/UI, and all parallel
privacy behavior.

**Blocked by:** Move timeline state and execution; Move project and character
libraries; Move thumbnail and waveform caches; Move take metadata, redaction
and segment spills; Move media browsing and source serving; Move the global
privacy authority and transitions.

- [ ] Assemble and attest the complete server/browser profile and switch all
      timeline, library, media, take, spill, settings, and recovery call sites.
- [ ] Delete the vendored backend, package shim, local state/byte codec, privacy
      routes/dialog/client, local token/mode/redaction/artifact policy, and
      positive fallback path.
- [ ] Align dependency, project, manager, documentation, and packaged browser
      metadata to the exact candidate suite.
- [ ] Run the full Director Python/JS suites and shared continuity,
      missing-package blocking, transition, leak, artifact, browser, and
      static-fallback evidence.

## Move workflow and editor privacy

**What to build:** Smart Prompt editor state uses shared private-by-default
snapshots and recovery while locked values remain protected and unmodified.

**Blocked by:** Build the shared acceptance harness.

- [ ] Declare prompt-library scope, hidden workflow field, mirrored mode,
      semantic projection, v1 schema/key bindings, and normalize/apply/clear
      adapters.
- [ ] Bind editor state, mode mirror, locked preservation, recovery, and product
      resolution entry to workflow/barrier handles.
- [ ] Stage removal of local promises/memos/sequence tracking, per-node
      serializers, graph patch, clear-on-failure, and toggle policy.
- [ ] Prove genuine old-schema migration, current read-back, original-byte
      preservation, private-default behavior, failure blocking, and unchanged
      editor/schema normalization.

## Move private import and export

**What to build:** Smart Prompt import/merge/replace/export uses the same
settled workflow snapshot and migrates historical packages only through
explicit authorized import and re-export.

**Blocked by:** Move workflow and editor privacy.

- [ ] Declare import-replace, import-merge, and export operations plus bare v1
      and export-wrapper reader bindings.
- [ ] Bind parser, normalization, destination-mode preservation, merge/replace,
      filename, and JSON wrapper adapters to shared snapshot/migration handles.
- [ ] Stage removal of direct decrypt/encrypt and local locked-state transition
      behavior while preserving picker/download and domain conflict rules.
- [ ] Prove genuine bare/export migration, explicit re-export receipt,
      original-byte failure preservation, snapshot reuse, and product
      merge/filename behavior.

## Move execution identity, dispatch and cache behavior

**What to build:** Smart Prompt execution resolves a protected reference with a
fresh grant and session-keyed identity instead of an unkeyed token or empty
fallback library.

**Blocked by:** Move workflow and editor privacy.

- [ ] Declare the exact semantic projection and protected resolve-prompt
      operation while retaining prompt selection, variables, cycles,
      validation, and output formatting as product behavior.
- [ ] Bind semantic projection and dispatcher adapters to shared protected
      references, backend resolution, grants, and session RAM cache.
- [ ] Remove unkeyed cache-token generation/resolution and missing/decrypt
      fallback-to-empty behavior behind the inactive execution path.
- [ ] Prove cross-session identity isolation, lock cache clear, grant
      revocation, missing/mismatched reference rejection, no default execution,
      and unchanged resolver outputs.

## Activate the Smart Prompt profile and remove its local privacy core

**What to build:** Smart Prompt switches atomically to one shared profile and
deletes its local codec, routes, request/unlock client, memo/recovery policy,
serialization patches, and fallback execution behavior.

**Blocked by:** Move workflow and editor privacy; Move private import and
export; Move execution identity, dispatch and cache behavior.

- [ ] Assemble and attest the complete server/browser profile, switch all
      editor, import/export, execution, recovery, and mode call sites, and
      activate only with every adapter present.
- [ ] Delete local privacy backend/frontend machinery and every duplicated
      crypto, token, retry, cache identity, recovery, or policy branch.
- [ ] Align dependency, project, manager, documentation, and packaged browser
      metadata to the exact candidate suite.
- [ ] Run the full unittest/JS syntax suites and shared legacy, execution,
      recovery, design-system, missing-package, leak, and duplication evidence.

## Assemble the signed five-artifact candidate suite

**What to build:** The complete local cutover is represented by one immutable
candidate manifest and five reproducible artifacts before anything is
published.

**Blocked by:** Activate the Utils profile and remove its local privacy core;
Activate the AIO profile and remove its local privacy core; Activate the
Director profile and delete every local fallback; Activate the Smart Prompt
profile and remove its local privacy core.

- [ ] Build `helto-privacy` and all four consumers from exact source identities
      with target versions, artifact hashes, profile fingerprints, environment
      tuples, previous suite, and rollback class.
- [ ] Verify every requirements, project, manager, lock/install,
      documentation, browser asset, and embedded profile declaration names the
      same exact candidate without local paths or floating ranges.
- [ ] Inspect artifact contents for all required modules/assets and reject
      consumer-local privacy engines, Director fallback files, duplicated UI,
      stale constants, or undeclared dependencies.
- [ ] Sign the immutable `cutover-pending` candidate manifest without treating
      the local build as a public or supported release.

## Prove clean installs and all 24 registration orders

**What to build:** The local candidate installs only from its declared
artifacts in clean environments and behaves identically for every server and
browser consumer load order.

**Blocked by:** Assemble the signed five-artifact candidate suite.

- [ ] For each supported environment tuple, install into empty site-packages
      and isolated ComfyUI/browser state using the tuple's exact interpreter,
      with no editable install, checkout `PYTHONPATH`, sibling import, existing
      privacy state, or browser cache.
- [ ] Exercise all 24 consumer registration orders before/after shared route
      attachment and duplicate identical imports.
- [ ] Require one canonical runtime, route family, browser module, UI mount,
      suite digest, and four exact fingerprints with no duplicate handlers or
      order-dependent state.
- [ ] Prove missing/stale shared or consumer artifacts, digest drift, corrupt
      profiles/adapters, duplicate IDs, and interrupted installation block
      generically before privacy-bearing configuration or serialization.

## Prove rendered, leak, fault and lifecycle acceptance

**What to build:** Every supported environment/renderer tuple produces complete
synthetic browser and fault evidence for the exact local candidate.

**Blocked by:** Prove clean installs and all 24 registration orders.

- [ ] Use disposable ComfyUI roots and isolated `chrome-devtools-axi` sessions
      for both legacy canvas and Nodes 2.0/Vue without attaching to the user's
      live service, browser, workflows, media, keys, or models.
- [ ] Cover private defaults, blocked/verification UI, locked byte-preserving
      saves, explicit reveal, cross-pack sessions, barriers, legacy receipts,
      recovery, transitions, records, leases, restart invalidation, and replay
      grants.
- [ ] Run the synthetic canary leak oracle over serialized state, routes, URLs,
      headers, DOM/accessibility, logs/errors, console/network, files, caches,
      sidecars, metadata, and outputs; key bytes are never permitted.
- [ ] Run deterministic encryption/persistence/replace/cleanup/streaming/
      cancellation/`BaseException`/timing/cache/process fault campaigns and
      require reproducible no-retry results with no partial success or
      plaintext staging.

## Publish the immutable cutover-pending artifacts

**What to build:** The exact locally accepted candidate becomes immutable
public GitHub artifacts while remaining explicitly non-activatable.

**Blocked by:** Prove rendered, leak, fault and lifecycle acceptance.

- [ ] Obtain fresh user authorization before creating tags, releases, pushes,
      or any other external state.
- [ ] Publish and verify the shared immutable tag/artifact first, then publish
      each already-tested consumer artifact with its exact shared dependency
      pin and suite identity.
- [ ] Verify public source/tag identities and downloaded hashes match the signed
      candidate manifest; never rebuild or mutate an existing artifact in
      place.
- [ ] Mark the suite `cutover-pending` so installation permits verification but
      activation remains impossible.

## Reproduce acceptance from public artifacts

**What to build:** The public GitHub artifacts independently reproduce the
exact local candidate and its entire zero-waiver acceptance result.

**Blocked by:** Publish the immutable cutover-pending artifacts.

- [ ] Install only from public dependency/manager metadata in fresh supported
      environment tuples with no checkout, local wheel, editable install, or
      resolver override.
- [ ] Reproduce all five hashes, the suite digest, profile fingerprints, 24
      load-order results, negative blocked states, full repository checks,
      rendered scenarios, leak oracle, and fault campaigns.
- [ ] Emit and sign the complete acceptance evidence manifest bound to the
      public suite digest, exact tuples, renderers, seeds, and artifacts.
- [ ] If any cell differs or fails, leave the candidate pending/failed and
      create new immutable versions rather than altering published artifacts.

## Promote the suite and verify the operator-blind cutover procedure

**What to build:** A publicly reproducible suite becomes `ready`, and its local
installation procedure proves exact readiness without exposing plaintext or
activating automatically.

**Blocked by:** Reproduce acceptance from public artifacts.

- [ ] Obtain fresh user authorization before promoting release state or
      changing the user's installed repositories/service.
- [ ] Sign the ready promotion for the unchanged suite digest and publish exact
      install, repair, activation, rollback, and previous-suite metadata.
- [ ] Use `cui-stop`, byte-copy the encrypted backup, install all five exact
      artifacts, use `cui-start`, verify generic readiness, and require a full
      browser reload; use `cui-restart` only when no stopped-interval work is
      required.
- [ ] Keep the installation `activation-required` until explicit user
      activation, and prove pre-activation rollback versus post-activation
      snapshot restoration/repair-forward rules without giving maintenance a
      decrypt or key-export capability.

## Check, re-save and seal legacy audit scopes

**What to build:** The user can verify the workflow/export/pack-state collection
they intend to preserve, rewrite every discovered legacy obligation, and seal
each reader scope explicitly.

**Blocked by:** Promote the suite and verify the operator-blind cutover
procedure.

- [ ] The user declares each audit scope and performs the content-level checks;
      agents may report protected counts/status but must not inspect decrypted
      workflow content, media, keys, or private browser state.
- [ ] Every discovered workflow, record, queue/store value, export, and durable
      selector mask receives a verified current rewrite/read-back receipt before
      its reader can be sealed.
- [ ] Seal only scopes with zero unresolved obligations, verified key imports,
      and current durable adjuncts; inactivity alone is insufficient.
- [ ] Automatically invalidate a seal and reopen its audit if the reader is
      used or new matching legacy data is discovered later.

## Remove sealed legacy readers in a later suite

**What to build:** Independently sealed legacy units can be removed through a
new coordinated suite without weakening current formats or deleting historical
keys.

**Blocked by:** Check, re-save and seal legacy audit scopes.

- [ ] Select only reader units whose complete declared scopes remain validly
      sealed and whose dependent container/byte reader graph permits removal.
- [ ] Remove each reader's implementation, registry entry, bindings,
      dependency declaration, fixtures, tests, audit label, and migration copy
      as one unit without editing unrelated readers/current codecs.
- [ ] Retain wrapped historical keys as decrypt-only and keep key pruning absent
      from the software release.
- [ ] Build a new suite ID and pass the complete local/public acceptance and
      coordinated release process before promoting the reader-removal suite.

## Prune wrapped historical keys

**What to build:** Historical decrypt-only keys whose reader dependencies have
been removed can be destroyed through a separate explicit irreversible
keystore transaction.

**Blocked by:** Remove sealed legacy readers in a later suite.

- [ ] Obtain fresh explicit user authorization that names the keys/scopes and
      acknowledges the irreversible loss of any unseen dependent ciphertext.
- [ ] Verify every dependent audit scope is sealed, reader unit has shipped
      removed, no retained wrapper can dispatch to it, and no later discovery
      has invalidated the evidence.
- [ ] Perform atomic keystore removal with verification and a sanitized audit
      result; never expose key bytes or decrypted payloads to the agent.
- [ ] Do not combine pruning with installation, activation, reader removal, or
      a routine software release.
