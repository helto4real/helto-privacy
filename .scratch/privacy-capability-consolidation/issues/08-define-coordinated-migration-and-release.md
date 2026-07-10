# Define the coordinated migration and release

Type: grilling
Status: resolved
Blocked by: 03, 06, 07, 14

## Question

In what dependency order should shared-package and consumer changes be
implemented, tested, versioned, and released so the four repositories complete
one coordinated cutover with a clear rollback boundary? Include synchronized
requirements/project/manager metadata, a release identity for the supported
five-repository set, clean installation with the ComfyUI interpreter, required
server/browser reloads, and handling of incomplete or rolled-back installs.

## Comments

### Constraints from the dependency map

- Python imports one `helto_privacy` distribution and browser clients import one
  shared ES module, so four consumer dependency declarations do not create four
  isolated runtimes.
- ComfyUI loads custom-node directories in unsorted order. Profile collection,
  route attachment, browser reconciliation, and readiness cannot depend on a
  particular consumer loading first.
- The approved cutover deliberately removes Director's fallback and AIO's soft
  token-guard fallback. Missing or incompatible shared behavior must become one
  visible blocked state, never a local implementation or authorization success.
- The target contract changes source interfaces and may write replacement
  persisted forms. A package rollback after current-format writes is not the
  same operation as rolling binaries back before activation.
- The slice DAG requires P0-P6 in `helto-privacy` before any consumer deletes its
  local policy implementation. A consumer profile activates atomically only when
  all of that pack's slices and adapter slots attest to one fingerprint.

### Recommended contract

1. Define one immutable **supported release set** for the coordinated cutover.
   Its manifest is owned and packaged by `helto-privacy` and contains a suite ID,
   privacy contract/profile schema version, exact shared distribution version,
   exact release tag/version and source commit for each consumer, expected
   profile IDs and fingerprints, artifact hashes, supported Python/ComfyUI
   bounds, and the manifest digest. Consumers embed only the expected suite ID
   and manifest digest; they do not maintain independent compatibility tables.
2. Dependency declarations use exact immutable artifacts or tags. The four
   `requirements.txt` files, every `pyproject.toml`, ComfyUI Manager metadata,
   lock/install files, README install commands, and profile constants name the
   same shared release. Floating branches, tag ranges, compatible-release
   operators, optional imports, vendored fallbacks, and duplicated direct
   `cryptography` ownership are removed where the shared distribution owns the
   dependency.
3. Implementation proceeds on a coordinated five-repository release branch or
   equivalent pinned worktrees. First implement and contract-test P0-P6 in the
   shared package. Then implement consumer profiles/adapters and move call sites
   in dependency order while testing against the exact unpublished shared commit.
   Delete pack-local privacy mechanics only after the replacement handle passes
   its consumer and shared contract tests. No intermediate branch is advertised
   as a supported mixed installation.
4. Pre-release integration builds all five artifacts and their metadata before
   any public tag is declared supported. A clean ComfyUI environment installs
   only from those declarations using the exact ComfyUI interpreter, loads all
   four consumers in varied orders, verifies one backend/browser runtime and all
   profile fingerprints, exercises genuine legacy/current fixtures, and runs the
   cross-repository browser scenarios from **Define cross-repository
   acceptance**.
5. Publication order is mechanical, not a rolling-compatibility promise: publish
   and verify the shared immutable artifact/tag first, then tag/publish each
   already-tested consumer with its exact pin, then publish the suite manifest
   as supported only after a second clean install resolves the public artifacts
   and reproduces the manifest digest. A shared tag that exists before all four
   consumer tags is `cutover-pending`, not a supported set.
6. Runtime suite state is one of `active`, `activation-required`, `incomplete`,
   `mismatch`, or `conflict`. Anything except `active` blocks private save, queue,
   serving, reveal, transition, migration, and execution. Unrelated product code
   may remain visible only if it cannot touch registered privacy-bearing state.
   The server readiness route and shared UI name missing/mismatched distribution
   IDs generically without exposing product data. Browser/server digest mismatch
   blocks before graph configuration or serialization.
7. Installation and upgrade are offline with respect to the running process:
   use the user's authoritative `cui-stop` command, back up the declared
   workflow/config/keystore/artifact scope, install the exact shared package with
   `COMFYUI_PYTHON -m pip`, update all four consumer artifacts and metadata as one
   set, and use `cui-start` to create a fresh Python process. `cui-restart` is
   reserved for cases where no installation, backup, repair, or rollback work is
   required between stop and start. Direct process-kill, service-manager, and
   substitute lifecycle commands are outside the supported procedure. After
   start, verify readiness and perform a full browser reload. Hot-reloading
   Python, updating one consumer in a running process, or retaining a cached old
   browser module is unsupported. Browser asset URLs include the suite/manifest
   digest so a normal full reload cannot reuse an incompatible module. Backup is
   a byte-for-byte copy operation and does not open encrypted records or export
   secret key material to the installer, operator, or agent.
8. The first start uses **verification mode**: registration, fingerprint checks,
   structural legacy-envelope probes, opaque non-exporting key-availability
   preflight, synthetic fixture/smoke checks, and read-only status are allowed,
   but decrypting live user payloads, current-format writes, migrations, queues,
   private serving, and transitions remain blocked. The maintenance actor may
   inspect manifests, digests, envelope headers, and opaque key identifiers, but
   receives neither plaintext nor key bytes. This is enforced with a dedicated
   maintenance capability whose API has no reveal, decrypt, key-export, or live
   payload-test operation; an agent is never issued a reveal-capable handle.
   After backup and readiness succeed, one explicit authorized suite activation
   writes an activation record bound to the manifest digest and enables the new
   writers; activation itself does not decrypt user data.
9. Before activation, rollback means stop ComfyUI and reinstall the entire prior
   supported release set; partial rollback is never supported. After activation,
   binary rollback alone is forbidden because new formats or migrations may have
   been written. Recovery requires stopping the process, restoring the complete
   pre-activation data snapshot, and reinstalling the previous full set. If that
   snapshot is incomplete, remain on the new set and repair forward.
10. A failed or interrupted install never invokes a legacy/local fallback. On
    restart the suite remains `incomplete` or `mismatch`, preserves original data
    and pending migration obligations, and offers exact repair instructions.
    Reinstalling the missing expected artifacts and restarting can complete the
    set; no consumer may silently rewrite profile fingerprints or accept a newer
    unlisted runtime.
11. Legacy-reader removal is a later supported release set with its own suite ID.
    It requires the relevant retirement seals before packaging. Historical-key
    pruning is not part of a software release and remains a separate authorized
    irreversible keystore action.
12. Each released set records provenance: signed tags or equivalent immutable
    source identities, built-artifact hashes, test run identity, manifest digest,
    previous supported set, and whether rollback requires data restoration. The
    manifest, not release timing or repository `main`, defines what is supported.

The first decision is whether the supported unit is this exact manifest-bound
five-repository set. The strict recommendation is yes: permitting independent
version ranges would recreate the ambiguous mixed-runtime state the cutover is
intended to remove.

### Decisions locked

- The sole supported compatibility unit is one exact five-repository supported
  release set. Its suite manifest fixes the shared contract, package/tag/commit
  identities, consumer profile fingerprints, artifact hashes, environment
  bounds, and manifest digest. Consumers declare that suite ID and digest;
  floating branches, compatible version ranges, optional shared dependencies,
  independent compatibility tables, and arbitrary mixed sets are unsupported.
- The first start of a newly installed supported release set is verification
  only. It may register components, compare suite and profile fingerprints,
  inspect structural legacy envelope metadata, preflight opaque key
  availability, create byte-for-byte backups, run synthetic fixtures, and report
  read-only status. The installer, operator, or agent receives neither plaintext
  user data nor secret key material. The agent is an untrusted maintenance
  principal, is never issued a reveal-capable handle, and can use only an API
  that omits reveal, decrypt, key-export, and live payload-test operations. Live
  payload decryption is prohibited in verification mode. It may not write or
  migrate privacy-bearing data, queue privacy work, serve private artifacts, or
  perform privacy transitions.
  Explicit authorized suite activation records the suite-manifest digest and
  enables the current writers without decrypting user data. Before activation,
  rollback restores the prior complete supported release set. After activation,
  rollback additionally requires the complete pre-activation data snapshot;
  without both, the installation must be repaired forward rather than partially
  rolled back.
- Supported lifecycle control uses the user's `cui-stop`, `cui-start`, and
  `cui-restart` commands. Installation, upgrade, repair, and rollback use
  `cui-stop`, perform all required offline work, then use `cui-start` and require
  a full browser reload. `cui-restart` is used only when no work must occur while
  ComfyUI is stopped. Generic process-kill, service-manager, hot-reload, and
  partial in-process upgrade paths are unsupported.
- Publication is two-phase. The immutable `helto-privacy` and four consumer
  artifacts are first published as one `cutover-pending` suite candidate whose
  manifest fixes their identities and hashes. Pending artifacts may be installed
  only for verification and cannot be activated. The suite is promoted to
  `ready` only after every exact artifact is available, all hashes and profile
  fingerprints match, and the clean-install acceptance matrix passes against
  that manifest digest. Promotion changes suite status, never an artifact; a
  failed candidate remains immutable and is superseded by a new suite ID.
- A failed, interrupted, incomplete, mismatched, or conflicting installation is
  a blocked installation. It preserves existing encrypted bytes and migration
  obligations, exposes only product-data-free readiness diagnostics, and blocks
  every privacy-bearing save, migration, queue, serve, reveal, and transition.
  It never falls back to consumer-local implementations, legacy writers,
  plaintext, an unlisted package version, or a partial supported set. Recovery
  requires `cui-stop`, exact repair to the declared suite manifest, `cui-start`,
  and a full browser reload; the repaired installation re-enters verification
  mode rather than activating automatically.
- Every suite manifest is immutable and signed. It records exact source tags or
  commits, built-artifact hashes, consumer profile fingerprints, acceptance-run
  identity, environment bounds and digest, the previous supported suite ID, the
  manifest digest, and whether rollback requires restoring data. Verification
  checks this evidence against installed bytes; repository `main`, publication
  timing, and mutable release metadata are never compatibility evidence.

## Answer

The cutover ships as one exact five-repository supported release set. An
immutable signed suite manifest owned by `helto-privacy` is the sole
compatibility authority: it binds the shared contract, exact source and artifact
identities for `helto-privacy` and all four consumers, profile fingerprints,
artifact hashes, Python and ComfyUI environment bounds, acceptance-run identity,
previous suite, rollback class, and its own digest. Every requirements,
project, ComfyUI Manager, lock/install, documentation, and embedded profile
declaration must resolve to that set. Floating ranges, optional shared imports,
vendored fallbacks, and arbitrary mixed versions are unsupported.

Implementation follows the slice DAG. `helto-privacy` first supplies and tests
the seven shared prerequisites P0-P6. Consumer profiles and product adapters are
then moved against that exact unpublished shared revision. A consumer deletes
its local privacy mechanics only after its complete profile compiles and all of
its replacement handles pass shared and consumer contract tests. Intermediate
branches are development artifacts, never supported installations.

Publication is two-phase. The five immutable artifacts are published as one
`cutover-pending` candidate and may be installed only in verification mode. A
clean ComfyUI environment installs exclusively from their declared metadata
with the ComfyUI interpreter, varies consumer registration order, verifies one
backend and browser runtime plus every profile fingerprint, exercises genuine
legacy and current fixtures, and runs the cross-repository browser matrix. Only
matching public artifacts and passing evidence promote the manifest to `ready`;
promotion never changes an artifact. A failed candidate is superseded by a new
suite ID and can never be activated.

The first start of a ready suite remains `activation-required`. Verification is
operator-blind: an untrusted installer, operator, or agent receives a dedicated
maintenance capability that can inspect public manifests, digests, structural
envelope headers, opaque key identifiers, and boolean readiness results or copy
encrypted bytes, but has no reveal, decrypt, key-export, or live payload-test
operation. Smoke tests use synthetic data. Backup, verification, and activation
do not decrypt user payloads or expose key bytes. Only an explicit authorized
suite activation binds the manifest digest, enables current writers, and moves
the installation to `active`.

Installation, upgrade, repair, and rollback are offline operations using the
user's lifecycle commands: `cui-stop`, perform the encrypted byte-for-byte
backup and all five-repository changes, then `cui-start`, verify readiness, and
perform a full browser reload. `cui-restart` is reserved for a restart that
requires no stopped-interval work. Generic process killing, service-manager
substitutes, hot Python reload, partial consumer updates, and cached incompatible
browser modules are unsupported; browser assets are keyed by the manifest
digest.

An incomplete, mismatched, or conflicting installation is blocked. It preserves
existing encrypted bytes and migration obligations, exposes only generic
product-data-free repair status, and permits no privacy-bearing save, migration,
queue, serving, reveal, execution, or transition. It cannot invoke a legacy or
consumer-local writer, accept plaintext fallback, or infer compatibility from a
nearby version. Exact repair followed by a fresh start returns to verification
mode rather than activating automatically.

Before activation, rollback restores the complete previous supported release
set. Activation is the data rollback boundary: after current writers may have
run, rollback additionally requires the complete pre-activation data snapshot
and prior suite. Without both, partial binary rollback is prohibited and the
installation must repair forward. Legacy-reader removal is a later exact suite
with the required retirement seals; wrapped historical-key pruning remains a
separate authorized irreversible action.

The durable rationale is recorded in
[ADR 0010](../../../docs/adr/0010-release-exact-suites-through-verification-and-activation.md).
