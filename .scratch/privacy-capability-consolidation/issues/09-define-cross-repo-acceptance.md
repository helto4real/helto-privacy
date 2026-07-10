# Define cross-repository acceptance

Type: grilling
Status: resolved
Blocked by: 05, 06, 07, 08, 10, 11, 12

## Question

What test fixtures, static checks, package-backed and fallback-path runs, and
real ComfyUI browser scenarios must pass across `helto-privacy` and all four
consumer packs before the consolidation specification is implementation-ready?
The fixture set must contain genuine ciphertext produced by the historical
writers, including every Utils byte generation and a referenced selector mask;
changing only the schema field of a current envelope is not sufficient proof.
Run the supported set from declared dependencies in a clean environment, vary
which consumer registers first, assert exactly one compatible canonical
runtime/UI, and cover missing/stale package behavior plus every retained
Director fallback mode.

## Comments

### Source-grounded planning baseline

- The planning snapshot is `helto-privacy` `d7af810`, Utils `a92ff97`, AIO
  `8cadac9`, Director `82c2a75`, and Smart Prompt `4ace56e`. These commits are
  evidence for current seams only; the future suite manifest binds the actual
  implementation artifacts under test.
- The verified local backend source is `/home/thhel/git/ComfyUI` at `e2a6e30d`,
  project version `0.27.0`. Its loader checks `NODE_CLASS_MAPPINGS` before
  `comfy_entrypoint` and collects `WEB_DIRECTORY` extensions. The currently
  resolved interpreter is `/home/thhel/.pyenv/versions/3.13.14/bin/python` with
  `comfyui_frontend_package` `1.45.20`; an acceptance run must record its own
  exact interpreter, backend commit, and frontend version rather than inherit
  these planning values.
- The user's `cui-start`, `cui-stop`, and `cui-restart` commands are aliases for
  the managed ComfyUI service lifecycle. Release rehearsal uses those commands
  as decided in **Define the coordinated migration and release**. Automated
  rendered tests use a disposable isolated ComfyUI data root and isolated
  `chrome-devtools-axi` session, never the user's workflow, browser profile,
  queue/history, media, keys, or live service data.
- Existing suites already cover useful product behavior: shared envelope,
  keystore, route, and recovery basics; Utils workflow/queue/media and both JS
  renderer helpers; AIO prompts, builder, library, run-info, and recovery;
  Director timeline, records, caches, media routes, spills, and redaction; and
  Smart Prompt serialization, import/export, execution tokens, recovery, and UI
  styling. The cutover must retain those suites while moving shared-policy
  assertions into one reusable contract harness.
- The legacy-data inventory proves the current fixture gap. Existing tests
  mostly reject old schemas and prefixes. Genuine historical output is still
  required for AIO v1, Smart Prompt v1/export forms, Utils workflow and queue
  wrappers, raw XOR, `HELTO_PRIV1`, `HELTO_PRIV2`, `HELTO_PRIV3`, JSON and
  binary key imports, a referenced selector mask, and Director's unchanged
  pre-extraction schema continuity.
- The earlier fallback question is no longer open. **Map per-consumer cutover
  slices** deletes Director's `_vendored_keystore.py`, compatibility shim, local
  codec, routes, and privacy UI, while **Define the coordinated migration and
  release** forbids local or legacy writer fallback. Acceptance therefore
  proves missing/stale package failure as a blocked negative path and proves
  the published artifacts contain no Director privacy fallback. Non-privacy
  Director product fallbacks remain consumer tests only where they can touch a
  protected projection or diagnostic surface.

### Recommended acceptance contract

1. `helto-privacy` owns a versioned cross-repository acceptance catalog. Every
   requirement has a stable evidence ID, owning layer, required fixtures,
   supported environment tuples, and allowed observation sinks. A run emits a
   machine-readable evidence manifest bound to the suite-manifest digest,
   exact source and artifact hashes, harness version, Python/ComfyUI/frontend
   tuple, renderer, registration order, test seed, and result for every ID.
2. Promotion is all-or-nothing. Every required evidence ID and every existing
   repository test/lint/type/package check must pass in the same candidate.
   Skips, xfails, waived failures, unexpected warnings, console errors, and
   retry-to-green results are failures. Platform exclusions reduce the suite's
   declared support matrix; they do not waive a cell inside it. Concurrency
   tests use recorded seeds and repeated clean runs to expose flakiness.
3. Static/package checks build all five immutable artifacts and inspect their
   contents and metadata before installation. They require exact suite pins and
   fingerprints everywhere; one packaged shared browser module; no consumer
   AES/keystore/token/session/lease/shell/recovery-policy implementation; no
   optional shared import, vendored privacy backend, local encrypt/decrypt route
   family, path-bearing private token, plaintext fallback, or stale local UI;
   and no missing packaged profile, adapter declaration, legacy binding, or
   manifest-digest asset key.
4. The canonical fixture catalog contains only synthetic non-user data, but its
   ciphertext is byte output from the genuine historical writer at a recorded
   repository commit. Each fixture records producer commit and function,
   generation command/container digest, format/schema/purpose, deterministic
   test key provenance, ciphertext hash, expected normalized product state, and
   owning reader ID. Stored mutated/tampered cases are labelled derived rather
   than historical. Re-generation must reproduce the catalog or require a new
   fixture version and review.
5. Fixture coverage includes every current state, byte, and chunked-byte schema
   and purpose plus every removable legacy reader/key unit. Each positive case
   proves exact probe/read, protected migration obligation, normalized equality,
   current-only transactional rewrite, read-back verification, receipt, and
   unchanged original bytes on injected failure. Negative cases cover wrong
   key, purpose, schema, algorithm, truncated/tampered bytes, malformed wrapper,
   unsupported data, missing adjunct, and failed atomic replacement. Readers
   have no writer interface. The selector workflow plus referenced historical
   mask must migrate or fail as one transaction.
6. The shared contract harness covers atomic profile validation and compilation,
   identical-registration idempotence, conflict/missing-adapter blocking,
   PromptServer-before/after registration, browser/server fingerprint
   attestation, private default and server-side floors, authorization, typed
   failures, operator-blind maintenance, snapshots/barriers, envelope
   dispositions, grants and revocation, minimal record shells, allowlisted safe
   projections, artifact storage/leases/streaming/sweeps, mode transitions,
   legacy obligations/receipts/seals, and separate historical-key pruning.
7. Consumer suites bind that shared harness to every U0-U7, A0-A4, D0-D6, and
   S0-S3 slice. They retain product normalization, node IDs/widget mappings,
   roots, encoders, record schemas, domain CRUD, media behavior, execution
   projections, and fallback semantics, while importing shared assertions for
   privacy behavior. At least one consumer integration test per registered
   surface proves the real adapter—not a duplicate mock implementation—reaches
   the shared handle.
8. Clean-install tests create an empty interpreter/site-packages, isolated
   ComfyUI user root, and exactly the five built artifacts. They install only
   through declared dependency/manager metadata using the recorded ComfyUI
   interpreter, with no workspace `PYTHONPATH`, editable install, implicit
   sibling checkout, existing keystore, or browser cache. The pre-publication
   run uses candidate artifacts; the promotion run downloads the immutable
   public artifacts and must reproduce their hashes and suite digest.
9. Registration tests exercise all 24 consumer directory/import orders for both
   backend and browser extension registration, including registrations before
   and after shared route attachment and duplicate identical imports. Every run
   must yield one canonical Python runtime, route family, browser module, UI
   mount, suite digest, and four exact profile fingerprints with no duplicate
   handlers or order-dependent state.
10. Negative installation cells remove or stale the shared package, each
    consumer in turn, and the browser module in turn; corrupt a profile and
    adapter slot; introduce duplicate IDs/fingerprints; and interrupt artifact
    installation. Each cell must enter the expected `incomplete`, `mismatch`,
    or `conflict` state before graph configuration or serialization, expose only
    product-data-free repair status, preserve encrypted bytes, and block every
    privacy-bearing operation. Exact repair and restart return to verification
    mode without auto-activation. No cell may import a local privacy fallback.
11. A forbidden-sink oracle plants unique synthetic canaries for prompts,
    names, tags, paths, filenames, tokens, keys, media metadata, and payload
    bytes. For each operation it scans workflow/execution JSON, public record
    shells, route bodies/headers/URLs, UI payloads and locked DOM, accessibility
    snapshots, logs, exceptions, filenames, cache/temp trees, sidecars, saved
    metadata, console, and relevant network records. A canary in any sink not
    explicitly authorized by that evidence ID fails the suite. Key bytes are
    never an allowed observation. The agent and harness see only synthetic
    canaries, never decrypted user data.
12. Real browser acceptance runs against a disposable instance through
    `chrome-devtools-axi`, separately for legacy canvas and Nodes 2.0/Vue for
    every supported frontend tuple. It proves private-by-default creation,
    verification/activation and blocked-suite UI, exactly one shared privacy
    surface, locked load without decrypt, byte-preserving locked save, explicit
    unlock/reveal, cross-pack session behavior, graph-wide save/queue barriers,
    failure blocking, migration/re-save and receipts, manual recovery, mode
    floors/transitions, minimal record shells, opaque media leases, lock/restart
    invalidation, and replay with a fresh grant. Renderer checks also cover
    stable sizing, full reload, keyboard/focus behavior, gold active versus blue
    focus, and unreadable hide/mask/peek states without ghost text, caret,
    selection, placeholder, path, name, prompt, metadata, or preview leakage.
13. Fault and lifecycle tests inject encryption, persistence, atomic replace,
    cleanup, streaming, cancellation, `BaseException`, route timing, browser
    cache, and process interruption failures. They prove bounded off-loop work,
    backpressure, exactly-once run cleanup, startup sweep, no named plaintext
    staging, no stale grant/lease/session reuse after lock or restart, no older
    generation overwriting newer state, and no partial privacy transition or
    migration success.
14. Release rehearsal proves `cutover-pending` cannot activate, public artifact
    promotion is reproducible, first start is verification-only, activation is
    explicit and non-decrypting, pre-activation rollback restores the previous
    full set, post-activation rollback requires both the previous set and the
    complete pre-activation data snapshot, incomplete rollback repairs forward,
    and a later sealed-reader-removal suite does not prune wrapped historical
    keys. The rehearsal uses `cui-stop`/`cui-start` and requires a full browser
    reload without giving the maintenance actor a reveal-capable handle.

The first decision is whether this catalog is a hard release gate. The strict
recommendation is yes: a signed exact suite should not be called `ready` while
any declared evidence cell is skipped, flaky, waived, or failing, because that
would make the suite manifest claim more support than was actually proven.

### Decisions locked

- The versioned acceptance catalog is a hard, all-or-nothing release gate. A
  suite candidate becomes `ready` only when every required evidence ID and all
  existing repository test, lint, type, static, and packaging checks pass
  together against the exact candidate artifacts. Skips, xfails, waivers,
  unexpected warnings or console errors, unrelated failures, and
  retry-to-green results all block promotion. An unsupported platform or
  environment tuple must be removed from the suite manifest and retested; it
  cannot be excluded from a run while remaining a supported claim. The signed
  acceptance evidence manifest records the complete result set and is bound to
  the suite-manifest digest.
- A historical compatibility fixture qualifies only when its ciphertext bytes
  were emitted by the genuine historical writer at a recorded immutable source
  commit using synthetic non-user plaintext and a test-only key. Its catalog
  entry records producer commit and function, reproducible generation command
  and environment identity, schema/format/purpose, reader ID, test-key
  provenance, ciphertext hash, and expected normalized product state. The
  corpus covers every retained current form and every removable legacy reader
  or key-import unit, including all Utils byte generations and one workflow
  whose historical selector mask is a durable referenced adjunct. Mutations
  used for negative tests are labelled derived. Schema-swapped current
  envelopes, hand-constructed lookalikes, unreproducible ciphertext, and real
  user data are not accepted as historical compatibility evidence.
- Clean-install acceptance builds and inspects the five exact candidate
  artifacts, then installs them only through their declared dependency and
  ComfyUI Manager metadata with the recorded ComfyUI interpreter. It uses an
  empty site-packages and isolated ComfyUI/browser state with no workspace
  `PYTHONPATH`, editable install, sibling-checkout import, pre-existing
  keystore/session, or browser cache. Both server and browser registration run
  in all 24 orders of the four consumers. Every order must yield exactly one
  canonical runtime, route family, browser module, privacy UI mount, suite
  digest, and the four expected profile fingerprints without duplicate or
  order-dependent handlers. Negative cells remove or stale each component,
  mismatch browser/server digests, corrupt registrations, and interrupt
  installation; each must block before privacy-bearing graph configuration or
  serialization, preserve encrypted bytes, and expose only generic repair
  status. Published Director artifacts must contain no vendored keystore,
  package shim, local codec/routes/UI, or other privacy fallback, and a missing
  shared package is tested only as a blocked failure path.
- Environment support is enumerated rather than inferred from broad ranges.
  Each supported environment tuple fixes the Python version, ComfyUI backend
  version and source identity, frontend package version, and renderer mode. The
  complete required acceptance catalog must pass for that exact tuple before it
  appears in the suite manifest. Minimum/maximum boundary tests do not imply
  support for untested combinations between them. Adding or changing any tuple
  requires a new complete evidence manifest bound to the candidate suite.
- Every privacy-bearing acceptance scenario uses unique synthetic canaries for
  protected prompts, names, tags, paths, filenames, tokens, metadata, payload
  bytes, and other sensitive classes. The evidence ID declares the exact sink
  and operation in which each canary may appear; authorized reveal widens only
  that named observation for that operation. The leak oracle scans serialized
  workflow and execution state, locked shells and UI payloads, route bodies,
  headers and URLs, logs and exceptions, DOM and accessibility snapshots,
  console and network records, cache/temp trees, filenames, sidecars, saved
  metadata, and produced artifacts. Any canary in an undeclared sink fails the
  suite. Secret key bytes are never an allowed observation. Tests and agents
  receive only synthetic fixture data and cannot substitute live workflows,
  user media, browser profiles, credentials, keys, or decrypted user values.
- Real rendered browser evidence is mandatory for every supported environment
  tuple and renderer mode. It uses a disposable ComfyUI instance with isolated
  custom nodes, user state, database, input/output/temp roots, and a named
  isolated `chrome-devtools-axi` session; it never attaches to the user's live
  service, browser profile, workflow, queue/history, model paths, media, or
  privacy state. The matrix proves private-by-default creation,
  verification/activation and blocked-suite UI, one shared privacy surface,
  locked load without decrypt, byte-preserving locked save, explicit authorized
  reveal, cross-pack session behavior, serialization/queue barriers, failure
  blocking, genuine legacy migration and receipts, manual recovery, mode floors
  and transitions, minimal record shells, opaque media leases, lock/restart
  invalidation, and replay with a fresh grant. It separately proves legacy and
  Vue renderer stability, full browser reload, keyboard/focus behavior, Helto
  gold active versus blue focus semantics, and unreadable hide/mask/peek states
  without ghost text, caret, selection, placeholder, path, name, prompt,
  metadata, or preview leakage. Unexpected console/network errors or server
  warnings fail the evidence cell.
- Suite release acceptance and local installation verification are separate
  gates. Release evidence is produced only from disposable environments and
  synthetic fixtures; the user's live installation, workflow collection,
  browser state, media, keys, and decrypted values can never supply or repair a
  suite evidence cell. On the actual installation, `cui-stop` brackets an
  encrypted byte-for-byte backup plus exact five-artifact install, repair, or
  rollback, and `cui-start` creates the fresh process before a full browser
  reload. The untrusted maintenance actor may compare artifacts, manifests,
  fingerprints, envelope headers, opaque key availability, and generic
  readiness only. It cannot decrypt a payload, export key material, or perform
  a live-data smoke test. Successful operator-blind installation verification
  still leaves the suite `activation-required`; only explicit user-authorized
  activation enables privacy-bearing writers and execution.
- `helto-privacy` owns the versioned acceptance catalog, evidence-manifest
  generator and verifier, historical fixture catalog and generators, shared
  contract harness, leak oracle, clean-install and load-order coordinator,
  fault-injection controls, and disposable ComfyUI/browser privacy scenarios.
  Consumer repositories contribute only their exact profiles and adapters,
  synthetic product fixtures, and product-semantic assertions. Every registered
  workflow, record, artifact, mode, authorization, execution, and legacy surface
  must have at least one integration test proving the real consumer adapter
  reaches its compiled shared handle. A consumer-local mock privacy engine or
  copied shared-policy suite cannot satisfy that proof and is rejected by the
  static duplication checks.
- Deterministic fault campaigns are mandatory acceptance evidence. Recorded
  seeds and controlled fault points cover encryption, persistence, atomic
  replacement, cleanup, bounded streaming, cancellation, `BaseException`,
  registration/route timing, browser caching, and process interruption or
  restart. Each campaign must prove that no plaintext is staged or leaked,
  original encrypted bytes remain authoritative, no partial transition,
  migration, receipt, or activation is reported, cleanup and startup sweeps
  complete exactly as declared, grants/leases/sessions cannot outlive lock or
  restart, and an older async generation cannot overwrite newer state. A
  non-reproducible or retry-only pass blocks suite promotion.

## Answer

Cross-repository acceptance is a versioned, shared, zero-waiver release gate.
`helto-privacy` owns an acceptance catalog whose stable evidence IDs cover the
shared contract, every consumer integration, every historical reader, clean
installation, rendered UI, failure paths, and release lifecycle. One signed
acceptance evidence manifest binds the complete result set to the candidate
suite digest, exact source and artifact hashes, harness version, test seed,
registration order, and supported environment tuple. A suite is not `ready` if
any required cell or existing repository check is skipped, xfailed, flaky,
waived, unexpectedly noisy, failing for an unrelated reason, or green only
after retry.

`helto-privacy` also owns the fixture generators/catalog, contract harness,
leak oracle, clean-install and load-order coordinator, deterministic fault
controls, and disposable ComfyUI/browser scenarios. Consumers provide only
their exact profiles, real adapters, synthetic product fixtures, and product
semantics. Each registered workflow, record, artifact, mode, authorization,
execution, and legacy surface needs a real integration proof that the consumer
adapter reaches its compiled shared handle. Static checks reject consumer-local
AES/keystore/session/token/lease/shell/recovery policy, optional shared imports,
local privacy route families or UI, path-bearing private tokens, plaintext
fallbacks, and copied shared-policy test engines. Director's vendored keystore,
shim, local codec/routes/UI, and positive fallback run are forbidden; package
absence is accepted only as a blocked negative case.

The implementation retains all existing product suites and adds the shared
catalog. At the planning baseline, the required repository commands include:

| Repository | Existing baseline retained by the gate |
| --- | --- |
| `helto-privacy` | The environment-tuple Python runs the full pytest suite plus package build/install/import and packaged browser-module checks. |
| `comfyui-utils` | `npm run test:js` and the full pytest suite with the shared package and ComfyUI source available to source tests. |
| AIO Image Generate | The environment-tuple Python runs the full pytest suite, including its Node-backed browser-module tests. |
| Director | The environment-tuple Python runs the full pytest suite with its ComfyUI source, plus `npm run test:js`. |
| Smart Prompt | The environment-tuple Python runs `python -m unittest discover`, plus `node --check web/js/smart_prompt_manager.js`. |

Every repository's declared lint, type, documentation, static, package, and
format checks are additive. Source tests may use explicit checkout paths, but
the clean-install gate may not use workspace `PYTHONPATH`, editable installs,
implicit sibling imports, or artifacts not declared by the suite manifest.

Historical compatibility evidence uses only synthetic non-user plaintext and
test-only keys, but ciphertext must be the byte output of the genuine writer at
a recorded immutable commit. Each fixture records the producer source and
function, reproducible generation environment/command, format/schema/purpose,
reader ID, test-key provenance, ciphertext hash, and expected normalized state.
The required catalog includes all current state/byte/chunked forms and:

- AIO v1 workflow/builder/record forms and its JSON-key import.
- Smart Prompt v1 workflow, bare-envelope and export-wrapper forms, plus its
  JSON-key import.
- Director's pre-extraction `helto.timeline-director` continuity and JSON-key
  import; this is current-format continuity, not a second legacy schema.
- Utils workflow prefix, raw XOR bytes, `HELTO_PRIV1`, `HELTO_PRIV2`,
  `HELTO_PRIV3`, queue wrapper, JSON and binary key imports, and a workflow with
  a referenced historical selector mask.

Schema-swapped current envelopes, hand-built lookalikes, unreproducible output,
and real user data do not qualify. Derived wrong-key/purpose/schema/algorithm,
tampered, truncated, malformed-wrapper, missing-adjunct, and failed-commit cases
are labelled as mutations. Every positive legacy case must probe/read exactly,
create a protected obligation, normalize correctly, perform a current-only
transactional rewrite and read-back, then issue a receipt. Injected failure must
preserve the original bytes and leave the obligation open. Reader units expose
no writer interface, and the Utils selector workflow plus durable mask migrate
atomically or not at all.

Shared contract cells prove atomic profile compilation, idempotent identical
registration, conflict/missing-adapter blocking, PromptServer timing
independence, browser/server fingerprint attestation, private-by-default mode
and server floors, authorization and typed failures, operator-blind maintenance,
snapshot/barrier/disposition behavior, grant revocation, minimal record shells,
allowlisted safe projections, artifact encryption/leases/streaming/cleanup,
all-or-nothing mode transitions, legacy obligations/receipts/seals, and key
pruning as a separate irreversible operation. Consumer cells bind those proofs
to every U0-U7, A0-A4, D0-D6, and S0-S3 cutover slice while retaining domain
normalization, node/widget mappings, roots, encoders, CRUD, media behavior,
execution projections, and privacy-relevant product fallback semantics.

Clean installation builds and inspects all five exact artifacts, installs them
only through declared dependency and ComfyUI Manager metadata with the recorded
ComfyUI interpreter, and starts from empty site-packages plus isolated
ComfyUI/browser state. Pre-publication runs use candidate artifacts; promotion
runs resolve the immutable public artifacts and reproduce their hashes and suite
digest. Server and browser registration execute all 24 consumer load orders,
including registration before/after route attachment and duplicate identical
imports. Every order yields exactly one runtime, route family, browser module,
UI mount, suite digest, and four expected fingerprints.

Support is enumerated as exact Python, ComfyUI backend identity, frontend
package, and renderer tuples. Every tuple passes the entire catalog; testing
minimum and maximum versions does not infer support between them. Negative
installation cells remove or stale the shared package, each consumer, and the
browser module; mismatch browser/server digests; corrupt profile/adapters;
duplicate IDs/fingerprints; and interrupt installation. Each case must block as
`incomplete`, `mismatch`, or `conflict` before privacy-bearing configuration or
serialization, preserve encrypted bytes and obligations, expose generic repair
status only, and return to verification—not activation—after exact repair.

Every privacy scenario plants unique synthetic canaries for prompts, names,
tags, paths, filenames, tokens, metadata, and payload bytes. Its evidence ID
declares the only permitted sink and operation. The leak oracle scans workflow
and execution JSON, locked shells and UI payloads, route bodies/headers/URLs,
logs/errors, filenames, caches/temp trees, sidecars, saved metadata, DOM and
accessibility snapshots, console, network records, and produced artifacts. Any
canary outside its authorization fails the suite; key bytes are never allowed.
Agents and test harnesses see only synthetic fixture data.

Rendered evidence is mandatory for every supported renderer tuple and uses a
disposable ComfyUI data root plus isolated `chrome-devtools-axi` session. It
never attaches to the user's live service or browser. It proves private-default
creation; blocked and verification UI; one shared privacy surface; locked load
without decrypt; byte-preserving locked save; explicit reveal; cross-pack
session behavior; save/queue barriers; legacy migration and receipts; manual
recovery; mode floors/transitions; record shells; opaque media leases;
lock/restart invalidation; replay with a fresh grant; full reload; stable legacy
and Vue rendering; keyboard/focus behavior; and Helto hide/mask/peek rules with
no readable ghost text, caret, selection, placeholder, name, path, prompt,
metadata, or preview. Unexpected server warnings, console errors, or network
errors fail their cell.

Deterministic fault campaigns inject encryption, persistence, atomic replace,
cleanup, streaming/backpressure, cancellation, `BaseException`, route timing,
browser-cache, process-interruption, and restart failures. They prove no
plaintext staging or leakage, no partial transition/migration/receipt, original
encrypted-byte authority, exactly-once cleanup plus startup sweep, no stale
grant/lease/session after lock or restart, and no older async generation
overwriting newer state. Seeds are recorded and clean repetitions must pass
without retry.

Suite acceptance is fully synthetic and disposable. The user's live
installation participates only in operator-blind installation verification:
`cui-stop`, byte-copy encrypted backup and exact five-artifact change,
`cui-start`, generic readiness checks, and full browser reload. The maintenance
actor has no reveal, decrypt, key-export, or live payload-test capability.
Successful verification remains `activation-required` until explicit user
activation. Release lifecycle evidence separately proves pending suites cannot
activate, public promotion is reproducible, pre-activation rollback restores
the prior set, post-activation rollback also requires the complete data
snapshot, incomplete rollback repairs forward, and later sealed-reader removal
does not prune wrapped historical keys.

The durable rationale is recorded in
[ADR 0011](../../../docs/adr/0011-gate-release-readiness-on-complete-synthetic-evidence.md).
