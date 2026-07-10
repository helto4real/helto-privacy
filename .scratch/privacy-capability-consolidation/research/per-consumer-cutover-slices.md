# Per-consumer privacy cutover slices

## Scope and fixed contract

This report maps the checked-out privacy surfaces in `comfyui-utils`, AIO Image
Generate, Director, and Smart Prompt Manager onto the approved atomic
`PrivacyProfile`/`ProductAdapter` interface. It is an implementation map, not a
compatibility promise for current source APIs. The target has one immutable,
fingerprinted `install(profile, adapters)` registration and one attested
`connectPrivacyPack(...)` browser connection; partial profiles, missing slots,
contract drift, and incompatible packages block private operations
([approved interface](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/06-prototype-target-privacy-interfaces.md:49),
[registration behavior](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/06-prototype-target-privacy-interfaces.md:75)).

The declarations below contain product facts only: scope and mode source,
workflow fields, record and artifact kinds, protected operations, generated
plaintext derivatives, semantic execution projections, adapter slots, and
legacy-reader bindings. Policy is not configurable by a consumer: private is
the default, the server resolves effective mode and floors, and mode transitions
are all-or-nothing
([mode policy](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/13-define-privacy-mode-authority-and-defaults.md:107),
[transition policy](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/13-define-privacy-mode-authority-and-defaults.md:122)).
Consumers retain state meaning and transformations; shared code owns decisions
to write, read, reveal, serve, redact, migrate, recover, or reject
([ownership rule](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/05-select-shared-capabilities-and-ownership.md:23)).

The profile notation uses the approved current schemas as `current_schema`:
`helto.comfyui-utils`, `helto.aio-image-generate.v2`,
`helto.timeline-director`, and `helto.smart-prompt-manager`. Reusing those
schema strings does not retain pack-local writers: after cutover, only the
shared snapshot/current writer may emit them. Existing code confirms those
schema bindings
([Utils schema](/home/thhel/git/comfyui-utils/shared/privacy.py:27),
[AIO schema](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:1),
[Director schema](/home/thhel/git/comfyui-helto-director/shared/privacy.py:30),
[Smart Prompt schema](/home/thhel/git/comfyui-helto-smartprompt/privacy.py:18)).

## Executive result

The cutover decomposes into seven shared-package prerequisites followed by
twenty-four consumer slices: eight for Utils, five for AIO, seven for Director,
and four for Smart Prompt. The dominant sequencing rule is replacement before
deletion: shared policy/lifecycle modules and a consumer's complete atomic
profile must exist before any local codec, route guard, token client, recovery
registry, serializer, artifact store, shell builder, or redaction branch is
removed. Consumer product normalization, persistence shape, media encoding,
allowed-root validation, editor behavior, and final product dispatch remain as
narrow adapters throughout.

## Shared-package slices that must land first

| ID | Shared slice | Required contract and why it precedes consumers |
| --- | --- | --- |
| P0 | Contract/profile runtime | Add the fixed contract identifier, immutable `PrivacyProfile` validator/fingerprint, atomic `install`, `BoundPrivacyPack`, browser attestation, order-independent PromptServer/hook reconciliation, and readiness failure. This is the root dependency for every profile and replaces the current package export surface, which exposes codecs/guards but no profile runtime ([current exports](/home/thhel/git/helto-privacy/helto_privacy/__init__.py:3), [approved target](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/06-prototype-target-privacy-interfaces.md:49)). |
| P1 | Server-authoritative mode, authorization, and browser client | Add declared/effective mode resolution, floors, transition transactions, shared protected-route dispatch, sanitized failures, one browser request client, bounded unlock retry, shared mode/status/recovery UI, and lock notifications. The current guard allows requests when no keystore exists, which cannot authorize a server-resolved private operation ([current guard](/home/thhel/git/helto-privacy/helto_privacy/guard.py:15), [server authority](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/13-define-privacy-mode-authority-and-defaults.md:114)). |
| P2 | Workflow snapshot, barrier, and execution | Add field disposition, canonical generation memos, concurrent preparation, failed-current tracking, graph-wide save/queue/export barriers, protected execution references, backend resolution, session-keyed semantic identities, RAM-only private cache, grants, and lock revocation. This replaces the current browser helper, which memoizes one field but has no graph transaction or execution grant ([current helper](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:403), [approved transaction](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/12-define-privacy-aware-serialization-and-execution.md:113)). |
| P3 | Records and redaction | Add opaque persistence, minimal locked shells, sensitive-by-default projection validation, authorized reveal, deletion while locked, safe diagnostics, and response/log/filename redaction. A locked shell may expose only opaque ID, kind, private flag, and fixed label; listing never decrypts ([record policy](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/10-define-private-record-shells-and-redaction.md:70)). |
| P4 | Managed artifacts and serving | Add atomic encrypted storage, purpose binding to profile/artifact/version, retention owners, opaque server-side leases, authenticated streaming, bounded off-loop work, cleanup ledgers, startup sweep, and transition-time plaintext-derivative purge. This must exist before any consumer deletes path tokens or cache/spill stores ([artifact contract](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/11-define-encrypted-artifact-lifecycle-and-serving.md:95), [lease contract](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/11-define-encrypted-artifact-lifecycle-and-serving.md:110)). |
| P5 | Legacy readers, key import, migration audit, and retirement | Implement physically separate reader units, dependency validation, protected obligations/receipts, transactional current rewrite/read-back, explicit audit scopes and retirement seals, and verified JSON/binary key import that unlinks the plaintext source instead of retaining `.migrated`. Readers have no writer interface and removal never prunes historical keys ([reader contract](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/07-define-legacy-read-retirement.md:149), [seal/key rules](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/07-define-legacy-read-retirement.md:189)). |
| P6 | Pack-state/secret transaction and common tests | Provide an opaque singleton-record/store path for queue state and provider secrets, plus historical ciphertext fixtures, isolated session harnesses, profile/browser attestation tests, and cross-pack policy assertions. Shared owns encrypted-field/blob mechanics while consumers retain domain schemas and update rules ([ownership matrix](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/05-select-shared-capabilities-and-ownership.md:30), [fixture requirement](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/07-define-legacy-read-retirement.md:197)). |

P0-P6 may be developed internally in increments, but no consumer may activate a
subset: the approved unit of adoption is the complete strict contract, and an
incomplete registration is a blocked state rather than degraded behavior
([atomicity](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/06-prototype-target-privacy-interfaces.md:75)).

## `comfyui-utils`

Target profile ID: `helto.utils`. All legacy booleans map `true -> private`,
`false -> public`, and missing/new state -> `inherit` (therefore private unless
an explicit public declaration is valid). Current node defaults are already
private for Prompt Enhancer and the media nodes
([Prompt Enhancer](/home/thhel/git/comfyui-utils/nodes/prompt_enhancer/__init__.py:98),
[image save](/home/thhel/git/comfyui-utils/nodes/save_image_advanced/__init__.py:49),
[video load](/home/thhel/git/comfyui-utils/nodes/load_video/__init__.py:165),
[video save](/home/thhel/git/comfyui-utils/nodes/save_video_advanced/__init__.py:380)).

### U0 — bootstrap, codec/routes, browser client, and recovery

- **Declarations/handles:** one pack profile declaring every resource below;
  browser `connectPrivacyPack({packId:"helto.utils", adapters:{...}})`; use
  `pack.readiness`, `pack.authorization`, and bound workflow/record/artifact/
  execution handles. The current pack separately registers the canonical UI and
  imports local privacy routes during package import
  ([bootstrap](/home/thhel/git/comfyui-utils/__init__.py:7)).
- **Replace/delete:** delete `shared/privacy.py` after its schema/purpose facts
  move into the profile; delete `web/privacy_common.js`,
  `web/privacy_envelope.js`, and `web/privacy_recovery.js`; remove selector
  `/encrypt` and `/decrypt` handlers from
  `helto_selector_backend/routes.py`. They currently duplicate codec wrapping,
  token transport, canonical memos, and descriptor registration
  ([backend wrapper](/home/thhel/git/comfyui-utils/shared/privacy.py:83),
  [browser memo](/home/thhel/git/comfyui-utils/web/privacy_envelope.js:93),
  [recovery catalog](/home/thhel/git/comfyui-utils/web/privacy_recovery.js:96),
  [local crypto routes](/home/thhel/git/comfyui-utils/helto_selector_backend/routes.py:207)).
- **Remain consumer-owned:** one server profile module and one browser adapter
  module containing node/field lookup, normalization/application, editor clear,
  and runtime reset functions. Product node/editor files remain and call bound
  handles instead of implementing policy; metadata must stay beside the pack
  ([metadata placement](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/04-place-consumer-specific-privacy-metadata.md:44)).
- **Tests/order:** replace wrapper-level JS stubs with profile fingerprint,
  browser/server attestation, missing-adapter/readiness, and shared recovery
  contract tests; retain product reset assertions now in
  `tests/js/privacy-recovery.test.js`
  ([descriptor/reset coverage](/home/thhel/git/comfyui-utils/tests/js/privacy-recovery.test.js:183)).
  Depends on P0-P2 and must precede U1-U7 deletion.

### U1 — selector workflow state and protected selector operations

- **Profile:** `PrivacyScope("selector", PropertyMode("privacyMode", legacy_bool=True))`;
  `WorkflowState("selector", node="HeltoImageSelector", current_schema="helto.comfyui-utils")`
  with private widget fields `selected_images` (`[]`), `edited_masks` (`{}`), and
  `edited_bboxes` (`{}`); semantic execution projection is exactly those three
  normalized values. Bind legacy container reader `utils-workflow-prefix` at
  those locations. The existing descriptors and parser identify the fields
  ([field catalog](/home/thhel/git/comfyui-utils/web/privacy_recovery.js:99),
  [backend parsing](/home/thhel/git/comfyui-utils/helto_selector_backend/image_processing.py:117)).
- **Protected operations:** selector folder/root discovery, scan, thumbnail,
  source view, mask read/write/delete/migrate, image paste/delete, cache clear,
  and root registration. These routes currently share one token guard and
  consumer path authorization
  ([route guard](/home/thhel/git/comfyui-utils/helto_selector_backend/routes.py:85),
  [mask and root routes](/home/thhel/git/comfyui-utils/helto_selector_backend/routes.py:231)).
  Use `workflow.prepare/save/resolve_execution`, `authorization.protect`, and
  artifact handles from U2.
- **ProductAdapter seams:** locate the three widgets/property, parse/normalize
  selection/mask/bbox maps, apply revealed state, clear `selectedPaths`,
  `editedMasks`, and `editedBboxes`, authorize product roots, and invoke scan/
  paste/delete logic. Keep `selector.js`, `image_processing.py`, and selector
  path/service logic; replace only their encryption, toggle-policy, recovery,
  and direct token calls
  ([runtime state](/home/thhel/git/comfyui-utils/web/privacy_recovery.js:41),
  [path authorization](/home/thhel/git/comfyui-utils/helto_selector_backend/routes.py:46)).
- **Legacy/tests/order:** `utils-workflow-prefix` depends on separate
  `utils-xor`, `utils-HELTO_PRIV1`, `utils-HELTO_PRIV2`, and
  `utils-HELTO_PRIV3` byte readers; the binary key importer supplies
  `key.bin`/`privacy_key.bin`. Add genuine ciphertext for every field and
  verify one snapshot rewrites fields plus referenced masks atomically. Retain
  selector parse/path tests and replace rejection-only coverage
  ([current legacy rejection](/home/thhel/git/comfyui-utils/helto_selector_backend/crypto.py:49),
  [current selector tests](/home/thhel/git/comfyui-utils/tests/test_backend.py:236)).
  Depends on P0-P2/P5 and U2; must cut over in the same commit set as U2.

### U2 — selector masks and thumbnails

- **Profile:** `ArtifactKind("selector-mask", purpose="selector-mask", v=1,
  retention="durable-adjunct", operations=("use","replace","delete"))` and
  `ArtifactKind("selector-thumbnail", purpose="selector-thumbnail", v=1,
  retention="regenerable-cache", operations=("preview",))`. Declare generated
  plaintext derivatives `masks/*.png`, `thumbnails/*.webp`, and interrupted temp
  variants; the workflow `edited_masks` field owns mask refs. Existing code
  distinguishes durable hashed mask files from thumbnail caches
  ([mask paths/refs](/home/thhel/git/comfyui-utils/helto_selector_backend/mask_storage.py:27),
  [thumbnail paths](/home/thhel/git/comfyui-utils/helto_selector_backend/thumbnail_cache.py:34)).
- **ProductAdapter seams/handles:** mask PNG normalize/encode/decode, cache key,
  owner resolution from image path, thumbnail generation, and regeneration stay
  consumer-owned; use `pack.artifacts("selector-mask")` and
  `pack.artifacts("selector-thumbnail")` for storage, reads, leases, transition
  purge, and cleanup. Allowed source roots remain the U1 adapter.
- **Replace/delete:** remove filesystem/encryption/lifecycle branches in
  `mask_storage.py` and `thumbnail_cache.py`; remove request-supplied privacy
  selection from selector thumbnail/mask endpoints. Keep image/PIL generation,
  keys, refs, and product deletion semantics
  ([current mask branch](/home/thhel/git/comfyui-utils/helto_selector_backend/mask_storage.py:74),
  [current thumbnail branch](/home/thhel/git/comfyui-utils/helto_selector_backend/thumbnail_cache.py:68),
  [request boolean](/home/thhel/git/comfyui-utils/helto_selector_backend/routes.py:115)).
- **Legacy/tests/order:** historical masks bind each exact byte reader and are
  part of the same migration receipt as their referencing workflow; thumbnails
  have no reader and are purged/regenerated. Preserve mask round-trip/delete and
  thumbnail regeneration tests, move storage/retention/permission/lease/sweep
  assertions to P4 contract tests
  ([current mask tests](/home/thhel/git/comfyui-utils/tests/test_backend.py:244),
  [current thumbnail tests](/home/thhel/git/comfyui-utils/tests/test_backend.py:400)).
  Depends on P4-P5 and blocks U1 completion.

### U3 — Prompt Enhancer workflow and provider settings

- **Profile:** `PrivacyScope("prompt-enhancer", WidgetMode("privacy_mode",
  legacy_bool=True))`; `WorkflowState("prompt-enhancer", node="HeltoPromptEnhancer")`
  with `script` and `variables`; semantic projection includes the resolved script
  and variables that affect provider output. Add singleton
  `RecordLibrary("prompt-provider-settings", kind="provider-credential",
  current_schema="helto.comfyui-utils", safe_projection=("tokenConfigured",
  "envTokenAvailable","authSource"))` with protected details/update/delete.
  Existing node and settings store identify those values
  ([node fields](/home/thhel/git/comfyui-utils/nodes/prompt_enhancer/__init__.py:98),
  [credential store](/home/thhel/git/comfyui-utils/shared/prompt_enhancer/provider_settings.py:21)).
- **Adapters/handles:** editor adapter reads/applies/clears script and variable
  state; semantic adapter normalizes prompt variables; provider-store adapter
  persists the opaque singleton and resolves the token only inside authorized
  provider dispatch. Use workflow snapshot/execution plus
  `records("prompt-provider-settings")`. Keep provider selection, model
  discovery, variable substitution, and generation code
  ([product execution](/home/thhel/git/comfyui-utils/nodes/prompt_enhancer/__init__.py:175),
  [provider route surface](/home/thhel/git/comfyui-utils/shared/prompt_enhancer/routes.py:219)).
- **Replace/delete:** remove encrypt/decrypt/memo/failure swallowing from
  `prompt_enhancer_helpers.js`; replace the credential encryption in
  `provider_settings.py` with the bound record/store handle. Plaintext `hf_token`
  is a one-time strict migration source, not a permanent reader
  ([current browser encryption](/home/thhel/git/comfyui-utils/web/prompt_enhancer_helpers.js:327),
  [current plaintext migration](/home/thhel/git/comfyui-utils/shared/prompt_enhancer/provider_settings.py:38)).
- **Legacy/tests/order:** bind `utils-workflow-prefix` plus its byte dependencies
  for script/variables; provider plaintext migration must write/read-back the
  current singleton before source removal. Retain prompt normalization/provider
  tests; convert credential tests and recovery tests to shared contracts
  ([current workflow tests](/home/thhel/git/comfyui-utils/tests/test_prompt_enhancer.py:451),
  [credential tests](/home/thhel/git/comfyui-utils/tests/test_prompt_enhancer.py:1148)).
  Depends on P0-P3/P5-P6.

### U4 — Privacy Show Any

- **Profile:** `PrivacyScope("privacy-show-any",
  PropertyMode("helto_privacy_show_any_privacy_mode", legacy_bool=True))` and
  `WorkflowState("privacy-show-any", node="HeltoPrivacyShowAny")` with mirrored
  widget `encrypted_text_state` and property
  `helto_privacy_show_any_encrypted_text_state` as one logical field. Declare
  protected operation `display-result`; it may reveal in the live UI only after
  authorization and must serialize one settled envelope to both projections
  ([current mirrored declarations](/home/thhel/git/comfyui-utils/web/privacy_recovery.js:162),
  [current mirror helper](/home/thhel/git/comfyui-utils/web/privacy_show_any_helpers.js:90)).
- **Adapters/handles:** consumer adapters convert arbitrary values to bounded
  text, locate/mirror the field, apply/clear live display widgets, and invoke
  the output node; use `workflow.prepare/save` and authorized reveal. Keep the
  value-to-text product logic
  ([backend conversion](/home/thhel/git/comfyui-utils/nodes/privacy_show_any/__init__.py:25)).
- **Replace/delete:** backend must stop calling `encrypt_selection` directly;
  remove per-node encryption promises, `graphToPrompt` patch, memo helpers, and
  recovery code from `privacy_show_any.js`/`privacy_show_any_helpers.js`, while
  keeping display/editor rendering
  ([current backend write](/home/thhel/git/comfyui-utils/nodes/privacy_show_any/__init__.py:44),
  [current lifecycle patch](/home/thhel/git/comfyui-utils/web/privacy_show_any.js:151)).
- **Legacy/tests/order:** bind `utils-workflow-prefix` at both mirrored locations
  with one obligation/receipt. Retain text-conversion tests and replace local
  serialization/recovery tests with P2 contract coverage
  ([current backend tests](/home/thhel/git/comfyui-utils/tests/test_backend.py:1639),
  [current recovery tests](/home/thhel/git/comfyui-utils/tests/js/privacy-recovery.test.js:233)).
  Depends on P0-P2/P5.

### U5 — queue manager persistence, capture, replay, and rerun

- **Profile:** `PrivacyScope("queue-manager", RecordMode("privacy_enabled",
  legacy_bool=True))`; singleton `RecordLibrary("queue-manager-state",
  kind="queued-workflow-state", current_schema="helto.comfyui-utils")` with all
  fields sensitive and no list projection beyond generic counts/status;
  protected operations `load`, `save`, `capture`, `submit`, `replay`, `rerun`,
  `preview`, `delete`, and `clear`. Queue state currently defaults private and
  stores workflow/executable payloads in SQLite
  ([default state](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:22),
  [SQLite schema](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:97)).
- **Adapters/handles:** queue-store adapter owns normalization, SQLite row
  identity, semantic comparison excluding `updated_at`, and queue/history state
  transitions; dispatch adapter invokes ComfyUI only after `execution` resolves
  a fresh snapshot/grant. Use singleton record, workflow barrier, execution,
  readiness, and authorization handles. Keep queue UI, ordering, retry, history,
  and batching behavior
  ([semantic comparison](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:77),
  [capture loop](/home/thhel/git/comfyui-utils/web/queue_manager_helpers.js:277)).
- **Replace/delete:** remove encryption/decryption and `privacy_enabled` trust
  from `queue_manager_store.py`; replace `queue_manager_routes.py` token/codec
  logic with protected singleton operations; remove queue-specific privacy
  request handling and toggle semantics from `queue_manager.js`. The product UI
  may mount the shared mode control
  ([current route](/home/thhel/git/comfyui-utils/shared/queue_manager_routes.py:17),
  [current toggle](/home/thhel/git/comfyui-utils/web/queue_manager.js:1148)).
- **Legacy/tests/order:** bind independent `utils-queue-wrapper` to
  `utils-HELTO_PRIV1/2/3` dependencies and binary key import; current-envelope
  JSON migration and historical SQLite bytes must both normalize, write, and
  read back before deletion. Preserve queue-domain tests; replace local crypto
  and toggle tests and add genuine legacy JSON/SQLite fixtures
  ([current migration](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:177),
  [current tests](/home/thhel/git/comfyui-utils/tests/test_queue_manager_store.py:81),
  [queue snapshot test](/home/thhel/git/comfyui-utils/tests/js/queue-manager.test.js:404)).
  Depends on P0-P2/P5-P6 and U1/U3/U4 snapshot registration.

### U6 — common private-media lease/serving surface

- **Profile:** `ArtifactKind("private-preview", purpose="private-media", v=1,
  retention="served-transient", operations=("preview",))` and protected
  operation `serve-source-media`. Declare all `helto_private/**` generated files
  and old node temp-preview directories as plaintext derivatives; original
  allowed user input/output files are explicitly not derivatives. Current tokens
  encrypt absolute paths for seven days and the route returns whole decrypted
  files
  ([token payload](/home/thhel/git/comfyui-utils/shared/privacy.py:136),
  [path-bearing record](/home/thhel/git/comfyui-utils/shared/privacy.py:198),
  [serving route](/home/thhel/git/comfyui-utils/shared/private_media_routes.py:17)).
- **Adapters/handles:** consumer allowed-root validators and media encoders
  supply existing sources or bytes; use artifact `write/lease/release` and the
  one shared lease route. Browser preview helpers receive opaque URLs from the
  bound façade.
- **Replace/delete:** delete `shared/private_media_routes.py` and all token,
  encrypted-temp, silent cleanup, and record-building functions in
  `shared/privacy.py`; replace private URL construction in comparer, queue,
  load-video, and save-image UI files. Shared serving supplies `private,
  no-store`, generic names, sanitized errors, bounded off-loop I/O, and sweep;
  consumer code never sees token semantics
  ([current cleanup](/home/thhel/git/comfyui-utils/shared/privacy.py:237),
  [current error handling](/home/thhel/git/comfyui-utils/shared/private_media_routes.py:31)).
- **Tests/order:** move token/file tests to lease/lock/restart/expiry/streaming/
  sweep contract tests; keep media rendering assertions
  ([current privacy tests](/home/thhel/git/comfyui-utils/tests/test_privacy.py:50)).
  Depends on P1/P4 and blocks U7.

### U7 — load/save/comparer image and video nodes

- **Profile:** each node gets a node-local declared-mode source with legacy
  bool mapping: `HeltoSaveImageAdvanced`, `HeltoImageComparer`,
  `HeltoLoadVideo`, `HeltoSaveVideoAdvanced`, and `HeltoVideoComparer`.
  `load-video-cache` is a regenerable artifact; image/video comparison and
  save previews are `private-preview` served transients; `save-video-replay` is
  a run-scoped spill owned by node/revision. Generated plaintext derivatives
  are load-video thumbnails/copies, comparer previews, save preview copies,
  save-video staging directories, and plaintext replay bundles. Current nodes
  expose those mode inputs and artifact branches
  ([image comparer](/home/thhel/git/comfyui-utils/nodes/image_comparer/__init__.py:118),
  [video comparer](/home/thhel/git/comfyui-utils/nodes/video_comparer/__init__.py:85),
  [load video](/home/thhel/git/comfyui-utils/nodes/load_video/__init__.py:165),
  [save video](/home/thhel/git/comfyui-utils/nodes/save_video_advanced/__init__.py:380)).
- **Adapters/handles:** retain image/video encoding, saved-output routing,
  filename/counter rules, masks, audio mux, folder alias/path validation,
  thumbnail generation/cache keys, replay payload serialization, and pause/
  release semantics. Use mode, artifact/lease, and execution handles for
  previews and replay. User-requested saved outputs remain consumer-owned files;
  only generated preview/replay derivatives enter P4
  ([save-image product path](/home/thhel/git/comfyui-utils/nodes/save_image_advanced/__init__.py:141),
  [load-video source resolution](/home/thhel/git/comfyui-utils/nodes/load_video/__init__.py:222)).
- **Replace/delete:** remove encrypted temp writes/path tokens from save image
  and comparers; replace load-video request `privacy` booleans and cache storage;
  replace save-video named plaintext private staging, preview copies, and replay
  encryption/lifecycle with memory/artifact/spill handles
  ([save-image preview](/home/thhel/git/comfyui-utils/nodes/save_image_advanced/__init__.py:390),
  [load-video cache](/home/thhel/git/comfyui-utils/nodes/load_video/video_io.py:111),
  [private staging/replay](/home/thhel/git/comfyui-utils/nodes/save_video_advanced/__init__.py:501),
  [video comparer preview](/home/thhel/git/comfyui-utils/nodes/video_comparer/__init__.py:143)).
- **Legacy/tests/order:** caches, previews, replay bundles, tokens, and staging
  files have no legacy reader; purge/regenerate them. Preserve output/encoding/
  replay product tests while moving privacy lifecycle assertions to P4
  ([load-video cache test](/home/thhel/git/comfyui-utils/tests/test_load_video_browser.py:100),
  [save-video privacy tests](/home/thhel/git/comfyui-utils/tests/test_backend.py:2531)).
  Depends on P1/P2/P4 and U6.

## AIO Image Generate

Target profile ID: `helto.aio-image-generation`. Existing `privacy_mode=false`
defaults on Generate and the Ideogram builder are legacy explicit-public
declarations only for already stored nodes; new/missing state declares
`inherit` and resolves private
([Generate field order/default surface](/home/thhel/git/comfyui-all-on-one-image-generation-node/nodes/aio_generate.py:71),
[builder current default](/home/thhel/git/comfyui-all-on-one-image-generation-node/nodes/ideogram4_prompt_builder.py:82),
[approved mapping](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/13-define-privacy-mode-authority-and-defaults.md:107)).

### A0 — bootstrap, codec route/client, and recovery

- **Declarations/handles:** one atomic profile and browser connection; use
  readiness/authorization/workflow/record/execution. Current AIO has a local
  codec service, `/aio_image_generate/privacy` route, request client, failed
  envelope set, and recovery descriptors
  ([service schema](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/privacy.py:33),
  [routes](/home/thhel/git/comfyui-all-on-one-image-generation-node/routes/privacy.py:19),
  [browser client](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:70),
  [recovery](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy_recovery.js:102)).
- **Replace/delete:** delete `services/privacy.py`, `routes/privacy.py`,
  `web/js/aio_privacy.js`, and `web/js/aio_privacy_recovery.js` after product
  adapters are extracted. This also removes the current fail-open `None` token
  guard and synchronous XHR writer
  ([fail-open guard](/home/thhel/git/comfyui-all-on-one-image-generation-node/routes/privacy.py:78),
  [sync writer](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:132)).
- **Remain/tests/order:** keep node/editor state transformations in their product
  files; replace privacy unit/JS recovery tests with profile/readiness,
  failed-current disposition, snapshot, and shared UI contracts while retaining
  product normalization tests
  ([current privacy tests](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_privacy.py:20),
  [current recovery tests](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_privacy_recovery_js.py:94)).
  Depends on P0-P2/P5 and precedes A1-A4 deletions.

### A1 — Generate and Krea prompts

- **Profile:** `PrivacyScope("generate", WidgetMode("privacy_mode",
  legacy_bool=True))`; `WorkflowState("generate-prompts", node="AIOImageGenerate")`
  fields `positive_prompt` and `negative_prompt`; `WorkflowState("krea-inpaint",
  node="AIOKrea2Settings")` field `inpaint_positive_prompt`, inheriting the
  Generate/upstream private floor rather than adding another toggle. Add
  semantic execution projections for the effective prompts and protected
  operations `generate`/`inpaint`. Current descriptors and Krea propagation
  establish those fields and inheritance behavior
  ([descriptors](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy_recovery.js:102),
  [Krea builder inheritance](/home/thhel/git/comfyui-all-on-one-image-generation-node/nodes/krea2_settings.py:137)).
- **Adapters/handles:** locate/apply/clear prompt widgets, recover unlinked
  workflow values, normalize linked versus local prompts, compute effective
  prompt/inpaint semantics, and invoke the existing generation pipeline after
  execution resolution. Use workflow snapshots, execution resolution/grants,
  and session-keyed identity. Keep model/settings/dimension/reference/pipeline
  behavior in `aio_generate.py`
  ([workflow value lookup](/home/thhel/git/comfyui-all-on-one-image-generation-node/nodes/aio_generate.py:188),
  [effective prompt use](/home/thhel/git/comfyui-all-on-one-image-generation-node/nodes/aio_generate.py:1265)).
- **Replace/delete:** remove browser `serializeValue` encryption/memos and
  backend direct `decrypt_text_if_encrypted`; executable inputs become shared
  protected refs rather than independently encrypted widget strings
  ([current serializer](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_image_generate.js:1316),
  [current backend reveal](/home/thhel/git/comfyui-all-on-one-image-generation-node/nodes/aio_generate.py:370)).
- **Legacy/tests/order:** bind `aio-v1-schema` plus `aio-json-key-import` at all
  three fields; add genuine v1 ciphertext and current-only rewrite fixtures.
  Preserve prompt resolution/link tests and replace envelope-reuse assertions
  with shared snapshot identity tests
  ([current prompt tests](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_aio_generate_node.py:1390),
  [current reuse test](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_aio_generate_node.py:230)).
  Depends on P0-P2/P5.

### A2 — Ideogram 4 prompt builder workflow/editor

- **Profile:** `PrivacyScope("ideogram-builder",
  WidgetMode("privacy_mode", legacy_bool=True))`; workflow fields for the ten
  sensitive widgets (`high_level_description`, `background`, `photo`,
  `art_style`, `aesthetics`, `lighting`, `medium`, `style_palette_data`,
  `elements_data`, `import_json`) and one whole-state logical field mirrored at
  property `aio_ideogram4_prompt_builder_state` and workflow keys
  `aio_ideogram4_prompt_builder`/legacy `ideo`. Declare the semantic execution
  projection as the normalized prompt, palette/elements, coordinates, and
  dimensions that affect outputs
  ([sensitive list/keys](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy_recovery.js:17),
  [builder schema](/home/thhel/git/comfyui-all-on-one-image-generation-node/nodes/ideogram4_prompt_builder.py:41)).
- **Adapters/handles:** editor adapter normalizes widget/DOM state, applies
  reveal, clears runtime memo/pending workflow state, and supplies execution
  semantics; dispatcher invokes `build_prompt`. Keep prompt construction,
  bounding boxes, palette/elements, preview rendering, and editor UI.
- **Replace/delete:** remove synchronous per-widget and whole-state encryption,
  custom locked-state preservation, recovery wiring, and direct mode toggle
  semantics from `aio_ideogram4_prompt_builder.js`; use the shared barrier and
  mounted control
  ([current sync field writer](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_ideogram4_prompt_builder.js:810),
  [current whole-state writer](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_ideogram4_prompt_builder.js:886)).
- **Legacy/tests/order:** bind `aio-v1-schema`/JSON key import to every field,
  property, and top-level key. One receipt covers all mirrored builder
  projections. Preserve builder product tests, replace direct privacy/cache
  tests with snapshot/barrier tests
  ([current product/privacy tests](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_ideogram4_prompt_builder.py:181),
  [recovery reset test](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_privacy_recovery_js.py:206)).
  Depends on P0-P2/P5 and A0.

### A3 — Ideogram prompt library

- **Profile:** `RecordLibrary("ideogram-prompts", kind="ideogram-prompt",
  current_schema="helto.aio-image-generate.v2", fixed_private_label="Private
  record", safe_projection=())`; protected `list`, `create`, `replace`, `patch`,
  `duplicate`, `use/details`, and `delete`. Name, description, tags, payload,
  timestamps, activity, summaries, and preview text are sensitive; only the
  strict minimal shell lists while locked. Current storage encrypts payload and
  metadata but still lists timestamps/activity
  ([current pack](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/ideogram4_prompt_library.py:261),
  [current public shell](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/ideogram4_prompt_library.py:320)).
- **Adapters/handles:** store adapter owns JSON document CRUD/atomic replacement,
  `_normalize_payload`, IDs, and domain naming; projection adapter validates
  Ideogram payload; product UI invokes `records("ideogram-prompts")` reveal
  before use/edit/duplicate. Shared records own shells, crypto, authorization,
  locked deletion, and failures.
- **Replace/delete:** rewrite `services/ideogram4_prompt_library.py` as a
  crypto-free opaque store/domain adapter and `routes/ideogram4_prompt_library.py`
  as thin product routes or remove it in favor of shared generic record routes;
  delete its token checks, shell builders, encryption, and raw exception
  responses
  ([current routes](/home/thhel/git/comfyui-all-on-one-image-generation-node/routes/ideogram4_prompt_library.py:69),
  [current error response](/home/thhel/git/comfyui-all-on-one-image-generation-node/routes/ideogram4_prompt_library.py:186)).
- **Legacy/tests/order:** bind `aio-v1-schema` and JSON key import to every
  private record. Receipt follows authorized reveal and verified current-record
  commit; deletion needs no decrypt. Preserve CRUD/normalization tests and move
  shell/auth/legacy fixtures to P3/P5 contracts
  ([current library tests](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_ideogram4_prompt_library.py:90)).
  Depends on P1/P3/P5/P6.

### A4 — run-info and private diagnostics

- **Profile:** protected operation `emit-run-info` with sensitive fields
  including `positive_prompt_override`, prompt/debug values, and any future
  consumer-derived diagnostics; no safe private projection is assumed beyond
  explicitly classified coarse performance booleans/counts. Current code
  encrypts only one settings key and omits debug when private
  ([current redaction](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/run_info.py:29),
  [current run-info projection](/home/thhel/git/comfyui-all-on-one-image-generation-node/nodes/aio_generate.py:1490)).
- **Adapters/handles:** keep run-info structure and performance calculation in
  `services/run_info.py`; adapter supplies the product mapping/safe allowlist and
  uses shared redaction/protected-operation output after server mode resolution.
  Delete direct `privacy.encrypt_state` calls and request-derived mode authority
  from that service.
- **Tests/order:** preserve run-info schema tests and replace the single-key
  encryption test with sensitive-by-default projection/redaction tests
  ([current test](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_run_info.py:190)).
  Depends on P1/P3 and A1/A2 effective-mode propagation.

## Director

Target profile ID: `helto.director`. Its existing global setting already
defaults/malformed-values to private and acts as a floor for media requests
([server default](/home/thhel/git/comfyui-helto-director/shared/timeline/global_settings.py:24),
[media floor](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:40)).

### D0 — keystore, codec, local routes, and parallel browser UI

- **Declarations/handles:** one atomic profile/browser connection plus
  readiness/authorization. Bind `director-json-key-import`; retain
  `helto.timeline-director` as current-format continuity, not a removable schema
  reader. Existing Director has a vendored keystore fallback, full local codec,
  local keystore/encrypt routes, and local token/dialog implementation
  ([fallback](/home/thhel/git/comfyui-helto-director/shared/privacy_keystore.py:5),
  [codec](/home/thhel/git/comfyui-helto-director/shared/privacy.py:78),
  [routes](/home/thhel/git/comfyui-helto-director/routes/privacy.py:31),
  [browser client](/home/thhel/git/comfyui-helto-director/web/timeline/privacy.js:1),
  [dialog](/home/thhel/git/comfyui-helto-director/web/timeline/privacy_unlock.js:49)).
- **Replace/delete:** delete `_vendored_keystore.py`, `privacy_keystore.py`,
  `shared/privacy.py`, `routes/privacy.py`, `web/timeline/privacy.js`, and
  `privacy_unlock.js` once adapters no longer import them. Missing/incompatible
  `helto-privacy` blocks private Director instead of silently activating a
  second implementation.
- **Tests/order:** move keystore/codec/guard tests to shared contract coverage;
  retain one Director integration fixture proving old
  `helto.timeline-director` data after verified JSON key import
  ([current keystore tests](/home/thhel/git/comfyui-helto-director/tests/timeline/test_privacy_keystore.py:40),
  [current codec tests](/home/thhel/git/comfyui-helto-director/tests/timeline/test_privacy.py:24)).
  Depends on P0-P2/P5 and precedes D1-D7 deletion.

### D1 — global privacy authority and transition

- **Profile:** `PrivacyScope("director-global",
  SettingMode("privacy.mode", legacy_bool=True), private_is_floor=True)`;
  declare parent/upstream floors for timeline, library records, media, takes,
  artifacts, and executions. Declare plaintext derivatives for all registered
  public cache/temp variants. Current setting normalization treats missing as
  private; current enable transition purges only media caches
  ([normalization](/home/thhel/git/comfyui-helto-director/shared/timeline/global_settings.py:115),
  [current transition](/home/thhel/git/comfyui-helto-director/routes/global_settings.py:39)).
- **Adapters/handles:** settings adapter reads/writes the product JSON setting;
  transition adapters enumerate sensitive product values and domain rewrites.
  Use shared mode/transition/status UI. Keep non-privacy global settings,
  validation, asset-root product configuration, and UI placement.
- **Replace/delete:** remove privacy transition/token/cache-purge policy from
  `routes/global_settings.py` and mode semantics from
  `web/timeline/global_settings.js`; the route calls the shared transition, and
  the frontend mounts the shared control
  ([current browser default](/home/thhel/git/comfyui-helto-director/web/timeline/global_settings.js:3)).
- **Tests/order:** preserve settings normalization and root tests; move mode
  precedence, authorization, purge-all-or-abort, and blocked-transition tests to
  P1/P4 contracts
  ([current transition tests](/home/thhel/git/comfyui-helto-director/tests/media/test_cache_routes.py:174)).
  Depends on P1/P4 and every D2-D7 derivative declaration; lands last within
  Director before profile activation.

### D2 — timeline workflow/editor and execution

- **Profile:** `WorkflowState("timeline", node="HeltoVideoTimelineDirector",
  scope="director-global", current_schema="helto.timeline-director")` with the
  hidden `video_timeline_json` logical field and a semantic execution projection
  of normalized timeline state that affects planning/rendering. Protected
  operations include save/export/queue/render/replay. Current editor encrypts
  the whole timeline synchronously and the backend decrypts it during parse
  ([widget](/home/thhel/git/comfyui-helto-director/nodes/video_timeline_director/node.py:71),
  [browser write](/home/thhel/git/comfyui-helto-director/web/timeline/state.js:365),
  [backend parse](/home/thhel/git/comfyui-helto-director/nodes/video_timeline_director/backend.py:63)).
- **Adapters/handles:** timeline adapter locates/normalizes/applies/clears state,
  flushes debounced edits into a captured generation, and invokes existing
  validation/planning only after execution resolution. Keep timeline editor,
  undo, normalization, validation, visible widget synchronization, and product
  executors. Use workflow snapshot/barrier and execution/grant handles.
- **Replace/delete:** remove synchronous encryption, local unlock flow, and the
  decrypt-failure substitution that replaces live state with a default; a
  locked/failed unedited envelope may only be preserved byte-for-byte and cannot
  execute
  ([current failure substitution](/home/thhel/git/comfyui-helto-director/web/timeline/state.js:86)).
- **Legacy/tests/order:** no separate schema reader; bind current continuity plus
  JSON key import. Add a locked-current fixture proving a later save cannot
  overwrite ciphertext with the default timeline. Preserve normalization/
  validation tests and move snapshot/disposition tests shared
  ([current backend decrypt test](/home/thhel/git/comfyui-helto-director/tests/director/test_video_timeline_director_node.py:175)).
  Depends on P0-P2/P5 and D0.

### D3 — project and character library

- **Profile:** two `RecordLibrary` declarations: `projects` kind
  `director-project` and `characters` kind `director-character`, both current
  schema `helto.timeline-director`, fixed label `Private record`, and empty
  default safe projection. Protect list/create/replace/patch/duplicate/use/
  preview/details/delete. Current private shells retain tags, timestamps,
  summaries, activity, and character labels, which the strict shell removes
  ([current entry](/home/thhel/git/comfyui-helto-director/shared/timeline_library.py:313),
  [current list shell](/home/thhel/git/comfyui-helto-director/shared/timeline_library.py:363),
  [character preview](/home/thhel/git/comfyui-helto-director/shared/timeline_library.py:585)).
- **Adapters/handles:** store adapter retains JSON CRUD/atomic persistence and
  IDs; project/character adapters retain normalization, embedded-media stripping,
  referenced-asset rules, validation, and authorized product preview/use
  projections. Shared records own crypto, shells, reveal authorization,
  redaction, and locked deletion.
- **Replace/delete:** rewrite `shared/timeline_library.py` as crypto-free opaque
  store/domain adapters; rewrite `routes/timeline_library.py` as protected thin
  domain routes or remove it for generic shared record routes; keep
  `web/timeline/library.js` product UI but replace direct fetch/privacy behavior.
  Current routes do not token-gate private operations and return raw errors
  ([current route family](/home/thhel/git/comfyui-helto-director/routes/timeline_library.py:62),
  [current error](/home/thhel/git/comfyui-helto-director/routes/timeline_library.py:253)).
- **Legacy/tests/order:** current schema continuity plus Director JSON key
  import; receipt only after authorized reveal and verified rewrite. Preserve
  CRUD/normalization/preview tests, replace current shell expectations with the
  strict minimal shell
  ([current library tests](/home/thhel/git/comfyui-helto-director/tests/timeline/test_library.py:324)).
  Depends on P1/P3/P5/P6 and D0.

### D4 — thumbnail and waveform caches

- **Profile:** artifacts `thumbnail` (`timeline-thumbnail-cache`, v1) and
  `waveform` (`timeline-waveform-cache`, v1), both `regenerable-cache` with
  `preview`; declare `.webp`, `.json`, and temp variants as plaintext
  derivatives. Current stores select encrypted/plain variants and compute cache
  keys from source path/stat/parameters
  ([purposes/paths](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:23),
  [cache key](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:317)).
- **Adapters/handles:** keep allowed-root validation, source decode, thumbnail/
  waveform encoding, cache-key and regeneration adapters; use bound artifact
  write/read/lease and shared serving. Keep bounded product media preparation,
  while P4 owns lifecycle and backpressure.
- **Replace/delete:** remove encryption/filesystem/cleanup/mode branches from
  `shared/media_cache.py`; replace `routes/media_cache.py` thumbnail/waveform
  serving with shared leases; remove request `privacy` authority and raw-path
  URLs. Keep domain `/view` only as a protected source-media operation through
  the allowed-root adapter
  ([current private branches](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:155),
  [current routes](/home/thhel/git/comfyui-helto-director/routes/media_cache.py:77)).
- **Legacy/tests/order:** no legacy readers; purge/regenerate caches. Preserve
  decode/root/cache-key tests, move atomic permissions/retention/lease/sweep/
  transition purge tests to P4
  ([current cache tests](/home/thhel/git/comfyui-helto-director/tests/media/test_cache_routes.py:430)).
  Depends on P1/P4 and D1 mode declaration.

### D5 — media browser, source viewing, and take discovery/deletion

- **Profile:** protected operations `folders`, `list-media`, `view-source`,
  `preview-source`, `list-project-takes`, and `delete-project-take`; source
  media is user-owned, not an artifact, while generated thumbnails use D4.
  Declare sensitive projections for folder paths, filenames, paths, timestamps,
  sizes, media metadata, storage roots, take metadata, and URLs. Current listing
  returns paths and builds path-bearing URLs; direct view routes do not enforce
  the private guard
  ([current listing](/home/thhel/git/comfyui-helto-director/routes/media_browser.py:124),
  [direct view](/home/thhel/git/comfyui-helto-director/routes/media_browser.py:245),
  [media-cache view](/home/thhel/git/comfyui-helto-director/routes/media_cache.py:138)).
- **Adapters/handles:** retain folder config, alias/path validation, allowed-root
  resolution, media metadata extraction, project take discovery/deletion, and
  domain UI. Shared authorization/redaction and artifact leases return opaque
  preview/source-view URLs. `media_privacy.py` becomes obsolete because mode and
  sanitized failures are shared
  ([allowed roots](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:55),
  [current helper](/home/thhel/git/comfyui-helto-director/routes/media_privacy.py:15)).
- **Replace/delete:** remove privacy branches/path URL construction/raw private
  errors from `routes/media_browser.py`, `routes/media_cache.py`, and browser
  `media_cache.js`/`media_picker.js`/`media_preview.js`; retain product UI and
  route payload validation through bound operations.
- **Legacy/tests/order:** no media-token/cache legacy reader. Preserve folder,
  path, discovery, and deletion tests; change URL/error/redaction expectations
  to opaque leases and strict projections
  ([current browser tests](/home/thhel/git/comfyui-helto-director/tests/media/test_browser_routes.py:101)).
  Depends on P1/P3/P4 and D4.

### D6 — take metadata, sidecars, UI redaction, and spills

- **Profile:** protected operation `capture-take` with sensitive-by-default
  registration/run metadata and an explicitly validated safe sidecar projection;
  `ArtifactKind("timeline-segment-spill", purpose="timeline-segment-cache",
  v=1, retention="run-scoped-spill")`; declare plaintext `.pt`, temp spill
  variants, and debug path fields as derivatives. Generated output media itself
  remains a user-owned output. Current take code redacts LoRA names/filenames/
  paths but retains many operational fields, and spills are locally encrypted
  and cleaned
  ([LoRA/filename redaction](/home/thhel/git/comfyui-helto-director/shared/timeline/take_capture.py:320),
  [sidecar contract](/home/thhel/git/comfyui-helto-director/shared/timeline/generated_capture.py:25),
  [spill store](/home/thhel/git/comfyui-helto-director/shared/segmented_executor.py:162)).
- **Adapters/handles:** take adapter retains registration/domain normalization,
  output association, safe projection candidates, and sidecar/product write;
  spill adapter retains `torch.save` encode/decode, segment IDs/shapes, and
  stitching. Use shared redaction/protected operation and artifact spill handle.
  Consumer LTX/WAN loops keep generation logic and `finally` ownership calls.
- **Replace/delete:** remove ad-hoc redaction decisions from
  `take_capture.py`, `generated_capture.py`, `timeline_take_capture/node.py`,
  browser take preview, and media browser; shared validator produces the only
  private projection. Replace `SegmentSpillStore` encryption/filesystem/
  cleanup ledger with the bound run-spill handle; keep tensor serialization and
  stitching
  ([current node redaction](/home/thhel/git/comfyui-helto-director/nodes/timeline_take_capture/node.py:668),
  [current cleanup](/home/thhel/git/comfyui-helto-director/shared/segmented_executor.py:235)).
- **Legacy/tests/order:** sidecars remain product data and need normalization,
  not a crypto reader; old caches/spills are startup-purged. Preserve take
  registration/domain and stitching tests; move redaction and spill lifecycle to
  P3/P4 contracts, retaining BaseException integration proof
  ([take redaction test](/home/thhel/git/comfyui-helto-director/tests/timeline/test_take_registration.py:374),
  [spill tests](/home/thhel/git/comfyui-helto-director/tests/shared/test_segmented_executor.py:554),
  [BaseException cleanup](/home/thhel/git/comfyui-helto-director/tests/shared/test_segmented_executor.py:690)).
  Depends on P1/P3/P4 and D1; D1 cannot activate until derivative enumeration is
  complete.

## Smart Prompt Manager

Target profile ID: `helto.smart-prompt`. Existing `privacyMode=false` is a
legacy explicit-public declaration only for stored state; missing/new state
becomes `inherit`/private under the shared resolver. Current state embeds its
boolean in the product state and mirrors it to `properties.spmPrivacyMode`
([current normalized state](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:823),
[property mirror](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:369)).

### S0 — bootstrap, codec routes/client, and recovery registration

- **Profile:** one scope `prompt-library`, one workflow resource from S1, and
  protected route operations for current encrypt/decrypt migration/reveal only
  through shared routes. Current code has a pack-local codec, three local
  privacy routes, local request/unlock retry, two recovery descriptors, and a
  memoized shared-module import
  ([codec](/home/thhel/git/comfyui-helto-smartprompt/privacy.py:18),
  [routes](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:161),
  [client](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:308),
  [recovery descriptors](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:412)).
- **Replace/delete:** delete `privacy.py`; remove local route definitions from
  `nodes.py`; remove `spmPrivacyPost`, browser token/unlock logic, local envelope
  memo, and recovery descriptors from `smart_prompt_manager.js`. Failed-current
  state becomes P2 disposition rather than a second consumer descriptor.
- **Remain/tests/order:** keep `schema.py`, `resolver.py`, validation, product
  editor, and product route/dispatch adapters. Replace codec/route/recovery tests
  with profile/readiness/browser contracts and retain normalization/reset
  adapter tests
  ([current privacy tests](/home/thhel/git/comfyui-helto-smartprompt/tests/test_privacy.py:47),
  [current recovery contract test](/home/thhel/git/comfyui-helto-smartprompt/tests/test_frontend.py:722)).
  Depends on P0-P2/P5 and precedes S1-S3 deletion.

### S1 — workflow/editor serialization and mode

- **Profile:** `PrivacyScope("prompt-library",
  PropertyMode("spmPrivacyMode", legacy_bool=True))` and
  `WorkflowState("prompt-library", node="SmartPromptManager",
  current_schema="helto.smart-prompt-manager")` with hidden `spm_data`; declare
  product normalize/apply/clear adapters and the S3 semantic execution
  projection. Current node stores only `spm_data`, seed, and reroll, while the
  browser owns live plaintext and async encryption
  ([node schema](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:200),
  [editor state setup](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:1775)).
- **Adapters/handles:** normalize full prompt-library state, locate/apply/clear
  editor data, mirror mode property, preserve locked unedited bytes, and invoke
  product resolve after shared execution resolution. Use workflow snapshot,
  barrier, recovery, and mounted mode UI.
- **Replace/delete:** remove local pending-promise/memo, sequence tracking,
  encryption failure fallback that clears privacy, per-node serialize hooks,
  `graphToPrompt` patch, and local confirmation/toggle semantics
  ([current pending memo](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:645),
  [current clear-on-failure](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:1986),
  [current serializer](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:2064),
  [current graph patch](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:1503)).
- **Legacy/tests/order:** bind `smart-prompt-v1-schema` and
  `smart-prompt-json-key-import`; genuine old-schema workflow fixtures must
  normalize, snapshot-write current, read back, and preserve original bytes on
  failure. Replace rejection-only tests and keep editor/domain normalization
  ([current rejection test](/home/thhel/git/comfyui-helto-smartprompt/tests/test_privacy.py:125),
  [current serialization tests](/home/thhel/git/comfyui-helto-smartprompt/tests/test_frontend.py:477)).
  Depends on P0-P2/P5 and S0.

### S2 — import/export

- **Profile:** protected operations `import-replace`, `import-merge`, and
  `export`; export is another projection of the same S1 snapshot, not an
  independent encryption pass. Bind legacy `smart-prompt-v1-schema` at bare
  envelope imports and `smart-prompt-export-v1` as the container reader for
  format `comfyui-helto-prompts.smart-prompt-manager.export`, version 1. Current
  helpers accept current envelopes/plain libraries but reject legacy envelopes
  ([current package format](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:857),
  [current parser](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:886)).
- **Adapters/handles:** consumer import adapter parses/normalizes libraries,
  preserves destination declared mode for plaintext imports, and performs domain
  merge/replace; export adapter selects product filename/JSON wrapper. Shared
  workflow/migration handles authorize reveal, provide the snapshot envelope,
  stage import, and issue a receipt only after explicit re-export/read-back.
- **Replace/delete:** remove direct decrypt/encrypt and locked-state transitions
  from import/export UI; keep picker/download, merge conflict rules, IDs, and
  product formatting
  ([current import flow](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:2368)).
- **Tests/order:** add genuine old export and bare-envelope fixtures; preserve
  merge/replace/filename tests, replace legacy rejection with migration/receipt
  tests
  ([current import/export tests](/home/thhel/git/comfyui-helto-smartprompt/tests/test_frontend.py:867)).
  Depends on P2/P5 and S1; reader removal requires explicit seals for both the
  schema and export-wrapper units.

### S3 — execution projection, cache identity, dispatch, and recovery failures

- **Profile:** semantic projection contains selected prompt/folder identity,
  prompt IDs/title/text, variables, and cycle state; protected operation
  `resolve-prompt`; private cache is shared unlocked-session RAM only. Current
  browser hashes this plaintext projection with unkeyed SHA-256, substitutes an
  `spm-cache-v1:` token into executable input, and the backend resolves saved
  workflow metadata
  ([current projection/token](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:1440),
  [current backend lookup](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:111)).
- **Adapters/handles:** semantic adapter returns the product projection;
  dispatcher invokes `selected_prompt`, variable resolution, validation, and
  output formatting inside `workflow.resolve_execution(...)`. Shared execution
  supplies the protected ref, keyed identity, grant, lock revocation, and RAM
  cache.
- **Replace/delete:** delete `spm-cache-v1` generation/resolution and backend
  empty-state-on-failure behavior. Missing metadata, locked keys, decrypt error,
  or mismatch rejects execution instead of returning an empty prompt library
  with warnings
  ([current fallback](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:139),
  [current node dispatch](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:239)).
- **Tests/order:** replace current cache-token resolution and warning tests with
  keyed-identity isolation, grant revocation, missing-reference rejection, lock
  cache-clear, and no-default-execution tests; retain resolver/domain output
  tests
  ([current cache tests](/home/thhel/git/comfyui-helto-smartprompt/tests/test_nodes.py:62),
  [current graph token test](/home/thhel/git/comfyui-helto-smartprompt/tests/test_frontend.py:363)).
  Depends on P2 and S1; S2 export also consumes the same settled snapshot.

## Legacy reader and key dependency ledger

The stable reader IDs should be finalized in P5, but the removal units and
edges are fixed. A reader is selected only at declared profile locations, has
no writer, and later removal requires its implementation, registry entry,
bindings, dependency declaration, fixtures, tests, audit label, and migration
copy to leave together
([unit rule](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/07-define-legacy-read-retirement.md:131),
[removal contents](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/07-define-legacy-read-retirement.md:197)).

| Unit | Bound locations | Dependencies and retirement edge |
| --- | --- | --- |
| `aio-v1-schema` | A1 Generate/Krea fields, A2 builder fields/property/workflow keys, A3 record payloads | Depends on verified `aio-json-key-import`; removal requires its own sealed audit scopes and genuine AIO v1 ciphertext. |
| `smart-prompt-v1-schema` | S1 `spm_data`, S2 bare imports/export contents | Depends on `smart-prompt-json-key-import`; `smart-prompt-export-v1` depends on this reader while retained. |
| `smart-prompt-export-v1` | S2 format/version wrapper | Container-only unit; cannot be removed before every scoped export is checked/re-exported and its seal remains valid. |
| `utils-workflow-prefix` | U1 selector fields, U3 script/variables, U4 mirrored Show Any field | Container unit depends on every byte generation it may dispatch to. |
| `utils-xor`, `utils-HELTO_PRIV1`, `utils-HELTO_PRIV2`, `utils-HELTO_PRIV3` | Bytes under the Utils prefix, historical masks, and historical queue wrappers as applicable | Separate byte units depend on verified binary key import; a retained prefix/queue wrapper prevents removal of a byte unit it may dispatch to. |
| `utils-queue-wrapper` | U5 historical JSON prefix and SQLite BLOB container | Depends on the exact applicable Utils byte readers; its receipt includes the current SQLite row read-back. |
| `utils-json-key-import`, `utils-binary-key-import`, `aio-json-key-import`, `smart-prompt-json-key-import`, `director-json-key-import` | Pack config key sources | Import units validate/wrap/reopen/verify and then unlink the plaintext source; they never keep `.migrated`. Imported keys stay decrypt-only until separate historical-key pruning after every dependent reader has shipped removed. |
| Director current continuity | D2 workflow and D3 records | `helto.timeline-director` is not a removable legacy schema reader; only the old JSON-key import is removable after verification. |

Every workflow migration that references a durable selector mask is
all-or-nothing across field envelopes and the mask; every queue or record
migration is write-plus-read-back; Smart Prompt files migrate only through
explicit import/re-export. A failure leaves the original bytes authoritative and
all obligations open
([atomic receipts](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/07-define-legacy-read-retirement.md:139),
[per-surface rule](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/07-define-legacy-read-retirement.md:171)).

## Implementation-slice matrix

| Consumer | Slice | Shared prerequisites | Consumer deliverable | Deletes/replaces | Must ship with |
| --- | --- | --- | --- | --- | --- |
| Utils | U0 bootstrap/profile | P0-P2, P5 | Atomic server/browser profile and real adapters | wrappers, local crypto routes/recovery catalog | U1-U7 metadata complete |
| Utils | U1 selector state | P0-P2, P5 | fields, normalization, roots, execution projection | local serialization/route policy | U2 durable-mask transaction |
| Utils | U2 masks/thumbnails | P4-P5 | payload/key/regeneration adapters | local storage/crypto/cleanup | U1 and historical mask fixtures |
| Utils | U3 Prompt Enhancer/provider | P0-P3, P5-P6 | workflow + singleton credential adapters | helper crypto and credential encryption | legacy prefix/key import |
| Utils | U4 Privacy Show Any | P0-P2, P5 | mirrored-field/display adapter | backend direct encrypt and lifecycle patch | one logical-field receipt |
| Utils | U5 queue manager | P0-P2, P5-P6 | singleton queue store + dispatch adapter | local crypto/toggle/auth policy | all registered workflow barriers |
| Utils | U6 private media | P1, P4 | roots/encoders + shared lease use | path tokens/private-media route | U7 preview producers |
| Utils | U7 media nodes | P1-P2, P4 | node scopes, encoders, output/replay adapters | temp/staging/cache privacy lifecycle | U6 and derivative purge list |
| AIO | A0 bootstrap/profile | P0-P2, P5 | atomic server/browser profile | local codec/routes/client/recovery | A1-A4 complete |
| AIO | A1 Generate/Krea | P0-P2, P5 | prompt fields/projection/dispatcher | per-widget crypto/decrypt | AIO v1 reader/key fixtures |
| AIO | A2 builder | P0-P2, P5 | editor normalization and mirrored state | synchronous serializers/recovery | A1 upstream floors |
| AIO | A3 library | P1, P3, P5-P6 | opaque store/domain projection | shells/crypto/auth/raw errors | v1 record rewrite receipts |
| AIO | A4 run-info | P1, P3 | safe product mapping | ad-hoc field encryption/debug rule | A1/A2 effective mode |
| Director | D0 bootstrap/profile | P0-P2, P5 | atomic profile + JSON key import | vendored/shared shim, local codec/routes/UI | D1-D6 complete |
| Director | D1 global mode | P1, P4 | setting/transition adapters | route/browser mode policy | every derivative declaration |
| Director | D2 timeline | P0-P2, P5 | editor/snapshot/execution adapters | sync crypto/default substitution | D0 key continuity |
| Director | D3 library | P1, P3, P5-P6 | project/character store/domain adapters | shells/crypto/ungated routes | D0 key continuity |
| Director | D4 caches | P1, P4 | decode/key/regeneration adapters | cache storage and path-serving | D5 source operations |
| Director | D5 media browser | P1, P3-P4 | roots/list/delete domain adapters | request mode/path URLs/raw errors | D4 leases, D6 redaction |
| Director | D6 takes/spills | P1, P3-P4 | safe projection + tensor spill adapters | ad-hoc redaction/local spill lifecycle | D1 transition enumeration |
| Smart Prompt | S0 bootstrap/profile | P0-P2, P5 | atomic profile/browser adapters | local codec/routes/client/recovery | S1-S3 complete |
| Smart Prompt | S1 workflow/editor | P0-P2, P5 | state/editor/clear adapters | memos, per-node serializer/toggle | v1 reader/key fixtures |
| Smart Prompt | S2 import/export | P2, P5 | parser/merge/export adapters | direct crypto/locked transitions | S1 snapshot and two reader units |
| Smart Prompt | S3 execution/cache | P2 | semantic projection/dispatcher | unkeyed token and empty fallback | S1 snapshot/grant |

## Dependency DAG in prose

P0 is the root. P1 (mode/authorization/browser), P2 (snapshot/execution), P3
(records/redaction), P4 (artifacts), P5 (legacy/audit/key import), and P6
(pack-state/common fixtures) build on P0 and must form one complete shared
contract before any consumer profile is enabled. P1 feeds P2-P4 because all
reveal, dispatch, record, and lease operations require the same server-resolved
mode/session. P5 feeds every legacy-bound workflow/record/store slice, and P6
feeds queue/provider and record-store cutovers.

Within Utils, U0 waits for the complete declarations; U2 and U1 are a cycle
resolved as one transaction (workflow refs plus durable masks); U3 and U4 join
the same graph-wide barrier; only then may U5 capture/replay snapshots. U6 must
land before U7 removes path tokens, and U7 completes the plaintext-derivative
set needed for transitions.

Within AIO, A0 binds A1-A4 atomically. A1 supplies the Generate/Krea floor and
execution seam used by A2; A3 and A4 can be implemented in parallel after
P3/P5, but neither may activate before the same profile fingerprint is complete.

Within Director, D0 establishes key continuity. D2/D3 then move current state
and records; D4 supplies managed previews consumed by D5; D6 supplies the last
redaction/spill/derivative declarations. D1 is implemented early but activated
last, because its public-to-private transaction must enumerate D2-D6 and abort
if any rewrite or purge fails.

Within Smart Prompt, S0 precedes S1; S2 consumes S1's exact snapshot; S3 consumes
S1's protected execution ref and grant. The schema reader precedes both workflow
and import reads, while the export wrapper depends on the schema reader.

Finally, the release edge is five-way and all-or-nothing: publish the complete
shared contract, pin all four profiles to that immutable release, run genuine
legacy/current fixtures and cross-pack load-order/attestation tests, and release
the supported set together. Legacy readers remain after cutover until explicit
per-reader audit scopes are sealed; reader removal is a later coordinated
release, and historical key pruning is a still-later explicit transaction
([retirement sequence](/home/thhel/git/helto-privacy/.scratch/privacy-capability-consolidation/issues/07-define-legacy-read-retirement.md:189)).
