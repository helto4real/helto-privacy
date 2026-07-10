# Current privacy capability inventory

## Scope and method

This report inventories privacy-domain behavior in `helto-privacy` and its four
current consumer packs. It uses the checked-out source, tests, and repository
documentation as primary evidence. It identifies capability ownership,
persisted data, public seams, duplication, divergence, and likely shared-domain
ownership. It deliberately does not design the target API.

The consumer packs inspected are:

- `/home/thhel/git/comfyui-utils`
- `/home/thhel/git/comfyui-all-on-one-image-generation-node`
- `/home/thhel/git/comfyui-helto-director`
- `/home/thhel/git/comfyui-helto-smartprompt`

## Executive finding

`helto-privacy` already owns the cryptographic and recovery foundation, but the
consumer packs still implement substantial privacy semantics independently.
The strongest duplication is not AES-GCM itself; it is the integration around
it: schema-scoped encrypt/decrypt routes, browser token transport and unlock
retry, encrypted-envelope recognition and in-memory reuse, workflow
serialization coordination, recovery registration, encrypted artifact
storage/serving, private record shells, and metadata redaction.

Several single-pack capabilities also belong in the shared privacy domain even
without current duplication: failed-envelope tracking, removable legacy-schema
recognition, privacy-safe error responses, plaintext-artifact cleanup, and
privacy-aware execution cache indirection.

## Capability inventory

### 1. Keystore, session, key rotation, and legacy-key import

Current shared ownership is strong. `helto-privacy` owns the password-wrapped
keystore, runtime session cache, bearer token, password changes, primary-key
rotation, and decrypt-only historical keys
([keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:1),
[public exports](/home/thhel/git/helto-privacy/helto_privacy/__init__.py:20)).
ComfyUI registration collects legacy key directories and migrates their keys on
initialization or unlock
([comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:43)).

Consumer divergence remains:

- Director still carries a package-first compatibility shim with a vendored
  keystore fallback
  ([privacy_keystore.py](/home/thhel/git/comfyui-helto-director/shared/privacy_keystore.py:1)).
- `comfyui-utils` installs a strict key provider that deliberately forbids the
  codec's plaintext-key fallback
  ([shared/privacy.py](/home/thhel/git/comfyui-utils/shared/privacy.py:40)).
- AIO and Smart Prompt explicitly require the shared keystore before writing,
  but express that policy in their own wrappers
  ([AIO privacy.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/privacy.py:148),
  [Smart Prompt privacy.py](/home/thhel/git/comfyui-helto-smartprompt/privacy.py:28)).

Assessment: the lifecycle belongs centrally and already does. Consumer-specific
fallback/strictness policy is a shared-domain decision, not four unrelated
implementations.

### 2. State, byte, and chunked-byte envelopes

`PrivacyEnvelopeCodec` owns schema-bound state envelopes, purpose-bound byte
envelopes, large-payload chunking, key lookup, and historical-key decryption
([envelope.py](/home/thhel/git/helto-privacy/helto_privacy/envelope.py:83)). The
shared tests pin the state envelope, Director-compatible AAD, byte-purpose
binding, and chunk tamper detection
([test_envelope.py](/home/thhel/git/helto-privacy/tests/test_envelope.py:24)).

Consumer duplication and divergence:

- Director still contains a complete local state/byte/chunked implementation
  with the same schema family and purpose binding
  ([Director privacy.py](/home/thhel/git/comfyui-helto-director/shared/privacy.py:30)).
- `comfyui-utils` wraps the codec with JSON/bytes conversion, purpose constants,
  strict keystore behavior, and error normalization
  ([Utils privacy.py](/home/thhel/git/comfyui-utils/shared/privacy.py:27)).
- AIO recognizes current schema `helto.aio-image-generate.v2` and legacy schema
  `helto.aio-image-generate`, but currently rejects the legacy schema instead of
  reading it
  ([AIO privacy.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/privacy.py:33)).
- Smart Prompt similarly recognizes but rejects
  `comfyui-helto-prompts.smart-prompt-manager`
  ([Smart Prompt privacy.py](/home/thhel/git/comfyui-helto-smartprompt/privacy.py:18)).

Assessment: the codec is centrally owned, but schema recognition, legacy reads,
serialization form, and fallback policy are still distributed privacy
semantics.

### 3. HTTP authorization and canonical keystore UI

The shared package owns header/cookie token authorization
([guard.py](/home/thhel/git/helto-privacy/helto_privacy/guard.py:11)), idempotent
ComfyUI keystore routes, and the served UI module
([comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:52)). The
browser module owns token storage, cookie rehydration, keystore operations, and
unlock/setup/change-password dialogs
([privacy_ui.js](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:39),
[privacy_ui.js](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:1047)).

Director still exposes a parallel `/helto_director/privacy` keystore/status
surface with its own token check
([Director routes/privacy.py](/home/thhel/git/comfyui-helto-director/routes/privacy.py:31))
and a second unlock dialog implementation
([privacy_unlock.js](/home/thhel/git/comfyui-helto-director/web/timeline/privacy_unlock.js:49)).

Assessment: canonical keystore authorization/UI already belongs centrally;
Director's parallel surface is direct duplication. Pack-owned routes that touch
private content still need pack-specific domain authorization, but should not
redefine token semantics.

### 4. Schema-scoped encrypt/decrypt route services

Every frontend-heavy consumer exposes pack-local HTTP operations that wrap its
schema codec:

- AIO registers status/encrypt/decrypt routes under
  `/aio_image_generate/privacy`
  ([routes/privacy.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/routes/privacy.py:19)).
- Smart Prompt registers status/encrypt/decrypt routes under
  `/helto_spm/privacy`
  ([nodes.py](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:161)).
- Director registers equivalent operations as part of its parallel privacy
  route family
  ([routes/privacy.py](/home/thhel/git/comfyui-helto-director/routes/privacy.py:78)).
- `comfyui-utils` exposes encryption through selector/privacy backend seams and
  forwards to the shared wrapper
  ([helto_selector_backend/crypto.py](/home/thhel/git/comfyui-utils/helto_selector_backend/crypto.py:37)).

The repeated semantics are token gating, JSON parsing, schema-codec invocation,
error conversion, and response shapes. Schema and state normalization remain
consumer-specific.

Assessment: strong shared-service candidate. The inventory does not decide
whether this becomes a route factory, registry, or another boundary.

### 5. Browser privacy request, token transport, and unlock retry

The shared browser module handles its own canonical keystore requests, but does
not expose a general pack-route request client. Consumers therefore repeat the
same privacy flow:

- `comfyui-utils` dynamically imports the shared module, attaches header and
  cookie credentials, converts HTTP errors, opens unlock/setup, and retries once
  ([privacy_common.js](/home/thhel/git/comfyui-utils/web/privacy_common.js:20),
  [privacy_common.js](/home/thhel/git/comfyui-utils/web/privacy_common.js:71)).
- AIO repeats token lookup, unlock-error recognition, request parsing, and one
  retry
  ([aio_privacy.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:70),
  [aio_privacy.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:110)).
- Smart Prompt repeats the same flow in `spmPrivacyPost`
  ([smart_prompt_manager.js](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:299)).
- Director keeps another token store/API client in its timeline frontend
  ([privacy.js](/home/thhel/git/comfyui-helto-director/web/timeline/privacy.js:7)).

Assessment: direct cross-pack duplication and a strong shared UI/service
candidate.

### 6. Envelope recognition, canonicalization, in-memory reuse, and fail-closed serialization

The shared recovery module already parses/validates envelopes, canonicalizes
values, memoizes an envelope per owner/field, and fails closed when encryption
is unavailable or invalid
([privacy_ui.js](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:366),
[privacy_ui.js](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:403),
[privacy_ui.js](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:427)).

Consumers still keep overlapping variants:

- `comfyui-utils` duplicates stable JSON canonicalization and `WeakMap`
  envelope memos, then delegates final encryption to the shared helper
  ([privacy_envelope.js](/home/thhel/git/comfyui-utils/web/privacy_envelope.js:5)).
- Smart Prompt has another `WeakMap` memo with concurrent pending-promise reuse
  ([smart_prompt_manager.js](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:645)).
- AIO has its own envelope parsing plus failed-envelope fingerprint tracking,
  which prevents structurally valid but undecryptable values from being treated
  as healthy recovery envelopes
  ([aio_privacy.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:16),
  [aio_privacy.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:211)).

Assessment: direct duplication. Concurrent encryption deduplication and
failed-current-envelope state are single-pack refinements that appear to belong
in the shared privacy domain.

### 7. Recovery registry, scanning, actions, and consumer metadata

The package owns descriptor normalization, loaded-graph scanning, sanitized
issue models, re-encrypt/reset/default actions, dirty marking, and the recovery
dialog
([privacy_ui.js](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:157),
[privacy_ui.js](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:184),
[privacy_ui.js](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:1152)).

Each consumer owns concrete descriptors and runtime reset behavior:

- `comfyui-utils` describes the selector, Prompt Enhancer, and Privacy Show Any
  surfaces
  ([privacy_recovery.js](/home/thhel/git/comfyui-utils/web/privacy_recovery.js:96)).
- AIO describes Generate, Krea Settings, and Ideogram Prompt Builder fields
  ([aio_privacy_recovery.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy_recovery.js:102)).
- Smart Prompt has both its normal descriptor and an extra descriptor for a
  current-schema envelope whose key is unavailable
  ([smart_prompt_manager.js](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:412)).

Assessment: the engine is shared, while concrete metadata placement is the
explicit unresolved decision in **Place consumer-specific privacy metadata**.
Locked-current-envelope recovery is a shared semantic even if the match hook
remains consumer-specific.

### 8. Encrypted artifacts, media serving, caches, and plaintext cleanup

The shared codec supplies byte encryption, but storage and serving semantics
are consumer-owned.

`comfyui-utils` implements:

- expiring encrypted path/content-type media tokens and encrypted temporary
  files
  ([shared/privacy.py](/home/thhel/git/comfyui-utils/shared/privacy.py:136),
  [shared/privacy.py](/home/thhel/git/comfyui-utils/shared/privacy.py:159));
- authenticated, off-event-loop private-media serving with path/error
  sanitization
  ([private_media_routes.py](/home/thhel/git/comfyui-utils/shared/private_media_routes.py:17));
- encrypted masks, thumbnails, video caches/replays, queue-manager state, and
  provider credentials
  ([mask_storage.py](/home/thhel/git/comfyui-utils/helto_selector_backend/mask_storage.py:77),
  [queue_manager_store.py](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:51),
  [provider_settings.py](/home/thhel/git/comfyui-utils/shared/prompt_enhancer/provider_settings.py:25));
- cleanup of known plaintext preview artifacts
  ([shared/privacy.py](/home/thhel/git/comfyui-utils/shared/privacy.py:237)).

Director implements:

- encrypted thumbnail and waveform caches
  ([media_cache.py](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:155));
- encrypted tensor spill files with path suppression in privacy mode
  ([segmented_executor.py](/home/thhel/git/comfyui-helto-director/shared/segmented_executor.py:163));
- authenticated media/browser routes, private cache-control, and privacy-safe
  errors
  ([routes/media_cache.py](/home/thhel/git/comfyui-helto-director/routes/media_cache.py:79),
  [media_privacy.py](/home/thhel/git/comfyui-helto-director/routes/media_privacy.py:15)).

Assessment: encrypted-artifact lifecycle, authenticated serving, safe errors,
private cache headers, and plaintext cleanup are shared privacy semantics.
Allowed roots, media decoding, cache keys, tensor serialization, and domain
payload construction remain consumer-specific.

### 9. Privacy-aware record libraries and safe public shells

AIO and Director independently implement the same higher-level storage pattern:
private records encrypt payload plus sensitive metadata, list operations expose
a placeholder/sanitized shell, and explicit use/preview operations decrypt the
record.

- AIO's Ideogram prompt library hides the real private name and stores payload,
  name, description, and tags inside `encrypted_payload`
  ([ideogram4_prompt_library.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/ideogram4_prompt_library.py:261)).
- Director's project/character library encrypts private payload/description
  (and project name), exposes public shells, and has sanitized preview
  projections
  ([timeline_library.py](/home/thhel/git/comfyui-helto-director/shared/timeline_library.py:313),
  [timeline_library.py](/home/thhel/git/comfyui-helto-director/shared/timeline_library.py:363)).

Assessment: strong shared-service candidate. Record schemas, normalization, and
domain-specific preview projections remain consumer behavior; private-shell and
sensitive-metadata rules belong to the privacy domain.

### 10. Privacy-mode redaction and information minimization

Privacy protection extends beyond encrypted fields:

- Director makes global privacy mode authoritative for media operations
  ([media_cache.py](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:40)),
  redacts LoRA names and suggested filenames in take metadata
  ([take_capture.py](/home/thhel/git/comfyui-helto-director/shared/timeline/take_capture.py:320)),
  suppresses paths in spill diagnostics, and sanitizes private route errors.
- AIO's library hides sensitive record metadata and lets undecryptable private
  entries remain deletable
  ([ideogram4_prompt_library.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/ideogram4_prompt_library.py:227)).
- `comfyui-utils` avoids echoing private media paths/token internals from route
  errors
  ([private_media_routes.py](/home/thhel/git/comfyui-utils/shared/private_media_routes.py:31)).
- The shared recovery dialog deliberately exposes labels/counts but not field
  plaintext
  ([privacy_ui.js](/home/thhel/git/helto-privacy/helto_privacy/web/privacy_ui.js:1246)).

Assessment: redaction policy and safe error/shell construction are shared
privacy capabilities. The exact fields requiring redaction are consumer domain
metadata.

### 11. Workflow serialization, queue payloads, and private execution caches

The frontend consumers must keep live plaintext usable while workflows store
encrypted values and queued inputs remain stable:

- AIO supports synchronous and asynchronous encryption, envelope reuse,
  failed-envelope recovery, and prompt serialization patches
  ([aio_privacy.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:132)).
- `comfyui-utils` applies its envelope helper across selector, Prompt Enhancer,
  Privacy Show Any, and queue-manager state
  ([privacy_envelope.js](/home/thhel/git/comfyui-utils/web/privacy_envelope.js:144)).
- Smart Prompt waits for pending privacy saves before `graphToPrompt`, replaces
  executable `spm_data` with a non-secret cache identity, and recovers saved
  encrypted state from workflow metadata on the backend
  ([smart_prompt_manager.js](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:1456),
  [nodes.py](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:111)).

Assessment: save/queue coordination, fail-closed waiting, stable envelope reuse,
and privacy-safe cache identities are shared privacy semantics. Consumer state
projection and ComfyUI widget indexing remain integration concerns.

### 12. Privacy test isolation and contract coverage

The shared package tests keystore lifecycle, legacy key import, token gating,
envelope compatibility, chunking, route registration, and the browser recovery
engine
([test_keystore.py](/home/thhel/git/helto-privacy/tests/test_keystore.py:27),
[test_comfy_ui.py](/home/thhel/git/helto-privacy/tests/test_comfy_ui.py:59),
[test_privacy_recovery_js.py](/home/thhel/git/helto-privacy/tests/test_privacy_recovery_js.py:1)).

Consumer coverage is broad but repo-specific:

- `comfyui-utils`: `tests/test_privacy.py`, `tests/test_queue_manager_store.py`,
  `tests/test_prompt_enhancer.py`, `tests/test_backend.py`, and the JS privacy
  suites.
- AIO: `tests/test_privacy.py`, `tests/test_privacy_recovery_js.py`,
  `tests/test_aio_generate_node.py`, and prompt-library/builder tests.
- Director: timeline privacy/keystore tests plus media-cache/browser, segmented
  executor, timeline-library, and JS media/timeline suites.
- Smart Prompt: privacy, node, schema, and Node-executed frontend tests.

Assessment: isolation of real keystore/session paths and reusable cross-pack
contract fixtures belong centrally. Product-state assertions remain in the
consumer suites.

## Persisted privacy data by owner

| Owner | Persisted data touched by privacy behavior |
| --- | --- |
| `helto-privacy` | Password-wrapped keystore, runtime session/token, imported decrypt-only legacy keys, schema-bound state envelopes, purpose-bound byte envelopes |
| `comfyui-utils` | Encrypted workflow widgets/properties, selector masks/thumbnails, video preview/replay artifacts, queue-manager SQLite payloads, provider secrets, encrypted private-media temp files and tokens |
| AIO | Encrypted prompt/settings/builder workflow values, Ideogram prompt-library records and private metadata, current `helto.aio-image-generate.v2` envelopes, recognized legacy `helto.aio-image-generate` values |
| Director | Encrypted timeline state, project/character library records, thumbnails/waveforms, segment spills, private media responses, redacted take metadata, legacy per-pack key compatibility |
| Smart Prompt | Encrypted `spm_data` workflow value, encrypted import/export packages, runtime-only envelope memos, queue cache tokens with workflow-metadata recovery, recognized legacy Smart Prompt schema |

## Candidate classification

### Already shared, but consumer duplication should be retired

- Keystore/session/token lifecycle.
- State/byte/chunked envelope codec.
- Header/cookie authorization semantics.
- Keystore status/setup/unlock/lock/password UI.
- Recovery registry, scanner, action engine, sanitized model, and dialog.

### Strong shared privacy capability candidates

- Schema-scoped encrypt/decrypt route registration and error mapping.
- General browser privacy request client with credential attachment, unlock, and
  one bounded retry.
- Envelope recognition, canonicalization, concurrent in-memory reuse, failed
  envelope tracking, and fail-closed serialization coordination.
- Recovery metadata/catalog registration and locked-current-envelope semantics.
- Encrypted artifact lifecycle: private writes, purpose binding, serving,
  cache-control, cleanup, and privacy-safe errors.
- Privacy-aware record persistence with encrypted sensitive metadata and safe
  public shells.
- Cross-cutting redaction/data-minimization policy.
- Workflow save/queue coordination and privacy-safe execution cache identities.
- Shared compatibility fixtures and isolated keystore/session test harnesses.

### Consumer behavior that should remain consumer-owned

- Concrete node types, widget/property names, state normalization, and domain
  validation.
- Media allowed-root policy, decoding/rendering, cache keys, and artifact
  payload formats.
- Timeline/project, prompt-library, selector, Prompt Enhancer, and Smart Prompt
  product behavior.
- Domain-specific metadata projections, while the privacy redaction contract
  remains shared.

## Divergences the later decisions must resolve

1. AIO and Smart Prompt recognize but currently reject their legacy schemas,
   while the destination requires legacy workflow data to remain readable until
   re-saved.
2. Director permits package/vendored and legacy-key fallback paths;
   `comfyui-utils`, AIO, and Smart Prompt enforce the shared keystore more
   strictly.
3. Browser encryption ranges from synchronous XHR (AIO) to async route clients
   and graph-to-prompt waiting (Smart Prompt and Utils).
4. Failed-current-envelope recovery exists explicitly in AIO and Smart Prompt,
   but is not a general shared concept.
5. Private artifacts use different authorization forms: a shared session token,
   an encrypted path token, privacy query state, or combinations of these.
6. Private record shells and redaction policies are independently encoded by
   AIO and Director.
7. Privacy defaults and the authority of global versus node-local privacy mode
   vary by consumer and data surface.

These are evidence for the existing ownership, metadata-placement, interface,
legacy-retirement, migration, and acceptance tickets. They are not target API
decisions.
