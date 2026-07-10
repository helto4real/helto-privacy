# Legacy workflow data and read obligations

## Scope and method

This report inventories privacy data that is actually persisted by
`helto-privacy` and its four consumer packs: workflow fields, user-managed
imports/exports, pack-managed JSON/SQLite state, encrypted artifacts, and key
material. It separates stored-data compatibility from source/API compatibility
and does not design a target API.

The checked-out source and tests are the primary evidence. The pre-migration
formats that no longer exist in the working trees were verified from local Git
history; reproducible `git show` commands are listed under **Historical source
provenance**.

## Executive finding

There are four distinct stored-data obligations:

1. Preserve all current shared-envelope data if the coordinated cutover changes
   its on-disk representation. The current state, byte, and chunked-byte formats
   are schema- and purpose-bound, not generic AES-GCM blobs.
2. Restore read support for AIO and Smart Prompt's pre-shared-package v1 state
   envelopes. Their cryptography is already structurally compatible with
   `PrivacyEnvelopeCodec`; only the original schema binding and imported
   `config/privacy_key.json` are missing.
3. Isolate a genuinely different `comfyui-utils` legacy decoder/importer for
   `__HELTO_ENC__:` workflow strings, older queue-manager payloads, and their
   binary key files. The current shared key importer cannot recover those keys.
4. Keep Director's existing `helto.timeline-director` envelopes readable. That
   schema never changed, and Director already registers its legacy JSON key
   directory, so this is preservation rather than a second legacy codec.

Unknown schemas, malformed encrypted-looking values, expired browser media
tokens, and regenerable caches are not minimum compatibility obligations. They
should continue to fail closed or be discarded/rebuilt.

## Canonical formats in the current checkout

### Shared state and byte envelopes

All current consumers ultimately use version `1`, algorithm `AES-256-GCM`, and
URL-safe base64 without padding. A state envelope is an object with
`version`, `schema`, `encrypted`, `algorithm`, `keyId`, `nonce`, and
`ciphertext`; its AAD is
`{schema}|1|AES-256-GCM|{keyId}`
([envelope.py](/home/thhel/git/helto-privacy/helto_privacy/envelope.py:119),
[envelope.py](/home/thhel/git/helto-privacy/helto_privacy/envelope.py:278)).

Byte envelopes add `purpose` and use schema `{schema}.bytes`; their AAD is
`{schema}.bytes|1|AES-256-GCM|{keyId}|{purpose}`. Large byte payloads use
`{schema}.bytes.chunked` plus `chunkSize`, `plaintextSize`, and indexed
`chunks`; each chunk binds its index, chunk count, and total plaintext size in
AAD
([envelope.py](/home/thhel/git/helto-privacy/helto_privacy/envelope.py:161),
[envelope.py](/home/thhel/git/helto-privacy/helto_privacy/envelope.py:281),
[envelope.py](/home/thhel/git/helto-privacy/helto_privacy/envelope.py:296)).
Changing a schema or purpose therefore changes authentication, not just format
dispatch.

Current state schemas are:

| Consumer | Current schema | Already-recognized older schema/prefix |
|---|---|---|
| `comfyui-utils` | `helto.comfyui-utils` | `__HELTO_ENC__:` (rejected) |
| AIO Image Generate | `helto.aio-image-generate.v2` | `helto.aio-image-generate` (rejected) |
| Director | `helto.timeline-director` | Same schema; no schema break |
| Smart Prompt | `helto.smart-prompt-manager` | `comfyui-helto-prompts.smart-prompt-manager` (rejected) |

The schema constants and current rejection behavior are explicit in
[Utils privacy.py](/home/thhel/git/comfyui-utils/shared/privacy.py:27),
[Utils crypto.py](/home/thhel/git/comfyui-utils/helto_selector_backend/crypto.py:38),
[AIO privacy.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/privacy.py:33),
[Director privacy.py](/home/thhel/git/comfyui-helto-director/shared/privacy.py:30), and
[Smart Prompt privacy.py](/home/thhel/git/comfyui-helto-smartprompt/privacy.py:18).

### Shared keystore, session, and old JSON keys

The persistent keystore defaults to
`~/.config/helto/privacy_keystore.json` (or `HELTO_PRIVACY_KEYSTORE`) and has
schema `helto.privacy-keystore`, version `1`, scrypt KDF metadata, and wrapped
DEK entries `{keyId, nonce, wrapped_key, primary?}`
([keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:41),
[keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:67),
[keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:137),
[keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:363)).
Old and rotated keys remain decrypt-only entries
([keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:240),
[keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:279)).

The unlocked session cache is `privacy_session.json` under the configured
runtime directory. It holds the bearer token, primary key id, and plaintext
DEKs; it is runtime state, not durable workflow compatibility data
([keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:76),
[keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:414),
[keystore.py](/home/thhel/git/helto-privacy/helto_privacy/keystore.py:436)).

The automatic legacy importer currently recognizes only
`<registered-dir>/privacy_key.json` containing `{keyId, key}` and retires it as
`.migrated`
([comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:16),
[comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:177),
[comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:198)).
That retirement is a rename, not deletion or cryptographic erasure: the
`.migrated` file still contains plaintext legacy key material. The later design
decision must define how successful import is verified and when that retained
file can be securely removed.
Director and Utils register a legacy directory, while AIO and Smart Prompt
currently do not
([Director registration](/home/thhel/git/comfyui-helto-director/__init__.py:95),
[Utils registration](/home/thhel/git/comfyui-utils/__init__.py:29),
[AIO registration](/home/thhel/git/comfyui-all-on-one-image-generation-node/__init__.py:85),
[Smart Prompt registration](/home/thhel/git/comfyui-helto-smartprompt/__init__.py:1)).

## Persisted data by consumer

### `comfyui-utils`

#### Workflow data

Privacy-mode workflows persist current `helto.comfyui-utils` state-envelope
strings in these locations:

- `HeltoImageSelector.widgets_values`: `selected_images`, `edited_masks`, and
  `edited_bboxes`; the node-level `properties.privacyMode` controls the policy
  ([privacy recovery descriptors](/home/thhel/git/comfyui-utils/web/privacy_recovery.js:96),
  [selector serialization](/home/thhel/git/comfyui-utils/web/selector.js:85),
  [selector serialization](/home/thhel/git/comfyui-utils/web/selector.js:473)).
- `HeltoPromptEnhancer.widgets_values`: `script` and `variables`, with the
  `privacy_mode` widget as policy state
  ([privacy recovery descriptors](/home/thhel/git/comfyui-utils/web/privacy_recovery.js:134),
  [prompt persistence](/home/thhel/git/comfyui-utils/web/prompt_enhancer_helpers.js:340),
  [variable persistence](/home/thhel/git/comfyui-utils/web/prompt_enhancer_helpers.js:861)).
- `HeltoPrivacyShowAny.widgets_values[0]` as `encrypted_text_state`, duplicated
  in `properties.helto_privacy_show_any_encrypted_text_state`; the display
  widget itself is explicitly non-serializing
  ([helpers](/home/thhel/git/comfyui-utils/web/privacy_show_any_helpers.js:9),
  [helpers](/home/thhel/git/comfyui-utils/web/privacy_show_any_helpers.js:90),
  [frontend serialization](/home/thhel/git/comfyui-utils/web/privacy_show_any.js:196)).

Each state envelope encrypts `{"data": <serialized plaintext>}`
([crypto.py](/home/thhel/git/comfyui-utils/helto_selector_backend/crypto.py:54)).
The old `__HELTO_ENC__:` values can occupy every one of the same workflow
fields; current code recognizes and rejects the prefix
([privacy_envelope.js](/home/thhel/git/comfyui-utils/web/privacy_envelope.js:5),
[crypto.py](/home/thhel/git/comfyui-utils/helto_selector_backend/crypto.py:49),
[backend test](/home/thhel/git/comfyui-utils/tests/test_backend.py:305)).

#### Pack-managed state and files

- `config/queue_manager_state.sqlite3` has one row with privacy flags and a
  `payload` BLOB. In privacy mode the BLOB is a current byte envelope with
  purpose `queue-manager-state`; `config/queue_manager_state.json` is a
  migration input whose encrypted `payload` is a current state-envelope string
  ([queue store](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:14),
  [queue store](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:50),
  [queue store](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:61),
  [queue store](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:97),
  [queue migration](/home/thhel/git/comfyui-utils/shared/queue_manager_store.py:177)).
  Pre-migration SQLite rows instead contain raw `HELTO_PRIV1/2/3` bytes, and
  encrypted legacy JSON uses `HELTO_QUEUE_MANAGER_STATE_V1:` plus base64 of
  those bytes. The current reader does not decode either historical form.
- `config/prompt enhancer/provider_settings.json` version `2` stores
  `hf_token_encrypted` as a current state envelope. A plaintext legacy
  `hf_token` is already read once and rewritten encrypted
  ([provider_settings.py](/home/thhel/git/comfyui-utils/shared/prompt_enhancer/provider_settings.py:12),
  [provider_settings.py](/home/thhel/git/comfyui-utils/shared/prompt_enhancer/provider_settings.py:21),
  [provider_settings.py](/home/thhel/git/comfyui-utils/shared/prompt_enhancer/provider_settings.py:89)).
- Selector masks (`<sha256>.png.enc`) are user-authored workflow adjuncts:
  the encrypted `edited_masks` workflow map records which source-image paths
  have masks, while the mask bytes live in the hashed pack-managed file. They
  are not regenerable and use purpose `selector-mask`
  ([mask references](/home/thhel/git/comfyui-utils/helto_selector_backend/mask_storage.py:25),
  [mask loading](/home/thhel/git/comfyui-utils/helto_selector_backend/image_processing.py:219)).
  Pre-migration mask files use the historical Utils byte generations and need
  a one-time reader/rewrite whenever a saved workflow still references them.
- Selector/load-video thumbnails (`.webp.enc`), private preview files, and Save
  Video replay bundles (`.pt.enc`) store current byte envelopes with purposes
  `selector-thumbnail`, `load-video-cache`, `private-media`, and
  `save-video-replay`
  ([purpose registry](/home/thhel/git/comfyui-utils/shared/privacy.py:28),
  [mask storage](/home/thhel/git/comfyui-utils/helto_selector_backend/mask_storage.py:74),
  [thumbnail cache](/home/thhel/git/comfyui-utils/helto_selector_backend/thumbnail_cache.py:68),
  [load-video cache](/home/thhel/git/comfyui-utils/nodes/load_video/video_io.py:111),
  [replay bundle](/home/thhel/git/comfyui-utils/nodes/save_video_advanced/__init__.py:633)).
  These are caches or runtime replay state and can be removed/rebuilt.
- Private-media tokens are current state envelopes containing version, path,
  content type, encrypted flag, purpose, issue time, and expiry
  ([privacy.py](/home/thhel/git/comfyui-utils/shared/privacy.py:136),
  [privacy.py](/home/thhel/git/comfyui-utils/shared/privacy.py:198)). They are
  time-limited bearer capabilities, not durable workflow data.

### `comfyui-all-on-one-image-generation-node`

#### Workflow data

Current workflow values use schema `helto.aio-image-generate.v2`; the plaintext
projection for a single sensitive value is `{"value": value}`
([aio_privacy.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:159)).
Persisted locations are:

- `AIOImageGenerate` widgets `positive_prompt` and `negative_prompt`.
- `AIOKrea2Settings` widget `inpaint_positive_prompt`.
- `AIOIdeogram4PromptBuilder` sensitive widgets
  `high_level_description`, `background`, `photo`, `art_style`, `aesthetics`,
  `lighting`, `medium`, `style_palette_data`, `elements_data`, and
  `import_json`.

The authoritative field list is in the recovery descriptors
([aio_privacy_recovery.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy_recovery.js:22),
[aio_privacy_recovery.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy_recovery.js:102)).

The prompt builder also persists one whole-state envelope containing version,
widget values, elements, palette, display settings, and active selection. It is
written to
`properties.aio_ideogram4_prompt_builder_state` and the top-level workflow key
`aio_ideogram4_prompt_builder`; the reader also accepts the older top-level key
`ideo`
([prompt builder](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_ideogram4_prompt_builder.js:33),
[prompt builder](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_ideogram4_prompt_builder.js:838),
[prompt builder](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_ideogram4_prompt_builder.js:886),
[prompt builder](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_ideogram4_prompt_builder.js:1201)).

The pre-shared-package schema `helto.aio-image-generate` used the same v1
envelope fields and AAD construction but a pack-local
`config/privacy_key.json`. Current code recognizes that schema and deliberately
rejects it
([AIO privacy.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/privacy.py:33),
[AIO privacy.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/privacy.py:99),
[AIO test](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_privacy.py:85)).

#### Pack-managed state

`config/ideogram4_prompt_library.json` version `1` stores private entries with a
public shell and `encrypted_payload`. The envelope contains `{payload, name,
description, tags}` and uses the same AIO schema as workflows
([library.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/ideogram4_prompt_library.py:19),
[library.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/ideogram4_prompt_library.py:261),
[library.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/ideogram4_prompt_library.py:343),
[library.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/ideogram4_prompt_library.py:457)).
Legacy-schema entries are currently undecryptable but deletable
([library test](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_ideogram4_prompt_library.py:151)).

### `comfyui-helto-director`

#### Workflow data

`HeltoVideoTimelineDirector.widgets_values` persists the hidden
`video_timeline_json` field. With global privacy mode enabled it is a JSON
string containing a `helto.timeline-director` state envelope whose plaintext is
`{"timeline": <VIDEO_TIMELINE>}`; otherwise it is plaintext timeline JSON
([node.py](/home/thhel/git/comfyui-helto-director/nodes/video_timeline_director/node.py:71),
[state.js](/home/thhel/git/comfyui-helto-director/web/timeline/state.js:25),
[state.js](/home/thhel/git/comfyui-helto-director/web/timeline/state.js:365),
[backend.py](/home/thhel/git/comfyui-helto-director/nodes/video_timeline_director/backend.py:63)).

Director's schema, envelope fields, state AAD, and old pack-local
`config/privacy_key.json` are identical to the shared codec's Director binding
([Director privacy.py](/home/thhel/git/comfyui-helto-director/shared/privacy.py:30),
[Director privacy.py](/home/thhel/git/comfyui-helto-director/shared/privacy.py:130),
[Director privacy.py](/home/thhel/git/comfyui-helto-director/shared/privacy.py:174),
[Director privacy.py](/home/thhel/git/comfyui-helto-director/shared/privacy.py:295),
[shared compatibility test](/home/thhel/git/helto-privacy/tests/test_envelope.py:46)).
Existing Director envelopes are therefore already decryptable after their old
key is imported.

#### Pack-managed state and files

- `config/director_library.json` version `1` stores project and character
  entries. Private entry envelopes contain `{payload, description}` and, for
  projects, `name`; the surrounding record remains a public shell
  ([timeline_library.py](/home/thhel/git/comfyui-helto-director/shared/timeline_library.py:25),
  [timeline_library.py](/home/thhel/git/comfyui-helto-director/shared/timeline_library.py:313),
  [timeline_library.py](/home/thhel/git/comfyui-helto-director/shared/timeline_library.py:385),
  [timeline_library.py](/home/thhel/git/comfyui-helto-director/shared/timeline_library.py:702)).
- `config/timeline_director_global_settings.json` stores the global
  `privacy.mode` flag in plaintext; it is policy state, not encrypted content
  ([global_settings.py](/home/thhel/git/comfyui-helto-director/shared/timeline/global_settings.py:19),
  [global_settings.py](/home/thhel/git/comfyui-helto-director/shared/timeline/global_settings.py:24),
  [global_settings.py](/home/thhel/git/comfyui-helto-director/shared/timeline/global_settings.py:61)).
- Private thumbnail and waveform caches use byte-envelope purposes
  `timeline-thumbnail-cache` and `timeline-waveform-cache`, with `.webp.enc`
  and `.json.enc` filenames
  ([media_cache.py](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:23),
  [media_cache.py](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:155),
  [media_cache.py](/home/thhel/git/comfyui-helto-director/shared/media_cache.py:167)).
- Segment spills are JSON-serialized byte envelopes over `torch.save` payloads,
  purpose `timeline-segment-cache`, stored as per-run `.pt.enc` files and
  deleted after execution
  ([segmented_executor.py](/home/thhel/git/comfyui-helto-director/shared/segmented_executor.py:162),
  [segmented_executor.py](/home/thhel/git/comfyui-helto-director/shared/segmented_executor.py:179),
  [segmented_executor.py](/home/thhel/git/comfyui-helto-director/shared/segmented_executor.py:235)).
  Caches and spills are regenerable and do not need legacy readers.
- Generated-take `.helto_take.json` sidecars are plaintext but privacy-sanitized
  records carrying a `privacy` section and redaction metadata; they are not
  encrypted envelopes
  ([take_capture.py](/home/thhel/git/comfyui-helto-director/shared/timeline/take_capture.py:35),
  [generated_capture.py](/home/thhel/git/comfyui-helto-director/shared/timeline/generated_capture.py:25),
  [capture node](/home/thhel/git/comfyui-helto-director/nodes/timeline_take_capture/node.py:546)).

### `comfyui-helto-smartprompt`

#### Workflow data

The hidden `spm_data` widget is the sole encrypted content field. A compact
workflow node serializes `[spm_data, seed, reroll]`; the separate
`properties.spmPrivacyMode` flag exists for recovery policy
([nodes.py](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:200),
[frontend](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:10),
[frontend](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:369),
[frontend](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:1246)).
The current envelope plaintext is the normalized whole library state. During
queue execution only, `output.inputs.spm_data` becomes a non-persisted
`spm-cache-v1:<hash>` identity; the backend resolves the real envelope from
workflow metadata
([frontend](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:1440),
[frontend](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:1469),
[nodes.py](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:81),
[nodes.py](/home/thhel/git/comfyui-helto-smartprompt/nodes.py:139)).

The old schema `comfyui-helto-prompts.smart-prompt-manager` used the same v1
envelope/AAD and a pack-local `config/privacy_key.json`. Current backend and
frontend recognize it only as unsupported and return an empty locked state or
recovery path instead of decrypting
([privacy.py](/home/thhel/git/comfyui-helto-smartprompt/privacy.py:18),
[privacy.py](/home/thhel/git/comfyui-helto-smartprompt/privacy.py:67),
[privacy test](/home/thhel/git/comfyui-helto-smartprompt/tests/test_privacy.py:124),
[node test](/home/thhel/git/comfyui-helto-smartprompt/tests/test_nodes.py:97)).

#### Import/export

Smart Prompt has no separate server-side library file. User exports use format
`comfyui-helto-prompts.smart-prompt-manager.export`, version `1`, with
`encrypted`, `spm_data`, and `exportedAt`; encrypted exports embed the envelope
string verbatim. The importer also accepts a bare current envelope or plaintext
library object, but explicitly rejects the old encrypted schema
([frontend](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:14),
[frontend](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:840),
[frontend](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:886),
[frontend](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:2372)).
Those exported files are durable user data and carry the same legacy obligation
as workflows.

## Historical formats no longer implemented in current source

### AIO and Smart Prompt: schema-only v1 divergence

Before the July 2 shared-package migrations, both packs independently wrote the
same seven-field AES-GCM state envelope now used by `PrivacyEnvelopeCodec`, with
AAD `{original-schema}|1|AES-256-GCM|{keyId}` and a pack-local JSON key file:

- AIO: schema `helto.aio-image-generate`, key
  `comfyui-all-on-one-image-generation-node/config/privacy_key.json`.
- Smart Prompt: schema
  `comfyui-helto-prompts.smart-prompt-manager`, key
  `comfyui-helto-smartprompt/config/privacy_key.json`.

These require no new cryptographic primitive. A codec bound to the original
schema plus the original key can decrypt them. The current AIO and Smart Prompt
registrations fail to contribute those key directories, which is why schema
recognition alone cannot recover the data.

### Utils: prefix and binary codec generations

Utils has a separate legacy lineage:

- Workflow strings are `__HELTO_ENC__:` plus standard-base64 encrypted bytes.
- The earliest selector bytes are `16-byte IV || XOR ciphertext`, where the
  keystream is concatenated HMAC-SHA256 blocks over
  `IV || counter_be32`. They use `config/key.bin` and are unauthenticated.
- Later shared-privacy bytes use `config/privacy_key.bin` (first 32 bytes) and
  one of:
  - `HELTO_PRIV1:` + 16-byte IV + XOR ciphertext + HMAC-SHA256 tag;
  - `HELTO_PRIV2:` + 12-byte nonce + AES-GCM ciphertext, with the magic prefix
    as AAD;
  - `HELTO_PRIV3:` + chunk metadata + chunked AES-GCM, with header and chunk
    index in AAD.
- The old selector decoder tries `privacy_key.bin` first and `key.bin` as a
  fallback. Current `helto-privacy` imports neither because its migration path
  reads only `privacy_key.json`.
- Old private-media tokens are
  `<base64url compact JSON>.<base64url HMAC-SHA256 signature>` under the same
  binary key. They are intentionally short-lived and do not require migration.
- Old queue-manager JSON payloads use
  `HELTO_QUEUE_MANAGER_STATE_V1:<base64 legacy bytes>`; old privacy-enabled
  SQLite rows store the legacy bytes directly.

The unauthenticated earliest format must be strictly gated by the exact prefix,
expected workflow field, and a discovered legacy key; it must never become a
general fallback for arbitrary bytes.

## Minimum removable legacy read obligations

### Required to satisfy saved-workflow compatibility

1. **Current formats remain readable.** If the cutover changes any stored
   representation, keep read-only recognition for current state envelopes under
   all four current schemas. For Director/Utils encrypted artifacts that are
   judged durable, preserve the exact byte schema and purpose bindings listed
   above. New writes must not select these readers.
2. **AIO old schema.** Recognize `helto.aio-image-generate` v1/AES-GCM in every
   AIO workflow location and in `ideogram4_prompt_library.json`; import the AIO
   `config/privacy_key.json`; decrypt with the old schema AAD; normalize the
   plaintext through current AIO state handling; write only the cutover format
   on the next successful save.
3. **Smart Prompt old schema.** Recognize
   `comfyui-helto-prompts.smart-prompt-manager` v1/AES-GCM in `spm_data`, bare
   envelope imports, and version-1 export packages; import the Smart Prompt
   `config/privacy_key.json`; decrypt with the old schema AAD; normalize through
   current Smart Prompt state handling; write only the cutover format on save or
   re-export.
4. **Utils workflow prefix and referenced masks.** Recognize
   `__HELTO_ENC__:` only for the six logical fields across their seven
   enumerated workflow storage locations (selector's three fields, Prompt
   Enhancer's two fields, and Privacy Show Any's mirrored widget/property).
   Decode the exact historical byte generations with `privacy_key.bin` and
   `key.bin`, then immediately route plaintext through the field's existing
   parser. Use the same isolated byte reader for referenced historical
   selector `.png.enc` mask files and rewrite them after successful read.
   Never silently turn a failed decode into an empty value or missing mask.
5. **Director continuity.** Preserve `helto.timeline-director` v1/AES-GCM reads
   for workflow timelines and `director_library.json`, plus import of Director's
   JSON legacy key. No second Director legacy schema is needed.
6. **Historical key ids remain decryptable.** The shared keystore must retain
   every imported and rotated-out DEK until the compatibility window closes;
   otherwise correct schema dispatch still cannot decrypt old data.

### Persisted pack state worth one-time import

These are not workflow files, but silently discarding them would lose user
state:

- Utils queue manager: read old privacy-enabled SQLite BLOBs and old
  `HELTO_QUEUE_MANAGER_STATE_V1:` JSON once, then rewrite the current/cutover
  row and retire the old form.
- Utils selector masks referenced by saved workflows: read historical
  `.png.enc` bytes once and rewrite them with the cutover byte contract.
- AIO and Director private library entries: use the same envelope adapters as
  workflow data.
- Smart Prompt user export files: use the same adapter as `spm_data`.
- Utils plaintext `hf_token`: keep the already-existing one-time rewrite.

### No legacy read obligation

- Encrypted thumbnails, waveform caches, temporary previews, video replay
  bundles, and segment spills can be deleted and regenerated. Their readers
  should fail closed, and migration may proactively purge old files. Selector
  masks are excluded because they contain user edits referenced by workflows.
- Expired or pre-cutover private-media bearer tokens should not be kept valid.
- `privacy_session.json` is runtime cache state and may be recreated by unlock.
- Unknown schema/algorithm combinations and malformed encrypted-looking data
  remain recovery/reset cases; inventing a decoder for them would weaken the
  stored-data boundary.

## Stored-data compatibility versus source/API compatibility

The coordinated cutover may freely change Python imports, JavaScript exports,
route paths, response shapes, registration calls, consumer adapters, and in-memory
state. None of those are compatibility constraints.

The compatibility boundary is the bytes already persisted: workflow widget and
property values, the two private libraries, Smart Prompt export files, and
valuable pack state such as the queue manager. A removable reader should be
isolated by exact format/schema, never used for writes, and observable so the
project can tell when legacy data was read and re-saved. Removal becomes safe
only after the user's workflow/library/export inventory has been checked and
re-saved and no legacy reads are observed during the agreed window.

## Fixture gap for implementation planning

Current consumer tests mostly prove that old schemas and prefixes are rejected;
they do not preserve genuine ciphertext produced by every historical writer.
Before implementation, the acceptance contract must require committed golden
fixtures generated from the cited pre-migration revisions for AIO, Smart
Prompt, every Utils workflow/byte generation, legacy queue state, and a
referenced selector mask. Those fixtures must decrypt through legacy readers
and re-save through only the cutover writer. Mutating a current envelope's
`schema` field is not equivalent because the schema is authenticated in AAD.

## Historical source provenance

The historical claims above are reproducible from the local repositories:

```text
cd /home/thhel/git/comfyui-all-on-one-image-generation-node
git show c925b24fc7028f09f07b6d685dcd3857db1eb399^:services/privacy.py

cd /home/thhel/git/comfyui-helto-smartprompt
git show ef9c9be999ac34998b669f539dbc5ece3f0ff8db^:privacy.py

cd /home/thhel/git/comfyui-utils
git show 964fceadf2facd3a2c0d0a18ea338ad2f8bf2453^:helto_selector_backend/crypto.py
git show 964fceadf2facd3a2c0d0a18ea338ad2f8bf2453^:shared/privacy.py
git show 964fceadf2facd3a2c0d0a18ea338ad2f8bf2453^:shared/queue_manager_store.py
```
