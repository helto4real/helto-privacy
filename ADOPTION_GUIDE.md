# Adopting `helto-privacy` in a Helto node pack

Instructions for an agent migrating a ComfyUI node pack from a local
plaintext key file (`config/privacy_key.json`) to this shared package.
Migration is part of adoption — do not treat them as separate projects.

Read `README.md` first for the file contract. The finished reference
implementation is `~/git/comfyui-helto-director` (commit `dd669d9`,
"Use shared privacy package and refresh media tokens"); when in doubt, copy
its patterns rather than inventing new ones.

## What adoption gives the pack

- Keys live password-protected in one keystore
  (`~/.config/helto/privacy_keystore.json`) shared by every Helto pack.
- One unlock covers all packs: the unlocked-session cache in
  `$XDG_RUNTIME_DIR/helto/` is machine-wide per user, and the browser token
  (localStorage + cookie `helto_privacy_token`) is per ComfyUI origin. If the
  user unlocked via the Timeline Director UI, your pack is already unlocked —
  server side and browser side.
- Old envelopes stay readable: the pack's legacy key is imported into the
  keystore as a decrypt-only entry.

## Invariants you must not break

The user has a live keystore with real encrypted data. These are frozen:

| Thing | Value |
|---|---|
| Keystore path / env override | `~/.config/helto/privacy_keystore.json` / `HELTO_PRIVACY_KEYSTORE` |
| Session dir env override | `HELTO_PRIVACY_SESSION_DIR` |
| Token header / cookie | `X-Helto-Privacy-Token` / `helto_privacy_token` |
| Error prefixes (frontends match on them) | `PRIVACY_LOCKED`, `PRIVACY_TOKEN_REQUIRED`, `PRIVACY_KEYSTORE_UNINITIALIZED`, `PRIVACY_KEYSTORE_EXISTS`, `PRIVACY_PASSWORD_INVALID`, `PRIVACY_PASSWORD_TOO_SHORT`, `PRIVACY_KEYSTORE_INVALID` |
| **The pack's own envelope schema string** | whatever it uses today — never change it, or the pack's existing envelopes become undecryptable |

## Step 0 — Survey the target pack

Before changing anything, map the existing privacy surface:

```
grep -rn "privacy_key\|AESGCM\|AES-256-GCM\|encrypt_state\|decrypt_state\|encrypted.*schema" --include="*.py" .
grep -rn "privacy" web/ routes/ 2>/dev/null
```

Record: (a) the envelope **schema string(s)** it writes into payloads,
(b) where its key file lives, (c) every caller of its encrypt/decrypt
functions, (d) which HTTP routes touch privacy data, (e) how the frontend
detects encrypted payloads and errors.

Then pick your case:

- **Case A — the pack uses the Helto envelope format** (JSON envelopes with
  `schema` / `keyId` / `nonce` / `ciphertext`, AAD =
  `"{schema}|{version}|{algorithm}|{keyId}"`, byte schema = `"{schema}.bytes"`).
  All packs derived from the Director's `shared/privacy.py` are Case A.
  Use `PrivacyEnvelopeCodec` — the rest of this guide.
- **Case B — a different envelope format.** Do NOT force the codec onto it
  (you would corrupt compatibility with the pack's existing data). Keep the
  pack's own envelope code and only replace its *key source* with the
  keystore primitives (`primary_session_key()`, `session_key_for(key_id)`,
  plus `initialize_keystore_with_legacy_migration` for its key file). The
  route/frontend/test steps below still apply.

## Step 1 — Dependency

Add to the pack's `requirements.txt` (create it if missing):

```
helto-privacy @ git+https://github.com/helto4real/helto-privacy.git@<coordinated-suite-tag>
cryptography>=42.0
```

Keep the explicit `cryptography` line — some ComfyUI installs resolve
requirements without full dependency resolution. Mirror both in
`pyproject.toml` `[project] dependencies` if the pack declares any.

## Step 2 — Replace the crypto internals, keep the pack's API

Create (or rewrite) the pack's privacy module as a thin wrapper around the
codec, preserving whatever function names the rest of the pack already calls
(`encrypt_state`, `decrypt_state`, `is_encrypted_payload`, `crypto_status`,
…) so callers and tests need no changes:

```python
from pathlib import Path
from helto_privacy import PrivacyEnvelopeCodec, PrivacyError  # noqa: F401
from helto_privacy import envelope as _envelope
from helto_privacy import initialize_keystore_with_legacy_migration

_SCHEMA = "helto.<this-pack's-existing-schema>"   # from Step 0 — DO NOT invent a new one
_codec = PrivacyEnvelopeCodec(_SCHEMA)


def config_dir() -> Path:
    # Anchor to THIS pack, never the process CWD (see warning below).
    return Path(__file__).resolve().parents[1] / "config"


def encrypt_state(state, base_dir=None):
    return _codec.encrypt_state(state, base_dir=base_dir)

def decrypt_state(payload, base_dir=None):
    return _codec.decrypt_state(payload, base_dir=base_dir)

# ...same one-liners for encrypt_bytes/decrypt_bytes/is_encrypted_payload/crypto_status...

def initialize_privacy_keystore(password: str):
    return initialize_keystore_with_legacy_migration(password, config_dir())
```

> **Warning — CWD footgun.** The package's own legacy fallback
> (`helto_privacy.envelope.key_path(None)`) resolves to
> `Path.cwd()/config`, which under ComfyUI is the *ComfyUI* directory, not
> the pack. Never rely on it. Always route legacy-file access through the
> pack-anchored `config_dir()` above: pass it to
> `initialize_keystore_with_legacy_migration`, and if the pack needs a
> legacy fallback for envelopes while no keystore exists, pass
> `base_dir=config_dir()` explicitly at those call sites. Once the user has
> a keystore (this user does), `base_dir=None` resolves to the keystore and
> the fallback never triggers.

If the pack loads under two module namespaces (ComfyUI loader packages under
a runtime name, like the Director's `comfyui_helto_director_runtime.*`),
both copies share state automatically because all state lives in files —
but keep that in mind when tests monkeypatch module attributes (see Step 5).

## Step 3 — Register the shared UI (this also handles migration)

In the pack's `__init__.py`, right where routes are registered today:

```python
from helto_privacy import register_helto_privacy_ui

register_helto_privacy_ui(legacy_key_dir=_PACKAGE_ROOT / "config")
```

This one call (idempotent across packs — the first pack in the ComfyUI
process wins, later calls only contribute their legacy dir) registers the
canonical endpoints `/helto_privacy/status`, `/unlock`, `/lock`,
`/keystore/init`, `/keystore/change_password`, profile mode status/transition
routes, and serves the shared browser client and UI at
`/helto_privacy/ui/privacy.js`.

**Migration is automatic.** Because the pack registered its legacy key
directory, its `privacy_key.json` is imported as a decrypt-only key at the
next keystore init *or unlock* — the only moments the password is in hand —
and renamed to `privacy_key.json.migrated` (a recoverable backup: never
delete it programmatically, never commit it; gitignore `config/*.json` and
`config/*.json.migrated`). The pack does NOT need its own "Set password"
action, unlock endpoints, or migration branching. The shared UI maps typed
failures such as `PRIVACY_PASSWORD_INVALID` to fixed, product-data-free text.

(`initialize_keystore_with_legacy_migration(password, legacy_dir)` still
exists for non-ComfyUI callers and scripted migration.)

## Step 4 — Gate routes, import the shared frontend

**Dispatch every privacy route through the bound pack authorization handle.**
Any endpoint that decrypts, encrypts, saves, queues, executes, or serves
privacy-mode content must name its scope and operation:

```python
from helto_privacy import PrivacyRouteError

@routes.post(f"{PREFIX}/decrypt")
async def post_decrypt(request):
    async def decrypt(authorization):
        return await product_service.decrypt(authorization)

    try:
        return await privacy.authorization.dispatch(
            request,
            "declared-scope-id",
            "state.decrypt",
            decrypt,
        )
    except PrivacyRouteError as error:
        return web.json_response(
            {"ok": False, "error": error.code},
            status=error.http_status,
        )
```

Dispatch requires an active exact suite and an initialized, unlocked keystore;
absence is never authorization. It accepts the current token from the header
**or** cookie, refuses scopes with incomplete transitions, and gives product
code only an opaque authorization capability. The cookie exists because
`<img>`/media elements cannot send custom headers; dispatch privacy-mode
thumbnail/preview routes too, not just JSON endpoints. The old token guards are
compatibility wrappers and now fail closed when no keystore exists.

**Frontend: connect the exact attested profile — do not copy request, session,
mode, or dialog code into the pack.**

```js
const suite = await fetch("/helto_privacy/status", { cache: "no-store" })
  .then((response) => response.json());
if (suite.suiteStatus !== "active" || !suite.suiteManifestDigest) {
  throw new Error("Helto privacy installation is blocked");
}
const { connectPrivacyPack } = await import(
  `/helto_privacy/ui/privacy_profile/${suite.suiteManifestDigest}.js`
);
const privacy = await connectPrivacyPack({
  app,
  packId: PROFILE_ID,
  profileFingerprint: PROFILE_FINGERPRINT,
  suiteManifestDigest: suite.suiteManifestDigest,
  adapters: browserAdapters,
});

await privacy.records(RECORD_RESOURCE_ID).invoke(
  "record.use",
  { recordId: opaqueRecordId },
);
```

Every declared browser adapter must implement
`onPrivacySessionChange({ state, revision })` and clear stale runtime state on
lock/revision changes. The snapshot contains no token. The request client owns
header/cookie restoration and one bounded unlock retry. Consumers call only
operations declared for the selected typed resource handle; there is no generic
authorization request port, arbitrary URL, or caller-selected HTTP method.
Consumers have no token
getter and must not inspect token storage or construct token-bearing requests. The shared
surface mounts once across all connected packs and owns setup, unlock, password
change, lock, readiness, recovery, mode status, confirmation, and transitions.
Missing/stale shared code is a blocked installation, not a local fallback.

For concealed product UI, reuse the shared Helto classes
`.helto-hidden-collapsed`, `.helto-text-masked`, `.is-private`,
`.helto-private-text`, and `.helto-private-label`. Do not weaken their opaque
background, transparent glyph/caret/placeholder, or pointer-blocking rules.
Call `concealPrivacyContent(element, { mode })` before locked content can be
observed; it destructively removes values, labels, media URLs, and subtree text
from the DOM and accessibility tree. After authorization, call
`preparePrivacyReveal(element)` and re-render from the authorized result. No
hover or focus state restores content, and the helper retains no plaintext.

## Step 5 — Privacy Recovery

Register privacy recovery descriptors from the pack frontend after importing
the shared module. The shared package owns scanning the loaded graph, showing
the recovery dialog, applying safe resets/encryption, and marking the graph
dirty. The pack only describes its nodes and sensitive controls:

```js
const privacy = await import("/helto_privacy/ui/privacy.js");

privacy.registerPrivacyRecoveryDescriptors("comfyui-utils", [
  {
    nodeType: "HeltoImageSelector",
    label: "Helto Multi-Image Selector",
    schema: "helto.comfyui-utils",
    privacy: { property: "privacyMode", default: true },
    fields: [
      { kind: "widget", name: "selected_images", defaultValue: "[]", sensitive: true, resetOnlyForLegacy: true },
      { kind: "widget", name: "edited_masks", defaultValue: "{}", sensitive: true, resetOnlyForLegacy: true },
      { kind: "widget", name: "edited_bboxes", defaultValue: "{}", sensitive: true, resetOnlyForLegacy: true },
    ],
    reencrypt: async (plaintext) => selectorApi.encrypt(plaintext),
  },
]);
```

Descriptors can match by `nodeType`/`nodeTypes` or a custom `match(node)`
function. Fields may target `{ kind: "widget", name }` or
`{ kind: "property", name }`, with optional `schema`, `schemas`,
`reencrypt`, `runtimeProperty`, `runtimeProperties`, and
`clearRuntimeState(node, context)`. Defaults are used for reset recovery;
`resetOnlyForLegacy: true` limits reset actions to legacy or incompatible
encrypted values for that field. Non-sensitive operational settings are left
untouched.

Use the shared dialog for manual or automatic recovery entry points:

```js
await privacy.showPrivacyRecoveryDialog({ mode: "manual" });
```

The dialog reports issue counts and node/control labels only. It must never
show plaintext field contents. The scanner handles:

- legacy `__HELTO_ENC__:` values
- encrypted-looking JSON that does not match the registered schema
- plaintext sensitive values while privacy is enabled
- missing privacy defaults on privacy-capable nodes
- locked/uninitialized encryption during re-encrypt recovery

Old legacy values without a pack-supplied migration adapter are reset-only.
Do not try to decrypt or display them in the browser.

For recovery-only re-encryption, replace fail-open helpers with the shared
fail-closed helper.
If privacy is enabled and encryption fails, this helper opens the shared
unlock/setup dialog, retries once, then throws a privacy error. Do not catch
that error and write plaintext.

```js
selectedImagesWidget.serializeValue = async () => {
  const plaintext = JSON.stringify(node.selectedPaths || []);
  return privacy.ensureEncryptedPrivacyValue({
    owner: node,
    fieldName: "selected_images",
    value: plaintext,
    privacyMode: node.properties?.privacyMode !== false,
    schema: "helto.comfyui-utils",
    defaultValue: "[]",
    encrypt: async (value) => selectorApi.encrypt(value),
  });
};
```

When privacy is disabled, `ensureEncryptedPrivacyValue(...)` returns the
plaintext serialization and clears its runtime memo. When privacy is enabled,
it accepts only a valid envelope for the registered schema; otherwise it
blocks with `PRIVACY_ENCRYPTION_FAILED` or
`PRIVACY_ENCRYPTION_UNAVAILABLE`.

Do not use this recovery helper as the normal save/queue implementation after
the coordinated cutover. Normal serialization uses the snapshot coordinator
below so every projection shares one generation and envelope.

## Step 6 — Bind privacy snapshots and serialization

Each protected-field browser adapter implements the full attested contract,
including these snapshot methods:

```js
const browserAdapters = {
  "prompt-state-ui": {
    normalize(node) {
      return normalizeProductState(node.runtimeState);
    },
    readProtected(node) {
      return node.widgets.find((widget) => widget.name === "private_state").value;
    },
    writeProtected(node, envelope) {
      writeExactSerializedWidgetValue(node, "private_state", envelope);
    },
    // apply, clear, onPrivacySessionChange, and reconciliation methods...
  },
};
```

`readProtected` must return the exact serialized ciphertext. `writeProtected`
must update the live widget plus every ComfyUI serialized representation used
by workflow and prompt projections. It must never write plaintext.

After every product edit, mark the declared field generation. Do not encrypt
inside a widget serializer:

```js
const workflow = privacy.workflow("prompt-library");
workflow.markEdited(node, "private-state");
```

The shared runtime eagerly prepares that generation. Async save, export,
queue-manager, replay, or direct API entry points wrap the complete operation
in `await workflow.runWithSnapshot(reason, async ({ graphToPrompt }) => {
... })`; this pins one transaction across every projection in the callback and
serializes overlapping operations. Use the callback's scoped `graphToPrompt`
invoker when that integration needs prompt generation. Do not call the wrapped
`app.graphToPrompt()` from inside the callback: ordinary app calls intentionally
queue as separate transactions. `workflow.settle(reason)` prepares a
transaction for an immediately following synchronous serializer. Synchronous
serialization calls
`workflow.requireSettled("serialize")` and aborts if the generation is not
already settled. Supported reasons include `manual-save`,
`autosave`, `export`, `graph-to-prompt`, `direct-queue`, `queue-manager`,
`partial-execution`, `subgraph`, and `replay`.

Use `workflow.workflowProjection(node, fieldId)` only for protected workflow
storage. `workflow.executionProjection(...)` rejects locked, failed, or
unsupported state. A successful settlement pins one immutable runtime
transaction; projections reject if the generation changes outside an active
barrier, while graph-to-prompt keeps its captured transaction pinned across
both ComfyUI passes. Execution-bearing reasons fail before queue logic when any
private field is locked or failed. Never catch a `PRIVACY_SNAPSHOT_*` error and
substitute an old envelope, empty/default state, or plaintext.

## Step 7 — Move private execution behind grants

For every product input that affects a private result, set `execution=True` on
its `ProtectedField` and declare one `SemanticExecutionProjection`. Bind an
execution resource to two server adapters:

```python
SemanticExecutionProjection(
    "generate-image",
    "generation",
    "prompt-state",
    "generation-projection",
    "generation-dispatch",
)
```

The projection adapter implements `project(fields, declaration)` and returns
only canonical JSON product semantics. The dispatch adapter implements
`dispatch(value, context, cancellation)`. It calls
`cancellation.checkpoint()` before any private effect or result publication and
at safe boundaries during long work. Do not log, persist, retain, or attach the
decrypted `fields` or projected `value` outside this call. Mutable values are
cleared after synchronous completion or after an async dispatcher finishes.

Inside the snapshot boundary, replace private executable inputs with one fresh
reference:

```js
const prepared = await privacy.workflow("prompt-state").runWithSnapshot(
  "direct-queue",
  () => privacy.execution("generation").prepare(node, "generate-image"),
);
queueInput.private_execution = prepared.reference;
```

`prepare()` rejects calls outside an active execution-bearing transaction. Do
not call the canonical prepare route directly; it is the fixed internal
transport for the typed browser handle, not a second queue path.

The backend product boundary calls
`resolved = privacy.execution("generation").dispatch(reference, context)` and
uses `resolved.value`. A reference is single-use and current-session-only.
Preparation remains ciphertext-only; decryption, semantic projection, and the
opaque identity are created at dispatch immediately before product logic.
Missing metadata, lock, unsupported state, decrypt failure, tampering, profile
conflict, or replay must abort product logic. Never catch a
`PRIVACY_EXECUTION_*` error to run with empty/default, stale, or public plaintext
state.

Use `cache_store(resolved.cache_identity, resolved.value)` and `cache_load(...)`
only for private results that may live in process RAM. A later fresh grant for
the same semantics consumes that RAM entry before product dispatch. The
identity is opaque and session-keyed; it is not a persistent cache key. Lock,
key rotation, session replacement, process restart, or profile invalidation
clears the partition and revokes pending grants. Public-mode execution remains
on the consumer's normal public path.

Delete the pack's local token resolver, unkeyed semantic hash, persistent
private cache, decrypt-to-default fallback, and replay reuse. The shared route,
browser execution handle, resolver, cancellation signal, and RAM cache are the
only private execution path.

## Step 8 — Move private record libraries behind minimal shells

Declare each private record kind on its typed record resource. Mint IDs with
`generate_private_record_id()`—never names, UUIDs from consumer data, paths,
timestamps, or content-derived hashes. A reveal-capable declaration gives each
fixed operation its own explicit output-field allowlist:

```python
RecordDeclaration(
    "prompt-record",
    "library",
    "main",
    "helto.example.prompt-record.v1",
    "prompt-store",
    projections=(
        RecordRevealProjection("use", ("prompt",)),
        RecordRevealProjection("details", ("summary",)),
    ),
)
```

The store implements `list_ids`, `read_protected`, `write_protected`, and
`delete`, plus the mode-transition methods. Reveal-capable stores also
implement `project(value, operation)`. `list_ids` must not read or decrypt a
record. `project` returns canonical JSON and every returned top-level field must
appear in that operation's `RecordRevealProjection.safe_fields`; omission means
sensitive. Do not put names,
descriptions, tags, timestamps, counts, paths, filenames, hashes, media facts,
or debug values into a locked listing.

Replace the pack's record routes with the typed browser handle:

```js
const records = privacy.records("library");
const shells = await records.list("prompt-record");
const revealed = await records.reveal("prompt-record", opaqueId, "use");
await records.delete("prompt-record", opaqueId); // Shared Helto confirmation modal.
```

The shared handle rebuilds locked shells as `{ id, kind, private: true,
label: "Private record" }` and discards every extra field. It supports only
declared `use`, `preview`, or `details` reveals. Delete and replacement work
while locked after shared confirmation; replacement accepts a protected current
envelope only. Do not register a generic `ProtectedOperation` on a record
resource or retain local duplicate, merge, edit, preview-metadata, record-token,
or decrypt-to-default routes.

Use `private_record_response_headers()` for private media/record responses and
`safe_record_diagnostic()` for coarse diagnostics. Never include an original
filename, path, prompt, name, tag, exception string, token, workflow value, or
record payload in logs, errors, filenames, or diagnostics. Errors expose only a
stable `PRIVACY_RECORD_*` code and fresh `hp-record-*` correlation ID.

## Step 9 — Tests (non-negotiable hygiene)

A test run once minted a real key file inside a repo's `config/` and it
nearly got committed. Every adopting pack must add an **autouse** fixture
(suite-wide `conftest.py`):

```python
import helto_privacy.keystore as hp_keystore
import <pack>.privacy as pack_privacy

@pytest.fixture(autouse=True)
def isolated_privacy(tmp_path_factory, monkeypatch):
    root = tmp_path_factory.mktemp("privacy")
    monkeypatch.setenv(hp_keystore.KEYSTORE_ENV, str(root / "privacy_keystore.json"))
    monkeypatch.setenv(hp_keystore.SESSION_DIR_ENV, str(root / "session"))
    monkeypatch.setattr(pack_privacy, "config_dir", lambda: root / "legacy_config")
```

Rules:

- Tests never read/write `~/.config/helto`, the real `XDG_RUNTIME_DIR`, or
  the repo's `config/`. After running the suite, verify:
  `git status --short` shows nothing under `config/`.
- Speed: `monkeypatch.setattr(hp_keystore, "SCRYPT_N", 2**12)` in
  keystore-heavy tests (unlock reads KDF params from the file, so this is
  safe).
- Port the behavior tests from
  `~/git/comfyui-helto-director/tests/timeline/test_privacy_keystore.py`:
  lifecycle, wrong password, legacy import + `.migrated` rename, old-envelope
  decrypt after migration, locked errors, token gating.
- Add one compat test: a hardcoded envelope produced by the pack's OLD code
  (generate it once with a throwaway key embedded in the test) must decrypt
  through the new wrapper.
- Never `git add -A` in these repos — key-adjacent files appear during
  manual testing. Stage paths explicitly and check `git log -p` for anything
  resembling `"key"`/`"wrapped_key"` values before pushing.

Execution adoptions also test protected-reference tampering, locked and failed
decrypt, exact execution-field membership, semantic identity stability across
randomized envelopes, identity change after unlock/rotation, single-use grants,
active cancellation, async plaintext cleanup, and RAM-cache invalidation.

Record adoptions also test non-decrypting locked lists, four-field shells,
opaque-ID rejection, authorization before read, allowlist rejection, decrypt
failure, mutable plaintext cleanup, locked confirmed delete/replacement,
one-use confirmation, generic filenames/headers, correlation-only errors, and
browser-side removal of injected names, paths, timestamps, and labels.

## Step 10 — Validation checklist

- [ ] Full pack test suite green, plus the new privacy tests.
- [ ] Suite leaves no files in `config/`, `~/.config/helto`, or the real
      runtime dir.
- [ ] With the package **uninstalled**, the pack either still works via its
      previous code path or fails with a readable install hint — decide and
      document (the Director keeps a vendored fallback; simpler packs may
      hard-require the dependency).
- [ ] Manual smoke test against the real ComfyUI: with the user's keystore
      unlocked, the pack encrypts with the shared primary key (envelope
      `keyId` matches `keystore_status()`), decrypts its pre-migration
      envelopes, and returns 401 + `PRIVACY_TOKEN_REQUIRED` on privacy routes
      without the token.
- [ ] Private queue payloads contain a protected reference but no semantic
      plaintext or pre-dispatch identity. Successful backend dispatch returns
      an opaque `hp-exec-v1:` identity; product logic is not invoked for a
      locked, tampered, failed, or replayed reference.
- [ ] Locking or rotating during a disposable synthetic private run requests
      cancellation at the next safe checkpoint and removes the private RAM
      cache. No external or persistent cache receives the result.
- [ ] Locked record listings call only `list_ids` and expose exactly opaque ID,
      kind, `private: true`, and `Private record`; reveal failures do not invoke
      product projection, while confirmed delete/replacement remain usable.
- [ ] Record responses and rendered shells contain none of the synthetic name,
      path, filename, timestamp, tag, hash, diagnostic, or exception canaries.
- [ ] `privacy_key.json` is gone (renamed `.migrated`) and gitignored.
- [ ] Commit style: single-line imperative subject, matching the pack's
      history.

## Do NOT

- Change the pack's envelope schema string or any AAD format.
- Delete key files (`.migrated` backups stay until the user removes them).
- Copy the keystore implementation into the pack — depend on the package;
  version bumps happen here, once.
- Log passwords, tokens, or key material anywhere, including test output.
