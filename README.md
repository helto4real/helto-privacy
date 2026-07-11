# helto-privacy

Shared privacy authority, transitions, keystore, envelopes, and protected-route
dispatch for Helto ComfyUI node packs.

## Atomic Privacy Profiles

Consumer packs declare product facts once and bind every required server
adapter atomically. The fixed contract returns typed handles and blocks partial
or conflicting installations; privacy policy, codecs, keys, and credentials
are not adapter seams.

```python
from helto_privacy import (
    AdapterSlot,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ResourceKind,
    install,
)

profile = PrivacyProfile(
    id="helto.example",
    distribution="comfyui-helto-example",
    resources=(
        ProfileResource(
            "privacy-mode",
            ResourceKind.MODE,
            adapter_slots=("mode-source", "mode-editor"),
        ),
    ),
    server_adapters=(
        AdapterSlot(
            "mode-source",
            ResourceKind.MODE,
            "privacy-mode",
        ),
    ),
    browser_adapters=(
        AdapterSlot(
            "mode-editor",
            ResourceKind.MODE,
            "privacy-mode",
            node_types=("HeltoExample",),
        ),
    ),
    scopes=(
        PrivacyScope(
            "example",
            "privacy-mode",
            "mode-source",
            mode_editor_adapter="mode-editor",
        ),
    ),
)

privacy = install(profile, {"mode-source": product_adapter})
mode = privacy.mode("privacy-mode")
privacy.readiness.require_ready()
privacy.authorization.require_ready()  # Also requires an active exact suite.
```

The shared browser module is keyed by the exact active suite digest and uses
the same profile fingerprint:

```javascript
const status = await fetch("/helto_privacy/status", { cache: "no-store" })
  .then((response) => response.json());
if (!status.ok || status.suiteStatus !== "active" || !status.suiteManifestDigest) {
  throw new Error("Helto privacy suite is not active");
}
const {
  connectPrivacyPack,
  PRIVACY_CONTRACT_V2,
} = await import(
  `/helto_privacy/ui/privacy_profile/${status.suiteManifestDigest}.js`
);

const privacy = await connectPrivacyPack({
  app,
  packId: "helto.example",
  contract: PRIVACY_CONTRACT_V2,
  profileFingerprint,
  suiteManifestDigest: status.suiteManifestDigest,
  adapters: { "mode-editor": editorAdapter },
})
```

`connectPrivacyPack` attests the server declaration before registering the one
shared ComfyUI extension. It reconciles existing, newly created, and loaded
nodes and remains blocked if fingerprints, adapter slots, or readiness drift.
Server and browser method contracts are derived from the typed declarations;
wrong-side, unused, missing, or method-incomplete adapters block atomically.
`profile.server_adapter_contracts` and `profile.browser_adapter_contracts`
provide the exact fixed method sets an adoption must implement.

Every browser adapter implements `onPrivacySessionChange(snapshot)`. The
snapshot contains only `state` and a monotonic `revision`; it never contains a
token. The shared surface mounts once regardless of pack load order and owns
setup, unlock, password change, lock, readiness, recovery, and mode controls.
Consumers invoke only operations declared for a typed resource handle instead
of using a generic command port or reading and attaching the token themselves:

```javascript
await privacy.records("library").invoke(
  "record.use",
  { recordId: opaqueRecordId },
);

privacy.session.subscribe(({ state, revision }) => {
  // Clear consumer runtime state on lock/revision change. No token is exposed.
});

const mode = await privacy.mode("privacy-mode").resolve("example");
```

The profile declaration fixes each operation's same-origin route and HTTP
method; consumers provide only its product payload. The private request
transport restores header/cookie authentication, retries one
setup/unlock flow at most once, rejects absolute or query-bearing targets, and
returns sanitized typed failures. A missing route is retried on the next call;
it is never memoized as permanently unavailable.

`concealPrivacyContent(element, { mode })` destructively removes locked values,
labels, media URLs, and subtree text from both DOM and accessibility exposure.
`preparePrivacyReveal(element)` only removes the concealment shell; callers
must populate content again from an authorized result. Hover and focus never
restore retained plaintext because the shared UI does not retain any.

## Server-authoritative Mode and Route Dispatch

Every scope has a three-state declaration (`inherit`, `private`, or `public`),
but only the server resolves its effective mode. Missing, malformed, and
inherited declarations default private. An explicit public declaration applies
only when no global, upstream, parent, record, artifact, execution, request, or
current-state floor requires privacy.

```python
from helto_privacy import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModeEvidence,
    ModeFacts,
)

resolution = mode.resolve(
    "example",
    ModeFacts(
        upstream=(
            ModeEvidence("source-image", EffectivePrivacyMode.PRIVATE),
        ),
    ),
)
assert resolution.effective is EffectivePrivacyMode.PRIVATE
```

Mode changes are authorized transactions. Every state, record, and artifact
adapter in the scope prepares first; shared policy then commits domain adapters
in deterministic order and the mode source last. Any failure rolls back all
attempted participants, preserves the prior established mode, and records a
durable blocked transition. Save, queue, serving, and execution routes for that
scope remain blocked across process restarts until the user explicitly restores
the prior declaration or retries the same target. A new persistent privacy floor
or an out-of-band declaration change also enters this blocked state; the server
keeps reporting the prior established protection until the registered product
surfaces have completed their rewrite. Request-only strengthening remains scoped
to that operation.

Adapters implement these product transformations; they never receive keys,
tokens, or policy hooks:

```python
from helto_privacy import ModeTransitionContext

def prepare_mode_transition(context: ModeTransitionContext): ...

def commit_mode_transition(scope_id, transition_id): ...
def rollback_mode_transition(scope_id, transition_id): ...  # idempotent
```

Protected routes use the bound authorization handle. It verifies exact-suite
readiness, requires an initialized and unlocked keystore plus the current
header/cookie token, checks durable transition state, and passes only an opaque
pack- and operation-bound capability into product code:

```python
async def post_use_record(request):
    async def use_record(authorization):
        return await product_service.use_record(authorization)

    return await privacy.authorization.dispatch(
        request,
        "example",
        "record.use",
        use_record,
    )
```

Use `privacy.authorization.authorize_request(request, "mode.transition")` for
protection changes. After showing the shared declassification warning and
receiving explicit confirmation, the caller must add
`X-Helto-Privacy-Declassification: confirmed` and call
`privacy.authorization.authorize_declassification(request, scope_id, target)`.
Its capability is session-, scope-, and target-bound and is consumed by one
private-to-public attempt. A missing keystore is never authorization. All
authorization, dispatch, mode-state, and transition failures are typed and
product-data-free.

## Exact Suite Verification and Activation

The five coordinated repositories are one privacy suite. Release tooling signs
an immutable `SuiteManifest` that binds exact source revisions, artifacts and
hashes, all four profile fingerprints, supported environment tuples,
acceptance evidence, the previous suite, and its rollback class. A separate
signed promotion moves that unchanged candidate from `cutover-pending` to
`ready`.

An installation must then measure an exact `InstalledSuiteInventory`. No
version compatibility is inferred: missing components are `incomplete`, any
identity or environment difference is `mismatch`, and competing declarations
are `conflict`. An exact promoted installation becomes
`activation-required`; privacy-bearing operations remain blocked until an
authorized activation is signed for both the manifest digest and measured
inventory digest.

Production callers use `SuiteInstallation.verify_installed(...)`, which hashes
the five immutable artifact files and reads profile fingerprints and embedded
suite declarations from the live process registries. The loaded browser module
posts its observed manifest digest to the canonical attestation route, and that
server-recorded value is included in verification. Callers do not construct or
assert their own inventory. The interpreter identity is measured by
`measure_runtime_environment(...)`; the ComfyUI backend/frontend identities and
renderer come from the host installation probe.

Activation does not decrypt product data. It atomically records the signed
authorization and the pre-activation snapshot digest as the rollback boundary,
then changes the installation to `active`. The record remains the rollback
boundary, but activation is process-scoped: every new ComfyUI process verifies
the record and still re-enters `activation-required`. This prevents a crashed
or storage-failed blocked process from replaying an old activation.

The activation inventory digest also binds a measured installation generation
derived from the five artifact files. Reinstalling or repairing exact bytes
therefore still requires a new signed activation instead of replaying the old
record.

If an active installation later becomes incomplete, mismatched, or conflicting,
the activation record is atomically quarantined: its rollback boundary is
retained, but it is no longer eligible to restore active state. The current
process remains latched blocked even after an in-process repair. Recovery must
use `cui-stop`, exact offline repair, `cui-start`, a full browser reload, and a
new explicit activation; hot repair never restores writers.

Maintenance code receives only `MaintenanceCapability`: signed manifest and
generic readiness, structurally filtered envelope headers, opaque key
availability, and encrypted byte copying. The interface deliberately has no
decrypt, reveal, key-export, or live-payload validation operation.

## File Contract

The keystore format is intentionally stable:

- Keystore file: `~/.config/helto/privacy_keystore.json`, or
  `HELTO_PRIVACY_KEYSTORE`.
- Session file: `$XDG_RUNTIME_DIR/helto/privacy_session.json`, or
  `HELTO_PRIVACY_SESSION_DIR`.
- Mode authority ledger: beside the keystore as `privacy_mode_state.json`, or
  `HELTO_PRIVACY_MODE_STATE`. It stores only modes, declaration/floor IDs,
  transition IDs/status, and adapter IDs; it never stores product values,
  credentials, keys, or decrypted content.
- Keystore schema: `helto.privacy-keystore`, version `1`.
- Key-wrap AAD: `helto.privacy-keystore|1|<keyId>`.
- Files are written through a temporary file and atomic replace; keystore and
  session files are mode `0600`, and directories are mode `0700` where the
  platform allows it.
- Route token names are `X-Helto-Privacy-Token` and `helto_privacy_token`.
  Confirmed declassification requests additionally use
  `X-Helto-Privacy-Declassification: confirmed`.

The only runtime dependency is `cryptography>=42.0`. The package does not
import ComfyUI.

## Quickstart

```python
from helto_privacy import PrivacyEnvelopeCodec

codec = PrivacyEnvelopeCodec("helto.my-pack")
envelope = codec.encrypt_state({"prompt": "private"})
state = codec.decrypt_state(envelope)
```

These writer/reveal methods require the process-wide exact suite to be active;
verification, pending, incomplete, mismatched, and conflicting states fail
closed. Verification tooling uses `MaintenanceCapability` instead of the codec.

For byte payloads:

```python
payload = codec.encrypt_bytes(b"private media preview", "thumbnail")
data = codec.decrypt_bytes(payload, "thumbnail")
```

## Keystore Lifecycle

```python
from helto_privacy import initialize_keystore, unlock_keystore, lock_keystore

initialize_keystore("correct horse battery")
unlock_keystore("correct horse battery")
lock_keystore()
```

Existing node packs with a legacy `privacy_key.json` can migrate it:

```python
from helto_privacy import initialize_keystore_with_legacy_migration

initialize_keystore_with_legacy_migration(
    "correct horse battery",
    "/path/to/nodepack/config",
)
```

If the shared keystore already exists, that call verifies the password, imports
the legacy key as decrypt-only via `add_keys_to_keystore`, and renames the
legacy file to `privacy_key.json.migrated`.

## Privacy Snapshots and Serialization Barriers

Every connected privacy profile compiles its protected workflow fields into a
runtime-only snapshot coordinator. One edit generation produces one settled
current envelope, and that exact envelope is reused by workflow metadata and
every queued projection. Equal concurrent settlement shares one pending
protection request; an older generation can never overwrite a newer edit. Each
settlement creates an immutable runtime transaction. Graph-to-prompt pins that
transaction until both workflow and executable projections finish, so a newer
edit cannot mix generations inside one operation.

Consumer browser adapters locate product state but do not decide privacy
policy. Workflow adapters implement `normalize(node, context)`,
`readProtected(node, context)`, and `writeProtected(node, envelope, context)`.
After a product edit, notify the typed workflow handle:

```js
const workflow = privacy.workflow("prompt-library");
workflow.markEdited(node, "private-state");
await workflow.settle("manual-save");
```

`settle()` prepares synchronous serialization. Consumer-owned asynchronous
save, export, replay, or queue-manager flows use
`workflow.runWithSnapshot(reason, async ({ graphToPrompt }) => { ... })`; every
projection made inside that callback is pinned to the same immutable
transaction. Direct integrations use the scoped `graphToPrompt` invoker when
they need prompt generation; ordinary `app.graphToPrompt()` calls remain queued
as separate transactions.

The shared profile runtime gates every `app.queuePrompt()` pass at its
`app.graphToPrompt()` boundary, plus root-graph serialization and nested
subgraph serialization. Autosave, manual save/export, queue-manager capture, partial
execution, and direct integrations either consume an already-settled snapshot
or abort with a sanitized `PRIVACY_SNAPSHOT_*` error. Consumer-owned direct API
or queue-manager entry points use the same `runWithSnapshot` boundary; there is
no second encryption path.

Envelope shape is never treated as proof of usability. The server classifies a
field as verified current, locked current, failed current, readable legacy, or
unsupported through real current decryption or an exact declared legacy
reader. Unedited locked/failed ciphertext can be copied exactly into workflow
storage, but reveal, execution, editing, default substitution, and plaintext
fallback remain blocked. Execution-bearing settlement reasons reject locked or
failed state before product queue logic receives a projection. A readable
legacy value is immediately rewritten as a current envelope before
serialization.

## Private Execution, Grants, and RAM Cache

Private queue payloads carry a protected execution reference, never a product
plaintext projection. Mark each protected field that affects execution with
`execution=True` and declare the consumer-owned semantic projection:

```python
from helto_privacy import SemanticExecutionProjection

profile = PrivacyProfile(
    # resources, adapters, scopes, and protected fields omitted
    execution_projections=(
        SemanticExecutionProjection(
            "generate-image",
            "generation",
            "prompt-state",
            "generation-projection",
            "generation-dispatch",
        ),
    ),
)

class GenerationProjection:
    def project(self, fields, declaration):
        return normalize_generation(fields["private-prompt"])

class GenerationDispatch:
    def dispatch(self, value, context, cancellation):
        cancellation.checkpoint()
        result = product_generate(value, context)
        cancellation.checkpoint()
        return result
```

`project` receives decrypted field values only in process memory. It returns the
smallest canonical JSON value that affects the product result. `dispatch`
receives that value only after the protected reference, current session, grant,
field set, decryption, and keyed identity have all validated. It must call the
cooperative cancellation checkpoint before revealing, persisting, or returning
private output and at safe boundaries during longer work. Both synchronous and
async dispatch adapters are supported; the shared runtime clears mutable
plaintext after the returned value or awaitable completes.

The browser creates the reference from the already-settled snapshot:

```js
const workflow = privacy.workflow("prompt-state");
const prepared = await workflow.runWithSnapshot("direct-queue", () => (
  privacy.execution("generation").prepare(node, "generate-image")
));
// Put prepared.reference in the private executable input. Preparation stays
// ciphertext-only and does not derive a semantic identity yet.
```

`BrowserExecutionHandle.prepare()` rejects calls outside an active
execution-bearing transaction. The canonical prepare HTTP route is an internal
transport for that handle, not a consumer API or a substitute for the snapshot
coordinator.

The product execution boundary consumes the reference once:

```python
execution = privacy.execution("generation")
resolved = execution.dispatch(protected_reference, product_context)
result = resolved.value
execution.cache_store(resolved.cache_identity, result)  # Optional RAM cache.
```

Async callers await `resolved` when their dispatch adapter is async. Replays
need a fresh browser snapshot and prepare request. Preparation validates and
copies only protected state; decryption, the consumer semantic projection, and
identity derivation occur together at dispatch immediately before product
logic. The returned public identity is an opaque, domain-separated HMAC of the
semantic projection and unlocked session; it is not plaintext, a path, an
envelope fingerprint, or an unkeyed content hash.
`execution.cache_store(identity, value)` and `cache_load(identity)` accept only
identities issued in the current unlocked session, keep isolated copies in
process RAM, and clear on lock, key rotation/session replacement, process
restart, or profile conflict. Consumers must not persist private cache entries
or send them to an external cache. A later fresh grant for the same semantic
projection returns the shared RAM entry before invoking product logic.

Public-mode product execution continues through the consumer's ordinary public
path. Do not send plaintext through the protected-reference route and do not
catch `PRIVACY_EXECUTION_*` failures to execute defaults or stale state.

## Private Records and Redaction

Private record libraries declare their protected schema, fixed reveal
operations, and exact projection-field allowlist. Every undeclared field is
sensitive:

```python
from helto_privacy import (
    RecordDeclaration,
    RecordRevealProjection,
    confirm_record_mutation,
    generate_private_record_id,
)

profile = PrivacyProfile(
    # resources, adapters, and scopes omitted
    records=(
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
        ),
    ),
)

class PromptStore:
    def list_ids(self): ...                  # Opaque generated IDs only.
    def read_protected(self, record_id): ... # Current encrypted envelope.
    def write_protected(self, record_id, value): ...
    def delete(self, record_id): ...

    def project(self, value, operation):
        if operation == "use":
            return {"prompt": value["prompt"]}
        return {"summary": value["summary"]}

record_id = generate_private_record_id()
```

`records.list_shells("prompt-record")` never calls `read_protected`. It returns
only opaque ID, record kind, `private: true`, and the fixed label
`Private record`. Names, descriptions, tags, timestamps, counts, paths,
filenames, hashes, media details, and diagnostics cannot enter a locked shell.

An authorized reveal decrypts only after the current session and stable mode
scope validate, runs the consumer projection, rejects every non-allowlisted
field, returns an isolated JSON value, and clears mutable plaintext:

```python
authorization = privacy.authorization.authorize_request(request, "record.use")
revealed = privacy.records("library").reveal(
    "prompt-record", record_id, "use", authorization
)
use_prompt(revealed.value["prompt"])
```

Delete and protected replacement remain available while locked, but require a
one-use confirmation bound to the exact pack, resource, kind, ID, and action.
Replacement accepts only a current protected envelope—never plaintext:

```python
confirmation = confirm_record_mutation(
    pack_id=privacy.profile.id,
    resource_id="library",
    record_kind="prompt-record",
    record_id=record_id,
    operation="delete",
    confirmed=user_confirmed,
)
privacy.records("library").delete("prompt-record", record_id, confirmation)
```

The attested browser handle exposes `list`, `reveal`, `delete`, and `replace`.
It owns a generic Helto-styled destructive confirmation modal and rebuilds every shell with
`redactPrivateRecordShell()`, discarding extra server/consumer metadata rather
than masking or retaining it. Generic protected operations cannot target a
record resource, so duplicate, merge, edit, or metadata-reveal escape hatches
cannot be registered.

Record responses use `Cache-Control: private, no-store`, `nosniff`,
`no-referrer`, a fresh opaque correlation ID, and generic download names from
`private_record_response_headers()`. `safe_record_diagnostic()` accepts only a
fixed stage plus coarse integer count and boolean flag. Raw exceptions, paths,
record values, and original filenames are never response or diagnostic fields.

## Shared UI and Canonical Routes (ComfyUI)

Inside ComfyUI, packs do not implement their own unlock endpoints or dialogs.
Each pack calls one function at load time:

```python
from helto_privacy import register_helto_privacy_ui

register_helto_privacy_ui(legacy_key_dir=Path(__file__).parent / "config")
```

Registration is idempotent across packs (first pack wins); every call also
records the pack's legacy `privacy_key.json` directory. It registers:

- `GET  /helto_privacy/status`
- `GET  /helto_privacy/profiles/{pack_id}`
- `GET  /helto_privacy/profiles/{pack_id}/modes`
- `POST /helto_privacy/profiles/{pack_id}/modes/{scope_id}/transition`
- `POST /helto_privacy/profiles/{pack_id}/fields/{field_id}/disposition`
- `POST /helto_privacy/profiles/{pack_id}/fields/{field_id}/protect`
- `POST /helto_privacy/profiles/{pack_id}/executions/{execution_id}/prepare`
- `GET  /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}`
- `POST /helto_privacy/profiles/{pack_id}/records/.../reveal/{operation}`
- `POST /helto_privacy/profiles/{pack_id}/records/.../delete`, `/replace`
- `POST /helto_privacy/suite/browser-attestation`
- `POST /helto_privacy/unlock`, `/lock`
- `POST /helto_privacy/keystore/init`, `/keystore/change_password`
- `GET  /helto_privacy/ui/privacy.js` — the shared browser client and UI
- `GET  /helto_privacy/ui/privacy_records.js` — opaque-ID validation and shell redaction
- `GET  /helto_privacy/ui/privacy_snapshot.js` — runtime snapshot coordinator
- `GET  /helto_privacy/ui/privacy_profile/{manifest_digest}.js` — the exact
  browser profile compiler

Legacy migration is automatic: when the keystore is created or unlocked, every
registered legacy key is imported as a decrypt-only entry and its file renamed
to `.migrated` — packs adopted after the keystore exists are picked up on the
next unlock.

The attested profile runtime imports the shared module and mounts its UI. Packs
may also import it to register recovery descriptors or use the canonical
concealment helpers; they do not ship another dialog or attach tokens:

```js
const privacy = await import("/helto_privacy/ui/privacy.js");
await privacy.showPrivacyKeystoreDialog("auto");   // setup or unlock as needed
privacy.registerPrivacyRecoveryDescriptors("helto.example", descriptors);
```

## Adoption Recipe

**Migrating a node pack? Follow [ADOPTION_GUIDE.md](ADOPTION_GUIDE.md)** —
step-by-step agent instructions including legacy key migration, route
gating, frontend token handling, and test hygiene. Summary:

For each Helto node pack:

1. Add:

   ```text
   helto-privacy @ git+https://github.com/helto4real/helto-privacy.git@<coordinated-suite-tag>
   cryptography>=42.0
   ```

2. Replace local key loading with `PrivacyEnvelopeCodec("<pack schema>")`.
3. On first password-protect action, call
   `initialize_keystore_with_legacy_migration(password, legacy_config_dir)`.
4. Dispatch protected routes through the installed pack's bound
   `privacy.authorization.dispatch(...)` handle.
5. Connect the exact browser profile, implement `onPrivacySessionChange`, and
   invoke only compiled typed methods such as
   `privacy.records("library").reveal("prompt-record", id, "use")`; never read
   the browser token or vendor a second privacy UI.

## Threat Model

Gained: stolen disks, backups, and synced dotfiles cannot decrypt private
state without the password. Other network clients cannot call privacy routes
without the session token.

Not gained: malware running as the same OS user while the keystore is unlocked
can read the session cache. Use full-disk encryption and encrypted swap for
the lower layers.

## Test Hygiene

Tests must set `HELTO_PRIVACY_KEYSTORE`, `HELTO_PRIVACY_SESSION_DIR`, and
`HELTO_PRIVACY_MODE_STATE` to temporary paths. They must not read or write
`~/.config/helto`, the real `XDG_RUNTIME_DIR`, or any node-pack `config/`
directory.
