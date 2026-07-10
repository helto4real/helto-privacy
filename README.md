# helto-privacy

Shared privacy keystore, envelope, and HTTP token-guard helpers for Helto
ComfyUI node packs.

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
then changes the installation to `active`. Restart verification reloads and
revalidates that record before restoring active state.

The activation inventory digest also binds a measured installation generation
derived from the five artifact files. Reinstalling or repairing exact bytes
therefore still requires a new signed activation instead of replaying the old
record.

If an active installation later becomes incomplete, mismatched, or conflicting,
the activation record is retained but marked for reactivation. The current
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
- Keystore schema: `helto.privacy-keystore`, version `1`.
- Key-wrap AAD: `helto.privacy-keystore|1|<keyId>`.
- Files are written through a temporary file and atomic replace; keystore and
  session files are mode `0600`, and directories are mode `0700` where the
  platform allows it.
- Route token names are `X-Helto-Privacy-Token` and `helto_privacy_token`.

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
- `POST /helto_privacy/suite/browser-attestation`
- `POST /helto_privacy/unlock`, `/lock`
- `POST /helto_privacy/keystore/init`, `/keystore/change_password`
- `GET  /helto_privacy/ui/privacy.js` — the shared unlock dialog (ES module)
- `GET  /helto_privacy/ui/privacy_profile/{manifest_digest}.js` — the exact
  browser profile compiler

Legacy migration is automatic: when the keystore is created or unlocked, every
registered legacy key is imported as a decrypt-only entry and its file renamed
to `.migrated` — packs adopted after the keystore exists are picked up on the
next unlock.

Frontends import the served module instead of shipping their own dialog:

```js
const privacy = await import("/helto_privacy/ui/privacy.js");
await privacy.showPrivacyKeystoreDialog("auto");   // setup or unlock as needed
privacy.ensureStoredPrivacyTokenCookie();          // before rendering privacy-mode <img>
```

## Adoption Recipe

**Migrating a node pack? Follow [ADOPTION_GUIDE.md](ADOPTION_GUIDE.md)** —
step-by-step agent instructions including legacy key migration, route
gating, frontend token handling, and test hygiene. Summary:

For each Helto node pack:

1. Add:

   ```text
   helto-privacy @ git+https://github.com/helto4real/helto-privacy.git@v0.3.0
   cryptography>=42.0
   ```

2. Replace local key loading with `PrivacyEnvelopeCodec("<pack schema>")`.
3. On first password-protect action, call
   `initialize_keystore_with_legacy_migration(password, legacy_config_dir)`.
4. Protect privacy routes with `check_privacy_token` or
   `aiohttp_check_privacy_token`.
5. Reuse the browser token already stored per origin by the Timeline Director
   UI. On `PRIVACY_LOCKED`, prompt the user to unlock via Timeline Director
   Global Settings or vendor the same unlock dialog.

## Threat Model

Gained: stolen disks, backups, and synced dotfiles cannot decrypt private
state without the password. Other network clients cannot call privacy routes
without the session token.

Not gained: malware running as the same OS user while the keystore is unlocked
can read the session cache. Use full-disk encryption and encrypted swap for
the lower layers.

## Test Hygiene

Tests must set `HELTO_PRIVACY_KEYSTORE` and `HELTO_PRIVACY_SESSION_DIR` to
temporary paths. They must not read or write `~/.config/helto`, the real
`XDG_RUNTIME_DIR`, or any node-pack `config/` directory.
