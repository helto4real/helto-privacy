# helto-privacy

Shared privacy keystore, envelope, and HTTP token-guard helpers for Helto
ComfyUI node packs.

## File Contract

The keystore format is intentionally stable:

- Keystore file: `~/.config/helto/privacy_keystore.json`, or
  `HELTO_PRIVACY_KEYSTORE`.
- Session file: `$XDG_RUNTIME_DIR/helto/privacy_session.json`, or
  `HELTO_PRIVACY_SESSION_DIR`.
- Keystore schema: `helto.privacy-keystore`. Version `1` password stores remain
  readable; version `2` stores declare either password or YubiKey FIDO2 unlock.
- Key-wrap AAD: `helto.privacy-keystore|<version>|<keyId>`.
- Files are written through a temporary file and atomic replace; keystore and
  session files are mode `0600`, and directories are mode `0700` where the
  platform allows it.
- Route token names are `X-Helto-Privacy-Token` and `helto_privacy_token`.

The base runtime dependency is `cryptography>=42.0`. YubiKey support uses the
optional `fido2>=2.2.1,<3` extra. The package does not import ComfyUI.

## Quickstart

```python
from helto_privacy import PrivacyEnvelopeCodec

codec = PrivacyEnvelopeCodec("helto.my-pack")
envelope = codec.encrypt_state({"prompt": "private"})
state = codec.decrypt_state(envelope)
```

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

### YubiKey FIDO2 unlock

Install the optional support in every Python environment that loads
`helto-privacy`:

```text
pip install 'helto-privacy[yubikey]'
```

This uses the same USB HID/FIDO2 interface used by browsers and FIDO SSH keys;
it does not require PC/SC. Run the local enrollment command:

```text
helto-privacy yubikey enroll
```

The command never accepts secrets as arguments. It prompts for the existing
privacy password when converting a password store and the YubiKey FIDO2 PIN.
With multiple connected security keys, disconnect all but the intended key or
select its non-secret HID path with `--device /dev/hidrawN` during enrollment.

Enrollment creates a non-discoverable FIDO2 credential with `hmac-secret` and
hardware-enforced `credProtect=userVerificationRequired`. It does not consume a
resident passkey slot and does not modify existing passkeys, OpenPGP, PIV, OTP,
SSH, or signing keys. Enrollment requires the PIN and two touches (credential
creation and secret verification). Each later unlock obtains a fresh signed
assertion and hardware-derived secret with one PIN verification and one touch.
Existing encrypted envelopes are not rewritten: their DEKs are rewrapped under
the FIDO2-derived KEK, and only the keystore file changes.

Conversion is intentionally YubiKey-only. The old privacy password stops
working, and losing the sole enrolled YubiKey permanently loses access to the
encrypted data. Upgrade every active Helto environment to a version-2-capable
`helto-privacy` before enrolling. Enrollment fails closed unless the connected
key advertises FIDO2, `hmac-secret`, `credProtect`, and a configured client PIN.
Wrong PIN attempts consume the authenticator's retry counter. To protect that
counter, YubiKey unlock requests are accepted only from a loopback client on
the ComfyUI host.

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
- `POST /helto_privacy/unlock`, `/lock`
- `POST /helto_privacy/keystore/init`, `/keystore/change_password`
- `GET  /helto_privacy/ui/privacy.js` — the shared unlock dialog (ES module)

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
   helto-privacy @ git+https://github.com/helto4real/helto-privacy.git@v0.6.0
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
state without the configured password or enrolled YubiKey. YubiKey stores
require the matching device, its PIN, and a physical touch for each unlock
action. Other network clients cannot call privacy routes without the session
token.

Not gained: malware running as the same OS user while the keystore is unlocked
can read the session cache. Use full-disk encryption and encrypted swap for
the lower layers.

## Test Hygiene

Tests must set `HELTO_PRIVACY_KEYSTORE` and `HELTO_PRIVACY_SESSION_DIR` to
temporary paths. They must not read or write `~/.config/helto`, the real
`XDG_RUNTIME_DIR`, or any node-pack `config/` directory.
