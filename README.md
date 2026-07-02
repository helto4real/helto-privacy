# helto-privacy

Shared privacy keystore, envelope, and HTTP token-guard helpers for Helto
ComfyUI node packs.

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

## Adoption Recipe

**Migrating a node pack? Follow [ADOPTION_GUIDE.md](ADOPTION_GUIDE.md)** —
step-by-step agent instructions including legacy key migration, route
gating, frontend token handling, and test hygiene. Summary:

For each Helto node pack:

1. Add:

   ```text
   helto-privacy @ git+https://github.com/helto4real/helto-privacy.git@v0.1.0
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
