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
helto-privacy @ git+https://github.com/helto4real/helto-privacy.git@v0.2.0
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
`/keystore/init`, `/keystore/change_password`, and serves the shared unlock
dialog at `/helto_privacy/ui/privacy.js`.

**Migration is automatic.** Because the pack registered its legacy key
directory, its `privacy_key.json` is imported as a decrypt-only key at the
next keystore init *or unlock* — the only moments the password is in hand —
and renamed to `privacy_key.json.migrated` (a recoverable backup: never
delete it programmatically, never commit it; gitignore `config/*.json` and
`config/*.json.migrated`). The pack does NOT need its own "Set password"
action, unlock endpoints, or migration branching. Wrong passwords surface as
`PRIVACY_PASSWORD_INVALID` — show the message as-is.

(`initialize_keystore_with_legacy_migration(password, legacy_dir)` still
exists for non-ComfyUI callers and scripted migration.)

## Step 4 — Gate routes, import the shared frontend

**Gate every privacy route the pack owns.** Any endpoint that decrypts,
encrypts, or serves privacy-mode content must call the guard first:

```python
from helto_privacy import aiohttp_check_privacy_token

@routes.post(f"{PREFIX}/decrypt")
async def post_decrypt(request):
    denied = aiohttp_check_privacy_token(request)
    if denied is not None:
        return denied
    ...
```

The guard is a no-op until a keystore exists (legacy installs keep working),
and accepts the token from the header **or** the cookie — the cookie exists
because `<img>`/media elements cannot send custom headers; gate privacy-mode
thumbnail/preview routes too, not just JSON endpoints.

**Frontend: import the served module — do not copy dialog code into the
pack.**

```js
let privacy = null;
try {
  privacy = await import("/helto_privacy/ui/privacy.js");
} catch {
  /* package not installed server-side: show
     "Unlock via Timeline Director → Global Settings" instead. */
}

// When an operation fails with a locked error:
if (privacy?.isPrivacyLockedError(error)) {
  const unlocked = await privacy.showPrivacyKeystoreDialog("auto");
  if (unlocked) retryTheOperation();
}

// Before rendering privacy-mode <img>/media elements:
privacy?.ensureStoredPrivacyTokenCookie();
```

`showPrivacyKeystoreDialog("auto")` picks setup vs unlock from keystore
status and resolves immediately if already unlocked; explicit modes
`"unlock"`, `"setup"`, `"change"` exist for settings-menu buttons. The module
also exports `fetchPrivacyStatus`, `lockPrivacyKeystore`,
`getStoredPrivacyToken` (attach as `X-Helto-Privacy-Token` on the pack's own
fetch/XHR calls), and `isPrivacyLockedError`. Token storage is per origin, so
an unlock through any pack — or the Timeline Director — covers this pack too.

## Step 5 — Tests (non-negotiable hygiene)

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

## Step 6 — Validation checklist

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
- [ ] `privacy_key.json` is gone (renamed `.migrated`) and gitignored.
- [ ] Commit style: single-line imperative subject, matching the pack's
      history.

## Do NOT

- Change the pack's envelope schema string or any AAD format.
- Delete key files (`.migrated` backups stay until the user removes them).
- Copy the keystore implementation into the pack — depend on the package;
  version bumps happen here, once.
- Log passwords, tokens, or key material anywhere, including test output.
