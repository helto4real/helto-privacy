# Release and installation coupling

## Scope and method

This report describes the current release, installation, import, registration,
and runtime-version coupling between `helto-privacy` and its four consumers. It
uses only the checked-out repositories, their local Git metadata, the local
ComfyUI loader source, and the installed ComfyUI Python environment. Findings
under **Current state** are observations; **Specification constraints** are
recommendations derived from them. This report does not define a migration or
release sequence.

Repositories inspected:

- `/home/thhel/git/helto-privacy`
- `/home/thhel/git/comfyui-utils`
- `/home/thhel/git/comfyui-all-on-one-image-generation-node`
- `/home/thhel/git/comfyui-helto-director`
- `/home/thhel/git/comfyui-helto-smartprompt`
- `/home/thhel/git/ComfyUI` for the custom-node loader

## Executive finding

The four packs do not currently declare one compatible shared-package release.
Utils, AIO, and Smart Prompt pin the Git tag `v0.3.0`; Director pins `v0.2.0`
in `requirements.txt` and omits `helto-privacy` from its `pyproject.toml`.
There is only one importable `helto_privacy` package per ComfyUI Python process,
so this is not four isolated dependencies: whichever shared distribution is
installed is the implementation used by every pack.

That mismatch is already behaviorally significant. `v0.3.0` added the browser
privacy-recovery and fail-closed serialization API used by the other three
packs. With a `v0.2.0` shared UI, Utils blocks private serialization because
the helper is missing, AIO falls back to its local encrypt path but loses shared
recovery, and Smart Prompt reports recovery as unavailable. Director continues
through a package-first vendored keystore shim and its own privacy routes/UI.

Registration has a second global coupling. The canonical routes and browser
module are registered once by the first successful pack call; later calls only
add legacy-key directories. ComfyUI loads custom-node directories sequentially
in unsorted `os.listdir()` order. The shared registration is intentionally
idempotent, but current consumers neither enforce a registration lifecycle nor
retry a failed early registration. Their browser imports also memoize a failed
dynamic import for the life of the page.

Finally, packaging and release verification are uneven: all shared dependency
references are direct Git tag URLs, only AIO mirrors the dependency in Python
project metadata, only AIO has `[tool.comfy]` metadata, the consumer repos have
no checked-in CI workflows or local Git tags, and no test currently installs
and loads the coordinated five-repository set from declared dependencies.

## Current state

### Dependency and release matrix

| Repository | Declared shared dependency | Python/manager metadata | Missing/incompatible behavior |
|---|---|---|---|
| `helto-privacy` | Distribution version `0.3.0`; runtime dependency `cryptography>=42.0` | Setuptools package; `web/*.js` included as package data | Own CI tests Python 3.10-3.13; no release/publish workflow |
| `comfyui-utils` | `helto-privacy @ ...@v0.3.0` plus `cryptography>=42.0` in `requirements.txt` | No `pyproject.toml` or Comfy registry manifest; V3 `comfy_entrypoint()` | Backend package import is required; v0.2 browser UI makes privacy serialization fail closed |
| AIO Image Generate | Same v0.3.0 pin in both `requirements.txt` and `pyproject.toml` | Project version `0.1.0`; only consumer with `[tool.comfy]` metadata | Pack can load without the package, but privacy crypto is unavailable and privacy token guards become no-ops |
| Director | `helto-privacy @ ...@v0.2.0` plus `cryptography>=42.0` in `requirements.txt` | Project version `0.0.1`; `pyproject.toml` lists only `cryptography` | Package is optional at import; vendored keystore plus local routes/UI remain |
| Smart Prompt | `helto-privacy @ ...@v0.3.0` plus `cryptography>=42.0` in `requirements.txt` | No `pyproject.toml` or Comfy registry manifest; classic mappings | Package import is required; recovery is feature-detected and can be absent |

The shared package version and packaged browser asset are declared in
[pyproject.toml](/home/thhel/git/helto-privacy/pyproject.toml:5). Its own README
prescribes the v0.3.0 direct Git reference for adopters
([README.md](/home/thhel/git/helto-privacy/README.md:98)). The three matching
consumer pins are in [Utils requirements](/home/thhel/git/comfyui-utils/requirements.txt:1),
[AIO requirements](/home/thhel/git/comfyui-all-on-one-image-generation-node/requirements.txt:1),
and [Smart Prompt requirements](/home/thhel/git/comfyui-helto-smartprompt/requirements.txt:1).
AIO duplicates that pin in project metadata and declares its Comfy publisher,
display name, and web directory
([AIO pyproject.toml](/home/thhel/git/comfyui-all-on-one-image-generation-node/pyproject.toml:1)).

Director is the outlier: its requirements pin v0.2.0
([Director requirements](/home/thhel/git/comfyui-helto-director/requirements.txt:1)),
while its project dependency list contains only `cryptography`
([Director pyproject.toml](/home/thhel/git/comfyui-helto-director/pyproject.toml:1)).
The local Git history confirms that `v0.3.0` added the recovery API to the
served browser module; `v0.2.0` exposes only keystore/token/dialog functions.
There is no Python `__version__` or shared API-version export in the package's
public module
([helto_privacy/__init__.py](/home/thhel/git/helto-privacy/helto_privacy/__init__.py:1)).

The inspected ComfyUI Python 3.13.14 environment currently has distribution
version `0.3.0`, installed from requested revision `v0.3.0` at commit
`d7af8108abb147c4d0734f33e29593c7dd61134b`. That makes the present machine
healthy, but it does not remove the conflicting declaration for a fresh or
reinstalled environment.

### One backend module and one browser module

Every normal consumer import uses the top-level name `helto_privacy`. Python
therefore shares one `sys.modules` instance across all packs. The shared
integration explicitly relies on that fact and keeps route registration and
legacy directories in module globals
([comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:1),
[comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:35)).
The first successful `register_helto_privacy_ui()` call installs the canonical
route set; subsequent calls return immediately after recording any supplied
legacy directory
([comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:43),
[comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:52)).

The route serves `privacy_ui.js` from the installed package with
`Cache-Control: no-cache`
([comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:138)).
Utils, AIO, and Smart Prompt all import the same absolute URL,
`/helto_privacy/ui/privacy.js`; the browser's ES-module cache consequently
makes its descriptor registry and memo state page-global. Their wrappers also
cache the import promise, including a resolved `null` after failure:

- [Utils privacy_common.js](/home/thhel/git/comfyui-utils/web/privacy_common.js:20)
- [AIO aio_privacy.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:78)
- [Smart Prompt smart_prompt_manager.js](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:308)

There is no production reset/retry of those failed promises. A transient 404
or an absent canonical route at the first import therefore disables the shared
UI for that pack until the page is reloaded.

### Custom-node load order and registration timing

ComfyUI obtains candidate packs with `os.listdir()` and imports each candidate
sequentially without sorting the names
([ComfyUI nodes.py](/home/thhel/git/ComfyUI/nodes.py:2322)). Therefore no Helto
pack can rely on being the first or last registrar.

The shared registrar returns `False` if `server.PromptServer.instance` or
`aiohttp` is unavailable; it does not schedule a later attempt
([comfy_ui.py](/home/thhel/git/helto-privacy/helto_privacy/comfy_ui.py:68)).
Current pack behavior is similarly one-shot:

- Utils calls registration directly during package import and passes its
  `config` directory
  ([Utils __init__.py](/home/thhel/git/comfyui-utils/__init__.py:7)).
- AIO checks `sys.modules["server"]`, registers only when the instance already
  exists, and wraps the callback in warning-and-continue handling. It does not
  pass a legacy directory
  ([AIO __init__.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/__init__.py:78)).
- Director calls registration in a broad `try/except`, passes its `config`
  directory, and treats the canonical UI as optional
  ([Director __init__.py](/home/thhel/git/comfyui-helto-director/__init__.py:87)).
- Smart Prompt imports the registrar and calls it directly without a legacy
  directory
  ([Smart Prompt __init__.py](/home/thhel/git/comfyui-helto-smartprompt/__init__.py:1)).

Later successful calls make backend route ownership independent of directory
order, and later Utils/Director calls still add their legacy directories.
However, if all calls happen before the server is usable, or the only later
calls suppress the failure, no current component performs a definitive retry.
AIO and Smart Prompt's missing `legacy_key_dir` arguments also mean their old
pack keys are not discovered by the generic registration path.

### Consumer import and fallback behavior

#### `comfyui-utils`: hard backend dependency, hard v0.3 browser capability

Utils imports the package registrar before importing its nodes and route
modules, and those modules directly import shared codecs and token guards
([Utils __init__.py](/home/thhel/git/comfyui-utils/__init__.py:7),
[Utils shared/privacy.py](/home/thhel/git/comfyui-utils/shared/privacy.py:12)).
A missing Python package therefore prevents the normal ComfyUI extension from
loading.

Its browser wrapper deliberately requires the v0.3
`ensureEncryptedPrivacyValue` export. If absent it throws
`PRIVACY_ENCRYPTION_UNAVAILABLE`, preserving fail-closed serialization.
Recovery registration and dialogs, in contrast, degrade to empty/no-op results
([privacy_common.js](/home/thhel/git/comfyui-utils/web/privacy_common.js:112),
[privacy_common.js](/home/thhel/git/comfyui-utils/web/privacy_common.js:120)).
Thus a v0.2 install can leave the pack visible while blocking private workflow
saves and silently removing recovery affordances.

#### AIO: soft dependency with a fail-open authorization fallback

AIO's privacy service catches any shared-package import error, exposes an
unavailable status, and leaves its codec unset so encryption/decryption fail
with a readable dependency error
([services/privacy.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/services/privacy.py:10)).
This allows the rest of the pack and its routes to load.

The route guards independently catch the same import failure and replace
`aiohttp_check_privacy_token` with `None`. Both the encrypt/decrypt routes and
the private prompt-library routes interpret a missing guard as authorization
success
([routes/privacy.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/routes/privacy.py:8),
[routes/privacy.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/routes/privacy.py:78),
[routes/ideogram4_prompt_library.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/routes/ideogram4_prompt_library.py:9),
[routes/ideogram4_prompt_library.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/routes/ideogram4_prompt_library.py:191)).
Crypto operations still fail while the codec is absent, but non-decrypting
private-record operations such as delete can proceed without the token. This
is a current fail-open installation hazard, not merely degraded UI.

With v0.2, AIO's browser code can still encrypt through its local route because
it falls back when the shared fail-closed helper is absent, but descriptor
registration and the recovery dialog become no-ops
([aio_privacy.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy.js:169),
[aio_privacy_recovery.js](/home/thhel/git/comfyui-all-on-one-image-generation-node/web/js/aio_privacy_recovery.js:184)).

#### Director: package-first vendored backend and parallel UI

Director's keystore shim imports `helto_privacy.keystore` when available and
otherwise imports `shared._vendored_keystore`
([privacy_keystore.py](/home/thhel/git/comfyui-helto-director/shared/privacy_keystore.py:1)).
Its state/byte codec remains pack-local and selects the shared/vendored
keystore only as its key source
([shared/privacy.py](/home/thhel/git/comfyui-helto-director/shared/privacy.py:25),
[shared/privacy.py](/home/thhel/git/comfyui-helto-director/shared/privacy.py:174)).

Director also registers `/helto_director/privacy/*` keystore and codec routes
with a local token guard
([routes/privacy.py](/home/thhel/git/comfyui-helto-director/routes/privacy.py:31),
[routes/privacy.py](/home/thhel/git/comfyui-helto-director/routes/privacy.py:78))
and its frontend uses a local `privacy.js`/`privacy_unlock.js` implementation,
not the canonical browser module. Missing `helto-privacy` therefore leaves
Director privacy available if `cryptography` is installed, but removes the
canonical route/UI contribution that the other packs expect. The vendored
implementation is a second release surface with no declared version or parity
check against the shared package.

#### Smart Prompt: hard package dependency, soft recovery capability

Smart Prompt imports `helto_privacy.envelope`, `helto_privacy.keystore`, and the
codec at module import, and its package initializer imports the shared
registrar unconditionally
([privacy.py](/home/thhel/git/comfyui-helto-smartprompt/privacy.py:8),
[Smart Prompt __init__.py](/home/thhel/git/comfyui-helto-smartprompt/__init__.py:1)).
A missing package therefore prevents normal pack loading.

The frontend feature-detects recovery exports. If they are missing it leaves
recovery unregistered and the manual action tells the user to update
`helto-privacy`
([smart_prompt_manager.js](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:465),
[smart_prompt_manager.js](/home/thhel/git/comfyui-helto-smartprompt/web/js/smart_prompt_manager.js:2135)).
Its pack-local encrypt/decrypt route and serialization flow do not otherwise
require the v0.3 recovery exports.

### Installation documentation and manager metadata

All four requirements files use Git URL references rather than a package-index
constraint, so installing a consumer requires Git/network access and resolves
to a repository tag, not a content hash. A shared-package release does not
reach a consumer until that consumer's reference is changed and its Python
requirements are installed again.

Documentation is inconsistent:

- Utils tells users to clone and restart but does not tell manual installers to
  install `requirements.txt`
  ([Utils README](/home/thhel/git/comfyui-utils/README.md:7)).
- AIO explicitly installs requirements and identifies ComfyUI Manager's
  automatic requirements step as optional behavior
  ([AIO README](/home/thhel/git/comfyui-all-on-one-image-generation-node/README.md:5)).
- Director also says clone and restart without a dependency-install command
  ([Director README](/home/thhel/git/comfyui-helto-director/README.md:33)). Its
  vendored keystore does not vendor `cryptography`, so privacy still depends on
  that requirement being installed.
- Smart Prompt explicitly installs requirements and says Manager handles them
  automatically
  ([Smart Prompt README](/home/thhel/git/comfyui-helto-smartprompt/README.md:7)).

Only AIO has `[tool.comfy]` metadata. Utils and Smart Prompt have no Python
project metadata, and Director's Python metadata does not declare the shared
dependency. No consumer contains a checked-in `comfy*.json`, `node_list.json`,
or install script in the inspected tree.

### Tests, CI, and release identity

`helto-privacy` is the only inspected repository with a checked-in GitHub
Actions workflow. It installs the package editable and runs `pytest` on Python
3.10 through 3.13
([ci.yml](/home/thhel/git/helto-privacy/.github/workflows/ci.yml:1)). It does not
build or publish an artifact.

The consumers have useful repo-local tests but no coordinated installation
test:

- Utils declares `npm run test:js` and has Python privacy tests, but its JS
  shared-module tests inject a stub instead of verifying the installed browser
  module
  ([package.json](/home/thhel/git/comfyui-utils/package.json:1),
  [privacy-common.test.js](/home/thhel/git/comfyui-utils/tests/js/privacy-common.test.js:10)).
- AIO's pytest config includes its test tree; its import test asserts that the
  canonical routes register, and its recovery JS tests read the installed
  package's browser source
  ([test_import.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_import.py:132),
  [test_privacy_recovery_js.py](/home/thhel/git/comfyui-all-on-one-image-generation-node/tests/test_privacy_recovery_js.py:5)).
- Director has Python and JS suites, but keystore tests exercise whichever
  shared/vendored backend imported in that environment rather than running a
  package-present/package-absent parity matrix
  ([test_privacy_keystore.py](/home/thhel/git/comfyui-helto-director/tests/timeline/test_privacy_keystore.py:5)).
- Smart Prompt documents its Python and JavaScript test commands, but its
  shared recovery contract test is skipped when the installed browser module
  lacks the v0.3 API
  ([Smart Prompt README](/home/thhel/git/comfyui-helto-smartprompt/README.md:287),
  [test_frontend.py](/home/thhel/git/comfyui-helto-smartprompt/tests/test_frontend.py:721)).

Local Git metadata shows tags `v0.1.0`, `v0.2.0`, and `v0.3.0` only in
`helto-privacy`; none of the four consumer checkouts has a tag. None contains a
checked-in release workflow. AIO and Director have static project versions,
while Utils and Smart Prompt expose no distribution version. There is therefore
no current cross-repository release identity or compatibility matrix to say
which five revisions form a supported set.

## Specification constraints

These are recommendations derived from the current facts. They define what a
coordinated-cutover specification must settle, not the order of implementation.

1. **Declare one shared API/protocol requirement for all consumers.** All four
   dependency surfaces must name the same immutable shared release (or an
   equivalent compatible range), including `requirements.txt`, project
   metadata, manager metadata, tests, and install docs. Director's v0.2.0 pin
   and pyproject omission cannot remain in the supported set.

2. **Make compatibility machine-readable.** The Python package, canonical
   status response, and browser module should expose a shared API/protocol
   version or explicit capabilities. Consumers should reject an incompatible
   package with one diagnostic rather than relying on scattered optional
   chaining and silent no-ops. Distribution version alone is not enough for
   independently evolving backend, route, and UI contracts.

3. **Adopt one strict missing-dependency policy.** Privacy enforcement must not
   disappear because an import failed. In particular, AIO's `None` guard must
   be treated as denial, not authorization. The specification must decide
   whether a pack may load non-private features without the package, but every
   private route, write, read, and destructive record operation must fail
   closed with an actionable install/version error.

4. **Eliminate load-order correctness.** Canonical route registration must run
   at a guaranteed ComfyUI lifecycle point or have an idempotent retry path.
   Legacy-key-directory contribution must work before and after the route
   owner registers. Frontend module loading must retry recoverable route timing
   failures instead of memoizing `null` forever. Correctness must be proven for
   multiple custom-node directory orders.

5. **Choose one supported fallback boundary.** Director's vendored keystore,
   local codec, local route family, and local dialog form a second release
   surface. Given shared ownership of reusable privacy services/UI, the
   specification must either remove that surface from the supported cutover or
   isolate it behind an explicit, tested compatibility adapter with a declared
   protocol and retirement condition. An unversioned silent fallback cannot
   coexist with a strict shared-package contract.

6. **Normalize install and manager metadata.** Each consumer needs a complete,
   matching dependency declaration in the metadata ComfyUI Manager actually
   consumes and an explicit manual-install command. The specification must also
   choose whether direct Git tags remain the distribution mechanism; if so,
   every supported consumer declaration must identify the same released tag
   and verification must start from a clean interpreter.

7. **Give every supported set a release identity.** Consumer versions/tags and
   a compatibility manifest are needed so support and rollback can identify
   the exact shared/consumer set. Static `0.0.1`/`0.1.0` metadata with untagged
   consumer heads is insufficient for a coordinated cutover.

8. **Require a clean, cross-repo acceptance matrix.** Validation must install
   declared dependencies into a fresh environment, load all four packs in more
   than one order, assert exactly one canonical route family, confirm every
   consumer's shared UI registration/capabilities, test missing and
   incompatible package behavior, and exercise any retained Director fallback
   both with and without the package. Existing per-repo unit suites remain
   necessary but do not prove installation compatibility.

9. **Keep stored-data compatibility independent of source compatibility.** The
   coordinated source/API break may require all consumers to update together,
   but the chosen release set must still load/decrypt the legacy schemas, keys,
   workflow fields, and pack-managed data recorded in the legacy-data ticket.
   A package-version error must never cause encrypted-looking data to be
   treated as plaintext or reset implicitly.

## Reproduction commands

The following local commands produced the non-file facts in this report:

```bash
# Tags, releases, and recent release identity
for repo in helto-privacy comfyui-utils \
  comfyui-all-on-one-image-generation-node \
  comfyui-helto-director comfyui-helto-smartprompt; do
  git -C /home/thhel/git/$repo tag --sort=version:refname
done

# Manager/install/release files and absence of consumer CI workflows
for repo in /home/thhel/git/helto-privacy \
  /home/thhel/git/comfyui-utils \
  /home/thhel/git/comfyui-all-on-one-image-generation-node \
  /home/thhel/git/comfyui-helto-director \
  /home/thhel/git/comfyui-helto-smartprompt; do
  rg --hidden --files "$repo" \
    -g 'requirements*.txt' -g 'pyproject.toml' -g 'comfy*.json' \
    -g 'node_list.json' -g 'install.py' -g '.github/**' -g '!/.git/**'
done

# Browser API delta that makes the v0.2/v0.3 pin mismatch behavioral
git -C /home/thhel/git/helto-privacy \
  diff v0.2.0..v0.3.0 -- helto_privacy/web/privacy_ui.js

# Installed ComfyUI interpreter distribution and exact VCS source
/home/thhel/.pyenv/versions/3.13.14/bin/python3.13 -c \
  'import importlib.metadata as m; d=m.distribution("helto-privacy"); print(d.version); print(d.read_text("direct_url.json"))'
```
