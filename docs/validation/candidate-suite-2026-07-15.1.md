# Candidate suite `helto-suite-2026-07-15.1`

This is the unsigned local build inventory for the coordinated candidate. It
is not a public, supported, installable-on-production, or activatable release.
The immutable signed `cutover-pending` manifest remains intentionally absent
until the complete acceptance evidence exists and signing is explicitly
authorized.

## Release identity

- Previous supported suite: none (this is the first exact five-artifact suite)
- Rollback class: `data-snapshot-required-after-activation`
- Acceptance catalog SHA-256:
  `b57d738cf5ab5978fcf05fc9f3873230ea75157f8a216002a2956a7f2febfd9b`
- Historical fixture catalog SHA-256:
  `99f22f0faa3e7bddadd672878ac14ef846e70efe1cabda94416eca241f8295d8`
- Artifact staging directory: `/tmp/helto-suite-20260715-2/artifacts`

The two declared environment tuples both use Python `3.13.14`, ComfyUI
backend `0.27.0+e2a6e30d892402ffcf01d6280c8e2744a4448b9d`, and frontend
`1.45.20`; one uses the `legacy` renderer and one uses the `vue` renderer.

## Exact artifacts

| Distribution | Version | Source revision | Artifact | SHA-256 |
| --- | --- | --- | --- | --- |
| `helto-privacy` | `0.4.0` | `2e85c71f9aa22bd47ee6f13f2add83d111ab4591` | `helto_privacy-0.4.0-py3-none-any.whl` | `7eba6a19ce3859f1320e0ee252b24827ac1d1862594311bbf87fa3084e72d440` |
| `comfyui-utils` | `0.1.0` | `cc8ec11507eeb86852892d355cba98f67f5d3ad2` | `comfyui-utils-0.1.0+cc8ec11.tar` | `70fce7da9a6c7cfeadbb530571883b81be488f3014d3b76350d6cb2a458544fa` |
| `comfyui-all-on-one-image-generation-node` | `0.1.0` | `27bd7dee087ad765bb78b59df95391609c467c32` | `comfyui-all-on-one-image-generation-node-0.1.0+27bd7de.tar` | `1202ac3739f45d635f5231f4e62ec619d28634d71680999bb1bd6a43e58b0adb` |
| `comfyui-helto-director` | `0.0.1` | `14fde8bc45884255815625df5c4c78c01ff69f8e` | `comfyui-helto-director-0.0.1+14fde8b.tar` | `5cac51f542bffa8d3e7709ae9273e50335e593454c2baa59455e79697fde2746` |
| `comfyui-helto-smartprompt` | `0.1.0` | `082e50212e09272cae9e3b3d2a3b84775ae83d63` | `comfyui-helto-smartprompt-0.1.0+082e502.tar` | `fc5b719c8f5317b088139cfa9b025712132a38cc7f6e3e2cea9cc4dbb12af932` |

The canonical source repositories are the matching repositories under
`https://github.com/helto4real/`.

## Profile identities

| Profile | Distribution | Fingerprint |
| --- | --- | --- |
| `helto.comfyui-utils` | `comfyui-utils` | `517c7d90d335ac12fd30e7fb0eafba9976b8fb8c1be9cdfa55aa508463760cbe` |
| `helto.aio-image-generation` | `comfyui-all-on-one-image-generation-node` | `f63424f85dfa083277d43069d1a399f500f77e132f001a9355da20dab0f133a1` |
| `helto.video-timeline-director` | `comfyui-helto-director` | `948ad2440e27b7fdba7e40ac1928424afae3b8a19c27d859ee61ce25f42ab835` |
| `helto.smart-prompt-manager` | `comfyui-helto-smartprompt` | `5a352fd3fb086cd3418039368457e7a2fbd8b4ae81aa0deae6151d8bcbd22352` |

## Reproducibility and inspection evidence

- Each consumer archive was generated twice with `git archive` from its exact
  committed revision and compared byte-for-byte.
- The shared wheel was generated twice from its exact source archive with
  `SOURCE_DATE_EPOCH=1784104800` and compared byte-for-byte.
- The accidental Smart Prompt wheel was rejected because it contained only
  distribution metadata and none of the custom-node implementation or browser
  assets.
- A tracked Python 3.12 bytecode file was removed from Utils before its final
  source identity and archive were created.
- Every consumer archive contains its required initializer, project and
  requirements metadata, profile builder/installer, and browser connector.
- Every dependency declaration contains the same exact shared revision twice
  (requirements and project metadata), with no local path, editable reference,
  floating branch, or stale shared revision.
- Backend and browser profile fingerprints match for all four consumers.
- Archive scanning found no bytecode, config payload, unsafe archive type,
  consumer-local AES/codec/token authority, privacy route, or vendored privacy
  fallback. The shared wheel contains the acceptance catalogs plus
  `privacy_client.js`, `privacy_profile.js`, and `privacy_snapshot.js`.

## Source-suite validation

- `helto-privacy`: 648 tests passed in the sandbox; the three localhost-bound
  aiohttp cases were the only sandbox denials, and the complete 27-test
  middleware module passed with isolated localhost permission.
- Utils: 279 Python tests and 194 JavaScript tests passed.
- AIO: 354 tests passed.
- Director: 653 Python tests and its declared 17-file JavaScript command
  passed.
- Smart Prompt: 76 tests passed and `smart_prompt_manager.js` passed syntax
  validation.

No live ComfyUI service, user workflow, queue/history, browser profile, media,
key, credential, publication target, or production installation was accessed.
