# Candidate suite `helto-suite-2026-07-15.2`

This is the unsigned local build and registration inventory for the corrected
coordinated candidate. It is not a public, supported,
installable-on-production, or activatable release. The immutable signed
`cutover-pending` manifest remains intentionally absent until the complete
acceptance evidence exists and signing is explicitly authorized.

## Release identity

- Previous supported suite: none (this is the first exact five-artifact suite)
- Rollback class: `data-snapshot-required-after-activation`
- Acceptance catalog SHA-256:
  `b57d738cf5ab5978fcf05fc9f3873230ea75157f8a216002a2956a7f2febfd9b`
- Historical fixture catalog SHA-256:
  `99f22f0faa3e7bddadd672878ac14ef846e70efe1cabda94416eca241f8295d8`
- Artifact staging directory: `/tmp/helto-suite-20260715-3/artifacts`

The two declared environment tuples both use Python `3.13.14`, ComfyUI
backend `0.27.0+e2a6e30d892402ffcf01d6280c8e2744a4448b9d`, and frontend
`1.45.20`; one uses the `legacy` renderer and one uses the `vue` renderer.

## Exact artifacts

| Distribution | Version | Source revision | Artifact | SHA-256 |
| --- | --- | --- | --- | --- |
| `helto-privacy` | `0.4.0` | `2e85c71f9aa22bd47ee6f13f2add83d111ab4591` | `helto_privacy-0.4.0-py3-none-any.whl` | `7eba6a19ce3859f1320e0ee252b24827ac1d1862594311bbf87fa3084e72d440` |
| `comfyui-utils` | `0.1.0` | `4bd0e2e49bd2e95c423b961f2feb8300abd41d77` | `comfyui-utils-0.1.0+4bd0e2e.tar` | `20d57f77004d421bc76645cd6ca127551976a21f5fd169bb1eaaf1571e8eab92` |
| `comfyui-all-on-one-image-generation-node` | `0.1.0` | `2237cbe1ee2d16e42d2e1975e52cef20ab1cf44e` | `comfyui-all-on-one-image-generation-node-0.1.0+2237cbe.tar` | `9cef534b575830235705354b652cf42e3fa9a154e051d0d1509a9be5dde44e10` |
| `comfyui-helto-director` | `0.0.1` | `738631f2f397cc6ef154ee8f416f5a8d20447927` | `comfyui-helto-director-0.0.1+738631f.tar` | `e59547f4a54798cd263bed46cfad87b4b839c66af0e4c1327714e56834d6e909` |
| `comfyui-helto-smartprompt` | `0.1.0` | `eec1c96866af5a1f434dfc869306474172fc68bb` | `comfyui-helto-smartprompt-0.1.0+eec1c96.tar` | `7e33011cbd8b040cc62ed03fc79e91c8c27c88ee50b60718174091e315168cc7` |

The canonical source repositories are the matching repositories under
`https://github.com/helto4real/`.

## Profile identities

| Profile | Distribution | Fingerprint |
| --- | --- | --- |
| `helto.comfyui-utils` | `comfyui-utils` | `517c7d90d335ac12fd30e7fb0eafba9976b8fb8c1be9cdfa55aa508463760cbe` |
| `helto.aio-image-generation` | `comfyui-all-on-one-image-generation-node` | `f63424f85dfa083277d43069d1a399f500f77e132f001a9355da20dab0f133a1` |
| `helto.director` | `comfyui-helto-director` | `948ad2440e27b7fdba7e40ac1928424afae3b8a19c27d859ee61ce25f42ab835` |
| `helto.smart-prompt-manager` | `comfyui-helto-smartprompt` | `5a352fd3fb086cd3418039368457e7a2fbd8b4ae81aa0deae6151d8bcbd22352` |

## Reproducibility and inspection evidence

- Each consumer archive was generated twice with `git archive` from its exact
  committed revision and compared byte-for-byte.
- The shared wheel is the byte-reproducible wheel built from shared revision
  `2e85c71f9aa22bd47ee6f13f2add83d111ab4591` with
  `SOURCE_DATE_EPOCH=1784104800`.
- Every consumer declares `helto-privacy==0.4.0` in requirements and project
  metadata. No declaration contains a local path, editable reference, Git URL,
  floating branch/range, or stale shared revision.
- Every consumer archive contains its required initializer, project and
  requirements metadata, profile builder/installer, and browser connector.
- Backend and browser profile fingerprints match for all four consumers.
- Archive scanning found no bytecode, config payload, unsafe archive type,
  consumer-local AES/codec/token authority, privacy route, or vendored privacy
  fallback. The shared wheel contains the acceptance catalogs plus
  `privacy_client.js`, `privacy_profile.js`, and `privacy_snapshot.js`.

## Clean installation and registration evidence

- A new Python `3.13.14` virtual environment started with empty site-packages.
  It installed only the candidate shared wheel plus pinned third-party wheels
  (`cryptography 49.0.0`, `cffi 2.0.0`, and `pycparser 3.0`) and extracted the
  four consumer artifacts into an isolated custom-node root.
- All four original `requirements.txt` files then resolved offline with
  `--no-index` and local `--find-links`; each reported the exact candidate
  `helto-privacy 0.4.0` as already satisfied. `pip check` reported no broken
  requirements. No editable install, checkout `PYTHONPATH`, sibling import,
  existing privacy state, or browser cache was present.
- The four real profile builders were imported from the extracted artifacts.
  Host-only `folder_paths`, `torch`, and `av` imports were synthetic stubs for
  this registration-only cell; no product adapter or profile declaration was
  replaced.
- All 24 backend registration orders ran in fresh processes. Every order
  produced the same four ready profiles and one installed shared runtime;
  duplicate identical registration remained idempotent. Canonical snapshot
  SHA-256:
  `2c16daad1e77290f57d88385304aeb816e8996ec374c18d64e5892bbed020ac3`.
- All 24 browser connector orders loaded the actual archived JavaScript module
  trees in fresh Node processes. Shared host imports were routed to one
  synthetic runtime module, all four exact connections were present, and a
  duplicate identical import retained module identity. Canonical snapshot
  SHA-256:
  `2a8cf434849bb414daf559737519f3598a28a93f15bb2d1102d49b3f40b4acd9`.

This registration evidence does not replace the required rendered legacy/Vue,
negative-installation, leak-oracle, fault, lifecycle, or release-rehearsal
cells. No live ComfyUI service, user workflow, queue/history, browser profile,
media, key, credential, publication target, or production installation was
accessed.
