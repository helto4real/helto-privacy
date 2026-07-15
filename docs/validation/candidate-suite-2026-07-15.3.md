# Candidate suite `helto-suite-2026-07-15.3`

This is the signed local `cutover-pending` candidate assembled after exact
clean-install, registration, negative-installation, rendered, leak, fault,
lifecycle, and repository checks. It is not published, supported, activatable
on a real installation, or authorized for production use.

## Immutable candidate identities

- Candidate manifest SHA-256:
  `f0901ec02c1a614633503c3eff768af5a1dda070ef272b2ad86e38de2dbdadb7`
- Acceptance evidence SHA-256:
  `07f3644dfa78d96586c02a0d1c76ea5b8a0d24fd372d17f43f6e95c42c15ae24`
- Acceptance proof-index SHA-256:
  `50f7f2da9e2631e4f067e91ae44d6a132f4474015656c32d11d11e7bc748635c`
- Acceptance catalog SHA-256:
  `b57d738cf5ab5978fcf05fc9f3873230ea75157f8a216002a2956a7f2febfd9b`
- Historical fixture catalog SHA-256:
  `99f22f0faa3e7bddadd672878ac14ef846e70efe1cabda94416eca241f8295d8`
- Signed candidate record SHA-256:
  `1c6c02086d5c3e9881478c90fc676e0994d08a72cbecf35ec74e7404aa995db8`
- Signed acceptance record SHA-256:
  `907b2e133951acbd402db0550a3f8f6d95317b47065791d4a4794780e4a0b826`
- Trusted-signer registry SHA-256:
  `a4ab1ade9593c6bed6f6bcf4b722948032815eebadf4f98a4c7626f76ee285b9`
- Manifest signer:
  `helto-suite-release-ed25519-e94ef2d597eb4276`
- Acceptance signer:
  `helto-acceptance-ed25519-734747580e2c6208`
- Previous supported suite: none
- Rollback class: `data-snapshot-required-after-activation`
- Local artifact staging: `/tmp/helto-suite-20260715-4/artifacts`

The canonical source and signed records are:

- `candidate-manifest-2026-07-15.3.unsigned.json`
- `candidate-manifest-2026-07-15.3.signed.json`
- `acceptance-evidence-2026-07-15.3.unsigned.json`
- `acceptance-evidence-2026-07-15.3.signed.json`
- `acceptance-proof-index-2026-07-15.3.json`
- `trusted-signers-2026.json` and its referenced public keys
- `publication-2026-07-15.3.json`

The evidence contains both declared tuples: Python `3.13.14`, ComfyUI backend
`0.27.0+e2a6e30d892402ffcf01d6280c8e2744a4448b9d`, frontend `1.45.20`,
and the `legacy` or `vue` renderer. Each tuple has all 21 catalog results marked
pass, all 24 profile registration orders, seed `2026071503`, zero retries, and
no warnings, errors, skips, xfails, or exclusions.

## Exact artifacts

| Distribution | Version | Source revision | Artifact SHA-256 |
| --- | --- | --- | --- |
| `helto-privacy` | `0.4.0` | `2e85c71f9aa22bd47ee6f13f2add83d111ab4591` | `7eba6a19ce3859f1320e0ee252b24827ac1d1862594311bbf87fa3084e72d440` |
| `comfyui-utils` | `0.1.0` | `4bd0e2e49bd2e95c423b961f2feb8300abd41d77` | `20d57f77004d421bc76645cd6ca127551976a21f5fd169bb1eaaf1571e8eab92` |
| `comfyui-all-on-one-image-generation-node` | `0.1.0` | `1c5ee8604ce8160dab5142113e7b491c703b876d` | `db5a80f6335fe7c55dcd538e584b7f6b6c7a48af36e65a77a7e2b7e8e09c1219` |
| `comfyui-helto-director` | `0.0.1` | `738631f2f397cc6ef154ee8f416f5a8d20447927` | `e59547f4a54798cd263bed46cfad87b4b839c66af0e4c1327714e56834d6e909` |
| `comfyui-helto-smartprompt` | `0.1.0` | `eec1c96866af5a1f434dfc869306474172fc68bb` | `7e33011cbd8b040cc62ed03fc79e91c8c27c88ee50b60718174091e315168cc7` |

The AIO archive was generated twice with `git archive` from `1c5ee86` and
matched byte-for-byte. The other four artifacts are the unchanged reproducible
artifacts from the corrected `.2` inventory. All four consumers retain the
exact `helto-privacy==0.4.0` requirement and contain no local path, editable
reference, Git dependency, floating range, consumer-local privacy engine, or
vendored fallback.

## Public cutover-pending publication

Each exact source revision has a signed annotated version tag and an immutable
GitHub prerelease containing the already-tested artifact. Fresh downloads from
all five releases matched the signed candidate hashes. Repository release
immutability is enabled, and GitHub reports every package release as
`immutable: true`.

| Distribution | Tag | Public release |
| --- | --- | --- |
| `helto-privacy` | `v0.4.0` | [cutover-pending release](https://github.com/helto4real/helto-privacy/releases/tag/v0.4.0) |
| `comfyui-utils` | `v0.1.0` | [cutover-pending release](https://github.com/helto4real/comfyui-utils/releases/tag/v0.1.0) |
| `comfyui-all-on-one-image-generation-node` | `v0.1.0` | [cutover-pending release](https://github.com/helto4real/comfyui-all-on-one-image-generation-node/releases/tag/v0.1.0) |
| `comfyui-helto-director` | `v0.0.1` | [cutover-pending release](https://github.com/helto4real/comfyui-helto-director/releases/tag/v0.0.1) |
| `comfyui-helto-smartprompt` | `v0.1.0` | [cutover-pending release](https://github.com/helto4real/comfyui-helto-smartprompt/releases/tag/v0.1.0) |

The suite index is the signed annotated tag and prerelease
`helto-suite-2026-07-15.3` in `helto-privacy`. It contains the five artifacts,
signed candidate and evidence records, proof index, trust metadata, and exact
checksums. None of these prereleases is a ready-promotion record.

## Clean install and registration

- A new Python `3.13.14` virtual environment installed the shared wheel and
  pinned third-party wheels offline from local artifacts. `pip check` passed,
  and isolated import resolved to that environment's site-packages rather than
  any checkout.
- All 24 real ComfyUI consumer load orders ran in fresh processes against the
  extracted exact archives. They produced one shared runtime, four exact
  profiles, and one canonical route family. Canonical observation SHA-256:
  `84a8f672f41e5780c7a0545829246c50aa9c5900448560bd22cae6bfee1d2fcb`.
- Thirteen negative inventory cases covered missing/stale shared or consumer
  artifacts, server/browser digest drift, corrupt or absent profiles,
  duplicate artifacts/profile IDs, conflicting declarations, and interrupted
  repair. Every case blocked the privacy gate; a fresh exact inventory remained
  `activation-required`.

## Rendered and leak evidence

Disposable ComfyUI roots and isolated `chrome-devtools-axi` profiles exercised
both renderers with synthetic prompts only.

- Legacy and Vue both showed explicit-public prompts, auto-masked private idle
  prompts, retained the live editable value, and preserved the selected range
  after mouse release.
- In both renderers the connected control held the live synthetic plaintext
  while widget/workflow storage held a protected envelope. Serialization
  contained `ciphertext` and `nonce` but not the canary.
- The canary was absent from serialized workflow state, resource URLs, browser
  console inventory, and network inventory.
- Pre-initializing the synthetic browser session before the active UI load
  removed the earlier fail-closed Queue Manager and snapshot startup errors;
  those messages were caused by the original harness ordering, not a product
  fallback.

The rehearsal bootstrap used fresh ephemeral test-only release, promotion, and
activation keys. Its provisional manifest digest is not the candidate identity
and is intentionally excluded from the unsigned candidate records.

## Repository, fault, and lifecycle evidence

- Shared runtime: 651 Python tests passed; historical fixtures reproduced
  byte-for-byte.
- AIO: 354 Python and 24 JavaScript tests passed.
- Utils: 279 Python tests, 19 Python subtests, and 194 JavaScript tests passed.
- Director: 653 Python tests and all 17 declared JavaScript suites passed.
- Smart Prompt: 76 documented `unittest` tests passed.
- All five worktrees passed `git diff --check` and were clean at evidence
  capture. The shared artifact's runtime/tests match the tested documentation
  HEAD byte-for-byte.

These suites cover deterministic exception and `BaseException` cleanup,
encryption/persistence/replace/streaming faults, restart invalidation,
transaction rollback/resume, cache/session cleanup, private defaults, locked
byte preservation, legacy readers, records, artifacts/leases, execution grants,
and cross-pack snapshot barriers with synthetic fixtures.

## Signature verification and authorization boundary

The exact candidate manifest and local pre-publication acceptance evidence were
Ed25519-signed after explicit user authorization. Verification used the tracked
public keys and returned `cutover-pending`; no promotion signature exists. The
private keys are untracked, repository-local files under
`.git/helto-signing/`, with a `0700` directory and `0600` key files.

The five package branches, signed tags, and cutover-pending prereleases were
published after separate explicit user authorization. No live installation,
activation, promotion, or real ComfyUI workflow/browser/runtime access
occurred. Public-artifact acceptance reproduction is the next release gate.
