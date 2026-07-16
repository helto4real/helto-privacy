# Candidate suite `helto-suite-2026-07-16.1`

This immutable `cutover-pending` suite replaces the failed
`helto-suite-2026-07-15.3` candidate. Its signed manifest contains the corrected
AIO `v0.1.1` artifact and the four unchanged artifacts from the previous
candidate. The original public-only reproduction passed its declared catalog,
but the later promotion preflight found that the catalog had not exercised a
production process-suite bootstrap. The suite is therefore not promotable and
is superseded by a new immutable candidate rather than modified.

## Signed identities

- Candidate manifest SHA-256:
  `ceaf87478eea1dba5ff8fe5fd6ebe4e53f27e812f49726b3fa85392f0d9d4bc9`
- Acceptance evidence SHA-256:
  `fccc636a53047caf50cfe1d548535977574cf278303e6fdfbea137bd5f79ee5a`
- Acceptance proof-index SHA-256:
  `ca1548fbaef1fe70de73f2470d160c18232787af394e181dd78a8e5ef8b3a820`
- Signed candidate record SHA-256:
  `85400ceea51ec0849d9fa968ae8e22ce28c1ce0a44fe2254676fecd3f332ce84`
- Signed acceptance record SHA-256:
  `710c79663fff3261f4d343c5ab4af01dfad5b61d03a8ab20e5e4b48a89a44aaa`
- Manifest signer: `helto-suite-release-ed25519-e94ef2d597eb4276`
- Acceptance signer: `helto-acceptance-ed25519-734747580e2c6208`
- Rollback class: `data-snapshot-required-after-activation`

## Exact artifact set

| Distribution | Version | Source revision | Artifact SHA-256 |
| --- | --- | --- | --- |
| `helto-privacy` | `0.4.0` | `2e85c71f9aa22bd47ee6f13f2add83d111ab4591` | `7eba6a19ce3859f1320e0ee252b24827ac1d1862594311bbf87fa3084e72d440` |
| `comfyui-utils` | `0.1.0` | `4bd0e2e49bd2e95c423b961f2feb8300abd41d77` | `20d57f77004d421bc76645cd6ca127551976a21f5fd169bb1eaaf1571e8eab92` |
| `comfyui-all-on-one-image-generation-node` | `0.1.1` | `6570804a02c945090bc8009e42c69162d6e1f533` | `d14bb30fb16e85a37b7ce1d899f3dc0354a2b216a9a1463e0fcae579f146d7aa` |
| `comfyui-helto-director` | `0.0.1` | `738631f2f397cc6ef154ee8f416f5a8d20447927` | `e59547f4a54798cd263bed46cfad87b4b839c66af0e4c1327714e56834d6e909` |
| `comfyui-helto-smartprompt` | `0.1.0` | `eec1c96866af5a1f434dfc869306474172fc68bb` | `7e33011cbd8b040cc62ed03fc79e91c8c27c88ee50b60718174091e315168cc7` |

All package releases and the suite release are immutable GitHub prereleases.
Fresh downloads of the 14 suite assets passed `SHA256SUMS`; both Ed25519
records and the OpenPGP suite tag verified. Publication details are recorded in
`publication-2026-07-16.1.json`.

## Acceptance and public reproduction

Both the pre-publication evidence and fresh public-download reproduction used
Python `3.13.14`, ComfyUI backend
`0.27.0+e2a6e30d892402ffcf01d6280c8e2744a4448b9d`, frontend `1.45.20`,
and both `legacy` and `vue` renderers. Disposable ComfyUI instances ran with
`--cpu`, isolated user/model/input/output/temp/session directories, no shared
models, and synthetic data only.

- 42/42 acceptance catalog cells passed with zero warnings, errors, skips,
  retries, xfails, or exclusions.
- 24/24 real ComfyUI consumer registration orders produced the same canonical
  observation.
- 13/13 negative inventory cases blocked correctly; the exact repaired
  inventory remained `activation-required`.
- Shared runtime: 651 Python tests passed.
- AIO: 354 Python and 26 JavaScript tests passed.
- Utils: 279 Python tests, 19 Python subtests, and 194 JavaScript tests passed.
- Director: 653 Python tests and all 17 declared JavaScript suites passed.
- Smart Prompt: 76 documented tests passed.

For both renderers, an AIO private prompt was empty in its idle visual and
accessibility surfaces, revealed during authorized pointer/focus interaction,
kept the selected `SYNTHETIC` range after mouse release, and returned to empty
after pointer leave. Workflow serialization contained a
`helto.aio-image-generate.v2` envelope and no synthetic plaintext. Known
frontend startup messages for an absent disposable previous workflow and
`user.css` were recorded separately; no functional privacy request failed.

The signed public reproduction is bound to the candidate manifest digest:

- reproduction evidence SHA-256:
  `2811cc879480b6425e3642d711cc38a7265fee89199f72150ce9bc37cf085dfd`
- signed reproduction record SHA-256:
  `3fa0222022312d7d0b7a0ca56508e5f1915ca3c2197efc880274cf6f89e71b4d`
- reproduction proof-index SHA-256:
  `f82c6fea3301ada3a65a756a5141ea1d36459ca3290d1aef3719470f17b35705`
- zero-waiver gate: `pass`

Canonical records are
`candidate-manifest-2026-07-16.1.{unsigned,signed}.json`,
`acceptance-evidence-2026-07-16.1.{unsigned,signed}.json`,
`acceptance-proof-index-2026-07-16.1.json`,
`public-reproduction-2026-07-16.1.json`,
`public-reproduction-evidence-2026-07-16.1.signed.json`, and
`public-reproduction-proof-index-2026-07-16.1.json`.

## Authorization boundary

No real ComfyUI workflow, queue, history, media, browser profile, runtime,
custom-node link, credential, or key content was inspected or changed. Every
temporary browser and ComfyUI process is stopped. The suite remains
`cutover-pending`; public reproduction success does not itself authorize a
promotion signature, real installation, activation, or old-workflow access.

## Promotion preflight failure

The authorized promotion preflight proved three missing production paths that
the disposable acceptance bootstrap had supplied only for the test process:

- no published component loaded the detached signed manifest and promotion into
  the real ComfyUI process;
- none of the four published consumers registered its suite declaration; and
- consumer frontends required `active` before connecting, so they could not
  submit the browser attestation needed to reach `activation-required`.

Installing the five immutable artifacts would consequently leave the real
server `incomplete`. No real installation was attempted, and the locally
created promotion record was discarded before commit or publication. The
replacement candidate must exercise its packaged bootstrap from a public-only
install and prove the full `ready` to `activation-required` transition.
