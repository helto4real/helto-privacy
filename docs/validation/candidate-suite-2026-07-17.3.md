# Ready suite `helto-suite-2026-07-17.3`

This immutable replacement fixes Nodes 2.0/Vue layout feedback in Smart Prompt
Manager and Timeline Director. Manual node height is now authoritative and no
DOM-widget callback feeds the measured node height back into Vue layout.

The same acceptance pass also found and fixed Timeline Director's Vue privacy
binding: Vue DOM widgets expose a non-configurable `value` property, so the
transition guard now wraps the widget's supported `setValue` hook while keeping
writes fail-closed during privacy transitions.

## Signed identities

- Suite manifest digest: `59e270f06e9bd85289407924866259f60651d99f5e97188a97708a0a60dc4eea`
- Signed candidate record SHA-256: `ccce9e54510840133ff561bdd36c94f395925b966900734b4ad5052114ace8fb`
- Acceptance evidence digest: `9bdc533b9779e050384e2b4cd4d611c7d14d795a6c04868ef37852b6ca2d42e1`
- Signed acceptance record SHA-256: `4e1c76920dbce902207912f28a336d870dc28c1106d4cb596507dbd21e23d9fa`
- Acceptance proof-index SHA-256: `a636bdf2aba249f2f123a0a82b4f84563468a5212e9c48110a52db54b0ffeaa9`
- Signed promotion record SHA-256: `b5ebd062143b4a3f8e5c23cdee9249e938d39d78761fc9266b7b77aee40eb708`
- Manifest signer: `helto-suite-release-ed25519-e94ef2d597eb4276`
- Acceptance signer: `helto-acceptance-ed25519-734747580e2c6208`
- Promotion signer: `helto-suite-promotion-ed25519-96aad83c09c02860`
- Rollback class: `data-snapshot-required-after-activation`

All Ed25519 signatures verified against the packaged public trust roots. The
component Git tags are OpenPGP-signed by fingerprint
`3C05EB796A428085D295B340392AFB734FE22D59`.

## Exact artifact set

| Distribution | Version | Source revision | Artifact SHA-256 |
| --- | --- | --- | --- |
| `helto-privacy` | `0.4.5` | `1b0aa03fbb5c03b1fd31175b502316581bff03f1` | `ab7fe5ee69e1dd175d405fcb0617a2046b121291644b6396de80fcec615b2627` |
| `comfyui-utils` | `0.1.6` | `7b0c3e9731f8d11ceac7895d078c7fb54e6e06c7` | `06fa4e45b072743e4fc38fb0bb5a3d78ade6d1be3b5170163b2970a7ce15d667` |
| `comfyui-all-on-one-image-generation-node` | `0.1.7` | `3edc6c7020daa586e0ec8548d6067e4862474c08` | `9285cf225b39b17d524c3d8995a4c02836fc6b357934721b6283dc4d7cab9d39` |
| `comfyui-helto-director` | `0.0.7` | `280336cd53c96229ce998bebdb06ca03d06d53eb` | `0dfff53780dbc636a2a81359130789312823667354c4adcede59eda83c14ca0d` |
| `comfyui-helto-smartprompt` | `0.1.6` | `1a137b40a3a7039d5791f00ace41bf4d3f65f4e3` | `35f4d79173f2b66269077f3f601a7a82313f4cb149b9f5260bd4f2176a615a8a` |

## Acceptance

- 44/44 catalog cells passed without warnings, errors, retries, or exclusions.
- 24/24 consumer registration orders produced one identical suite snapshot.
- Shared runtime: 661 Python tests passed for the unchanged exact wheel.
- Utils: 280 Python tests, 19 Python subtests, and 12 JavaScript suites passed.
- AIO: 354 Python tests passed.
- Director: 653 Python tests and all 18 JavaScript suites passed.
- Smart Prompt: 77 tests passed.
- In the CPU-only Nodes 2.0 browser, Smart Prompt remained `[448, 900]` and
  Director remained `[400, 700]` over two settling intervals. Both frames used
  `height: 100%`, `max-height: none`, and both privacy UIs were available.

## Safety boundary

All browser and ComfyUI checks used `--cpu`, temporary product directories, a
clean ComfyUI archive, an isolated browser profile, and synthetic privacy state.
No real workflow, prompt, queue, history, media, browser profile, credential,
key bytes, decrypted value, or KJNodes code was read or changed.

The signed promotion authorizes the suite as ready. Installing it in the real
ComfyUI environment still requires exact artifact installation, restart,
browser attestation, and explicit activation against a complete current backup.
