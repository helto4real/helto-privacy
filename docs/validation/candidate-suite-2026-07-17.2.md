# Ready suite `helto-suite-2026-07-17.2`

This immutable replacement corrects browser authorization after a ComfyUI
backend restart. A fresh browser must hold its own authorization token even
when the backend keystore session is already unlocked. The protected route now
preserves `PRIVACY_TOKEN_REQUIRED`, allowing the shared UI to show the unlock
dialog instead of a generic privacy snapshot error.

## Signed identities

- Suite manifest digest:
  `fa17e90a952b276e52ad4be86fc010c880b98e71dc1efee0f416f3d885a43094`
- Signed candidate record SHA-256:
  `63ac525d8ec00ed150085cbcaf283738ff5135f5d5cc6d7f77fd38bed0500a9c`
- Acceptance evidence digest:
  `01784a44db7e174addad4806af2a89a7d20d7eddf3ca5a8b27df99b28cffaf74`
- Signed acceptance record SHA-256:
  `c68a661933672e7eb7e3f918f5a0d9667b92f67342d4c7348a751512b4d63567`
- Acceptance proof-index SHA-256:
  `b69309ecbbd949e06538bb08928f176306a1e0cd67b87098a1943dd04d4fb1e5`
- Public-reproduction evidence digest:
  `e352c7548b3c336b497839452909461305f503970a70f9c1774cfa0209e73a2d`
- Signed public-reproduction record SHA-256:
  `d898a13647dcded40e31be50ef6a4b83ecdadb2a35bd1caf4393ec0409b9f0fe`
- Public-reproduction proof-index SHA-256:
  `0557556b7f7a5a25051407b0b92fd5b28e3e31b8b69006320215f94935718e6a`
- Signed promotion record SHA-256:
  `e9eae99935a0a8068ae570818a62df8a48bddfd9f0ef63d33e0823905e9592fa`
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
| `comfyui-utils` | `0.1.5` | `83ce9ad1e47e85cfde592e2b403a0f282a19c51d` | `5fc09726153ec5ea2a101b22156cbb4f2296aae815b4adb5ebeead36a0cba486` |
| `comfyui-all-on-one-image-generation-node` | `0.1.6` | `5c05cdfe187034a5e6e63a6a70eee6d14315e825` | `1604837231af629933ffdb75b3ba7f64e406d2e97430cd0ed90a086082eac209` |
| `comfyui-helto-director` | `0.0.6` | `1591aeb2a70701085239ee2db80c0c3040ee1bae` | `e50997f1daeded42eab39afef90cd3a081280647f868fc8ae9ebe5bfd474129a` |
| `comfyui-helto-smartprompt` | `0.1.5` | `457aadd5709bd6d9c043ddfdb72106e5ab7c1858` | `d859e3c534221b48ac72f489e5c59f9788f6354a6140bc085e417385c16c7e9a` |

## Acceptance and public reproduction

The exact wheel was installed into a fresh environment and the four consumer
archives were extracted into canonical custom-node directories. Tests used
Python `3.13.14`, ComfyUI backend
`0.27.0+e2a6e30d892402ffcf01d6280c8e2744a4448b9d`, frontend `1.45.20`,
and both legacy and Nodes 2.0/Vue renderer evidence.

- 44/44 catalog cells passed with no warnings, errors, retries, or exclusions.
- 24/24 consumer registration orders produced one identical process-suite
  snapshot.
- Two independent wheel builds were byte-identical.
- Shared runtime: 661 Python tests passed.
- Utils: 280 Python tests, 19 Python subtests, and 194 JavaScript tests passed.
- AIO: 354 Python tests and 26 JavaScript tests passed.
- Director: 653 Python tests and all 17 JavaScript suites passed.
- Smart Prompt: 76 Python/unittest checks and all 4 JavaScript suites passed.
- Every public component artifact was downloaded again from GitHub and matched
  the signed manifest byte for byte.

The CPU-only production bootstrap performed explicit activation with a
synthetic pre-activation backup digest. After restarting the backend, a fresh
isolated browser with no local authorization token observed the expected
`explicit_process_activation_required` gate. After process activation, the UI
showed `Unlock Privacy Keystore`; unlocking succeeded and the protected Queue
Manager load returned an empty synthetic revision without
`PrivacySnapshotError` or `PrivacyPackConnectionError`.

## Safety and authorization boundary

All accepted browser and ComfyUI runs used `--cpu`, temporary product
directories, a clean ComfyUI archive, isolated browser profiles, and synthetic
privacy state. No real workflow, prompt, queue, history, media, browser profile,
credential, key bytes, decrypted value, or KJNodes code was read or changed.

The signed promotion authorizes the suite as `ready`; it does not activate
privacy or authorize access to old workflows in the user's real ComfyUI
installation. Real activation still requires the user's complete
pre-activation backup SHA-256 digest.
