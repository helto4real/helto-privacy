# Ready suite `helto-suite-2026-07-16.3`

This immutable replacement adds fail-closed compatibility for the exact trusted
KJNodes CrossGraphSetGet submission wrapper. KJNodes is not modified or disabled.
The shared runtime accepts only the pinned SHA-256 source fingerprint; unknown,
changed, or late wrappers remain blocked.

## Signed identities

- Suite manifest digest:
  `946a3a4eb4be098adc7abf53ab33f6ee39b015a03e67a028a679f25e1f848ecf`
- Signed candidate record SHA-256:
  `cd35310c81cfca09c268051c640026f000d569240066362c22c3fd1ebadb169e`
- Acceptance evidence digest:
  `89903e2d6b0a08690dea78996f9c48197e2614a6b425d0dad6dd65974f4c3155`
- Signed acceptance record SHA-256:
  `9da3958b0a08eb9d67b4f3139fdaef4b8795710e0f5155b9291914e027941ebe`
- Acceptance proof-index SHA-256:
  `1328a2d858b73f50a136a3637d8a445daa61e64c1bd7c2628900016405ed635b`
- Public-reproduction evidence digest:
  `fab86e3c921032c9736eb8b94a2a6b5f983edd996640a74fbe11dc2c3ac86808`
- Signed public-reproduction record SHA-256:
  `ed62c1866d06b1ca9c0a1d647149b2a88aa98f46f1177ed710034fb5f16196b4`
- Public-reproduction proof-index SHA-256:
  `5d5a45968000e2d8e0033492c3ca8a65eb0f9df846e823c0e2a51a00047ef1ba`
- Signed promotion record SHA-256:
  `7145f54f85afd86633bb090bbaf5f0085897ac282403bc61bab2a74a39f7af52`
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
| `helto-privacy` | `0.4.2` | `4a48ff0bb518eee385881d30cf8632f29a65cb03` | `2e0c31106383cb245cb479155fa2778b5fc86c32ab142be0a290c236a3a8c8bf` |
| `comfyui-utils` | `0.1.2` | `77872eba9874f9b32644b65f2449e183df62daff` | `aa454c1979f9e3b49d350335b862756873f471aae4eccb9b6545ba394a488265` |
| `comfyui-all-on-one-image-generation-node` | `0.1.3` | `cf025e8381bb4a40b34a84426347192840daf900` | `57c4f9351b11e8f744c60834b31ca3b98db8c5a3fa7d1c01d8bf3c3748c4ca7c` |
| `comfyui-helto-director` | `0.0.3` | `b29105ccc09aa4b5849c81adde1ebbdd58875c03` | `7bb2f15e57af98f5e54ac6b51836ee6c8758be0e941cf20cb24083afb4dc48cf` |
| `comfyui-helto-smartprompt` | `0.1.2` | `6e2e5c7d5b6af63185de1eec0946370d5cf9150e` | `5096a408ce02b57995004f81a6667429fce35c85bcaab6c081702249b6652e0e` |

## Acceptance and public reproduction

The exact wheel was installed into fresh environments and the four consumer
archives were extracted into canonical custom-node directories. Tests used
Python `3.13.14`, ComfyUI backend
`0.27.0+e2a6e30d892402ffcf01d6280c8e2744a4448b9d`, frontend `1.45.20`,
and both legacy and Nodes 2.0/Vue renderers.

- 44/44 catalog cells passed with no warnings, errors, skips, retries, xfails,
  or exclusions.
- 24/24 consumer registration orders produced one identical process-suite
  snapshot in both the local and public-download environments.
- Two independent builds of every artifact were byte-identical.
- Shared runtime: 649 Python tests passed and 6 were skipped.
- Utils: 279 Python tests, 19 Python subtests, and all 12 JavaScript test files
  passed.
- AIO: 354 Python tests passed, including its JavaScript integration checks.
- Director: 653 Python tests and all 17 JavaScript suites passed.
- Smart Prompt: 76 Python/unittest checks and all 4 JavaScript suites passed.

Both production-bootstrap passes used the exact artifact set. For legacy and
Vue, the process started at `ready`, then changed to `activation-required` with
`explicit_activation_required` after the real isolated browser attested the
exact manifest. The keystore stayed uninitialized and activation was not
performed. Extension resources were canonical and unique; there were no privacy
profile, manifest, or renderer conflicts.

After the five component prereleases were published, all five artifacts were
downloaded fresh from GitHub. Their bytes matched the manifest, and a second
fresh wheel environment plus canonical archive extraction reproduced all 24
registration orders and both renderer transitions. The public-reproduction
record is signed and bound to the exact suite manifest.

## Safety and authorization boundary

Every accepted browser and ComfyUI run used `--cpu`, empty temporary product
directories, a clean ComfyUI Git archive, and isolated HOME, XDG, user, model,
input, output, temp, database, keystore, session, mode, artifact, operation,
relocation, migration, and activation paths. Accepted runs used only a newly
created blank workflow. No real workflow, queue, history, media, browser profile,
credential, key value, decrypted value, or prompt content was read or changed.

Two discarded startup attempts used the real ComfyUI core checkout before the
clean core archive was prepared. ComfyUI automatically loaded its local
extra-model-paths configuration before command-line directory overrides, so
those model search paths were registered and may have had filenames enumerated
during node initialization. The attempts used CPU and isolated user/workflow,
database, output, and Helto state; no model file content, workflow, prompt, queue,
history, media, key, credential, decrypted value, or browser profile was read or
changed. Both processes were stopped, and no evidence from them was accepted.

The signed promotion authorizes the suite as `ready`, but it does not activate
privacy, access old workflows, or authorize changes to the user's real ComfyUI
installation. Installation and activation remain separate operations.
