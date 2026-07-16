# Ready suite `helto-suite-2026-07-16.2`

This immutable replacement closes the production-bootstrap gap found in
`helto-suite-2026-07-16.1`. Each published consumer now carries its exact suite
declaration, and the shared package loads the detached signed manifest and
promotion into the real ComfyUI process before browser verification.

## Signed identities

- Suite manifest digest:
  `67be7afd73534b8a0c53ab67e17678d69fc8ca20aee60e545200533c1413236e`
- Signed candidate record SHA-256:
  `436cac5dbaadeb4f9f94258331d9ef01026b5dc58c374c33ae4bc216215a5b51`
- Acceptance evidence digest:
  `c3ab15e2b72b32a19f75a0cfea315ab27b40153b88f5c3e628ea90fcc33c6254`
- Signed acceptance record SHA-256:
  `0096e26eb4f0d23614e8a414921a5ff201fa505d0158a1437e80a669b2323b8b`
- Acceptance proof-index SHA-256:
  `f47439a1d20d05ce8135b6d825bf4f562d9111bf9b64b2daf4bf5f7047c24606`
- Public-reproduction evidence digest:
  `ce966f6fb8fc8fe9035251aada6d9dd37d7b09157260d109b641f61c191884e9`
- Signed public-reproduction record SHA-256:
  `bc4cb4bb860ce0198608021001dd2670e76fc929faaa6f460719ebefc4105d02`
- Public-reproduction proof-index SHA-256:
  `87b454b19e77908a270cf3ab47f6304b48dcecb5f347f1eba17daa9b8ae1cedd`
- Signed promotion record SHA-256:
  `01d42bd44efeea95efb0302da09b856054466aace9a1b643094791a33851b742`
- Manifest signer: `helto-suite-release-ed25519-e94ef2d597eb4276`
- Acceptance signer: `helto-acceptance-ed25519-734747580e2c6208`
- Promotion signer: `helto-suite-promotion-ed25519-96aad83c09c02860`
- Rollback class: `data-snapshot-required-after-activation`

All Ed25519 signatures verified against the packaged public trust roots. The
component and suite Git tags are OpenPGP-signed by fingerprint
`3C05EB796A428085D295B340392AFB734FE22D59`.

## Exact artifact set

| Distribution | Version | Source revision | Artifact SHA-256 |
| --- | --- | --- | --- |
| `helto-privacy` | `0.4.1` | `0ffdc15bfb03136d0d234f49ac9497bd425d0631` | `69c461c0942b5d14a28a40c162c2ac4ca1ad6ef2eb0c7fedf45402783a473169` |
| `comfyui-utils` | `0.1.1` | `7c1053f33abf695e5d02514d56db6c5b007c19ea` | `e4c80568d73ea2a84870b6e3afa6f82d94b1c82642082ccd9d304fccd47023b0` |
| `comfyui-all-on-one-image-generation-node` | `0.1.2` | `8112dc6392787f60019c464ba4dd6962551166c7` | `c079b2ebc245b8e8ffe1035e195b12480bf3cf92a9cc81a131dba4ca98e8dc66` |
| `comfyui-helto-director` | `0.0.2` | `d2b51fc6ecce0f1b693c3c8b535832e8aee816ed` | `bb10d5222a5d74387e31eaa640ae9a35fb966f432b3a3393ba4c7486ca4b4a97` |
| `comfyui-helto-smartprompt` | `0.1.1` | `9ccd58d66947a4b749cf51e80516b10f6adad094` | `c18939beb10f8aa6f231bff644d3675883b63dfe6e121b4340dea135939530d5` |

## Acceptance and public reproduction

The exact wheel was installed into a fresh environment and the four consumer
archives were extracted into canonical custom-node directories. Tests used
Python `3.13.14`, ComfyUI backend
`0.27.0+e2a6e30d892402ffcf01d6280c8e2744a4448b9d`, frontend `1.45.20`,
and both legacy and Nodes 2.0/Vue renderers.

- 44/44 catalog cells passed with no warnings, errors, skips, retries, xfails,
  or exclusions.
- 24/24 consumer registration orders produced one identical process-suite
  snapshot.
- The exact installed wheel resolved from the fresh environment, and two
  independent wheel builds were byte-identical.
- Shared runtime: 654 Python tests passed.
- Utils: 279 Python tests, 19 Python subtests, and all 12 JavaScript test files
  passed.
- AIO: 354 Python tests and its JavaScript suite passed.
- Director: 653 Python tests and all 17 JavaScript suites passed.
- Smart Prompt: 76 Python/unittest checks and all 4 JavaScript suites passed.

The production-bootstrap proof used real ComfyUI processes with the packaged
bootstrap, packaged trust roots, and consumer declarations. Both renderer
processes started at `ready`, then changed to `activation-required` with
`explicit_activation_required` after a real isolated browser attested the exact
manifest. The keystore stayed uninitialized and activation was not performed.
All extension resources used canonical package paths; there were no duplicate
versioned resources or `browser_profile_conflict` messages.

After the five component prereleases were published, all five artifacts were
downloaded fresh from GitHub. Their bytes matched the manifest, and a second
fresh wheel environment plus canonical archive extraction reproduced the same
legacy and Vue production-bootstrap transition. The public-reproduction record
is signed and bound to the exact suite manifest.

The ready suite prerelease was then published with 22 assets. A fresh download
verified every one of the 21 entries in `SHA256SUMS`, the OpenPGP suite tag, the
signed manifest, the complete signed acceptance evidence, the signed public
reproduction record, and the signed readiness promotion.

## Safety and authorization boundary

All accepted browser and ComfyUI runs used `--cpu`, isolated HOME, XDG,
custom-node, user, model, input, output, temp, database, keystore, session,
mode, artifact, operation, relocation, migration, and activation paths. They
used empty or built-in synthetic frontend state only. No real workflow, queue,
history, media, browser profile, credential, key value, decrypted value, or
prompt content was read or changed.

During an earlier discarded smoke attempt, the launcher isolated ComfyUI user
state but initially inherited the default Helto keystore path. The process was
stopped immediately. Only product-data-free status booleans were observed; no
path, key, credential, prompt, workflow, queue/history, media, or decrypted
content was read. Every accepted run explicitly redirected all Helto paths to
temporary directories.

The signed promotion authorizes the suite as `ready`, but it does not activate
privacy, access old workflows, or authorize changes to the user's real ComfyUI
installation. Real installation and activation remain separate user-approved
steps.
