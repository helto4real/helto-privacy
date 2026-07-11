# Shared browser privacy UI validation

Validated 2026-07-11 against a disposable ComfyUI 0.27.0 instance with
frontend 1.45.20 and an isolated `chrome-devtools-axi` browser profile. The
instance loaded one synthetic custom node that registered the local
`helto-privacy` checkout. It did not load the user's ComfyUI service, workflows,
media, keystore, browser profile, or credentials.

## Synthetic scenario

- Mounted two synthetic attested packs in opposite calls to the same shared
  module.
- Returned fixed product-data-free mode facts for one synthetic scope per pack.
- Broadcast a disposable synthetic session token and inspected only the public
  session snapshot and rendered DOM.
- Opened the surface by keyboard-accessible button and traversed its controls
  with `Tab`.
- Inserted synthetic canary content into a disposable field, applied the shared
  concealment contract, and inspected computed styles and DOM/accessibility
  exposure.

## Observed evidence

- Exactly one `role="region"`, labelled `Helto privacy`, served both packs.
- Neither served module exported the raw token read/write functions, session
  publisher, generic request client, or generic mode client. The profile
  transport exposed only canonical server-attested typed operations.
- The public session state became `unlocked`; neither the token nor either
  content canary appeared in surface text or session events.
- Setup, unlock, password change, lock, recovery, declared/effective mode,
  inheritance, floor, transition, and apply controls were present in the
  accessibility tree.
- A synthetic failed transition refreshed the server facts to `blocked`,
  rendered only the fixed `Privacy mode transition failed.` status, and did not
  expose the synthetic exception diagnostic.
- Canonical tokens resolved to peach `#fab387` for active/primary state and blue
  `#89b4fa` for focus. Keyboard focus rendered the blue border and three-pixel
  focus ring.
- The masked field resolved transparent glyph, text-fill, and caret colors on
  the same opaque `#181825` background token. Collapsed content resolved to
  opacity `0`, `pointer-events: none`, and `blur(8px)`.
- `concealPrivacyContent` removed synthetic value, placeholder, name, title,
  media/source attributes, subtree content, and accessibility exposure. Hover
  and focus did not restore content; `preparePrivacyReveal` restored only the
  empty shell for an authorized caller to populate.
- The disposable server log contained no privacy errors, warnings, or
  tracebacks. The frontend's unrelated fresh-profile 404s for absent user CSS
  and empty user-data directories were identified separately.

The shared surface is ordinary DOM and does not depend on legacy canvas versus
Nodes 2.0 rendering. This run proves it in the current Vue host. Full
legacy-canvas and Vue consumer-node parity remains a coordinated-suite
acceptance cell after the dependent repositories adopt this release.
