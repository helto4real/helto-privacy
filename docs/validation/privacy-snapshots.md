# Privacy snapshot validation

Validated 2026-07-11 against the local `helto-privacy` checkout, a disposable
ComfyUI 0.27.0 instance, and frontend 1.45.20. The instance loaded one
synthetic custom node and used empty temporary input, output, user, model, and
database locations. It did not load the user's ComfyUI service, workflows,
media, keystore, browser profile, or credentials.

## Automated evidence

- The complete Python and JavaScript suite passed: 143 tests.
- Real current-envelope decryption distinguishes verified, locked, and failed
  state without exposing plaintext or cryptographic diagnostics.
- Readable legacy values are rewritten through the current codec; unsupported
  values fail closed.
- Equal concurrent preparations share one encryption result, while a stale
  generation cannot overwrite a newer edit.
- One immutable transaction remains pinned across workflow and executable
  projections even when a newer generation settles during the operation.
- Consumer-owned async save/export/queue-manager callbacks use the same pinned,
  serialized transaction boundary as graph-to-prompt.
- The callback's scoped graph-to-prompt invoker reuses its transaction without
  deadlocking; a generation change before use aborts as stale, while unrelated
  app graph-to-prompt calls remain serialized behind the active callback.
- Locking invalidates executable use of an already-active transaction while
  leaving its exact protected workflow projection available to fail closed.
- Locked and failed current envelopes remain byte-exact workflow-save state,
  cannot be replaced, cannot enter execution projections, and make
  execution-bearing settlement fail before queue logic.
- Public effective mode bypasses private protection; changing back to private
  mode rechecks the protected envelope before use.
- Manual save, autosave, export, graph-to-prompt, direct queue, partial
  execution, root-graph serialization, and nested-subgraph serialization use
  the shared settlement barrier.
- Settlement timeout, adapter read/write mismatch, unknown fields, and forged
  authorization all fail closed with fixed error codes.

## Disposable ComfyUI evidence

- The isolated instance started with only the synthetic custom node enabled.
- `GET /helto_privacy/ui/privacy_snapshot.js` returned `200`, JavaScript content
  type, and `Cache-Control: no-cache`.
- The served module was byte-identical to the checked-out
  `helto_privacy/web/privacy_snapshot.js` source.
- The built wheel contains `privacy_client.js`, `privacy_profile.js`, and
  `privacy_snapshot.js`.

The in-app browser could not attach a disposable test tab after two attempts,
so no browser-runtime claim is made for this run. The coordinator behavior was
instead exercised in Node as an ES module, including the ComfyUI-shaped graph
and queue barriers. A fresh browser smoke remains part of the coordinated
consumer cutover acceptance run.
