# Private execution and grant validation

Validated 2026-07-11 against the local `helto-privacy` checkout, Python 3.13.14,
and the Codex in-app browser. All execution values, envelopes, tokens, grants,
and results were disposable synthetic fixtures. The run did not load the
user's ComfyUI service, workflows, media, keystore, browser profile, caches, or
credentials.

## Automated evidence

- The complete Python and JavaScript suite passed: 157 tests.
- Protected preparation accepts exactly the declared execution fields and
  rejects plaintext, missing fields, malformed envelopes, decrypt failure, and
  reference tampering before product dispatch.
- Preparation validates and copies ciphertext without decrypting or invoking a
  consumer adapter. At dispatch, randomized envelopes for equal semantic
  product state derive the same opaque identity within one session. A fresh
  unlock or primary-key rotation derives a different identity without exposing
  plaintext, paths, ciphertext, or an unkeyed content digest.
- A grant dispatches once. Replay after consumption, lock/unlock, or rotation is
  rejected, and a blocked mode transition prevents product logic from running.
- Lock and profile invalidation revoke pending grants and request cooperative
  cancellation of active work. Mutable plaintext projections are cleared after
  synchronous completion, asynchronous completion, and cancellation.
- Private cache entries are isolated copies held only in process RAM. Unknown
  identities are rejected; lock, session replacement, key rotation, and profile
  conflict clear their partitions.
- The canonical ComfyUI prepare route returns `Cache-Control: no-store` and the
  protected single-use reference. Its tested response contains neither a
  dispatch identity nor semantic plaintext.

## In-app browser evidence

A disposable localhost server exposed the checked-out shared browser modules
under their canonical route layout and returned one synthetic attested profile.
The page used one synthetic node, a fixed protected-envelope string, and a
synthetic session token.

- The shared browser runtime connected the exact profile and installed its
  lifecycle/snapshot boundary.
- `BrowserExecutionHandle.prepare()` settled the edited field and sent exactly
  one request to
  `/helto_privacy/profiles/helto.synthetic/executions/dispatch/prepare`.
- The request contained the declared projection and current protected value;
  the returned value was a protected single-use reference. No semantic identity
  is created in the browser or before backend dispatch.
- A prepare attempt outside an active transaction was rejected. The same call
  inside `runWithSnapshot("direct-queue", ...)` reported `PASS — active snapshot
  produced a ciphertext-only reference`, and the browser console contained no
  errors.

The disposable server and browser tab were stopped and removed after the run.
Dependent node packs still require their coordinated consumer-specific queue
and product-dispatch acceptance tests during cutover.
