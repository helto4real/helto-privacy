# Private records and redaction validation

Validated 2026-07-11 against the local `helto-privacy` checkout, Python 3.13.14,
and the Codex in-app browser. All record identifiers, envelopes, projections,
values, paths, tokens, and mutations were disposable synthetic fixtures. The
run did not load the user's ComfyUI service, workflows, media, queue, history,
keystore, browser profile, caches, or credentials.

## Automated evidence

- The complete Python and JavaScript suite passed: 174 tests.
- Locked listing calls only the store adapter's opaque-ID seam and returns the
  exact shell `{id, kind, private: true, label: "Private record"}`. It never
  calls record read, decrypt, or projection code.
- Record IDs are minted by the shared `hp-rec-*` generator; bare hashes,
  UUID-shaped consumer data, and consumer-authored slugs are rejected without
  appearing in errors or diagnostics.
- Reveal requires a current `record.<operation>` authorization, stable bound
  mode scope, a declaration-authorized operation, successful decryption, and a
  JSON-safe top-level projection contained by that exact operation's allowlist.
- Projection, decrypted mutable plaintext, and adapter-retained mutable
  plaintext are cleared after success or failure. Read, decrypt, projection,
  and adapter failures collapse to stable product-data-free error codes with
  fresh correlation IDs.
- Delete and protected replacement remain available while locked, require an
  immutable one-use confirmation bound to the exact mutation, and do not read
  or decrypt the old record. Replacement rejects plaintext and accepts only a
  structurally current encrypted envelope.
- The server and browser expose only fixed typed list, reveal, delete, and
  replace routes. Generic operations cannot target record resources, and there
  are no duplicate, merge, or edit escape hatches.
- Private response defaults use `private, no-store`, disable referrers and MIME
  sniffing, vary on privacy authorization state, emit opaque correlation IDs,
  and provide only generic download filenames. Diagnostics accept only coarse
  allowlisted stages, counts, and flags.

## In-app browser evidence

A disposable localhost server exposed the checked-out browser modules under
their canonical route layout and returned one synthetic attested profile. Its
record-list response deliberately included a private name, path, timestamp, and
replacement label as redaction canaries.

- The shared browser runtime connected the exact profile and returned only the
  four-field generic locked shell; no canary appeared in rendered page text.
- The typed handle completed one declared reveal and confirmed delete and
  replacement requests. The server verified the exact destructive-confirmation
  header before accepting either mutation.
- Both Helto-styled confirmation modals were generic and contained neither
  record ID nor record kind; cancel held initial focus and destructive actions
  used the danger treatment.
- A second destructive confirmation atomically cancelled and resolved the
  first, left exactly one modal, and completed without a hanging caller.
- A generic `invoke("record.edit")` call and an undeclared `merge` reveal were
  rejected before transport.
- The page reported `PASS — shell, reveal, delete, and replace verified`.
  There were no application console errors; the only warning was
  Electron's expected content-security-policy warning for the disposable page.

The browser tab and server were stopped and the temporary fixture was removed.
Dependent node packs still require their coordinated consumer-specific record
acceptance tests during cutover.
