# Select shared capabilities and ownership

Type: grilling
Status: resolved
Blocked by: 01, 02

## Question

Which inventoried capabilities should `helto-privacy` own, which behavior is
genuinely pack-specific, and where should each consumer integration boundary
sit?

Judge single-pack capabilities as well as duplicated ones, using privacy-domain
ownership and consistency benefit rather than duplication count alone.

## Answer

The user's standing ownership rule is decisive: privacy services and UI belong
in `helto-privacy` whenever shared ownership improves reuse or consistency,
including useful capabilities that currently exist in only one pack.
Duplication count is evidence, not the ownership test.

The ownership test is semantic: behavior belongs to `helto-privacy` when it
decides whether protected data may be written, read, revealed, served,
redacted, migrated, recovered, or rejected. A consumer pack owns the meaning
and shape of its product state. It supplies consumer privacy metadata and
product transformations across a consumer integration, but it does not
redefine privacy policy or failure behavior.

| Capability group | `helto-privacy` owns | Consumer integration owns |
| --- | --- | --- |
| Keys and envelopes | Keystore/session/token lifecycle, key rotation, strict key lookup, state/byte/chunked codecs, purpose binding, legacy-key import and secure retirement, exact read-only legacy format adapters, and fail-closed errors | Schema and purpose identifiers, locations of historical key/data sources, product plaintext normalization, and when product state should be re-saved |
| Authorization and privacy UI | Token semantics, header/cookie checks, status/setup/unlock/lock/password UI, privacy error classification, bounded unlock retry, and the general browser privacy request module | Product route payload validation and invoking the shared authorization/interface from pack-owned domain routes |
| Schema-scoped encryption routes | Registration, request/response handling, token gating, codec dispatch, parsing, and privacy-safe error mapping | Declaring the schema binding and product state projection; no pack-local encrypt/decrypt route implementation |
| Workflow recovery and serialization | Envelope recognition, canonical comparison, memo/reuse and concurrent-save coordination, failed-envelope tracking, scanning/actions/dialog UI, dirty marking, fail-closed save/queue waiting, and privacy-safe execution identities | Node/field identification, reading and writing product state, ComfyUI widget/property indexing, domain normalization, and product runtime reset behavior |
| Encrypted artifacts and private media | Private writes, byte-purpose enforcement, atomic permissions, authenticated handles/tokens, private serving headers, safe errors, cleanup, and lifecycle enforcement | Allowed roots, cache keys, media/tensor encoding, payload construction, product-specific lifetime classification, and regeneration logic |
| Private records and redaction | Encryption-at-rest mechanics, safe-shell invariants, decrypt authorization, undecryptable-record behavior, generic redaction, and path/log/error/filename minimization | Record schemas, domain validation, sensitive-field declarations, safe product projections, and use/preview behavior after authorized decryption |
| Pack-managed secrets and state | Reusable encrypted-field/blob persistence, strict plaintext migration, and secure file handling | Provider configuration meaning, queue semantics, SQLite/JSON domain schemas, and product-level update rules |
| Privacy-mode enforcement | Fail-closed meaning, explicit-public versus protected-state rules, and consistent enforcement across storage, routes, artifacts, and UI | Declaring which product setting is the mode source and mapping legacy product settings; the exact authority/default policy remains a dedicated decision |
| Contract testing | Canonical historical ciphertext fixtures, isolated keystore/session harnesses, shared interface contract suites, and cross-pack policy assertions | Product normalization, widget mapping, domain route, rendering, and end-to-end integration tests |

Shared UI ownership includes unlock/setup, status, recovery, privacy request
handling, and reusable protected-state behavior. Product editors, timeline
controls, prompt builders, media viewers, and other domain UI remain in their
consumer packs; they cross the shared seam for privacy behavior. General
theming remains outside this map.

The consumer integration seam sits where product-specific state becomes a
privacy operation: the pack supplies product facts, opaque state/bytes, and
domain transformations; the shared module performs the privacy lifecycle and
returns protected data, a private handle, a sanitized result, or a typed
failure. Keystore internals, nonces, browser tokens, retry rules, cleanup rules,
and recovery mechanics must not leak through that interface.

This should produce deep shared modules rather than pass-through wrappers. If
`helto-privacy` were removed, substantial privacy logic would have to reappear
in every consumer. Removing a consumer integration should remove only that
pack's product mapping. The physical home and registration shape of consumer
privacy metadata is deliberately left to **Place consumer-specific privacy
metadata**, and concrete interfaces remain for **Prototype the target privacy
interfaces**.
