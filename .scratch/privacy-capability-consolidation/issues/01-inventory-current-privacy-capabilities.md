# Inventory current privacy capabilities

Type: research
Status: resolved
Blocked by: none

## Question

What privacy-domain capabilities currently exist in `helto-privacy` and each of
the four consumer packs, where do their semantics duplicate or diverge, and
which single-pack capabilities appear to belong to the shared privacy domain?

The inventory must identify owning files, public seams, persisted data touched,
tests, and consumer-specific behavior without deciding the target API. Capture
the findings as a linked Markdown research asset.

## Answer

Research asset: [Current privacy capability inventory](../research/current-privacy-capability-inventory.md)

The inventory found twelve privacy capability families. The shared package
already owns the keystore/session lifecycle, envelope codec, token guard,
canonical keystore UI, and recovery engine, but consumers still duplicate or
extend their semantics through local wrappers and compatibility paths.

The strongest shared-domain candidates are schema-scoped route services, a
general browser privacy client, envelope reuse and fail-closed serialization,
recovery metadata and locked-envelope handling, encrypted artifact lifecycle,
privacy-aware record shells, redaction policy, serialization/queue
coordination, and common contract fixtures. Concrete product state, media
decoding/root policy, and domain normalization remain consumer behavior.

The research also exposed three policy areas large enough for dedicated
decisions: private record/redaction rules, encrypted artifact serving and
cleanup, and privacy-aware workflow/queue serialization.
