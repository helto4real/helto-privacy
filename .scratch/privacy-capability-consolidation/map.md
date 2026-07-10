# Consolidate privacy capabilities in helto-privacy

## Destination

Produce an implementation-ready consolidation specification for
`helto-privacy` and its four consumer packs: decide what privacy behavior moves
here, define the target contracts and removable legacy read paths, and chart a
coordinated migration, verification, and release sequence.

## Notes

- Scope is strictly privacy behavior. General theming, route utilities, and
  test infrastructure are out of scope unless they exist specifically to
  enforce a privacy contract.
- Current consumer packs are `comfyui-utils`,
  `comfyui-all-on-one-image-generation-node`, `comfyui-helto-director`, and
  `comfyui-helto-smartprompt`.
- A capability may qualify for shared ownership even if only one current
  consumer implements it.
- Privacy services and UI belong in `helto-privacy` whenever shared ownership
  improves reuse or consistency. Consumers retain genuinely pack-specific
  product behavior and the minimum integration required to describe it.
- Consumer source APIs may change. All four consumer packs will move through a
  coordinated cutover rather than support arbitrary mixed versions.
- Existing encrypted workflow data must still load and decrypt. New writes use
  replacement contracts, while isolated legacy read paths remain removable
  after workflows have been checked and re-saved.
- This map plans and decides; it does not implement the package or consumer
  migrations.
- Sessions should consult `/wayfinder` and `/domain-modeling`. Use `/research`
  for cross-repository inventories and `/codebase-design` plus
  `/design-an-interface` when shaping the target interfaces.
- Domain vocabulary lives in [`CONTEXT.md`](../../CONTEXT.md). Compatibility
  and ownership boundaries are recorded in
  [`ADR 0001`](../../docs/adr/0001-coordinate-api-breaks-preserve-workflow-data.md)
  and
  [`ADR 0002`](../../docs/adr/0002-own-reusable-privacy-services-and-ui.md).
  Consumer metadata placement is recorded in
  [`ADR 0003`](../../docs/adr/0003-keep-consumer-privacy-metadata-with-consumers.md),
  and the private-record shell and redaction contract in
  [`ADR 0004`](../../docs/adr/0004-use-minimal-private-record-shells.md).
  Privacy-artifact lifecycle and serving are recorded in
  [`ADR 0005`](../../docs/adr/0005-manage-privacy-artifacts-with-scoped-leases.md),
  and private serialization and execution coordination in
  [`ADR 0006`](../../docs/adr/0006-coordinate-private-serialization-with-snapshots.md).
  Privacy-mode authority and the private-by-default policy are recorded in
  [`ADR 0007`](../../docs/adr/0007-default-private-and-resolve-mode-server-side.md).
  The target consumer and browser interface shape is recorded in
  [`ADR 0008`](../../docs/adr/0008-compile-atomic-privacy-profiles.md).
  Legacy-reader migration evidence and retirement are recorded in
  [`ADR 0009`](../../docs/adr/0009-retire-legacy-readers-with-sealed-audits.md).
  Exact release-set publication, operator-blind verification, and explicit
  activation are recorded in
  [`ADR 0010`](../../docs/adr/0010-release-exact-suites-through-verification-and-activation.md).
  The zero-waiver synthetic acceptance gate and evidence boundary are recorded
  in
  [`ADR 0011`](../../docs/adr/0011-gate-release-readiness-on-complete-synthetic-evidence.md).

## Decisions so far

<!-- Closed ticket titles and one-line decision gists are appended here. -->

- [Inventory current privacy capabilities](issues/01-inventory-current-privacy-capabilities.md) — Twelve capability families expose duplicated route/client, serialization, recovery, artifact, private-record, redaction, and test semantics around the already-shared crypto foundation.
- [Map legacy workflow data and read obligations](issues/02-map-legacy-workflow-data.md) — Preserve persisted bytes through exact read-only adapters: original AIO/Smart schemas, unchanged Director bindings, and Utils prefix/binary generations, with historical-key import, golden fixtures, observable re-save, and no legacy writes.
- [Map release and installation coupling](issues/03-map-release-and-installation-coupling.md) — One installed privacy runtime serves every consumer, so the cutover must align pins/capabilities, remove fail-open dependency behavior, tolerate any load order, and identify one verifiable five-repository release set.
- [Place consumer-specific privacy metadata](issues/04-place-consumer-specific-privacy-metadata.md) — Consumer packs own thin registrations of product facts and adapters; `helto-privacy` owns the versioned contract, validation, lifecycle, registry, privacy behavior, and generic UI without a production catalog of pack details.
- [Select shared capabilities and ownership](issues/05-select-shared-capabilities-and-ownership.md) — `helto-privacy` owns privacy policy and lifecycle mechanics across backend and UI; consumer integrations own only product meaning, metadata, transformations, and domain behavior at a narrow seam.
- [Define private record shells and redaction](issues/10-define-private-record-shells-and-redaction.md) — Locked shells are minimal and never decrypt; private data is sensitive by default, only explicitly allowlisted projections may be revealed after authorization, and undecryptable records remain listable and deletable while all use fails closed.
- [Define encrypted artifact lifecycle and serving](issues/11-define-encrypted-artifact-lifecycle-and-serving.md) — Privacy artifacts use enforced retention classes, encrypted atomic storage, current-session plus opaque scoped leases, streaming private responses, and interruption-safe retirement without plaintext staging or path-bearing URLs.
- [Define privacy-aware serialization and execution](issues/12-define-privacy-aware-serialization-and-execution.md) — One fail-closed privacy snapshot feeds workflow and execution projections through a graph-wide barrier, with byte-preserving locked saves, verified dispatch-time decrypt, session-keyed semantic identities, and revocable private execution grants.
- [Define privacy-mode authority and defaults](issues/13-define-privacy-mode-authority-and-defaults.md) — Private is the canonical default; explicit public is a durable opt-out only without a privacy floor, effective mode is resolved server-side, and protection changes are authorized all-or-nothing transitions.
- [Prototype the target privacy interfaces](issues/06-prototype-target-privacy-interfaces.md) — Each consumer supplies one immutable privacy profile plus narrow product adapters; `helto-privacy` atomically compiles the fixed contract suite into typed server and browser handles with exact fingerprint attestation.
- [Define legacy read retirement](issues/07-define-legacy-read-retirement.md) — Exact per-format readers produce protected obligations and only verified all-or-nothing current rewrites produce receipts; explicit user seals permit later reader removal, while wrapped-key pruning remains separate and irreversible.
- [Map per-consumer cutover slices](issues/14-map-per-consumer-cutover-slices.md) — Seven shared prerequisites and twenty-four consumer slices map every privacy surface to atomic profiles, real product adapters, shared handles, deletions, retained domain behavior, legacy dependencies, tests, and release-order edges.
- [Define the coordinated migration and release](issues/08-define-coordinated-migration-and-release.md) — One signed exact five-repository suite publishes in two phases, installs and verifies operator-blind through managed lifecycle commands, activates explicitly at the data rollback boundary, and blocks all incomplete or mismatched privacy operations without fallback.
- [Define cross-repository acceptance](issues/09-define-cross-repo-acceptance.md) — Suite readiness requires complete zero-waiver evidence from genuine synthetic historical fixtures, exact environment tuples, all load orders, leak-oracle and fault campaigns, and isolated rendered scenarios, while live installations remain operator-blind verification only.

## Not yet specified

- Nothing. The implementation handoff is fully specified by the resolved
  capability ownership, profile interface, per-consumer slice DAG, legacy
  retirement, coordinated release, and acceptance tickets.

## Out of scope

- Implementing changes in `helto-privacy` or any consumer pack during this
  wayfinding effort.
- Consolidating non-privacy Helto design-system, generic ComfyUI route, or
  general-purpose test helpers.
- Supporting arbitrary mixed old/new package combinations during rollout.
