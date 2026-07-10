# Map per-consumer cutover slices

Type: research
Status: resolved
Blocked by: 06, 07

## Question

How does each current privacy implementation in `comfyui-utils`,
`comfyui-all-on-one-image-generation-node`, `comfyui-helto-director`, and
`comfyui-helto-smartprompt` map to the approved privacy profile declarations,
narrow product adapters, shared bound handles, and obsolete code that must be
deleted?

Produce an implementation-slice matrix that identifies the server and browser
profile entries, real adapter seams, shared capability dependencies, legacy
reader dependencies, consumer-local deletions, and cross-repository ordering
edges for every inventoried privacy surface. Do not implement the migration.

## Answer

Research asset: [Per-consumer privacy cutover slices](../research/per-consumer-cutover-slices.md)

The coordinated cutover requires seven shared-package prerequisites: the
contract/profile runtime; server-authoritative mode, authorization, and browser
client; workflow snapshot/barrier/execution; records and redaction; managed
artifacts and serving; legacy readers/key import/migration audit; and shared
pack-state plus contract-test mechanics. They may be implemented internally in
increments, but consumers activate the fixed privacy contract suite atomically
and never negotiate a weaker subset.

The four consumer migrations decompose into twenty-four slices: eight for
Utils, five for AIO, seven for Director, and four for Smart Prompt. Every slice
identifies its privacy-profile declaration, real product adapters, shared bound
handles, consumer files and mechanics to delete or replace, product behavior to
retain, legacy reader/key dependencies, test movement, and blocking edges.

Utils couples selector workflow state with durable mask migration, moves queue
state and provider secrets behind shared protected persistence, and replaces
all path-bearing private-media tokens with managed artifact leases. AIO moves
Generate/Krea/builder fields through shared snapshots, the Ideogram library
through shared record handles, and run-info through sensitive-by-default safe
projections. Director removes its vendored keystore, duplicate codec/routes/UI,
then moves global mode, timeline state, libraries, caches, media browsing, take
redaction, and spills onto the shared contract while keeping media/domain
adapters. Smart Prompt removes its codec/routes/token/memo/recovery stack and
replaces its unkeyed cache token plus fallback-to-empty execution with shared
snapshots, protected references, grants, and dispatch-time reveal.

The implementation order is replacement before deletion. Shared prerequisites
land first; a consumer's complete immutable server/browser profile and all
required adapters are then validated under one fingerprint; call sites move to
bound handles; only afterward are duplicate privacy implementations deleted.
Legacy units remain installed after cutover until their audit scopes receive
explicit retirement seals, and historical-key pruning stays a later separate
irreversible action. The artifact's dependency DAG is the input to
**Define the coordinated migration and release**.
