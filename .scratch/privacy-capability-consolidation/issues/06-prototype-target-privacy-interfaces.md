# Prototype the target privacy interfaces

Type: prototype
Status: resolved
Blocked by: 04, 05, 10, 11, 12, 13

## Question

What should the target `helto-privacy` module, service, browser UI, and consumer
integration interfaces look like when applied to representative capabilities
from all four packs?

Use `/codebase-design`, `/design-an-interface`, and `/prototype` to produce
contrasting concrete interface shapes for live human evaluation. The artifact
must expose ownership, lifecycle, error handling, and persisted-data seams
without implementing production behavior. It must also expose the shared
protocol/capability check and the order-independent ComfyUI registration seam.
Use consumer-owned thin registrations; do not prototype a central production
catalog of the four current packs.

## Comments

Prototype assets:

- [Target privacy interface designs](../prototypes/target-privacy-interfaces/DESIGNS.md)

Three radically different seams were prototyped against order-independent
bootstrap, Utils selector state and masks, AIO private prompt records, Director
privacy floors and media leases, and Smart Prompt legacy state plus queued
execution:

1. A minimal manifest with one closed `perform(Intent)` command port.
2. A flexible typed capability graph compiled into granular handles.
3. An atomic pack profile compiled into bound workflow, record, and artifact
   handles.

The recommended design is the atomic pack profile. It activates one fixed,
strict contract as a coherent bundle, keeps ordinary adoption declarative, and
returns discoverable typed handles without exposing a large capability graph.
Internally it retains immutable profile fingerprints and exact browser/server
contract attestation. It has no generic custom-operation escape hatch and no
consumer-selectable privacy policy.

The user approved the recommended atomic pack-profile design. The throwaway
terminal comparison shell was removed after this verdict was captured.

## Answer

The target interface is an atomic, consumer-owned privacy profile compiled by
`helto-privacy` into a bound pack interface. One `install(profile, adapters)`
entry point validates and fingerprints the complete server profile, activates
the fixed shared privacy contract suite, and returns typed workflow, record,
artifact, authorization, readiness, and execution handles. The browser uses one
`connectPrivacyPack(...)` entry point to attest to the same contract and profile
fingerprint, bind product editor adapters, attach shared ComfyUI lifecycle hooks,
and mount shared privacy UI.

The privacy profile declares product facts only: stable consumer and resource
IDs, privacy scopes and mode sources, protected node/field locations, current
schemas and purpose IDs, legacy reader IDs, record kinds, artifact kinds and
retention classes, protected domain operations, semantic execution projections,
and required product adapter slots. The private base default, mode precedence,
authorization, encryption, record-shell shape, redaction, error mapping, leases,
grants, cleanup, recovery, transitions, and serialization barriers are fixed by
the shared contract and cannot be configured by a consumer.

Product adapters exist only at real seams: locating and normalizing product
state, applying authorized revealed state, persisting opaque record data,
encoding or decoding product payloads, validating allowed source roots,
declaring semantic execution projections, and invoking product logic after
successful shared resolution. There is no generic custom-operation adapter,
consumer policy hook, raw codec, decrypt function, token checker, shell builder,
or lease/grant issuer.

Registration is atomic, immutable, and independent of ComfyUI load order. The
profile is recorded before or after PromptServer becomes available; the shared
runtime attaches one generic route and hook family when possible and reconciles
existing plus future node definitions. Identical fingerprints are idempotent;
conflicts, missing adapters, incompatible suites, and browser/server drift leave
the consumer visibly blocked. Private operations never run against a partial or
unverified profile.

Legacy formats are named by profile bindings but implemented as isolated shared
readers with no write interface. A successful legacy read produces normalized
in-memory product state and the next write uses the current contract. Reader
selection, historical-key access, re-save observability, and later deletion
remain shared lifecycle behavior rather than consumer crypto adapters.

The minimal `perform(Intent)` design was rejected because its large intent union
hides discoverability behind a nominally tiny method. The granular capability
graph was rejected because the coordinated five-repository cutover does not need
consumer-assembled capability sets, cross-language slot proliferation, or a
permanent capability-version matrix. The chosen profile retains the graph's
immutable fingerprinting and the minimal design's closed resource vocabulary
without exposing either design's larger misuse surface. The durable rationale is
recorded in
[ADR 0008](../../../docs/adr/0008-compile-atomic-privacy-profiles.md).
