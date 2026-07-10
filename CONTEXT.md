# Helto Privacy

Helto Privacy owns reusable privacy-domain behavior for Helto ComfyUI node
packs, including services and UI, while leaving pack-specific product behavior
in each consuming pack.

## Language

**Shared privacy capability**:
A privacy-specific behavior whose contract belongs to `helto-privacy` and can
be reused by consumer packs. Existing duplication is evidence for extraction,
not a prerequisite.
_Avoid_: Common feature, shared feature

**Consumer pack**:
A Helto ComfyUI custom-node package that depends on `helto-privacy` while
retaining its own node schemas and product behavior.
_Avoid_: Consumer repo, client

**Consumer integration**:
Pack-owned adapter code that connects a consumer pack's nodes, routes, or UI to
a shared privacy capability without redefining that capability's semantics.
_Avoid_: Glue, duplicate implementation

**Privacy policy**:
The shared rules that determine when protected data may be written, read,
revealed, served, redacted, migrated, or rejected. Consumer packs describe
where the policy applies but cannot weaken its fail-closed behavior.
_Avoid_: Consumer preference, pack privacy behavior

**Consumer privacy metadata**:
Pack-specific facts describing where private product data exists and how it
maps to product state, such as schema and purpose names, sensitive fields, and
the source of privacy mode. The facts are consumer-specific even when a shared
privacy capability interprets them.
_Avoid_: Privacy policy, shared behavior

**Coordinated cutover**:
A release boundary where `helto-privacy` and all known consumer packs move as
one supported set. Arbitrary mixed versions are not supported, but an
incomplete set must be detected rather than silently degraded.
_Avoid_: Rolling compatibility, independent consumer upgrade

**Legacy workflow data**:
Encrypted state written by an older privacy implementation that must remain
readable until its workflow has been checked and re-saved with the current one.
_Avoid_: Old data, obsolete workflow

**Legacy read path**:
An isolated, removable compatibility path that reads legacy workflow data but
is never used for new writes.
_Avoid_: Backward-compatible implementation, permanent fallback

**Locked record shell**:
The minimal non-decrypting representation of a private record: an opaque
generated ID, record kind, private flag, and fixed generic label. It contains
no consumer-derived descriptive or activity metadata.
_Avoid_: Public record, redacted record copy

**Safe projection**:
A consumer-declared, explicitly allowlisted view that `helto-privacy` validates
before revealing it through an authorized privacy operation. Fields are
sensitive by default; omission from the allowlist means hidden.
_Avoid_: Non-sensitive by assumption, best-effort redaction

**Authorized reveal**:
An explicit use, preview, or details operation that passes shared authorization
before requesting decryption. Listing a locked record is not an authorized
reveal and must never decrypt.
_Avoid_: Private listing, implicit unlock

**Privacy artifact**:
Generated data managed by the shared privacy lifecycle and encrypted at rest
while privacy is authoritative. Existing user-owned source and output files are
not privacy artifacts even when served privately.
_Avoid_: Private file, encrypted cache

**Artifact retention class**:
The shared lifetime category of a privacy artifact: durable adjunct,
regenerable cache, run-scoped spill, or served transient. It defines what owns
the artifact and which event retires it.
_Avoid_: Consumer cleanup policy, arbitrary TTL

**Artifact lease**:
A short-lived server-side binding between an opaque random ID, one artifact,
and an allowed reveal operation. It is usable only with a current authorized
privacy session and contains no path or session credential.
_Avoid_: Media token, signed path, permanent URL

**Plaintext derivative**:
A generated unencrypted cache, preview, spill, or temporary representation of
private data. An original user-owned input or output is not a plaintext
derivative.
_Avoid_: Source media, public artifact

**Privacy snapshot**:
The consumer-normalized private state captured at one edit generation for a
single save or execution transaction. Every protected projection of that
transaction represents the same snapshot.
_Avoid_: Live editor state, serialization pass

**Serialization barrier**:
The shared gate that permits a private save or execution projection only when
its privacy snapshot has a settled protected representation.
_Avoid_: Best-effort flush, serialization hook

**Envelope disposition**:
The operational state of encrypted data: verified current, locked current,
failed current, readable legacy, or unsupported. Structural envelope shape
alone does not determine usability.
_Avoid_: Valid envelope, parse status

**Semantic execution projection**:
The consumer-declared subset of normalized product state that can affect an
execution result. Presentation and editor-only state do not belong to it.
_Avoid_: Full editor state, serialized workflow

**Execution grant**:
A session-bound authorization to dispatch one protected execution snapshot.
Locking or restarting invalidates any grant that has not dispatched.
_Avoid_: Queue token, permanent execution permission

**Declared privacy mode**:
A consumer-normalized setting of `inherit`, `private`, or `public`. New and
missing state inherits the shared private default; only a known explicit
`public` declaration expresses a public opt-out.
_Avoid_: Privacy boolean, effective protection

**Effective privacy mode**:
The server-resolved protection state after applying the private base default,
the declared mode, scoped policy, privacy floors, and captured data state. It is
authoritative for storage, serving, serialization, execution, and UI status.
_Avoid_: UI toggle, request privacy flag

**Privacy floor**:
A private constraint imposed by scoped policy or protected upstream, parent,
record, artifact, or execution state. A floor may be strengthened but cannot be
weakened by a local declaration or request.
_Avoid_: Default mode, inherited preference

**Declassification**:
An authorized all-or-nothing transition from private to public that rewrites
protected storage and retires protected derivatives. Setting a public
declaration alone does not declassify existing data. Each attempt consumes
fresh warning-confirmation evidence bound to its session, pack, scope, and
target.
_Avoid_: Disable privacy, plaintext fallback

**Protection transition**:
An all-or-nothing change of effective privacy mode that establishes the target
storage and artifact state before reporting success. An incomplete transition
blocks affected operations rather than advertising unverified protection.
_Avoid_: Toggle, best-effort migration

**Privacy contract suite**:
The versioned, coherent set of shared privacy capabilities and invariants that
all consumer packs activate together. It is adopted as a whole rather than
assembled or weakened per consumer.
_Avoid_: Capability menu, optional privacy features

**Privacy profile**:
A consumer-owned immutable declaration of the product facts and adapter slots
that place one consumer pack's protected state within the privacy contract
suite. It describes product meaning but does not define privacy policy.
_Avoid_: Central consumer catalog, consumer privacy policy

**Product adapter**:
A consumer-owned implementation at a declared seam that locates, transforms,
persists, or invokes product state without deciding privacy policy.
_Avoid_: Privacy plug-in, policy callback, escape hatch

**Migration obligation**:
A discovered legacy item that must be verified in the current format before its
legacy reader may become removal-eligible.
_Avoid_: Migration warning, legacy hit

**Migration receipt**:
Protected evidence that one migration obligation was rewritten and read back
successfully through the current privacy contract.
_Avoid_: Save attempt, legacy read log

**Legacy audit scope**:
The user-declared set of workflows, libraries, exports, and pack state whose
legacy data must be checked before retirement.
_Avoid_: Automatic workflow inventory, inactivity window

**Retirement seal**:
Explicit user attestation that a legacy audit scope is complete and has no
unresolved migration obligations. A later legacy read invalidates the seal.
_Avoid_: Automatic expiry, last-used timestamp

**Historical key pruning**:
The explicit irreversible removal of a wrapped decrypt-only historical key
after every dependent legacy reader has been retired. It is separate from both
reader removal and plaintext source-key cleanup.
_Avoid_: Automatic key cleanup, reader deletion

**Legacy reader unit**:
One independently detectable legacy format and the complete support needed to
read, audit, verify, and later remove it. Container units declare dependencies
on any byte-format units they may dispatch to.
_Avoid_: Compatibility layer, bundled legacy mode

**Supported release set**:
The exact five-repository combination recognized as one compatible Helto
privacy installation. Versions outside that combination are not inferred to be
compatible.
_Avoid_: Version range, rolling compatibility

**Suite manifest**:
The immutable identity of a supported release set, binding its contract,
repository releases, profile fingerprints, artifacts, environment bounds, and
digest.
_Avoid_: Compatibility table, latest versions

**Cutover-pending suite**:
An exact, immutable five-repository release candidate whose artifacts may be
installed for verification but cannot be activated. Failure produces a new
suite ID rather than modified artifacts.
_Avoid_: Prerelease dependency range, partially supported release

**Ready suite**:
A cutover-pending suite promoted for activation only after all declared
artifacts, hashes, profile fingerprints, and clean-install acceptance evidence
match its manifest digest.
_Avoid_: Latest release, individually compatible packages

**Active installation**:
A ready suite whose exact installed bytes passed verification and whose manifest
digest was explicitly activated. It is the only runtime state permitted to
perform privacy-bearing writes or execution.
_Avoid_: Installed package, ready release

**Blocked installation**:
An installed suite whose artifacts are incomplete, mismatched, or conflicting.
It preserves encrypted data, exposes only product-data-free repair status, and
permits no privacy-bearing operation or fallback implementation until the exact
declared suite is restored and verified.
_Avoid_: Degraded mode, best-effort compatibility

**Verification mode**:
The pre-activation state of a newly installed supported release set, allowing
readiness checks and migration preflight without permitting privacy-bearing
writes or execution.
_Avoid_: Dry run, partial activation

**Suite activation**:
The explicit authorized act that binds a ready installation to its suite
manifest and enables its writers. It is the boundary after which rollback
requires restoring pre-activation data.
_Avoid_: First start, automatic upgrade

**Operator-blind maintenance**:
Installation, verification, backup, repair, and rollback operations that may
inspect public manifests, digests, envelope headers, and opaque key identifiers
or copy encrypted bytes, but never disclose plaintext user data or secret key
material to the installer, operator, or agent. A dedicated maintenance
capability omits reveal, decrypt, key-export, and live payload-test operations;
an agent is never issued a reveal-capable handle. Payload decryption remains an
authorized operation inside the privacy runtime and is not a maintenance probe.
_Avoid_: Privileged maintenance, decrypt to verify

**Acceptance catalog**:
The versioned set of evidence obligations a supported release set must satisfy.
Any skipped, waived, flaky, or failing obligation prevents the suite becoming
ready.
_Avoid_: Test checklist, best-effort matrix

**Acceptance evidence manifest**:
The immutable attestation that one exact suite candidate satisfied every
acceptance-catalog obligation across its declared environment matrix.
_Avoid_: CI report, green build

**Historical ciphertext fixture**:
A compatibility artifact emitted by an exact historical writer from synthetic
state and a test-only key, with reproducible source provenance and an expected
normalized result.
_Avoid_: Mock ciphertext, schema-swapped envelope

**Clean suite installation**:
An isolated installation resolved only from one suite manifest's declared
artifacts and metadata, without importing a workspace checkout, existing
privacy state, or browser cache.
_Avoid_: Developer environment, package-backed enough

**Supported environment tuple**:
One exact Python, ComfyUI backend, frontend package, and renderer combination
whose complete acceptance catalog has passed for a supported release set.
_Avoid_: Version range, assumed compatible environment

**Leak oracle**:
The acceptance authority that tracks unique synthetic private canaries and
fails when one appears outside the exact observation authorized for an
operation. Secret key bytes are never an authorized observation.
_Avoid_: Log scan, best-effort redaction test

**Rendered acceptance run**:
A browser-level proof of one supported environment tuple and renderer using
only isolated ComfyUI state, an isolated browser session, and synthetic privacy
fixtures.
_Avoid_: Live smoke test, manual UI check

**Installation verification**:
The operator-blind local proof that installed artifacts match one ready suite
and its activation prerequisites, without decrypting user payloads. It is not
suite acceptance and does not activate writers.
_Avoid_: Live acceptance test, automatic activation

**Acceptance harness**:
The shared `helto-privacy` machinery that executes the acceptance catalog and
collects evidence while consumers contribute only real product profiles,
adapters, and semantic fixtures.
_Avoid_: Consumer test framework, copied policy suite

**Fault campaign**:
A reproducible acceptance run that injects deterministic failures across a
privacy transaction and proves original-byte authority, cleanup, and absence of
partial success or disclosure.
_Avoid_: Chaos test, retry loop
