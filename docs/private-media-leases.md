# Private media leases

Private previews and authorized existing-file views use the same shared
artifact route. A consumer supplies media bytes or an allowed-root validator;
`helto-privacy` owns encrypted storage, publication, opaque leases, authenticated
streaming, revocation, expiry, cleanup, and restart recovery.

`ArtifactPublicationService` is the node-producer composition seam. One service
coordinates every preview kind on a bound artifact resource, returns only opaque
artifact references, retires replacements, and invokes owner release or startup
sweep exactly once. Retiring any artifact also revokes every server-held lease
for that reference, including a stream already in progress. The browser's
attested artifact handle exchanges the reference for its operation-scoped
preview lease.

Multi-item previews use `write_group()` and `retire_group()`. Each item gets a
distinct served-transient owner so retention never invalidates a sibling, while
replacement revokes the complete prior reference set under one ledger lock.
If deleting ciphertext is interrupted, the ledger still forgets the complete
old group so its references become unreadable immediately; startup orphan sweep
finishes the physical cleanup.

Durable producers that may discover several artifacts for one logical owner use
`ArtifactHandle.reconcile_owner(kind, owner_id, keep=(reference, ...))`. The
shared ledger first proves every kept reference is a current, authoritative
artifact for that exact pack, resource, kind, and owner, then retires every
other matching artifact, including durable adjuncts. Duplicate, foreign,
missing, cleanup-pending, and stale kept references reject the whole operation
without partial reconciliation. The result is only a retired count; paths and
loser identifiers are never returned. Revocation is committed before physical
deletion, so cleanup failures and interruptions remain unreadable and retryable
through the normal reconciliation or sweep path.

`RunScopedArtifactPublicationService` is the pause/replay spill seam. It opens
one exactly-once cleanup session over `ArtifactHandle.run()`, sanitizes
read/write/cleanup failures, invalidates every reference when the session
closes, and leaves interruption recovery to the shared startup sweep. A
run-scoped spill may declare no browser operation because it is read only by its
own server-side run; all other retention classes must still declare at least one
typed lease operation. The run captures server-resolved mode once. Private,
missing, inherited, or malformed declarations use the encrypted `.hpa` path;
only explicit public mode uses an opaque plaintext `.spill` with `0600` file and
`0700` directory permissions. Public spills remain ledger-bound and
process-epoch-stale, never receive browser leases, and are swept with encrypted
spills before readiness. Active runs block scope transitions, while cleanup
continues after lock. Failed public-spill cleanup keeps the run admitted, marks
the ledger entry cleanup-pending, blocks reads and mode transitions, and permits
an explicit cleanup retry before admission is released.

Non-spill artifacts capture the stable effective mode on write. Private values
use authenticated `.hpa`; public values use the exact digest-checked `.hpu`
container without consulting the keystore. The ledger owns the full `.hpu`
SHA-256, and a public lease retains the validated no-follow descriptor identity
until consumption so a path replacement invalidates the lease. Durable
adjuncts keep their opaque
reference while a non-destructive transition stages and verifies the opposite
representation. Regenerable caches and served transients instead stage logical
retirement and regenerate in the target mode after commit. Public leases remain
typed, opaque, one-use, revision-bound, and restart-local, but do not require a
privacy session. Declaration drift, staged entries, or ledger/file mode drift
blocks without trying the other representation.

`stream-v1` declarations are limited to run-scoped spills, regenerable caches,
and served transients. Durable adjuncts still use `bounded-bytes-v1`: their mode
transition preserves the reference by converting between private and public
representations, and the shared service does not yet provide a bounded
stream-to-stream durable conversion. Rejecting that declaration in both the
server profile and browser attestation keeps an impossible transition contract
from reaching runtime. Regenerable and served stream artifacts remain safe
because mode transition retires them instead of converting them.

`RootBoundSourceLeasePublisher` is the existing-file seam. Consumers remain
responsible for deciding which roots and media formats are valid and return a
`root_bound_source(...)` descriptor. Only path-free lease data crosses to the
browser. On use, the shared service opens the resolved root and every descendant
with directory-relative, no-follow descriptors, verifies the original inode,
accepts only regular files, and reads one bounded chunk at a time. It creates no
artifact copy and never materializes the full source.

Browsers use `resolveArtifactLeaseURL()` from
`/helto_privacy/ui/privacy_artifacts.js`. It accepts exactly
`{url, expiresInSeconds}` with a canonical `/helto_privacy/artifacts/hp-lease-*`
URL. Query strings, fragments, paths to original files, names, credentials,
encrypted path tokens, and extra metadata are rejected.

The underlying artifact contract proves the remaining lifecycle properties:
leases are one-use and current-session-bound; lock, restart, expiry, explicit
revocation, and profile invalidation make them unusable; responses use a generic
name with `private, no-store`; streaming is chunked with bounded off-loop work;
route failures are sanitized; and initialization sweeps interrupted transient
state. All proofs use synthetic fixtures only.
