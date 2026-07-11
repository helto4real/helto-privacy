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
