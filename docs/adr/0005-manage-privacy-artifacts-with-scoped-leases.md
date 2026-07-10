# Manage privacy artifacts with scoped leases

`helto-privacy` owns privacy-artifact storage, four enforced retention classes,
purpose validation, retirement, sweeping, and authenticated serving through
server-held opaque leases plus the current privacy session. Generated private
data is atomically encrypted before filesystem exposure, is never staged in a
named plaintext file, and is served through bounded private streams; this
replaces path-bearing URLs and consumer-defined cleanup while preserving
consumer ownership of allowed roots, payload formats, cache keys, and domain
regeneration.
