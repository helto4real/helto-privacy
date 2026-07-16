# Release exact suites through verification and activation

`helto-privacy` and its four consumers ship as one exact signed supported release
set whose immutable suite manifest is the sole compatibility authority. Five
fixed artifacts are published first as `cutover-pending` and become `ready` only
after their hashes, profile fingerprints, clean-install environment, and
cross-repository acceptance evidence match; failed candidates receive new suite
IDs rather than mutated artifacts. A ready suite first starts in operator-blind
verification mode, where an untrusted agent has no decrypt, reveal, key-export,
or live payload-test capability, and only explicit authorized activation enables
current writers and establishes the data rollback boundary. Installation and
recovery use `cui-stop` and `cui-start`, plus a full browser reload; incomplete
or mismatched sets block every privacy-bearing operation without local, legacy,
or plaintext fallback. Floating compatibility ranges, rolling mixed releases,
automatic first-start activation, hot reload, and partial rollback were rejected
because each could create an unverifiable or fail-open privacy runtime.

The signed manifest and promotion are detached from the five artifacts to avoid
self-referential artifact hashes. The shared wheel embeds only stable manifest
and promotion trust roots plus a generic fail-closed loader. Each consumer
embeds the immutable suite ID, while the detached signed manifest binds that ID
to the exact five artifact hashes and four live profile fingerprints. The
operator-installed process configuration supplies only local artifact paths and
the interpreter/backend/frontend identity. The exact browser renderer is
attested by the loaded fixed browser module and matched to a signed environment
tuple; neither source can change signed identities.
