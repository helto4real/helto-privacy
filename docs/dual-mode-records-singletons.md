# Dual-mode records and singletons

Records and singletons capture their effective privacy mode when written. A
private value uses the existing authenticated encrypted envelope. An explicitly
public value uses an exact versioned public representation and does not require
an unlocked privacy keystore for typed status, mutation, or reveal operations.
Public does not bypass product contracts: records still expose only a declared
reveal projection, singleton payload kinds remain exact, and malformed or
mixed-mode representations fail closed.
Record listing reads revisioned opaque snapshots solely to classify their exact
representation. It never decrypts, and one public/private/malformed drift item
blocks the whole listing instead of producing a misleading shell.

The server resolves mode from the bound scope before every operation. A direct
setting change that differs from established mode blocks the operation; storage
is never reinterpreted from the new declaration. Private operations continue to
require a current operation authorization. Public operations do not require a
privacy-session authorization, because no private reveal is taking place.

## Current representations

- Private record and singleton fields retain their existing current encrypted
  state envelopes.
- Public record and singleton fields use `helto.public-state` version 1 with the
  exact product schema and `private: false`.
- Private singleton blobs retain their current encrypted byte envelopes.
- Public singleton blobs use `helto.public-bytes` version 1 with the exact
  product schema, purpose, and canonical base64url bytes.

No profile declaration changed, so profiles that do not otherwise change keep
the same fingerprint.

## Transition building blocks

The typed record and singleton services expose representation-only transition
building blocks:

1. `prepare_*_mode_transition_value` decrypts or reads the established
   representation, constructs the exact target representation, and changes no
   storage.
2. `classify_*_mode_transition_value` identifies original, target, or divergent
   storage after an interruption without revealing product data;
   `verify_*_mode_transition_value` checks an exact expected disposition.
3. `commit_*_mode_transition_value` persists and reads back the target
   idempotently. Record and singleton commits use adapter-owned cross-process
   revisioned compare-and-swap.
4. `rollback_*_mode_transition_value` restores and verifies the original
   representation idempotently. Both rollback paths compare the exact committed
   snapshot and advance the revision, so they cannot overwrite a concurrent
   newer writer or make an earlier CAS revision reusable.

Prepared objects keep values out of `repr`. The shared transition coordinator
serializes them only inside an authenticated encrypted journal bound to the
pack, exact profile fingerprint, scope, transition identity, prior and target
modes, and the complete ordered participant manifest. The manifest includes
every declared record kind and singleton in the scope, plus server-durable
workflow state, external-browser workflow state, managed artifacts, and the
mode source.

The coordinator plans all participants without mutation, persists the
`preparing` journal, prepares and verifies non-destructively, then persists the
`committing` boundary. Product state, records, singletons, and artifact target
representations commit before the mode source. Failures before prior
representation retirement roll back in exact reverse participant order. Once
retirement begins, recovery completes forward so a removed prior artifact is
never treated as rollback-capable. The mode source is compare-and-set last,
followed by the authoritative scope-state update.

Incomplete journals keep protected operations blocked. Restart classification
either restores the exact prior record, singleton, artifact, and product-state
representations or finishes a retirement-phase transition forward. Journal
publication is revisioned and crash-safe: an encrypted journal revision is
written and authenticated before its digest is installed by scope-state CAS,
and superseded or unreferenced revisions are removed only after the new state
is authoritative.
