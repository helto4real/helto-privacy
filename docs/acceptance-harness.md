# Cross-repository acceptance harness

`helto-privacy` owns the release-gate vocabulary and evidence verifier for the
coordinated five-artifact suite. The built-in catalogs are:

- `helto_privacy/acceptance/data/catalog-v2.json`
- `helto_privacy/acceptance/data/historical-fixtures-v1.json`

The acceptance catalog declares stable evidence IDs, exact supported
Python/ComfyUI/frontend/renderer tuples, fixture bindings, owning layers, and
the only observation sinks authorized for each case. Changing a requirement or
environment creates a new catalog version; a release must not rewrite a
published version.

## Zero-waiver evidence

`AcceptanceRunner` executes one case for every catalog ID. It records sanitized
observation digests, warnings, error logs, skips, xfails, and deterministic
fault results. `verify_acceptance_evidence()` accepts a manifest only when:

- it is Ed25519-signed and bound to the exact suite-manifest digest;
- artifact and source identities exactly equal the five suite artifacts;
- every declared environment and all 24 consumer registration orders ran;
- every catalog evidence ID passed once with no retry;
- there are no skips, xfails, warnings, errors, or support exclusions.

`ContractAdapterCase` additionally requires a real adapter to report the
compiled shared handle it reached. Consumer source/artifact scans use
`scan_consumer_privacy_duplication()` to reject local crypto, token authority,
privacy route, or vendored fallback implementations.

`installation.production-bootstrap` starts from only the five public artifacts
plus detached signed suite records. It must use the packaged trust roots and
consumer declarations—not a test-only bootstrap—connect a real browser in
verification mode, and prove the process changes from `ready` to
`activation-required` without activation or access to live product data.

## Synthetic-only leak and fault testing

Acceptance uses unique `SyntheticCanary` values. `CanaryLeakOracle` scans all
reported sinks and rejects a product canary outside its requirement's explicit
allowlist. Key canaries are forbidden in every sink, including otherwise
authorized sinks.

The harness and agents must never inspect a user's workflows, keys, browser
profile, queue/history, media, or live ComfyUI service. Rendered tests use a
disposable instance and synthetic data. `DeterministicFaultController` records
its seed and supports both normal exception and `BaseException` cleanup paths.

## Historical fixture reproducibility

The committed fixtures contain public synthetic values only. Each catalog
entry records its pinned producer repository/commit/function, reader, schema,
purpose, deterministic test-key derivation, ciphertext digest, normalized-state
digest, generator command, and the digest of
`generator-environment-v1.json`. Tamper/truncation cases are explicitly `derived`
and point to their historical source.

From a source checkout, verify byte-for-byte reproducibility with:

```bash
python -m helto_privacy.acceptance.generate_fixtures --check
```

Regeneration reproduces the pinned historical writer algorithms with fixed
public test keys and nonces. It reads no runtime configuration or user data.
Any output change requires a reviewed new fixture/catalog version.
