# Historical privacy fixtures

These fixtures contain only synthetic test data. They were produced by running
the named historical writer from the exact commit recorded in each JSON file,
with a deterministic test key and nonce. No live workflow, user configuration,
runtime key, or browser state was read.

The state fixture digest is SHA-256 over canonical JSON for the complete
encrypted envelope. The export digest covers the complete canonical package.
Tests verify these digests before using a fixture.

Sources:

- AIO field and prompt-builder state: `services/privacy.py:encrypt_state` at
  `3e3e656a4b0dd9b40535a900b2f198264b21b0c1`.
- Smart Prompt state: `privacy.py:encrypt_state` at
  `b2db6fffbb1653f266f0c32982dbb8f5d7096b8c`.
- Smart Prompt export: `web/js/smart_prompt_manager.js:buildSpmExportPackage`
  at `b2db6fffbb1653f266f0c32982dbb8f5d7096b8c`.
- Director state: `shared/privacy.py:encrypt_state` at `73b7255`. Director's
  envelope schema already matches the shared current reader, so only its
  historical key import is required.

The key derivation labels are deliberately public and fixture-specific. These
keys must never be used outside tests.
