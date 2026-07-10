# Map legacy workflow data and read obligations

Type: research
Status: resolved
Blocked by: none

## Question

Which encrypted values and privacy state are persisted in existing workflows or
pack-managed data across the four consumers, which schemas and formats write
them, and what must a removable legacy read path recognize so those workflows
can still load and decrypt after the coordinated cutover?

Separate stored-data compatibility from consumer source compatibility and
capture the findings as a linked Markdown research asset.

## Answer

Research asset: [Legacy workflow data and read obligations](../research/legacy-workflow-data-and-read-obligations.md)

Stored-data compatibility is limited to bytes already persisted in workflows,
private libraries, Smart Prompt exports, valuable pack state, referenced
selector masks, and historical keys. Consumer Python/JavaScript APIs and route
shapes may change during the coordinated cutover.

AIO and Smart Prompt need read-only codecs bound to their original v1 schemas
plus import of their currently unregistered `config/privacy_key.json` files.
Director needs continuity for its unchanged schema and purpose-bound byte
formats. Utils needs a separate, tightly gated adapter for
`__HELTO_ENC__:` values, `key.bin`/`privacy_key.bin`, `HELTO_PRIV1/2/3`, legacy
queue state, and referenced encrypted masks.

All adapters must be exact-format, fail-closed, observable, and unreachable
from new writes. Historical ciphertext fixtures—not current envelopes with a
mutated schema—are required to prove the read-and-resave path. Secure legacy
key import must also replace the current practice of retaining plaintext key
material in `.migrated` files.
